package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/netlink"
)

func main() {
	config := nfqueue.Config{
		NfQueue:      0,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nfq, err := nfqueue.Open(&config)
	if err != nil {
		log.Fatalf("Failed to open NFQueue: %v", err)
	}
	defer nfq.Close()
	if err := nfq.SetOption(netlink.NoENOBUFS, true); err != nil {
		log.Printf("failed to set netlink option %v: %v\n",
			netlink.NoENOBUFS, err)
		return
	}

	gopacketCallback := func(a nfqueue.Attribute) int {
		id := *a.PacketID

		p := gopacket.NewPacket(*a.Payload, layers.LayerTypeEthernet, gopacket.Default)

		ethernetLayer := p.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			log.Println(string(ethernetPacket.Payload))
			log.Println(string(ethernetPacket.Contents))

			log.Printf("  Source MAC: %s, Destination MAC: %s\n", ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
		}
		nfq.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}
	nfq.RegisterWithErrorFunc(context.TODO(), gopacketCallback, errorFunc)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}
func errorFunc(err error) int {
	// log.Printf("Error: %v", err)
	return 0
}
