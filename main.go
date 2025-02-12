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
		packet := gopacket.NewPacket(*a.Payload, layers.LayerTypeEthernet, gopacket.Default)
		log.Println(packet.String())
		// 检查数据包的协议类型
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			log.Printf("Packet is UDP")
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			log.Printf("Packet is TCP")
		}
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			log.Printf("Packet is IPv4")
		}
		if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			log.Printf("Packet is IPv6")
		}
		if geneveLayer := packet.Layer(layers.LayerTypeGeneve); geneveLayer != nil {
			log.Printf("Packet is Geneve")
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
