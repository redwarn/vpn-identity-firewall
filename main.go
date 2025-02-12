package main

import (
	"fmt"
	"os"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

func main() {
	var err error

	nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()

	for true {
		select {
		case p := <-packets:
			PacketLayers := p.Packet.Layers()
			ip := PacketLayers[3].(*layers.IPv4)
			fmt.Println("src_ip: %s dst_ip: %s", ip.SrcIP, ip.DstIP)
			p.SetVerdict(netfilter.NF_ACCEPT)
		}
	}
}
