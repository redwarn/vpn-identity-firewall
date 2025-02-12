package main

import (
	"fmt"
	"os"

	"github.com/AkihiroSuda/go-netfilter-queue"
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
			layers := p.Packet.Layers()
			for i := 0; i <= len(layers)-1; i++ {
				fmt.Println(layers[i].LayerType())
			}
			p.SetVerdict(netfilter.NF_ACCEPT)
		}
	}
}
