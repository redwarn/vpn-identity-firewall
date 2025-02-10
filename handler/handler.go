package handler

import (
	"context"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snapLen = 8500
	promisc = false
	timeout = pcap.BlockForever
	device  = "eth0"
)

func Start(ctx context.Context) error {

	handle, err := pcap.OpenLive(device, snapLen, promisc, timeout)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %w", device, err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("udp and port %d", genevePort)
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return run(ctx, handle, packetSource)
}

func run(ctx context.Context, handle *pcap.Handle, packetSource *gopacket.PacketSource) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				if err == pcap.NextErrorTimeoutExpired {
					continue
				}
				log.Printf("failed to read packet: %v", err)
				continue
			}

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					log.Printf("TCP: %s:%d -> %s:%d",
						ip.SrcIP,
						tcp.SrcPort,
						ip.DstIP,
						tcp.DstPort,
					)
				}
			}

			p, err := NewPacket(packet)
			if err != nil {
				log.Printf("Failed to create a packet: %s", err)
				continue
			}
			p.SwapSrcDstIPv4()

			response, err := p.Serialize()
			if err != nil {
				log.Printf("failed to serialize packet: %s", err)
				continue
			}

			if err := handle.WritePacketData(response); err != nil {
				log.Printf("failed to write response: %v", err)
			}
		}
	}
}
