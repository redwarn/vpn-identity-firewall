package handler

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func Start(ctx context.Context) error {
	handle, err := pcap.OpenLive("eth0", 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open failed: %w", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp dst port 6081"); err != nil {
		return fmt.Errorf("BPF filter error: %w", err)
	}

	return run(ctx, handle)
}
func run(ctx context.Context, handle *pcap.Handle) error {
	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			packet, err := source.NextPacket()
			if err != nil {
				if err == pcap.NextErrorTimeoutExpired {
					continue
				}
				log.Printf("failed to read packet: %v", err)
				continue
			}
			p, err := NewPacket(packet)
			if err != nil {
				continue
			}

			p.SwapSrcDstIPv4()

			response, err := p.Serialize()
			if err != nil {
				log.Printf("failed to serialize packet: %s", err)
				continue
			}
			fmt.Println(string(response))
			err = handle.WritePacketData(response)
			if err != nil {
				log.Printf("failed to write response: %v", err)
			}
			log.Printf("[%s] Response packet sent.", time.Now().Format(time.RFC3339))
		}
	}
}
