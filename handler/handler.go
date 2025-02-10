package handler

import (
	"context"
	"fmt"
	"log"

	"golang.org/x/sys/unix"
)

const chatPort = 3000

func Start(ctx context.Context) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("failed to create a RAW socket: %w", err)
	}
	defer unix.Close(fd)

	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("failed to set IP_HDRINCL flag: %w", err)
	}

	return run(ctx, fd)
}

func run(ctx context.Context, fd int) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			buffer := make([]byte, 8500)
			length, raddr, err := unix.Recvfrom(fd, buffer, 0)
			if err != nil {
				log.Printf("failed to read UDP message %v", err)
				continue
			}
			packet, err := NewPacket(buffer[:length])
			if err != nil {
				continue
			}

			srcIP, dstIP, srcPort, dstPort, err := packet.GetInnerAddresses()
			if err != nil {
				log.Printf("failed to get inner addresses: %v", err)
			} else {
				log.Printf("Geneve Inner Packet - Src: %s:%d, Dst: %s:%d",
					srcIP, srcPort, dstIP, dstPort)
			}

			packet.SwapSrcDstIPv4()

			response, err := packet.Serialize()
			if err != nil {
				log.Printf("failed to serialize packet: %s", err)
				continue
			}
			err = unix.Sendto(fd, response, 0, raddr)
			if err != nil {
				log.Printf("failed to write response: %v", err)
			}
		}
	}
}
