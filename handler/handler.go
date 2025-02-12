package handler

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	bufferSize    = 65535 // 使用标准最大IP包大小
	maxRetryCount = 3     // 错误重试次数
)

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, bufferSize)
		},
	}
)

func Start(ctx context.Context) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("failed to create RAW socket: %w", err)
	}
	defer unix.Close(fd)

	if err := configureSocket(fd); err != nil {
		return err
	}

	return run(ctx, fd)
}

func configureSocket(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("failed to set IP_HDRINCL flag: %w", err)
	}
	return nil
}

func run(ctx context.Context, fd int) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			buffer := bufferPool.Get().([]byte)
			length, raddr, err := unix.Recvfrom(fd, buffer, 0)
			if err != nil {
				bufferPool.Put(buffer)
				log.Printf("socket read error from %v: %v", formatSockaddr(raddr), err)
				continue
			}

			go func(data []byte, sa unix.Sockaddr) {
				defer bufferPool.Put(buffer)
				if err := handlePacket(fd, data[:length], sa); err != nil {
					log.Printf("Packet handling error: %v", err)
				}
			}(buffer, raddr)
		}
	}
}

func handlePacket(fd int, data []byte, raddr unix.Sockaddr) error {
	packet, err := NewPacket(data)
	if err != nil {
		return fmt.Errorf("packet parsing error: %w", err)
	}

	if srcIP, dstIP, srcPort, dstPort, err := packet.GetInnerAddresses(); err == nil {
		log.Printf("Geneve Inner Packet - Src: %s:%d, Dst: %s:%d",
			srcIP, srcPort, dstIP, dstPort)
	}

	packet.SwapSrcDstIPv4()

	response, err := packet.Serialize()
	if err != nil {
		return fmt.Errorf("serialization error: %w", err)
	}

	for i := 0; i < maxRetryCount; i++ {
		if err := unix.Sendto(fd, response, 0, raddr); err == nil {
			return nil
		}
		log.Printf("retry %d sending to %s failed: %v",
			i+1, formatSockaddr(raddr), err)
	}
	return fmt.Errorf("max retries exceeded sending to %s", formatSockaddr(raddr))
}

func formatSockaddr(sa unix.Sockaddr) string {
	switch addr := sa.(type) {
	case *unix.SockaddrInet4:
		return fmt.Sprintf("%s:%d", net.IP(addr.Addr[:]), addr.Port)
	case *unix.SockaddrInet6:
		return fmt.Sprintf("[%s]:%d", net.IP(addr.Addr[:]), addr.Port)
	default:
		return "unknown address"
	}
}
