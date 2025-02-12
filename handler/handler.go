package handler

import (
	"context"
	"fmt"
	"log"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	bufferSize = 65535
	maxWorkers = 400
)

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, bufferSize)
		},
	}
	semaphore = make(chan struct{}, maxWorkers)
)

func Start(ctx context.Context) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("failed to create RAW socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
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
			if err := processPacket(fd); err != nil {
				log.Printf("Packet processing error: %v", err)
			}
		}
	}
}
func processPacket(fd int) error {
	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	if err := unix.SetNonblock(fd, false); err != nil {
		return fmt.Errorf("set blocking failed: %w", err)
	}

	length, raddr, err := unix.Recvfrom(fd, buffer, 0)
	if err != nil {
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return nil
		}
		return fmt.Errorf("receive failed: %w", err)
	}

	select {
	case semaphore <- struct{}{}:
		go func(data []byte, sa unix.Sockaddr) {
			defer func() {
				<-semaphore
				if r := recover(); r != nil {
					log.Printf("panic in packet handler: %v", r)
				}
			}()

			handlePacket(fd, data, sa)
		}(append([]byte(nil), buffer[:length]...), raddr)
		return nil
	default:
		log.Printf("Worker pool full, dropping packet")
		return nil
	}
}

func handlePacket(fd int, data []byte, raddr unix.Sockaddr) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic during packet handling: %v", r)
		}
	}()
	packet, err := NewPacket(data)
	if err != nil {
		log.Printf("Packet parsing error: %v", err)
		return
	}
	packet.SwapSrcDstIPv4()

	response, err := packet.Serialize()
	if err != nil {
		log.Printf("Serialization error: %v", err)
		return
	}

	if err := unix.Sendto(fd, response, 0, raddr); err != nil {
		log.Printf("Sending error %s", err)
	}
}
