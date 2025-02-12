package handler

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	bufferSize     = 65535
	maxWorkers     = 20 // 最大并发worker数量
	maxRetryCount  = 3
	receiveTimeout = 100 * time.Millisecond
)

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, bufferSize)
		},
	}
	semaphore = make(chan struct{}, maxWorkers) // 并发控制信号量
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
			if err := processPacket(ctx, fd); err != nil {
				log.Printf("Packet processing error: %v", err)
			}
		}
	}
}
func processPacket(ctx context.Context, fd int) error {
	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	if err := unix.SetNonblock(fd, false); err != nil {
		return fmt.Errorf("set blocking failed: %w", err)
	}

	// 设置接收超时
	tv := unix.NsecToTimeval(receiveTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("set receive timeout failed: %w", err)
	}

	length, raddr, err := unix.Recvfrom(fd, buffer, 0)
	if err != nil {
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return nil // 超时不是错误
		}
		return fmt.Errorf("receive failed: %w", err)
	}

	select {
	case semaphore <- struct{}{}: // 获取worker槽位
		go func(data []byte, sa unix.Sockaddr) {
			defer func() {
				<-semaphore // 释放worker槽位
				if r := recover(); r != nil {
					log.Printf("panic in packet handler: %v", r)
				}
			}()

			handlePacket(fd, data, sa)
		}(append([]byte(nil), buffer[:length]...), raddr)
		return nil
	default:
		log.Printf("Worker pool full, dropping packet from %s", formatSockaddr(raddr))
		return nil
	}
}

func handlePacket(fd int, data []byte, raddr unix.Sockaddr) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic during packet handling: %v", r)
		}
	}()

	start := time.Now()
	defer func() {
		log.Printf("Packet processed in %v", time.Since(start))
	}()

	// 原有处理逻辑...
	packet, err := NewPacket(data)
	if err != nil {
		log.Printf("Packet parsing error: %v", err)
		return
	}

	// if srcIP, dstIP, srcPort, dstPort, err := packet.GetInnerAddresses(); err == nil {

	// log.Printf("Geneve Inner Packet - Src: %s:%d, Dst: %s:%d",
	// 	srcIP, srcPort, dstIP, dstPort)
	// }

	packet.SwapSrcDstIPv4()

	response, err := packet.Serialize()
	if err != nil {
		log.Printf("Serialization error: %v", err)
		return
	}

	for i := 0; i < maxRetryCount; i++ {
		if err := unix.Sendto(fd, response, 0, raddr); err == nil {
			return
		}
		// 指数退避重试
		time.Sleep(time.Duration(1<<uint(i)) * time.Millisecond)
	}
	log.Printf("Max retries exceeded sending to %s", formatSockaddr(raddr))
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
