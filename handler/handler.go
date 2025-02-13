package handler

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sys/unix"
)

const (
	bufferSize = 65535
	maxWorkers = 400
)

var (
	packetCreateFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packet_create_failures_total",
		Help: "Total number of failed new packet calls",
	})

	packetSerializeFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packet_create_failures_total",
		Help: "Total number of failed packet serialize calls",
	})
	packetSendFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packet_create_failures_total",
		Help: "Total number of failed packet sendto calls",
	})

	packetProcessSuccess = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packet_process_success_total",
		Help: "Total number of successful process packet calls",
	})
	packetReceive = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packet_receive_total",
		Help: "Total number of receive packet  calls",
	})
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

	if err := unix.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("failed to set non-blocking mode: %w", err)
	}

	return run(ctx, fd)
}

func run(ctx context.Context, fd int) error {
	epollFd, err := createEpoll(fd)
	if err != nil {
		return fmt.Errorf("failed to create epoll: %w", err)
	}
	defer unix.Close(epollFd)

	events := make([]unix.EpollEvent, maxWorkers)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			n, err := unix.EpollWait(epollFd, events, -1)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				return fmt.Errorf("epoll wait failed: %w", err)
			}

			for i := 0; i < n; i++ {
				if events[i].Fd == int32(fd) {
					packetReceive.Inc()
					if err := processPacket(fd); err != nil {
						log.Printf("Packet processing error: %v", err)
					}
				}
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
		packetCreateFailures.Inc()
		return
	}
	packet.SwapSrcDstIPv4()

	response, err := packet.Serialize()
	if err != nil {
		packetSerializeFailures.Inc()
		log.Printf("Serialization error: %v", err)
		return
	}

	if err := unix.Sendto(fd, response, 0, raddr); err != nil {
		packetSendFailures.Inc()
		log.Printf("Sending error %s", err)
	}
	packetProcessSuccess.Inc()
}

func createEpoll(fd int) (int, error) {
	epollFd, err := unix.EpollCreate1(0)
	if err != nil {
		epollCreateFailures.Inc()
		return -1, fmt.Errorf("epoll create failed: %w", err)
	}

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fd),
	}

	if err := unix.EpollCtl(epollFd, unix.EPOLL_CTL_ADD, fd, &event); err != nil {
		unix.Close(epollFd)
		return -1, fmt.Errorf("epoll ctl failed: %w", err)
	}

	return epollFd, nil
}

func init() {
	prometheus.MustRegister(packetCreateFailures)
	prometheus.MustRegister(packetProcessSuccess)
	prometheus.MustRegister(packetReceive)
	prometheus.MustRegister(packetSendFailures)
	prometheus.MustRegister(packetSerializeFailures)
}
