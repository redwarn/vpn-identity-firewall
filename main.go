package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"

	"vpn-identity-firewall/handler"
)

func listenHealthCheck(ctx context.Context, port int) {
	addr := net.TCPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: port,
	}
	listener, err := net.ListenTCP("tcp4", &addr)
	if err != nil {
		log.Panicf("failed to start listening for health check: %v", err)
	}
	defer listener.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := listener.AcceptTCP()
			if err != nil {
				log.Printf("failed to accept connection: %v", err)
				continue
			}
			log.Printf("accepted health check connection from %v", conn.RemoteAddr())

			conn.Close()
		}
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go func() {
		<-stopChan
		log.Printf("stopping")
		cancel()
	}()
	go listenHealthCheck(ctx, 8080)

	fmt.Println("Staring VPN Identity Firewall...")

	var wg sync.WaitGroup
	wg.Add(1)
	go func(ctx context.Context) {
		err := handler.Start(ctx)
		if err != nil {
			log.Printf("Handler stopped: %s", err)
		}
		wg.Done()
	}(ctx)

	wg.Wait()
	log.Printf("DONE")
}
