package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"

	"net/http"
	"vpn-identity-firewall/handler"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func HealthCheck() {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("healthz"))
	})
	http.ListenAndServe(":8080", nil)
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
	go HealthCheck()

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
