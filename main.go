package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	flag.Parse()

	// Capture exit signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Start HTTP server that listens on hhtp://localhost8081/dhcp/start
	go func() {
		// Handler waiting for the startup request form the controller to start DHCP client
		http.HandleFunc("/dhcp/start", func(w http.ResponseWriter, r *http.Request) {
			log.Println("HTTP /dhcp/start received : initiating client DHCP")
			//Start DORA process
			go mainDHCPLogic()
			fmt.Fprintln(w, "DHCP client started")
		})

		log.Println("Listening on http://0.0.0.0:8081/dhcp/start")
		if err := http.ListenAndServe("0.0.0.0:8081", nil); err != nil {
			log.Fatalf("HTTP Server error: %v", err)
		}
	}()

	// Wait for SIGTERM
	<-c
	log.Println("Shutdown signal received. Exit program.")
	os.Exit(0)
}
