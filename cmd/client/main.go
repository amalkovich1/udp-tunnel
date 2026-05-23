package main

import (
	"crypto/cipher"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/amalkovich1/udp-tunnel/pkg/tunnel"
)

var (
	listenAddr  = flag.String("listen", "127.0.0.1:10800", "TCP listen (local proxy)")
	serverAddr  = flag.String("server", "161.97.94.240:40000", "UDP server address")
	password    = flag.String("pass", "werther-tunnel-2026", "Encryption password")
	timeout     = flag.Duration("timeout", 30*time.Second, "Idle session timeout")
)

func main() {
	flag.Parse()

	key := tunnel.DeriveKey(*password)
	aead, err := tunnel.NewAEAD(key)
	if err != nil {
		log.Fatalf("Failed to create AEAD: %v", err)
	}

	serverUDP, err := net.ResolveUDPAddr("udp", *serverAddr)
	if err != nil {
		log.Fatalf("Resolve server: %v", err)
	}

	udpConn, err := net.DialUDP("udp", nil, serverUDP)
	if err != nil {
		log.Fatalf("Dial UDP: %v", err)
	}
	defer udpConn.Close()

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Listen TCP: %v", err)
	}
	defer listener.Close()

	log.Printf("UDP tunnel client started")
	log.Printf("Local proxy: %s", *listenAddr)
	log.Printf("Server: %s", *serverAddr)
	log.Printf("Encryption: ChaCha20-Poly1305")

	var wg sync.WaitGroup

	// Heartbeat
	go func() {
		hb := tunnel.Heartbeat()
		for {
			udpConn.Write(hb)
			time.Sleep(5 * time.Second)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		listener.Close()
		os.Exit(0)
	}()

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			break
		}
		wg.Add(1)
		go handleClient(clientConn, udpConn, aead, &wg)
	}
	wg.Wait()
}

func handleClient(local net.Conn, remote *net.UDPConn, aead cipher.AEAD, wg *sync.WaitGroup) {
	defer local.Close()
	defer wg.Done()

	stats := tunnel.NewStats()
	buf := make([]byte, 2048)

	for {
		local.SetReadDeadline(time.Now().Add(*timeout))
		n, err := local.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("Connection idle timeout, sent=%d recv=%d", stats.BytesSent, stats.BytesReceived)
				return
			}
			if err == io.EOF {
				return
			}
			log.Printf("Read error: %v", err)
			return
		}

		data := buf[:n]
		pkt := &tunnel.Packet{Data: data}
		enc := pkt.Encrypt(aead)
		stats.BytesReceived += int64(len(data))

		_, err = remote.Write(enc)
		if err != nil {
			log.Printf("Write to server error: %v", err)
			return
		}

		respBuf := make([]byte, 2048)
		remote.SetReadDeadline(time.Now().Add(30 * time.Second))
		respN, err := remote.Read(respBuf)
		if err != nil {
			log.Printf("Read from server error: %v", err)
			return
		}

		respRaw := respBuf[:respN]
		if tunnel.IsHeartbeat(respRaw) {
			continue
		}

		respPkt, err := tunnel.DecryptPacket(respRaw, aead)
		if err != nil {
			log.Printf("Decrypt response error: %v", err)
			continue
		}

		if respPkt.Data != nil {
			stats.BytesSent += int64(len(respPkt.Data))
			_, err = local.Write(respPkt.Data)
			if err != nil {
				log.Printf("Write to local error: %v", err)
				return
			}
		}
	}
}
