package main

import (
	"encoding/binary"
	"flag"
	"crypto/cipher"
	"fmt"
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
	listenAddr = flag.String("listen", "127.0.0.1:10800", "SOCKS5 listen address")
	serverAddr = flag.String("server", "161.97.94.240:40000", "UDP server address")
	password   = flag.String("pass", "werther-tunnel-2026", "Encryption password")
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

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Listen TCP: %v", err)
	}
	defer listener.Close()

	log.Printf("UDP tunnel client (SOCKS5) started on %s", *listenAddr)
	log.Printf("Server: %s", *serverAddr)
	log.Printf("Encryption: ChaCha20-Poly1305")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		listener.Close()
		os.Exit(0)
	}()

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			break
		}
		go handle(client, aead, serverUDP)
	}
}

func handle(client net.Conn, aead cipher.AEAD, serverAddr *net.UDPAddr) {
	defer client.Close()

	buf := make([]byte, 4096)

	// 1. SOCKS5 auth
	_, err := io.ReadAtLeast(client, buf[:2], 2)
	if err != nil {
		return
	}
	nmethods := buf[1]
	_, err = io.ReadAtLeast(client, buf[:nmethods], int(nmethods))
	if err != nil {
		return
	}
	client.Write([]byte{0x05, 0x00})

	// 2. Read SOCKS5 request
	_, err = io.ReadAtLeast(client, buf[:4], 4)
	if err != nil {
		return
	}
	ver, cmd, atyp := buf[0], buf[1], buf[3]
	if ver != 5 || cmd != 1 {
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	var host string
	var port uint16
	switch atyp {
	case 1:
		_, err = io.ReadFull(client, buf[:4])
		host = net.IP(buf[:4]).String()
	case 3:
		_, err = io.ReadFull(client, buf[:1])
		if err != nil {
			return
		}
		hostLen := buf[0]
		_, err = io.ReadFull(client, buf[:hostLen])
		if err != nil {
			return
		}
		host = string(buf[:hostLen])
	case 4:
		_, err = io.ReadFull(client, buf[:16])
		host = net.IP(buf[:16]).String()
	}
	if err != nil {
		return
	}
	_, err = io.ReadFull(client, buf[:2])
	if err != nil {
		return
	}
	port = binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", host, port)
	log.Printf("CONNECT %s", target)

	// 3. Connect to UDP server
	remote, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return
	}
	defer remote.Close()

	// 4. Send target info
	hostBytes := []byte(host)
	targetInfo := make([]byte, 4+len(hostBytes)+2)
	binary.BigEndian.PutUint32(targetInfo[:4], uint32(len(hostBytes)))
	copy(targetInfo[4:], hostBytes)
	binary.BigEndian.PutUint16(targetInfo[4+len(hostBytes):], port)
	tgtPkt := &tunnel.Packet{Data: targetInfo}
	remote.Write(tgtPkt.Encrypt(aead))

	// 5. SOCKS5 OK
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// 6. Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)

	// UDP -> TCP: read responses from server, write to SOCKS5 client
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			remote.SetReadDeadline(time.Now().Add(5 * time.Minute))
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			raw := buf[:n]
			if tunnel.IsHeartbeat(raw) {
				continue
			}
			pkt, err := tunnel.DecryptPacket(raw, aead)
			if err != nil {
				continue
			}
			if pkt.Data != nil {
				_, err := client.Write(pkt.Data)
				if err != nil {
					return
				}
			}
		}
	}()

	// TCP -> UDP: read from SOCKS5 client, send to server
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := client.Read(buf)
			if err != nil {
				return
			}
			pkt := &tunnel.Packet{Data: buf[:n]}
			remote.Write(pkt.Encrypt(aead))
		}
	}()

	wg.Wait()
}
