package main

import (
	"crypto/cipher"
	"encoding/binary"
	"flag"
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

	var wg sync.WaitGroup

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
		wg.Add(1)
		go handleSOCKS5(client, serverUDP, aead, &wg)
	}
	wg.Wait()
}

// SOCKS5 handshake
func handleSOCKS5(client net.Conn, serverAddr *net.UDPAddr, aead cipher.AEAD, wg *sync.WaitGroup) {
	defer client.Close()
	defer wg.Done()

	// 1. Read auth methods
	buf := make([]byte, 257)
// 	_, err := io.ReadAtLeast(client, buf[:2], 2)
	_, err := io.ReadAtLeast(client, buf[:2], 2)
	if err != nil {
		return
	}
	nmethods := buf[1]
  _, err = io.ReadAtLeast(client, buf[:nmethods], int(nmethods))
	if err != nil {
		return
	}

	// 2. Reply: no auth
	client.Write([]byte{0x05, 0x00})

	// 3. Read request
  _, err = io.ReadAtLeast(client, buf[:4], 4)
	if err != nil {
		return
	}
	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 { // only CONNECT
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	var host string
	var port uint16
	switch atyp {
	case 1: // IPv4
  _, err = io.ReadAtLeast(client, buf[:4], 4)
		if err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 3: // Domain
  _, err = io.ReadAtLeast(client, buf[:1], 1)
		if err != nil {
			return
		}
		len := buf[0]
  _, err = io.ReadAtLeast(client, buf[:len], int(len))
		if err != nil {
			return
		}
		host = string(buf[:len])
	case 4: // IPv6
  _, err = io.ReadAtLeast(client, buf[:16], 16)
		if err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}
  _, err = io.ReadAtLeast(client, buf[:2], 2)
	if err != nil {
		return
	}
	port = binary.BigEndian.Uint16(buf[:2])

	target := fmt.Sprintf("%s:%d", host, port)
	log.Printf("CONNECT %s", target)

	// 4. Reply success (we'll send actual response after UDP relay)
	// Defer sending reply until we get first data back
	replyOK := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	client.Write(replyOK)

	// 5. Relay via UDP tunnel
	remote, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Printf("Dial UDP: %v", err)
		return
	}
	defer remote.Close()

	// Send target info first: 4 bytes hostLen + host + 2 bytes port
	hostBytes := []byte(host)
	targetInfo := make([]byte, 4+len(hostBytes)+2)
	binary.BigEndian.PutUint32(targetInfo[:4], uint32(len(hostBytes)))
	copy(targetInfo[4:], hostBytes)
	binary.BigEndian.PutUint16(targetInfo[4+len(hostBytes):], port)

	// Send as first packet — server will connect to this target
	tgtPkt := &tunnel.Packet{Data: targetInfo}
	remote.Write(tgtPkt.Encrypt(aead))

	// Wait for OK from server
	respBuf := make([]byte, 2048)
	remote.SetReadDeadline(time.Now().Add(10 * time.Second))
	respN, err := remote.Read(respBuf)
	if err == nil {
		respRaw := respBuf[:respN]
		if !tunnel.IsHeartbeat(respRaw) {
			respPkt, err := tunnel.DecryptPacket(respRaw, aead)
			if err == nil && respPkt.Data != nil && len(respPkt.Data) > 0 {
				client.Write(respPkt.Data)
			}
		}
	}

	// Bidirectional relay
	var wg2 sync.WaitGroup
	wg2.Add(2)

	// Client → Server
	go func() {
		defer wg2.Done()
		buf := make([]byte, 2048)
		for {
			n, err := client.Read(buf)
			if err != nil {
				return
			}
			data := buf[:n]
			pkt := &tunnel.Packet{Data: data}
			remote.Write(pkt.Encrypt(aead))
		}
	}()

	// Server → Client
	go func() {
		defer wg2.Done()
		buf := make([]byte, 2048)
		for {
			remote.SetReadDeadline(time.Now().Add(120 * time.Second))
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
				client.Write(pkt.Data)
			}
		}
	}()

	wg2.Wait()
}
