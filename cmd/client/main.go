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

	var wg sync.WaitGroup
	for {
		client, err := listener.Accept()
		if err != nil {
			break
		}
		wg.Add(1)
		go handle(client, aead, serverUDP, &wg)
	}
	wg.Wait()
}

func handle(client net.Conn, aead cipher.AEAD, serverAddr *net.UDPAddr, wg *sync.WaitGroup) {
	defer client.Close()
	defer wg.Done()

	// 1. SOCKS5 auth
	buf := make([]byte, 4096)
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

	// 2. SOCKS5 request
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
		io.ReadFull(client, buf[:4])
		host = net.IP(buf[:4]).String()
	case 3:
		io.ReadFull(client, buf[:1])
		len := buf[0]
		io.ReadFull(client, buf[:len])
		host = string(buf[:len])
	case 4:
		io.ReadFull(client, buf[:16])
		host = net.IP(buf[:16]).String()
	}
	io.ReadFull(client, buf[:2])
	port = binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", host, port)
	log.Printf("CONNECT %s", target)

	// 3. Connect to server via UDP
	remote, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Printf("Dial UDP: %v", err)
		return
	}
	defer remote.Close()

	// Send target info
	hostBytes := []byte(host)
	targetInfo := make([]byte, 4+len(hostBytes)+2)
	binary.BigEndian.PutUint32(targetInfo[:4], uint32(len(hostBytes)))
	copy(targetInfo[4:], hostBytes)
	binary.BigEndian.PutUint16(targetInfo[4+len(hostBytes):], port)

	tgtPkt := &tunnel.Packet{Data: targetInfo}
	remote.Write(tgtPkt.Encrypt(aead))

	// 4. Reply SOCKS5 OK
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// 5. Sequential relay: write then read
	for {
		// Read from SOCKS5 client
		n, err := client.Read(buf)
		if err != nil {
			return
		}
		data := buf[:n]

		// Encrypt & send UDP
		pkt := &tunnel.Packet{Data: data}
		remote.Write(pkt.Encrypt(aead))

		// Read all response chunks from server
		for {
			remote.SetReadDeadline(time.Now().Add(2 * time.Second))
			respN, err := remote.Read(buf)
			if err != nil {
				break
			}
			raw := buf[:respN]
			if tunnel.IsHeartbeat(raw) {
				continue
			}
			respPkt, err := tunnel.DecryptPacket(raw, aead)
			if err != nil {
				continue
			}
			if respPkt.Data != nil {
				client.Write(respPkt.Data)
			}
		}
	}
}
