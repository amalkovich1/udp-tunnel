package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/amalkovich1/udp-tunnel/pkg/tunnel"
	kcp "github.com/xtaci/kcp-go"
)

var (
	listenAddr = flag.String("listen", "127.0.0.1:10800", "SOCKS5 listen")
	serverAddr = flag.String("server", "161.97.94.240:40000", "KCP server")
)

func main() {
	flag.Parse()

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Listen TCP: %v", err)
	}
	defer listener.Close()
	log.Printf("KCP SOCKS5 client on %s -> %s", *listenAddr, *serverAddr)

	for {
		client, err := listener.Accept()
		if err != nil {
			break
		}
		go handle(client)
	}
}

func mustKCP() *kcp.UDPSession {
	bc, err := kcp.NewNoneBlockCrypt(nil)
	if err != nil {
		log.Fatalf("KCP crypt: %v", err)
	}
	conn, err := kcp.DialWithOptions(*serverAddr, bc, 0, 0)
	if err != nil {
		log.Fatalf("KCP dial: %v", err)
	}
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWindowSize(1024, 1024)
	conn.SetMtu(1400)
	conn.SetACKNoDelay(true)
	conn.SetStreamMode(false)
	return conn
}

func handle(client net.Conn) {
	defer client.Close()

	buf := make([]byte, 4096)

	// SOCKS5 auth
	if _, err := io.ReadAtLeast(client, buf[:2], 2); err != nil {
		return
	}
	nmethods := buf[1]
	if _, err := io.ReadAtLeast(client, buf[:nmethods], int(nmethods)); err != nil {
		return
	}
	client.Write([]byte{0x05, 0x00})

	// SOCKS5 request
	if _, err := io.ReadAtLeast(client, buf[:4], 4); err != nil {
		return
	}
	if buf[0] != 5 || buf[1] != 1 {
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	var host string
	var port uint16
	switch buf[3] {
	case 1:
		io.ReadFull(client, buf[:4])
		host = net.IP(buf[:4]).String()
	case 3:
		io.ReadFull(client, buf[:1])
		l := buf[0]
		io.ReadFull(client, buf[:l])
		host = string(buf[:l])
	case 4:
		io.ReadFull(client, buf[:16])
		host = net.IP(buf[:16]).String()
	}
	io.ReadFull(client, buf[:2])
	port = binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", host, port)
	log.Printf("CONNECT %s", target)

	// Connect via KCP
	kcpConn := mustKCP()
	defer kcpConn.Close()

	// Send target info
	if _, err := kcpConn.Write(tunnel.EncodeTargetInfo(host, port)); err != nil {
		return
	}

	// SOCKS5 OK
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Bidirectional relay
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// SOCKS5 → KCP
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 4096)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			client.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := client.Read(buf)
			if err != nil {
				return
			}
			if _, err := kcpConn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// KCP → SOCKS5
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 4096)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			kcpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := kcpConn.Read(buf)
			if err != nil {
				return
			}
			if _, err := client.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("Disconnected %s", target)
}
