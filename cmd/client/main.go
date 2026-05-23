package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/amalkovich1/udp-tunnel/pkg/tunnel"
	kcp "github.com/xtaci/kcp-go"
)

var (
	listenAddr = flag.String("listen", "127.0.0.1:10800", "SOCKS5 listen addr")
	serverAddr = flag.String("server", "161.97.94.240:40000", "KCP server addr")
)

func main() {
	flag.Parse()

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Listen TCP: %v", err)
	}
	defer listener.Close()

	log.Printf("KCP tunnel client (SOCKS5) on %s", *listenAddr)
	log.Printf("KCP server: %s", *serverAddr)

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("Accept: %v", err)
			break
		}
		go handle(client)
	}
}

func handle(client net.Conn) {
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
		hostLen := buf[0]
		io.ReadFull(client, buf[:hostLen])
		host = string(buf[:hostLen])
	case 4:
		io.ReadFull(client, buf[:16])
		host = net.IP(buf[:16]).String()
	}
	io.ReadFull(client, buf[:2])
	port = binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", host, port)
	log.Printf("CONNECT %s", target)

	// 3. Connect to KCP server
		block, _ := kcp.NewNoneBlockCrypt(nil)
		kcpConn, err := kcp.DialWithOptions(*serverAddr, block, 0, 0)
	if err != nil {
		log.Printf("KCP dial: %v", err)
		return
	}
	defer kcpConn.Close()

	// Fast mode
	kcpConn.SetNoDelay(1, 10, 2, 1)
	kcpConn.SetWindowSize(1024, 1024)
	kcpConn.SetMtu(1400)
	kcpConn.SetACKNoDelay(true)

	// 4. Send target info first
	targetInfo := tunnel.EncodeTargetInfo(host, port)
	_, err = kcpConn.Write(targetInfo)
	if err != nil {
		log.Printf("KCP write targetInfo: %v", err)
		return
	}

	// 5. SOCKS5 OK
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// 6. Bidirectional relay
	done := make(chan struct{}, 2)

	// SOCKS5 → KCP
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, err := client.Read(buf)
			if err != nil {
				return
			}
			_, err = kcpConn.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	// KCP → SOCKS5
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			kcpConn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := kcpConn.Read(buf)
			if err != nil {
				return
			}
			_, err = client.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	<-done
	log.Printf("Disconnected %s", target)
}
