package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/amalkovich1/udp-tunnel/pkg/tunnel"
	kcp "github.com/xtaci/kcp-go"
)

func main() {
	listenAddr := ":40000"

	block, err := kcp.NewNoneBlockCrypt(nil)
	if err != nil {
		log.Fatalf("KCP crypt: %v", err)
	}
	lis, err := kcp.ListenWithOptions(listenAddr, block, 0, 0)
	if err != nil {
		log.Fatalf("KCP listen: %v", err)
	}
	defer lis.Close()

	log.Printf("KCP tunnel server on %s", listenAddr)
	log.Printf("Waiting for KCP sessions...")

	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			log.Printf("Accept: %v", err)
			continue
		}

		// Fast mode: no delay, fast retransmit
		conn.SetNoDelay(1, 10, 2, 1)
		conn.SetWindowSize(1024, 1024)
		conn.SetMtu(1400)
		conn.SetACKNoDelay(true)

		clientAddr := conn.RemoteAddr().String()
		log.Printf("New KCP session from %s", clientAddr)

		go handleKCP(conn, clientAddr)
	}
}

func handleKCP(kcpConn *kcp.UDPSession, clientAddr string) {
	defer kcpConn.Close()

	// 1. Read target info first
	buf := make([]byte, 4096)
	n, err := kcpConn.Read(buf)
	if err != nil {
		log.Printf("Read target info from %s: %v", clientAddr, err)
		return
	}

	host, port, err := tunnel.DecodeTargetInfo(buf[:n])
	if err != nil {
		log.Printf("Bad target info from %s: %v", clientAddr, err)
		return
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	log.Printf("Session %s -> %s", clientAddr, target)

	// 2. Connect to target
	tcpConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("TCP dial %s: %v", target, err)
		return
	}
	defer tcpConn.Close()

	// 3. Bidirectional relay
	done := make(chan struct{}, 2)

	// KCP → TCP
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, err := kcpConn.Read(buf)
			if err != nil {
				return
			}
			_, err = tcpConn.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	// TCP → KCP
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			tcpConn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := tcpConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					// Timeout is OK
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
				}
				return
			}
			_, err = kcpConn.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	<-done
	log.Printf("Session %s closed", clientAddr)
}
