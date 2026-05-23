package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/amalkovich1/udp-tunnel/pkg/tunnel"
	kcp "github.com/xtaci/kcp-go"
)

func main() {
	lis, err := kcp.ListenWithOptions(":40000", mustBlockCrypt(), 0, 0)
	if err != nil {
		log.Fatalf("KCP listen: %v", err)
	}
	defer lis.Close()
	log.Printf("KCP tunnel server on :40000")

	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			log.Printf("Accept: %v", err)
			continue
		}
		conn.SetNoDelay(1, 10, 2, 1)
		conn.SetWindowSize(1024, 1024)
		conn.SetMtu(1400)
		conn.SetACKNoDelay(true)

		go handleKCP(conn)
	}
}

func mustBlockCrypt() kcp.BlockCrypt {
	bc, err := kcp.NewNoneBlockCrypt(nil)
	if err != nil {
		log.Fatalf("KCP crypt: %v", err)
	}
	return bc
}

func handleKCP(kcpConn *kcp.UDPSession) {
	clientAddr := kcpConn.RemoteAddr().String()
	defer kcpConn.Close()

	// Read target info
	buf := make([]byte, 4096)
	n, err := kcpConn.Read(buf)
	if err != nil {
		return
	}
	host, port, err := tunnel.DecodeTargetInfo(buf[:n])
	if err != nil {
		return
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	log.Printf("KCP %s -> %s", clientAddr, target)

	// Connect to target via TCP
	tcpConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("TCP dial %s: %v", target, err)
		return
	}
	defer tcpConn.Close()
	log.Printf("TCP %s connected", target)

	// Bidirectional relay with context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// KCP → TCP: read from client, write to target
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
			n, err := kcpConn.Read(buf)
			if err != nil {
				return
			}
			if _, err := tcpConn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// TCP → KCP: read response from target, write back to client
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
			n, err := tcpConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			if _, err := kcpConn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("Session %s -> %s closed", clientAddr, target)
}
