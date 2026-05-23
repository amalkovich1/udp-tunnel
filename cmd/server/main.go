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
	block, _ := kcp.NewNoneBlockCrypt(nil)
	lis, err := kcp.ListenWithOptions(":40000", block, 0, 0)
	if err != nil {
		log.Fatalf("KCP listen: %v", err)
	}
	defer lis.Close()
	log.Printf("KCP tunnel server on :40000")

	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			continue
		}
		conn.SetNoDelay(1, 10, 2, 1)
		conn.SetWindowSize(1024, 1024)
		conn.SetMtu(1400)
		conn.SetACKNoDelay(true)
		conn.SetStreamMode(false)
		go handleKCP(conn)
	}
}

func handleKCP(kcpConn *kcp.UDPSession) {
	clientAddr := kcpConn.RemoteAddr().String()
	defer kcpConn.Close()

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

	tcpConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("TCP dial %s: %v", target, err)
		return
	}
	defer tcpConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)

	// KCP → TCP: read len + data, write to target
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
			// Read 4 bytes length prefix
			if _, err := kcpConn.Read(buf[:4]); err != nil {
				return
			}
			pktLen := int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
			if pktLen < 1 || pktLen > 4096 {
				return
			}
			// Read data
			if _, err := kcpConn.Read(buf[:pktLen]); err != nil {
				return
			}
			log.Printf("KCP→TCP %s: write %d bytes", target, pktLen)
			if _, err := tcpConn.Write(buf[:pktLen]); err != nil {
				return
			}
		}
	}()

	// TCP → KCP: read response, send len + data
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
			// Send length prefix
			log.Printf("TCP→KCP %s: write %d bytes", target, n)
			if _, err := kcpConn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("Session %s -> %s closed", clientAddr, target)
}
