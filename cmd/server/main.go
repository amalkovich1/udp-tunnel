package main

import (
	"crypto/cipher"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/amalkovich1/udp-tunnel/pkg/tunnel"
)

var (
	listenAddr  = flag.String("listen", ":40000", "UDP listen address")
	targetAddr  = flag.String("target", "127.0.0.1:9443", "TCP target (Xray inbound)")
	password    = flag.String("pass", "werther-tunnel-2026", "Encryption password")
	timeout     = flag.Duration("timeout", 60*time.Second, "Connection idle timeout")
	portRange   = flag.Bool("port-range", false, "Listen on random port 40000-44999")
)

func main() {
	flag.Parse()

	key := tunnel.DeriveKey(*password)
	aead, err := tunnel.NewAEAD(key)
	if err != nil {
		log.Fatalf("Failed to create AEAD: %v", err)
	}

	addr := *listenAddr
	if *portRange {
		addr = ":0"
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("Resolve UDP: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Listen UDP: %v", err)
	}
	defer conn.Close()

	log.Printf("UDP tunnel server started on %s", conn.LocalAddr())
	log.Printf("Forwarding to TCP target: %s", *targetAddr)
	log.Printf("Encryption: ChaCha20-Poly1305")

	// sessions map
	type session struct {
		clientAddr *net.UDPAddr
		tcpConn    net.Conn
		lastSeen   time.Time
		stats      *tunnel.Stats
	}
	sessions := make(map[string]*session)

	buf := make([]byte, 2048)

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout: cleanup stale sessions
				now := time.Now()
				for key, s := range sessions {
					if now.Sub(s.lastSeen) > *timeout {
						s.tcpConn.Close()
						delete(sessions, key)
						log.Printf("Session %s timed out (sent=%d recv=%d)",
							key, s.stats.BytesSent, s.stats.BytesReceived)
					}
				}
				continue
			}
			log.Printf("Read error: %v", err)
			continue
		}

		raw := buf[:n]
		keyStr := clientAddr.String()

		// Heartbeat packet — just update lastSeen
		if tunnel.IsHeartbeat(raw) {
			if s, ok := sessions[keyStr]; ok {
				s.lastSeen = time.Now()
			}
			continue
		}

		pkt, err := tunnel.DecryptPacket(raw, aead)
		if err != nil {
			log.Printf("Decrypt error from %s: %v", clientAddr, err)
			continue
		}

		s, exists := sessions[keyStr]
		if !exists {
			// New session — connect to Xray
			tcpConn, err := net.DialTimeout("tcp", *targetAddr, 5*time.Second)
			if err != nil {
				log.Printf("TCP dial to %s failed: %v", *targetAddr, err)
				continue
			}
			s = &session{
				clientAddr: clientAddr,
				tcpConn:    tcpConn,
				lastSeen:   time.Now(),
				stats:      tunnel.NewStats(),
			}
			sessions[keyStr] = s
			log.Printf("New session from %s -> %s", clientAddr, *targetAddr)
		}
		s.lastSeen = time.Now()

		if pkt.Data != nil {
			s.stats.BytesReceived += int64(len(pkt.Data))
			// Write to Xray
			_, err := s.tcpConn.Write(pkt.Data)
			if err != nil {
				log.Printf("Write to Xray error: %v", err)
				s.tcpConn.Close()
				delete(sessions, keyStr)
				continue
			}
		}

		// Read response from Xray (non-blocking attempt)
		respBuf := make([]byte, 2048)
		s.tcpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		respN, err := s.tcpConn.Read(respBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				if err != io.EOF {
					log.Printf("Read from Xray error: %v", err)
				}
				s.tcpConn.Close()
				delete(sessions, keyStr)
				continue
			}
			// Timeout on read is OK — no response yet
			continue
		}

		// Have response — encrypt and send back
		respPkt := &tunnel.Packet{Data: respBuf[:respN]}
		encResp := respPkt.Encrypt(aead)
		s.stats.BytesSent += int64(len(respBuf[:respN]))
		conn.WriteToUDP(encResp, clientAddr)
	}

	// Cleanup on exit
	for _, s := range sessions {
		s.tcpConn.Close()
	}
}
