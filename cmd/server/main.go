package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/amalkovich1/udp-tunnel/pkg/tunnel"
)

var (
	listenAddr = flag.String("listen", ":40000", "UDP listen address")
	password   = flag.String("pass", "werther-tunnel-2026", "Encryption password")
)

func main() {
	flag.Parse()

	key := tunnel.DeriveKey(*password)
	aead, err := tunnel.NewAEAD(key)
	if err != nil {
		log.Fatalf("Failed to create AEAD: %v", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		log.Fatalf("Resolve UDP: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Listen UDP: %v", err)
	}
	defer conn.Close()

	log.Printf("UDP tunnel server started on %s", conn.LocalAddr())
	log.Printf("Encryption: ChaCha20-Poly1305")

	type session struct {
		clientAddr *net.UDPAddr
		tcpConn    net.Conn
		lastSeen   time.Time
	}
	sessions := make(map[string]*session)
	var mu sync.Mutex

	buf := make([]byte, 4096)

	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				mu.Lock()
				now := time.Now()
				for key, s := range sessions {
					if now.Sub(s.lastSeen) > 5*time.Minute {
						s.tcpConn.Close()
						delete(sessions, key)
						log.Printf("Session %s timed out", key)
					}
				}
				mu.Unlock()
				continue
			}
			log.Printf("Read error: %v", err)
			continue
		}

		raw := buf[:n]
		keyStr := clientAddr.String()

		if tunnel.IsHeartbeat(raw) {
			mu.Lock()
			if s, ok := sessions[keyStr]; ok {
				s.lastSeen = time.Now()
			}
			mu.Unlock()
			continue
		}

		pkt, err := tunnel.DecryptPacket(raw, aead)
		if err != nil {
			log.Printf("Decrypt error from %s: %v", clientAddr, err)
			continue
		}

		mu.Lock()
		s, exists := sessions[keyStr]
		mu.Unlock()

		if !exists {
			data := pkt.Data
			if len(data) < 6 {
				log.Printf("Bad initial packet from %s", clientAddr)
				continue
			}
			hostLen := binary.BigEndian.Uint32(data[:4])
			if len(data) < int(4+hostLen+2) {
				log.Printf("Bad initial packet (short) from %s", clientAddr)
				continue
			}
			host := string(data[4 : 4+hostLen])
			port := binary.BigEndian.Uint16(data[4+hostLen:])
			target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

			log.Printf("New session %s -> %s", clientAddr, target)

			tcpConn, err := net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				log.Printf("TCP dial %s failed: %v", target, err)
				continue
			}

			s = &session{
				clientAddr: clientAddr,
				tcpConn:    tcpConn,
				lastSeen:   time.Now(),
			}
			mu.Lock()
			sessions[keyStr] = s
			mu.Unlock()

			// Goroutine: TCP -> UDP (responses back to client)
			go func(s *session) {
				buf := make([]byte, 4096)
				for {
					s.tcpConn.SetReadDeadline(time.Now().Add(2 * time.Minute))
					n, err := s.tcpConn.Read(buf)
					if err != nil {
						mu.Lock()
						delete(sessions, s.clientAddr.String())
						mu.Unlock()
						return
					}
					pkt := &tunnel.Packet{Data: buf[:n]}
					conn.WriteToUDP(pkt.Encrypt(aead), s.clientAddr)
				}
			}(s)

			// Don't write target info to TCP connection
			continue
		}

		s.lastSeen = time.Now()

		// Forward data to target
		if pkt.Data != nil {
			_, err := s.tcpConn.Write(pkt.Data)
			if err != nil {
				log.Printf("TCP write error for %s: %v", keyStr, err)
				s.tcpConn.Close()
				mu.Lock()
				delete(sessions, keyStr)
				mu.Unlock()
			}
		}
	}
}
