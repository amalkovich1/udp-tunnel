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
		target     string
		tcpConn    net.Conn
		lastSeen   time.Time
		mu         sync.Mutex
	}
	sessions := make(map[string]*session)
	var mu sync.Mutex

	buf := make([]byte, 1400)

	// Helper: ensure TCP connection is alive, reconnect if needed
	ensureConn := func(s *session) (net.Conn, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.tcpConn != nil {
			return s.tcpConn, nil
		}
		tcpConn, err := net.DialTimeout("tcp", s.target, 10*time.Second)
		if err != nil {
			return nil, err
		}
		s.tcpConn = tcpConn
		// Start reader goroutine for new connection
		go func(s *session) {
			buf := make([]byte, 1400)
			for {
				tcpConn.SetReadDeadline(time.Now().Add(2 * time.Minute))
				n, err := tcpConn.Read(buf)
				if err != nil {
					s.mu.Lock()
					tcpConn.Close()
					s.tcpConn = nil // mark as closed, will reconnect on next write
					s.mu.Unlock()
					return
				}
				pkt := &tunnel.Packet{Data: buf[:n]}
				conn.WriteToUDP(pkt.Encrypt(aead), s.clientAddr)
			}
		}(s)
		return tcpConn, nil
	}

	writeToSession := func(s *session, data []byte) bool {
		tcpConn, err := ensureConn(s)
		if err != nil {
			return false
		}
		_, err = tcpConn.Write(data)
		if err != nil {
			tcpConn.Close()
			s.mu.Lock()
			s.tcpConn = nil
			s.mu.Unlock()
			return false
		}
		return true
	}

	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				mu.Lock()
				now := time.Now()
				for key, s := range sessions {
					if now.Sub(s.lastSeen) > 5*time.Minute {
						s.mu.Lock()
						if s.tcpConn != nil {
							s.tcpConn.Close()
						}
						s.mu.Unlock()
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
			if len(pkt.Data) < 6 {
				log.Printf("Bad initial packet from %s", clientAddr)
				continue
			}
			hostLen := binary.BigEndian.Uint32(pkt.Data[:4])
			if len(pkt.Data) < int(4+hostLen+2) {
				continue
			}
			host := string(pkt.Data[4 : 4+hostLen])
			port := binary.BigEndian.Uint16(pkt.Data[4+hostLen:])
			target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

			log.Printf("New session %s -> %s", clientAddr, target)

			s = &session{clientAddr: clientAddr, target: target, lastSeen: time.Now()}
			mu.Lock()
			sessions[keyStr] = s
			mu.Unlock()

			// Connect on first data (not target info)
			continue
		}

		s.lastSeen = time.Now()

		// Forward data to target
		if pkt.Data != nil {
			if !writeToSession(s, pkt.Data) {
				log.Printf("Write failed for %s", keyStr)
				// Don't delete session — will retry on next packet
			}
		}
	}
}
