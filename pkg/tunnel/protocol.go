package tunnel

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	IVSize   = 12
	MACSize  = 16
	KeySize  = 32            // ChaCha20-Poly1305 key
	MaxLen = 1300          // Max UDP payload
	HeaderLen = 4            // 4 bytes: data length
)

func DeriveKey(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:]
}

func NewAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// Packet format: [dataLen:4][IV:12][encrypted data][MAC:16]
// or nil if dataLen is heartbeat marker (0xFFFFFFFF)

type Packet struct {
	Data []byte // plaintext data
}

func (p *Packet) Encrypt(aead cipher.AEAD) []byte {
	iv := make([]byte, IVSize)
	rand.Read(iv)

	nonce := iv[:aead.NonceSize()]
	enc := aead.Seal(nil, nonce, p.Data, nil)

	raw := make([]byte, HeaderLen+IVSize+len(enc))
	binary.BigEndian.PutUint32(raw[:4], uint32(len(p.Data)))
	copy(raw[4:4+IVSize], iv)
	copy(raw[4+IVSize:], enc)
	return raw
}

func DecryptPacket(raw []byte, aead cipher.AEAD) (*Packet, error) {
	if len(raw) < HeaderLen+IVSize {
		return nil, io.ErrUnexpectedEOF
	}
	dataLen := binary.BigEndian.Uint32(raw[:4])
	if dataLen == 0xFFFFFFFF {
		// heartbeat
		return &Packet{Data: nil}, nil
	}
	iv := raw[4 : 4+IVSize]
	enc := raw[4+IVSize:]

	nonce := iv[:aead.NonceSize()]
	plain, err := aead.Open(nil, nonce, enc, nil)
	if err != nil {
		return nil, err
	}
	return &Packet{Data: plain}, nil
}

// Heartbeat returns a serialised heartbeat marker
func Heartbeat() []byte {
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint32(raw[:4], 0xFFFFFFFF)
	return raw
}

func IsHeartbeat(raw []byte) bool {
	return len(raw) >= HeaderLen && binary.BigEndian.Uint32(raw[:4]) == 0xFFFFFFFF
}

// ByteCount reader helper
type ByteCount struct {
	N int64
}

func (b *ByteCount) Write(p []byte) (int, error) {
	b.N += int64(len(p))
	return len(p), nil
}

// Stats for logging
type Stats struct {
	BytesSent     int64
	BytesReceived int64
	StartTime     time.Time
}

func NewStats() *Stats {
	return &Stats{StartTime: time.Now()}
}

// EncodeTargetInfo packs host:port into [4B hostLen][host][2B port]
func EncodeTargetInfo(host string, port uint16) []byte {
	hostBytes := []byte(host)
	buf := make([]byte, 4+len(hostBytes)+2)
	binary.BigEndian.PutUint32(buf[:4], uint32(len(hostBytes)))
	copy(buf[4:], hostBytes)
	binary.BigEndian.PutUint16(buf[4+len(hostBytes):], port)
	return buf
}

// DecodeTargetInfo extracts host and port from target info packet
func DecodeTargetInfo(data []byte) (string, uint16, error) {
	if len(data) < 6 {
		return "", 0, io.ErrUnexpectedEOF
	}
	hostLen := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(4+hostLen+2) {
		return "", 0, io.ErrUnexpectedEOF
	}
	host := string(data[4 : 4+hostLen])
	port := binary.BigEndian.Uint16(data[4+hostLen:])
	return host, port, nil
}
