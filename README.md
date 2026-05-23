# UDP Tunnel for Xray

Bypass DPI by tunnelling Xray traffic over ChaCha20-Poly1305 encrypted UDP.

## Architecture

```
Browser → SOCKS5 :10808 → Xray :10808 → Tunnel Client → UDP → Tunnel Server → TCP → Xray inbound :9443
```

## Build

### Server (Linux)
```bash
cd cmd/server && go build -o ../../bin/server .
```

### Client (Windows)
```bash
cd cmd/client && go build -o ../../bin/client.exe .
```

## Run

### Server
```bash
./bin/server -listen :40000 -target 127.0.0.1:9443 -pass "werther-tunnel-2026"
```

### Client
```bash
client.exe -listen 127.0.0.1:10800 -server 161.97.94.240:40000 -pass "werther-tunnel-2026"
```

Then set Xray outbound to proxy 127.0.0.1:10800 (not to Contabo directly).
