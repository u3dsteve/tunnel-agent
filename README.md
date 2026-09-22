# High-Performance UDP Tunnel Agent

## Overview

The **UDP Tunnel Agent** is a secure, high-throughput, loss-resistant proxy service designed for reliable network communication over lossy, unstable, or heavily inspected links. Written in Python 3.10+, it encapsulates TCP application traffic into encrypted UDP datagrams, applying Forward Error Correction (FEC) to eliminate retransmission delays caused by packet loss while employing anti-analysis protections against network censorship.

### What It Does

In network environments with high packet loss or strict stateful inspection, standard TCP connections suffer severe throughput collapse. This agent bypasses these bottlenecks:

1. **Traffic Interception**: Accepts TCP connections on a local entry point.
2. **FEC Encoding & Obfuscation**: Splits stream data into shards, generates Reed-Solomon-style parity shards via Galois Field $\text{GF}(2^8)$ arithmetic, and appends dynamic random-length padding.
3. **AEAD Encryption & Replay Defense**: Encrypts payloads using ChaCha20-Poly1305 AEAD, embedding strict monotonic 64-bit sequence validation and timestamp tracking.
4. **UDP Transport**: Transmits datagrams over UDP to eliminate TCP head-of-line blocking.
5. **Reconstruction & Forwarding**: The remote endpoint validates sequence numbers, reconstructs lost data shards in real time using surviving parity shards with timeout protection, decrypts the payload, and forwards clean TCP streams to the destination.

---

## Architectural Data Flow

```text
[ Local Client App ]
       │ (TCP)
       ▼
[ Tunnel Client ]  ─── Encrypt, Obfuscate & FEC (UDP) ───►  [ Tunnel Server ]
  • Listens locally                                           • Listens on UDP port
  • Encrypts via ChaCha20-Poly1305                            • Validates monotonic 64-bit sequence & timestamp
  • Appends parity shards (GF 2^8)                            • Recovers lost shards via FEC (configurable timeout)
  • Injects dynamic random padding                            • Decrypts & reconstructs stream
  • Asynchronously resolves DDNS (thread-isolated)            • Automatic reorder buffer expiry (5s)
                                                                     │ (TCP)
                                                                     ▼
                                                           [ Remote Target Service ]
                                                           (e.g., SSH, Web, Proxy)
```

---

## Key Features

* **AEAD Security & Hardened Replay Defense**: Secured with ChaCha20-Poly1305 authenticated encryption derived from a Pre-Shared Key (PSK) via SHA-256. Incorporates strict monotonic 64-bit sequence tracking (`max_seen_seq`) and timestamp validation (±15s) to entirely prevent packet replay and injection attacks. **No sequence number wrap-around** — supports indefinite 7×24 operation.
* **FEC Loss Resilience & DoS Mitigation**: Configurable $(k, m)$ matrix parameters recover from up to $\frac{m}{k+m}$ random packet loss without request-response round-trips. Includes a configurable asynchronous timeout wrapper (default 0.5s) during matrix inversion to protect against CPU starvation and malicious decoding DoS vectors.
* **Anti-DPI & Traffic Obfuscation**: Injects randomized padding (0–15 bytes) into every datagram to defeat Deep Packet Inspection (DPI) heuristics.
* **Mandatory Audit Logging**: Enforces operational compliance by keeping logging active at a minimum of `info` level (disabling logs is restricted to satisfy security audit requirements).
* **Seamless DDNS Resilience**: Built-in background resolver asynchronously monitors and updates target IP addresses for dynamic hostnames without dropping active client connections. DNS lookups are thread-isolated to prevent event loop blocking.
* **Robust Reorder Buffer**: Handles out-of-order packet delivery with a 256-slot window and **automatic 5-second expiry** to prevent sequence deadlock and memory leaks under pathological network conditions.
* **Asynchronous Non-Blocking I/O**: Leverages native Python `asyncio` event loops for high-concurrency multiplexing.
* **Delegated Resource Management**: Memory limits are safely managed and enforced at the container or systemd runtime level, avoiding unhandled interpreter-level `MemoryError` crashes.

---

## Prerequisites & Dependencies

### System Requirements

* **OS**: Linux (Debian 11+ / Ubuntu 22.04+)
* **Python**: Python 3.10+

### Dependencies (`requirements.txt`)

```text
PyYAML>=6.0
cryptography>=41.0.0
numpy>=1.21
```

---

## Configuration Reference

### Client Config (`config_client.yaml`)

```yaml
# Operation role: "client"
role: "client"

# Pre-Shared Key (PSK). Must match server.
psk: "YourSuperSecretPasswordKey2026!"

# FEC parameters (Data shards k, Parity shards m)
# (4, 2) tolerates up to 33% random packet loss
fec_k: 4
fec_m: 2

# FEC decode timeout (seconds). Increase for high-latency networks.
# Default: 0.5
fec_decode_timeout: 0.5

# Logging level: "debug" | "info" (Compliance enforced: logging cannot be disabled)
log_level: "info"

# Local TCP ingress
listen:
  host: "127.0.0.1"
  port: 1080

# Remote UDP egress endpoint
tunnel:
  host: "my-server.ddns.net"
  port: 9999
```

### Server Config (`config_server.yaml`)

```yaml
# Operation role: "server"
role: "server"

# Pre-Shared Key (PSK). Must match client.
psk: "YourSuperSecretPasswordKey2026!"

# FEC parameters (Must match client)
fec_k: 4
fec_m: 2

# FEC decode timeout (seconds). Increase for high-latency networks.
# Default: 0.5
fec_decode_timeout: 0.5

# Logging level: "debug" | "info"
log_level: "info"

# Inbound UDP tunnel endpoint
tunnel:
  host: "0.0.0.0"
  port: 9999

# Final TCP destination
target:
  host: "127.0.0.1"
  port: 22
```

---

## Deployment Option 1: Docker & Docker Compose (Recommended)

Containerized deployment isolates the runtime environment. Using `network_mode: host` bypasses the Docker Userland Proxy to maximize UDP throughput.

### Project Layout

```text
/opt/tunnel-agent/
├── Dockerfile
├── docker-compose.yml
├── tunnel_agent.py
├── requirements.txt
├── config_client.yaml
└── config_server.yaml
```

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tunnel_agent.py .

RUN useradd -m -u 10001 appuser
USER appuser

ENTRYPOINT ["python", "-u", "tunnel_agent.py"]
CMD ["config.yaml"]
```

### docker-compose.yml

```yaml
services:
  tunnel-client:
    build: .
    container_name: tunnel-client
    restart: always
    network_mode: "host"
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    deploy:
      resources:
        limits:
          memory: 128M
    volumes:
      - ./config_client.yaml:/app/config.yaml:ro

  tunnel-server:
    build: .
    container_name: tunnel-server
    restart: always
    network_mode: "host"
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    deploy:
      resources:
        limits:
          memory: 256M
    volumes:
      - ./config_server.yaml:/app/config.yaml:ro
```

### Execution Commands

```bash
# Build and run server service
docker compose up -d --build tunnel-server

# Build and run client service
docker compose up -d --build tunnel-client

# View live logs
docker compose logs -f
```

---

## Deployment Option 2: Systemd Native Service (Debian/Ubuntu)

Ideal for bare-metal host deployments or resource-constrained VPS instances.

### Setup Steps

```bash
# 1. Create dedicated system user and directory
sudo useradd -r -s /bin/false tunneluser
sudo mkdir -p /opt/tunnel-agent

# 2. Copy source files and setup Python virtual environment
sudo cp tunnel_agent.py config_server.yaml requirements.txt /opt/tunnel-agent/
cd /opt/tunnel-agent
sudo python3 -m venv venv
sudo ./venv/bin/pip install --upgrade pip
sudo ./venv/bin/pip install -r requirements.txt
sudo chown -R tunneluser:tunneluser /opt/tunnel-agent
```

### Service Unit File (`/etc/systemd/system/tunnel-agent.service`)

```ini
[Unit]
Description=Production UDP Tunnel Agent Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tunneluser
Group=tunneluser
WorkingDirectory=/opt/tunnel-agent
ExecStart=/opt/tunnel-agent/venv/bin/python /opt/tunnel-agent/tunnel_agent.py /opt/tunnel-agent/config_server.yaml

Restart=always
RestartSec=3s

# Security Hardening Controls
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
ReadOnlyPaths=/opt/tunnel-agent

# Memory Resource Constraints
MemoryMax=160M
MemoryHigh=128M

[Install]
WantedBy=multi-user.target
```

### Execution Commands

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tunnel-agent
sudo journalctl -u tunnel-agent -f -o cat
```

---

## Production Kernel & Network Tuning

Adjust kernel parameters to prevent UDP socket buffer overflow drops under heavy traffic.

### 1. System Control Parameters (`/etc/sysctl.conf`)

```ini
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 2621440
net.core.wmem_default = 2621440
```

Apply immediately:

```bash
sudo sysctl -p
```

### 2. Firewall Settings (`iptables`)

Open the configured UDP tunnel port on the server host:

```bash
sudo iptables -A INPUT -p udp --dport 9999 -j ACCEPT

# Persist rules across reboots (Debian/Ubuntu)
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

---

## Troubleshooting

### Issue: FEC decode timeouts appear frequently in logs
- **Cause**: Network latency exceeds the configured `fec_decode_timeout` (default 0.5s).
- **Solution**: Increase `fec_decode_timeout` in the configuration file (e.g., `1.0` for satellite links).

### Issue: "FEC decode timeout" warnings under high load
- **Cause**: CPU saturation or network congestion delaying packet arrival.
- **Solution**: Adjust `fec_k` and `fec_m` parameters for your link conditions, or increase `fec_decode_timeout`.

### Issue: High memory usage after long runtime
- **Check**: Ensure memory limits are properly configured via Docker (`deploy.resources.limits.memory`) or systemd (`MemoryMax`).
- **Solution**: Verify container/host resource constraints are correctly applied.
