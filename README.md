# High-Performance UDP Tunnel Agent

## Overview

The **UDP Tunnel Agent** is a secure, high-throughput, loss-resistant proxy service designed for reliable network communication over lossy, unstable, or heavily inspected links. Written in Python 3.10+, it encapsulates TCP application traffic into encrypted UDP datagrams, applying Forward Error Correction (FEC) to eliminate retransmission delays caused by packet loss while employing anti-analysis protections against network censorship.

### What It Does

In network environments with high packet loss or strict stateful inspection, standard TCP connections suffer severe throughput collapse. This agent bypasses these bottlenecks:

1. **Traffic Interception**: Accepts TCP connections on a local entry point.
2. **FEC Encoding & Obfuscation**: Splits stream data into shards, generates Reed-Solomon-style parity shards via Galois Field `GF(2^8)` arithmetic, and appends dynamic random-length padding.
3. **AEAD Encryption & Replay Defense**: Encrypts payloads using ChaCha20-Poly1305 AEAD, embedding a timestamp plus a strictly monotonic 64-bit sequence number for replay protection.
4. **UDP Transport**: Transmits datagrams over UDP to eliminate TCP head-of-line blocking.
5. **Backpressure**: Applies an in-flight group watermark per session to avoid blasting UDP until the kernel drops packets.
6. **Reconstruction & Forwarding**: The remote endpoint validates timestamp/sequence, reconstructs lost data shards in real time using surviving parity shards, decrypts the payload, and forwards clean TCP streams to the destination.

---

## Architectural Data Flow

```text
[ Local Client App ]
       │ (TCP)
       ▼
[ Tunnel Client ]  ─── Encrypt, Obfuscate & FEC (UDP) ───►  [ Tunnel Server ]
  • Listens locally                                           • Listens on UDP port
  • Encrypts via ChaCha20-Poly1305                            • Validates timestamp + 64-bit sequence
  • Appends parity shards (GF 2^8)                            • Recovers lost shards via FEC
  • Injects dynamic random padding                            • Decrypts & reconstructs stream
  • Asynchronously resolves DDNS (thread-isolated)            • Reorder buffer with 0.2s gap expiry
  • In-flight watermark backpressure                          • Backpressure on target TCP reads
                                                                     │ (TCP)
                                                                     ▼
                                                           [ Remote Target Service ]
                                                           (e.g., SSH, Web, Proxy)
```

---

## Key Features

* **AEAD Security & Replay Defense**: Secured with ChaCha20-Poly1305 authenticated encryption derived from a Pre-Shared Key (PSK) via SHA-256. Each datagram carries a 32-bit timestamp and a 64-bit sequence; replayed or stale packets are rejected via a sliding `(timestamp, sequence)` window.
* **FEC Loss Resilience**: Configurable `(k, m)` matrix parameters recover from up to `m / (k + m)` random packet loss without request-response round-trips. Parity generation and matrix inversion are vectorised when numpy is available and fall back to precomputed GF lookup tables otherwise. Inverse matrices for common loss patterns are cached.
* **Anti-DPI & Traffic Obfuscation**: Injects randomized padding (0–15 bytes) into every datagram to defeat naive Deep Packet Inspection (DPI) heuristics.
* **Mandatory Audit Logging**: Enforces operational compliance by keeping logging active at a minimum of `info` level (disabling logs is restricted to satisfy security audit requirements).
* **Seamless DDNS Resilience**: Built-in background resolver asynchronously monitors and updates target IP addresses for dynamic hostnames without dropping active client connections. DNS lookups are thread-isolated to prevent event loop blocking.
* **Robust Reorder Buffer**: Handles out-of-order packet delivery with a 256-slot window and a **200 ms gap timeout** so a single missing packet cannot stall the entire stream behind multi-second delays.
* **Backpressure**: Each session tracks its in-flight FEC group count and pauses reading from the TCP socket when the watermark is exceeded. This avoids the classic "TCP reads as fast as it can, UDP silently drops" collapse.
* **Control-Plane Reliability**: Handshake, `CMD_CLOSE`, and heartbeat packets are retransmitted on a short schedule so a single UDP loss does not stall a session until idle timeout.
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
```

numpy is **optional** and only used to accelerate FEC math. When absent, the agent falls back to a precomputed GF(256) lookup table implementation and remains fully functional. To enable the accelerated path:

```text
numpy>=1.21
```

---

## Configuration Reference

All fields marked *optional* fall back to safe defaults if omitted. `fec_k`, `fec_m`, and `psk` **must match on both sides**; mismatched FEC parameters cause every group to be silently dropped.

### Client Config (`config_client.yaml`)

```yaml
role: "client"

# Must match server.
psk: "YourSuperSecretPasswordKey2026!"

# FEC parameters. (4, 2) tolerates up to 33% random packet loss per group.
fec_k: 4
fec_m: 2

# "debug" | "info"
log_level: "info"

# Local TCP ingress
listen:
  host: "127.0.0.1"
  port: 1080

# Remote UDP egress endpoint
tunnel:
  host: "my-server.ddns.net"
  port: 9999

# ---- Optional tuning ----

# Maximum accepted clock skew between client and server, in seconds.
# Must be within [1.0, 300.0]. Raise only if NTP cannot keep the hosts aligned.
timestamp_tolerance: 60.0

# Bytes buffered before flushing a CMD_DATA chunk. Hard limit is 8192.
send_buffer_size: 4096

# How long to wait for more TCP data before flushing. Lower = lower latency,
# higher CPU wakeups per session.
send_timeout: 0.02

# Scales derived stream / reorder / buffer caps. Does not reserve memory.
available_memory_mb: 512

# Per-session backpressure watermark: max in-flight FEC groups before the
# agent pauses reading from the local TCP socket.
# Lower (e.g. 128) = safer on lossy / low-bandwidth links.
# Higher (e.g. 2048) = more aggressive on LAN / high-bandwidth links.
inflight_max: 512

# Approximate pipe drain rate used to decay the in-flight counter.
inflight_decay_per_sec: 1000
```

### Server Config (`config_server.yaml`)

```yaml
role: "server"

# Must match client.
psk: "YourSuperSecretPasswordKey2026!"

# Must match client.
fec_k: 4
fec_m: 2

# "debug" | "info"
log_level: "info"

# Inbound UDP tunnel endpoint
tunnel:
  host: "0.0.0.0"
  port: 9999

# Final TCP destination
target:
  host: "127.0.0.1"
  port: 22

# ---- Optional tuning (same semantics as client) ----
timestamp_tolerance: 60.0
send_buffer_size: 4096
send_timeout: 0.02
available_memory_mb: 512
inflight_max: 512
inflight_decay_per_sec: 1000
```

> The `fec_decode_timeout` field from earlier revisions is no longer used. It was never read by the agent; FEC group expiry is handled internally.

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

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

RUN useradd --create-home --shell /usr/sbin/nologin tunnel \
    && chown -R tunnel:tunnel /app

COPY --chown=tunnel:tunnel tunnel_agent.py .

USER tunnel

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
    mem_limit: 128m
    memswap_limit: 128m
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes:
      - ./config_client.yaml:/app/config.yaml:ro

  tunnel-server:
    build: .
    container_name: tunnel-server
    restart: always
    network_mode: "host"
    mem_limit: 256m
    memswap_limit: 256m
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes:
      - ./config_server.yaml:/app/config.yaml:ro
```

> `mem_limit` is used instead of `deploy.resources.limits.memory` so the file works with both Docker Compose v1 and v2. If you only use Compose v2 and prefer the `deploy` block, it is equivalent.

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

## Tuning Cheatsheet

| Link profile | `fec_m` | `inflight_max` | `send_timeout` | `send_buffer_size` |
|---|---|---|---|---|
| LAN / stable | 1 | 2048 | 0.01 | 8192 |
| Home broadband | 2 | 512 | 0.02 | 4096 |
| 4G / lossy | 2 | 128 | 0.02 | 4096 |
| Satellite / high RTT | 3 | 64 | 0.05 | 8192 |

Guidance:

- Raising `fec_m` costs bandwidth but improves burst-loss tolerance.
- Lowering `inflight_max` makes the agent more conservative on lossy links; raising it trades loss for throughput on clean links.
- `send_timeout` is the dominant factor for idle-connection latency vs. CPU cost.

---

## Troubleshooting

### Issue: Throughput collapses on a lossy link
- **Cause**: Without enough parity or with too-aggressive in-flight limits, FEC cannot recover bursts and the reorder buffer skips forward frequently.
- **Solution**: Increase `fec_m` (e.g. `4, 2` → `4, 3`). Lower `inflight_max` if kernel `sendto` drops are suspected (`netstat -su` shows `send buffer errors`).

### Issue: Interactive sessions (SSH, RDP) feel laggy
- **Cause**: `send_timeout` or `send_buffer_size` is too large; small keystrokes wait for the flush timer.
- **Solution**: Lower `send_timeout` to `0.01` and `send_buffer_size` to `2048`. Watch CPU usage; the timer fires once per session per `send_timeout`.

### Issue: Sessions disappear after ~2 minutes of inactivity
- **Cause**: The agent's idle session timeout is 120 seconds. Some middleboxes also expire UDP mappings before that.
- **Solution**: The client sends heartbeats every 8 seconds and the server replies, which should keep NAT bindings alive. If your middlebox is more aggressive, lower `HEARTBEAT_INTERVAL` in the source (constant near the top of `tunnel_agent.py`).

### Issue: "re-handshake" warnings in server logs
- **Cause**: A second client tried to reuse a session ID that is still held by a different source IP. Session IDs are chosen randomly per client, so this is rare; it usually indicates a NAT misconfiguration or a duplicated client.
- **Solution**: Confirm only one client is running per session ID. No action is required if it is transient.

### Issue: High memory usage after long runtime
- **Check**: Ensure memory limits are properly configured via Docker (`mem_limit`) or systemd (`MemoryMax`).
- **Solution**: Also lower `available_memory_mb`; this reduces the maximum concurrent streams and reorder window derived caps.

### Issue: Clock-skew errors after the server has been running for months
- **Cause**: The replay window is bounded by `timestamp_tolerance`. If NTP is unavailable and the client's clock drifts, packets will be silently rejected.
- **Solution**: Restore NTP, or raise `timestamp_tolerance` (up to 300 seconds).
