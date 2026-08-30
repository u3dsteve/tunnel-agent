import asyncio
import logging
import os
import signal
import socket
import struct
import sys
import time
import yaml
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Configure logger instance
logger = logging.getLogger("tunnel_agent")

# ==================== 0. System Utilities & Diagnostics ====================
def setup_logging(level_setting: str):
    """
    Configures log level according to user preference:
    - "調試" / "debug": Detailed debug logging
    - Default: Standard operational logging (INFO minimum, compliance enforced)
    """
    level_str = str(level_setting).strip().lower()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    
    logger.handlers.clear()
    logger.addHandler(handler)
    
    if level_str in ("debug", "調試"):
        logger.setLevel(logging.DEBUG)
    else:  # Default to INFO (off/disable option removed for security audit compliance)
        logger.setLevel(logging.INFO)

def setup_memory_limit(limit_mb: int):
    """
    Memory limit enforcement delegated to container (Docker/K8s) or systemd runtime.
    """
    logger.info("Memory limit delegated to container/systemd runtime.")

async def safe_close_writer(writer: asyncio.StreamWriter | None):
    """Gracefully closes a StreamWriter and waits for underlying socket cleanup."""
    if not writer:
        return
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

# ==================== 1. Dynamic DNS & Address Resolver ====================
class DynamicResolver:
    """
    Handles asynchronous domain resolution with cached addresses.
    Re-resolves DNS records automatically on startup, network disconnection, or sending errors.
    """
    def __init__(self, host: str, port: int, socktype=socket.SOCK_DGRAM):
        self.host = host
        self.port = port
        self.socktype = socktype
        self._cached_family = None
        self._cached_sockaddr = None

    async def get_address(self, force_refresh: bool = False):
        if force_refresh or self._cached_sockaddr is None:
            logger.debug(f"Resolving DNS for host {self.host}:{self.port}...")
            try:
                res = await asyncio.to_thread(socket.getaddrinfo, self.host, self.port, socket.AF_UNSPEC, self.socktype)
                if not res:
                    raise ValueError(f"DNS resolution empty for {self.host}")
                family, _, _, _, sockaddr = res[0]
                self._cached_family = family
                self._cached_sockaddr = sockaddr
                logger.info(f"DNS resolved successfully: {self.host} -> {sockaddr[0]}")
            except Exception as e:
                logger.error(f"Failed to resolve address for {self.host}:{self.port} - {e}")
                if force_refresh and self._cached_sockaddr:
                    logger.warning("Retaining legacy cached address due to DNS lookup failure.")
                else:
                    raise
        return self._cached_family, self._cached_sockaddr

    def invalidate(self):
        """Invalidates the cached address to trigger a fresh DNS lookup on next attempt."""
        logger.debug(f"Invalidating cached IP address for {self.host}")
        self._cached_sockaddr = None

# ==================== 2. GF(2^8) Gauss-Jordan FEC Engine ====================
EXP_TABLE = [0] * 512
LOG_TABLE = [0] * 256

def _init_gf():
    poly = 0x11D
    x = 1
    for i in range(255):
        EXP_TABLE[i] = x
        EXP_TABLE[i + 255] = x
        LOG_TABLE[x] = i
        x = (x << 1) ^ (poly if (x & 0x80) else 0)

_init_gf()

def gf_mul(a, b):
    return 0 if a == 0 or b == 0 else EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]]

def gf_inv(a):
    if a == 0:
        raise ZeroDivisionError()
    return EXP_TABLE[255 - LOG_TABLE[a]]

def gf_mat_inv(mat, k):
    """Computes matrix inverse in GF(2^8) using Gauss-Jordan elimination."""
    aug = [row[:] + [1 if i == j else 0 for j in range(k)] for i, row in enumerate(mat)]
    for i in range(k):
        pivot = aug[i][i]
        if pivot == 0:
            for r in range(i + 1, k):
                if aug[r][i] != 0:
                    aug[i], aug[r] = aug[r], aug[i]
                    pivot = aug[i][i]
                    break
        inv_p = gf_inv(pivot)
        aug[i] = [gf_mul(x, inv_p) for x in aug[i]]
        for r in range(k):
            if r != i and aug[r][i] != 0:
                factor = aug[r][i]
                aug[r] = [aug[r][c] ^ gf_mul(aug[i][c], factor) for c in range(2 * k)]
    return [row[k:] for row in aug]

class TrueFECEngine:
    def __init__(self, k=4, m=2):
        self.k = k
        self.m = m
        self.full_matrix = []
        for i in range(k):
            self.full_matrix.append([1 if i == j else 0 for j in range(k)])
        for i in range(m):
            row = [gf_inv((i + 1) ^ (m + j + 1)) for j in range(k)]
            self.full_matrix.append(row)

    def encode(self, data: bytes) -> list[bytes]:
        shard_len = (len(data) + self.k - 1) // self.k
        padded = data.ljust(shard_len * self.k, b'\x00')
        data_shards = [padded[i * shard_len:(i + 1) * shard_len] for i in range(self.k)]
        
        all_shards = list(data_shards)
        for i in range(self.m):
            p_shard = bytearray(shard_len)
            row = self.full_matrix[self.k + i]
            for j in range(self.k):
                coef = row[j]
                d = data_shards[j]
                for idx in range(shard_len):
                    p_shard[idx] ^= gf_mul(d[idx], coef)
            all_shards.append(bytes(p_shard))
        return all_shards

    def decode(self, received_dict: dict, shard_len: int, orig_len: int) -> bytes:
        recv_ids = sorted(list(received_dict.keys()))[:self.k]
        sub_matrix = [self.full_matrix[sid] for sid in recv_ids]
        inv_matrix = gf_mat_inv(sub_matrix, self.k)
        
        recovered_shards = []
        for i in range(self.k):
            rec_s = bytearray(shard_len)
            inv_row = inv_matrix[i]
            for j, sid in enumerate(recv_ids):
                coef = inv_row[j]
                s_data = received_dict[sid]
                for idx in range(shard_len):
                    rec_s[idx] ^= gf_mul(s_data[idx], coef)
            recovered_shards.append(bytes(rec_s))
            
        assembled = b"".join(recovered_shards)
        return assembled[:orig_len]

# ==================== 3. Reorder Buffer ====================
class ReorderBuffer:
    def __init__(self, max_window=256, timeout=5.0):
        self.expected_seq = 0
        self.buffer = {}  # seq -> (cmd, payload, timestamp)
        self.max_window = max_window
        self.timeout = timeout

    def push(self, seq: int, cmd: int, payload: bytes, now: float = None) -> list[tuple[int, bytes]]:
        if now is None:
            now = time.monotonic()

        # Clean up expired gaps to prevent sequence deadlock and memory leaks
        while self.buffer:
            min_seq = min(self.buffer.keys())
            _, _, ts = self.buffer[min_seq]
            if now - ts > self.timeout:
                self.expected_seq = min_seq
                break
            else:
                break

        if seq < self.expected_seq:
            return []
        if seq < self.expected_seq + self.max_window:
            self.buffer[seq] = (cmd, payload, now)
        
        ready = []
        while self.expected_seq in self.buffer:
            cmd, payload, _ = self.buffer.pop(self.expected_seq)
            ready.append((cmd, payload))
            self.expected_seq += 1
        return ready

# ==================== 4. Crypto & Anti-Replay Engine ====================
class SecureTunnelCrypto:
    def __init__(self, psk: str):
        import hashlib
        self.aead = ChaCha20Poly1305(hashlib.sha256(psk.encode()).digest())
        self.max_seen_seq = -1

    def encrypt(self, plain: bytes, seq: int) -> bytes:
        nonce = os.urandom(12)
        pad_len = os.urandom(1)[0] % 16
        padding = os.urandom(pad_len)
        ts = int(time.time())
        
        # 64-bit sequence number (!IQB: uint32 ts, uint64 seq, uint8 pad_len)
        meta = struct.pack("!IQB", ts, seq, pad_len)
        return nonce + self.aead.encrypt(nonce, meta + padding + plain, None)

    def decrypt(self, raw: bytes) -> bytes | None:
        if len(raw) < 12 + 16 + 13:
            return None
        nonce, ciphertext = raw[:12], raw[12:]
        try:
            decrypted = self.aead.decrypt(nonce, ciphertext, None)
            ts, seq, pad_len = struct.unpack("!IQB", decrypted[:13])
            now_ts = int(time.time())
            
            if abs(now_ts - ts) > 15:
                return None
            
            if seq <= self.max_seen_seq:
                return None
            self.max_seen_seq = seq
                
            return decrypted[13 + pad_len:]
        except Exception:
            return None

# ==================== 5. Core Forward Agent ====================
FEC_HDR_FMT = "!IBBBH"   # [Group ID (4B)] [Shard ID (1B)] [K (1B)] [M (1B)] [Payload Len (2B)]
FEC_HDR_SIZE = struct.calcsize(FEC_HDR_FMT)

INNER_HDR_FMT = "!BII"   # [CMD (1B)] [Session ID (4B)] [Session Seq (4B)]
INNER_HDR_SIZE = struct.calcsize(INNER_HDR_FMT)

SAFE_SHARD_SIZE = 1200   # Prevent MTU fragmentation overflow (1200B * K)

class ForwardAgent(asyncio.DatagramProtocol):
    def __init__(self, config, tunnel_resolver: DynamicResolver = None):
        self.config = config
        self.role = config["role"]
        self.crypto = SecureTunnelCrypto(config["psk"])
        self.fec = TrueFECEngine(k=config.get("fec_k", 4), m=config.get("fec_m", 2))
        self.fec_decode_timeout = float(config.get("fec_decode_timeout", 0.5))
        self.tunnel_resolver = tunnel_resolver
        self.current_server_addr = None  # Dynamic target IP for client mode
        
        self.udp_transport = None
        self.sessions = {}       # sid -> sess_dict
        self.fec_groups = {}     # group_id -> {shards: {}, created_at: float}
        self.tunnel_seq = 0
        self.group_counter = 0
        self.next_sid = 1
        self.gc_task = None
        self.dns_task = None

    def connection_made(self, transport):
        self.udp_transport = transport
        self.gc_task = asyncio.create_task(self.gc_loop())
        if self.role == "client" and self.tunnel_resolver:
            self.dns_task = asyncio.create_task(self.dns_refresh_loop())

    def send_via_tunnel(self, payload: bytes, target_addr=None):
        self.group_counter = (self.group_counter + 1) % 0xFFFFFFFF
        group_id = self.group_counter
        shards = self.fec.encode(payload)
        
        dest_addr = self.current_server_addr if self.role == "client" else target_addr
        if self.role == "client" and not dest_addr:
            logger.error("Drop packet: Dynamic Server IP unavailable.")
            return

        for shard_id, shard_data in enumerate(shards):
            self.tunnel_seq += 1  # 64-bit sequence increment without modulo wrap
            fec_hdr = struct.pack(FEC_HDR_FMT, group_id, shard_id, self.fec.k, self.fec.m, len(payload))
            encrypted = self.crypto.encrypt(fec_hdr + shard_data, self.tunnel_seq)
            
            try:
                self.udp_transport.sendto(encrypted, dest_addr)
            except OSError as e:
                logger.error(f"UDP send error encountered: {e}")
                if self.tunnel_resolver:
                    self.tunnel_resolver.invalidate()

    def datagram_received(self, data, addr):
        decrypted = self.crypto.decrypt(data)
        if not decrypted or len(decrypted) < FEC_HDR_SIZE:
            return

        group_id, shard_id, k, m, orig_len = struct.unpack(FEC_HDR_FMT, decrypted[:FEC_HDR_SIZE])
        shard_payload = decrypted[FEC_HDR_SIZE:]

        if group_id not in self.fec_groups:
            self.fec_groups[group_id] = {"shards": {}, "created_at": time.monotonic()}
            
        grp = self.fec_groups[group_id]
        grp["shards"][shard_id] = shard_payload

        if len(grp["shards"]) >= k:
            shards = grp["shards"]
            del self.fec_groups[group_id]
            asyncio.create_task(self._decode_fec_group(group_id, shards, len(shard_payload), orig_len, addr))

    async def _decode_fec_group(self, group_id: int, shards: dict, shard_len: int, orig_len: int, addr):
        try:
            recovered = await asyncio.wait_for(
                asyncio.to_thread(self.fec.decode, shards, shard_len, orig_len),
                timeout=self.fec_decode_timeout
            )
            self.process_payload(recovered, addr)
        except asyncio.TimeoutError:
            logger.warning(f"FEC decode timeout for group {group_id}, dropping")
        except Exception as e:
            logger.debug(f"FEC recovery execution error: {e}")

    def process_payload(self, payload: bytes, addr):
        if len(payload) < INNER_HDR_SIZE:
            return
        cmd, sid, seq = struct.unpack(INNER_HDR_FMT, payload[:INNER_HDR_SIZE])
        content = payload[INNER_HDR_SIZE:]
        now = time.monotonic()

        sess = self.sessions.get(sid)
        if not sess and self.role == "server" and cmd == 1:
            sess = {
                "writer": None,
                "reorder": ReorderBuffer(),
                "pending": [],
                "last_active": now,
                "seq_out": 0,
                "closed_remote": False,
                "addr": addr
            }
            self.sessions[sid] = sess
            asyncio.create_task(self.start_target_conn(sid, addr))

        if sess:
            sess["last_active"] = now
            ordered_packets = sess["reorder"].push(seq, cmd, content if cmd == 1 else b"", now)
            
            for pkt_cmd, pkt_data in ordered_packets:
                if pkt_cmd == 2:
                    sess["closed_remote"] = True
                elif pkt_data:
                    if sess["writer"]:
                        sess["writer"].write(pkt_data)
                    else:
                        sess["pending"].append(pkt_data)

            if sess.get("closed_remote"):
                writer = sess.pop("writer", None)
                if writer:
                    asyncio.create_task(safe_close_writer(writer))
                self.sessions.pop(sid, None)

    async def start_target_conn(self, sid, client_addr):
        target_cfg = self.config["target"]
        writer = None
        target_resolver = DynamicResolver(target_cfg["host"], target_cfg["port"], socket.SOCK_STREAM)
        
        try:
            try:
                _, sockaddr = await target_resolver.get_address()
                reader, writer = await asyncio.open_connection(sockaddr[0], sockaddr[1])
            except (OSError, asyncio.TimeoutError) as err:
                logger.warning(f"Connection failed to target. Re-resolving address: {err}")
                _, sockaddr = await target_resolver.get_address(force_refresh=True)
                reader, writer = await asyncio.open_connection(sockaddr[0], sockaddr[1])

            sess = self.sessions.get(sid)
            if not sess:
                await safe_close_writer(writer)
                return

            sess["writer"] = writer
            
            for pkt in sess["pending"]:
                writer.write(pkt)
            sess["pending"].clear()

            if sess.get("closed_remote"):
                await safe_close_writer(sess.pop("writer", None))
                self.sessions.pop(sid, None)
                return

            max_chunk = (self.fec.k * SAFE_SHARD_SIZE) - INNER_HDR_SIZE
            while True:
                data = await reader.read(max_chunk)
                if not data:
                    break
                
                sess = self.sessions.get(sid)
                if not sess:
                    break
                
                sess["last_active"] = time.monotonic()
                seq_out = sess["seq_out"]
                sess["seq_out"] += 1
                
                msg = struct.pack(INNER_HDR_FMT, 1, sid, seq_out) + data
                self.send_via_tunnel(msg, client_addr)
        except Exception as e:
            logger.debug(f"Target connection error for session {sid}: {e}")
            target_resolver.invalidate()
        finally:
            sess = self.sessions.pop(sid, None)
            if sess:
                seq_out = sess.get("seq_out", 0)
                msg = struct.pack(INNER_HDR_FMT, 2, sid, seq_out)
                self.send_via_tunnel(msg, client_addr)
                await safe_close_writer(sess.get("writer") or writer)
            elif writer:
                await safe_close_writer(writer)

    async def dns_refresh_loop(self, interval: int = 60):
        """Periodically polls DNS for potential Server IP changes (DDNS resilience)."""
        while True:
            await asyncio.sleep(interval)
            try:
                _, sockaddr = await self.tunnel_resolver.get_address(force_refresh=True)
                if self.current_server_addr != sockaddr:
                    logger.info(f"DDNS IP Update detected: {self.current_server_addr} -> {sockaddr}")
                    self.current_server_addr = sockaddr
            except Exception as e:
                logger.warning(f"Background DDNS refresh encountered an error: {e}")

    async def gc_loop(self):
        while True:
            await asyncio.sleep(5)
            now = time.monotonic()
            
            stale_groups = [gid for gid, g in self.fec_groups.items() if now - g["created_at"] > 3.0]
            for gid in stale_groups:
                del self.fec_groups[gid]

            stale_sids = [sid for sid, s in self.sessions.items() if now - s["last_active"] > 60.0]
            for sid in stale_sids:
                sess = self.sessions.pop(sid, None)
                if sess and sess.get("writer"):
                    asyncio.create_task(safe_close_writer(sess["writer"]))

    async def close_all_sessions(self):
        if self.gc_task:
            self.gc_task.cancel()
        if self.dns_task:
            self.dns_task.cancel()
        sids = list(self.sessions.keys())
        for sid in sids:
            sess = self.sessions.pop(sid, None)
            if sess and sess.get("writer"):
                await safe_close_writer(sess["writer"])

# ==================== 6. Entry Point & Signal Handling ====================
async def main():
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    with open(config_file, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    setup_logging(cfg.get("log_level", "一般"))
    setup_memory_limit(cfg.get("memory_limit_mb", 128))

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def shutdown_handler():
        logger.info("Shutdown signal received. Initiating graceful shutdown...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown_handler)
        except NotImplementedError:
            pass

    if cfg["role"] == "client":
        t_cfg, l_cfg = cfg["tunnel"], cfg["listen"]
        tunnel_resolver = DynamicResolver(t_cfg["host"], t_cfg["port"], socket.SOCK_DGRAM)
        agent = ForwardAgent(cfg, tunnel_resolver=tunnel_resolver)
        
        # Initial resolution to configure IP family and cache initial target address
        family, remote_sockaddr = await tunnel_resolver.get_address(force_refresh=True)
        agent.current_server_addr = remote_sockaddr
        
        # Bind locally without fixing remote_addr to allow seamless DDNS IP switching
        bind_ip = "::" if family == socket.AF_INET6 else "0.0.0.0"
        transport, _ = await loop.create_datagram_endpoint(
            lambda: agent,
            local_addr=(bind_ip, 0),
            family=family
        )
        
        async def handle_client_tcp(reader, writer):
            sid = agent.next_sid
            agent.next_sid = (agent.next_sid + 1) % 0xFFFFFFFF
            
            agent.sessions[sid] = {
                "writer": writer,
                "reorder": ReorderBuffer(),
                "pending": [],
                "seq_out": 0,
                "last_active": time.monotonic()
            }
            
            max_chunk = (agent.fec.k * SAFE_SHARD_SIZE) - INNER_HDR_SIZE
            try:
                while True:
                    data = await reader.read(max_chunk)
                    if not data:
                        break
                    
                    sess = agent.sessions.get(sid)
                    if not sess:
                        break
                    
                    sess["last_active"] = time.monotonic()
                    seq_out = sess["seq_out"]
                    sess["seq_out"] += 1
                    
                    msg = struct.pack(INNER_HDR_FMT, 1, sid, seq_out) + data
                    agent.send_via_tunnel(msg)
            finally:
                sess = agent.sessions.get(sid)
                if sess:
                    seq_out = sess["seq_out"]
                    msg = struct.pack(INNER_HDR_FMT, 2, sid, seq_out)
                    agent.send_via_tunnel(msg)
                    agent.sessions.pop(sid, None)
                await safe_close_writer(writer)

        listen_resolver = DynamicResolver(l_cfg["host"], l_cfg["port"], socket.SOCK_STREAM)
        _, listen_sockaddr = await listen_resolver.get_address(force_refresh=True)
        
        server = await asyncio.start_server(handle_client_tcp, listen_sockaddr[0], listen_sockaddr[1])
        logger.info(f"[Client Agent] Listening on TCP {l_cfg['host']}:{l_cfg['port']} -> Tunnel UDP {t_cfg['host']}:{t_cfg['port']}")
        
        async with server:
            await stop_event.wait()
            
        transport.close()
        await agent.close_all_sessions()
    else:
        t_cfg = cfg["tunnel"]
        tunnel_resolver = DynamicResolver(t_cfg["host"], t_cfg["port"], socket.SOCK_DGRAM)
        agent = ForwardAgent(cfg, tunnel_resolver=tunnel_resolver)
        
        family, local_sockaddr = await tunnel_resolver.get_address(force_refresh=True)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: agent,
            local_addr=local_sockaddr,
            family=family
        )
        logger.info(f"[Server Agent] Listening on Tunnel UDP {t_cfg['host']}:{t_cfg['port']}...")
        
        await stop_event.wait()
        transport.close()
        await agent.close_all_sessions()

    logger.info("Agent stopped cleanly.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass