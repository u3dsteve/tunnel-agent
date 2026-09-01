import asyncio
import hashlib
import logging
import os
import signal
import socket
import struct
import sys
import time
import yaml
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from typing import Dict, Tuple, Optional, List

# ==================== 0. System Initialization & Config ====================
logger = logging.getLogger("tunnel_agent")

def setup_logging(level_setting: str):
    """Enforce INFO minimum for operational compliance unless DEBUG is requested."""
    level = logging.DEBUG if str(level_setting).lower() == "debug" else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)

class MemoryTuner:
    """Dynamic buffer scaling based on available memory limits."""
    def __init__(self, mem_mb: int):
        self.mem_mb = max(int(mem_mb), 128)
        ratio = self.mem_mb / 512.0
        self.max_streams = min(int(1024 * ratio), 8192)
        self.tcp_buf_limit = min(int(1048576 * ratio), 4194304)
        self.reorder_window_limit = 256
        self.seen_seq_ttl = 30.0
        self.seen_seq_limit = 5000

# ==================== 1. Crypto & Anti-Replay Engine ====================
class SecureTunnelCrypto:
    def __init__(self, psk: str, tuner: MemoryTuner):
        key = hashlib.sha256(psk.encode()).digest()
        self.aead = ChaCha20Poly1305(key)
        self.tuner = tuner
        self.seen_sequences: Dict[int, float] = {}  # seq -> timestamp

    def encrypt(self, plain: bytes, seq: int) -> bytes:
        nonce = os.urandom(12)
        ts = int(time.time())
        pad_len = os.urandom(1)[0] % 16
        padding = os.urandom(pad_len)
        # Header: Timestamp(4B), Seq(8B), PadLen(1B) -> 13 Bytes total
        header = struct.pack("!IQB", ts, seq, pad_len)
        return nonce + self.aead.encrypt(nonce, header + padding + plain, None)

    def decrypt(self, raw: bytes) -> Optional[bytes]:
        if len(raw) < 12 + 16 + 13: 
            return None
            
        nonce, ciphertext = raw[:12], raw[12:]
        try:
            decrypted = self.aead.decrypt(nonce, ciphertext, None)
            ts, seq, pad_len = struct.unpack("!IQB", decrypted[:13])
            now = time.time()

            # Timestamp tolerance check (±15 seconds)
            if abs(now - ts) > 15: 
                return None
            
            if seq in self.seen_sequences: 
                return None
            self.seen_sequences[seq] = now
            
            # Fast FIFO cleanup on overflow to prevent O(N log N) sorting CPU spikes
            if len(self.seen_sequences) > self.tuner.seen_seq_limit:
                cutoff = now - self.tuner.seen_seq_ttl
                expired = [s for s, t in self.seen_sequences.items() if t < cutoff]
                if expired:
                    for s in expired: 
                        del self.seen_sequences[s]
                else:
                    # Pop oldest 1000 items in O(1) time utilizing dict insertion order
                    keys_to_pop = list(self.seen_sequences.keys())[:1000]
                    for s in keys_to_pop:
                        del self.seen_sequences[s]
                
            return decrypted[13 + pad_len:]
        except Exception:
            return None

# ==================== 2. FEC Engine (GF2^8 Gauss-Jordan) ====================
EXP_TABLE = [0] * 512
LOG_TABLE = [0] * 256

def _init_gf():
    poly, x = 0x11D, 1
    for i in range(255):
        EXP_TABLE[i] = EXP_TABLE[i+255] = x
        LOG_TABLE[x] = i
        x = (x << 1) ^ (poly if (x & 0x80) else 0)
_init_gf()

def gf_mul(a, b): return 0 if a == 0 or b == 0 else EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]]
def gf_inv(a): return EXP_TABLE[255 - LOG_TABLE[a]]

class OptimizedFECEngine:
    def __init__(self, k, m):
        self.k, self.m = k, m
        self.matrix = [[1 if i == j else 0 for j in range(k)] for i in range(k)]
        for i in range(m):
            self.matrix.append([gf_inv((i + 1) ^ (m + j + 1)) for j in range(k)])

    def encode(self, data: bytes) -> List[bytes]:
        shard_len = (len(data) + self.k - 1) // self.k
        padded = data.ljust(shard_len * self.k, b'\x00')
        shards = [padded[i*shard_len : (i+1)*shard_len] for i in range(self.k)]
        for i in range(self.m):
            p_shard = bytearray(shard_len)
            row = self.matrix[self.k + i]
            for j in range(self.k):
                coef, d = row[j], shards[j]
                for idx in range(shard_len): 
                    p_shard[idx] ^= gf_mul(d[idx], coef)
            shards.append(bytes(p_shard))
        return shards

    def decode(self, received: dict, shard_len: int, orig_len: int) -> bytes:
        if all(i in received for i in range(self.k)):
            return b"".join(received[i] for i in range(self.k))[:orig_len]
        
        recv_ids = sorted(list(received.keys()))[:self.k]
        sub_matrix = [self.matrix[sid] for sid in recv_ids]
        inv_matrix = self._mat_inv(sub_matrix, self.k)
        
        recovered = []
        for i in range(self.k):
            rec_s = bytearray(shard_len)
            inv_row = inv_matrix[i]
            for j, sid in enumerate(recv_ids):
                coef, s_data = inv_row[j], received[sid]
                for idx in range(shard_len): 
                    rec_s[idx] ^= gf_mul(s_data[idx], coef)
            recovered.append(bytes(rec_s))
        return b"".join(recovered)[:orig_len]

    def _mat_inv(self, mat, k):
        aug = [row[:] + [1 if i == j else 0 for j in range(k)] for i, row in enumerate(mat)]
        for i in range(k):
            pivot = aug[i][i]
            if pivot == 0:
                for r in range(i+1, k):
                    if aug[r][i] != 0: 
                        aug[i], aug[r] = aug[r], aug[i]
                        pivot = aug[i][i]
                        break
            inv_p = gf_inv(pivot)
            aug[i] = [gf_mul(x, inv_p) for x in aug[i]]
            for r in range(k):
                if r != i:
                    f = aug[r][i]
                    aug[r] = [aug[r][c] ^ gf_mul(aug[i][c], f) for c in range(2*k)]
        return [row[k:] for row in aug]

# ==================== 3. Core Forward Agent ====================
FEC_HDR = "!IBBBH" 
CMD_HDR = "!BII"   
CMD_DATA, CMD_CLOSE, CMD_ACK, CMD_HEARTBEAT = 1, 2, 3, 4

class ForwardAgent(asyncio.DatagramProtocol):
    def __init__(self, config: dict, tuner: MemoryTuner):
        self.config = config
        self.tuner = tuner
        self.crypto = SecureTunnelCrypto(config["psk"], tuner)
        
        self.fec_k = int(config.get("fec_k", 4))
        self.fec_m = int(config.get("fec_m", 2))
        self.fec_decode_timeout = float(config.get("fec_decode_timeout", 0.5))
        self.fec = OptimizedFECEngine(self.fec_k, self.fec_m)
        
        self.sessions = {}
        self.fec_groups = {}
        self.tunnel_seq = 0
        self.group_id = 0
        self.transport = None
        self.server_addr = None
        self.bg_tasks = []
        
        self.next_sid = 1
        self._last_no_target_warning = 0.0

    def get_next_sid(self) -> int:
        max_attempts = self.tuner.max_streams + 1
        for _ in range(max_attempts):
            sid = self.next_sid
            self.next_sid = (self.next_sid + 1) & 0xFFFFFFFF
            if self.next_sid == 0:
                self.next_sid = 1
            if sid not in self.sessions and sid != 0:
                return sid
        sid = self.next_sid
        self.next_sid = (self.next_sid + 1) & 0xFFFFFFFF
        if sid == 0:
            sid = 1
        return sid

    def connection_made(self, transport):
        self.transport = transport
        self.bg_tasks.append(asyncio.create_task(self.gc_loop()))
        if self.config["role"] == "client":
            self.bg_tasks.append(asyncio.create_task(self.heartbeat_loop()))
            self.bg_tasks.append(asyncio.create_task(self.dns_refresh_loop()))

    def send_via_tunnel(self, payload: bytes, addr=None) -> bool:
        """Encapsulate payload into FEC shards and send. Returns False if OS socket buffer overflows."""
        target = addr or self.server_addr
        if not target: 
            now = time.monotonic()
            if now - self._last_no_target_warning > 5.0:
                logger.warning("[Send] No target address available, dropping packet (suppressing for 5s).")
                self._last_no_target_warning = now
            else:
                logger.debug("[Send] No target address available, dropping packet.")
            return True

        self.group_id = (self.group_id + 1) % 0xFFFFFFFF
        shards = self.fec.encode(payload)
        
        buffer_ok = True
        for i, shard in enumerate(shards):
            self.tunnel_seq = (self.tunnel_seq + 1) & 0xFFFFFFFFFFFFFFFF
            fec_head = struct.pack(FEC_HDR, self.group_id, i, self.fec_k, self.fec_m, len(payload))
            enc = self.crypto.encrypt(fec_head + shard, self.tunnel_seq)
            try:
                self.transport.sendto(enc, target)
            except OSError:
                buffer_ok = False # OS socket send buffer full
        return buffer_ok

    def datagram_received(self, data, addr):
        dec = self.crypto.decrypt(data)
        if not dec or len(dec) < 9: 
            return
        
        gid, sid, k, m, olen = struct.unpack(FEC_HDR, dec[:9])
        shard_data = dec[9:]
        
        if gid not in self.fec_groups:
            self.fec_groups[gid] = {
                "shards": {}, "time": time.monotonic(), 
                "k": k, "m": m, "olen": olen, "decoded": False
            }
        
        g = self.fec_groups[gid]
        if g.get("decoded"):
            return

        g["shards"][sid] = shard_data
        
        if len(g["shards"]) >= k:
            g["decoded"] = True
            shards = g.pop("shards")
            asyncio.create_task(self.decode_and_process(gid, shards, len(shard_data), olen, addr))

    async def decode_and_process(self, gid, shards, slen, olen, addr):
        try:
            plain = await asyncio.wait_for(
                asyncio.to_thread(self.fec.decode, shards, slen, olen),
                timeout=self.fec_decode_timeout
            )
            self.process_inner_cmd(plain, addr)
        except asyncio.TimeoutError:
            logger.warning(f"[Security] FEC group {gid} decode timeout, dropping (DoS defense).")
        except Exception as e:
            logger.debug(f"[FEC] Decode failed: {e}")

    def process_inner_cmd(self, data, addr):
        if len(data) < 9: 
            return
            
        cmd, sid, seq = struct.unpack(CMD_HDR, data[:9])
        pay = data[9:]
        
        if cmd == CMD_HEARTBEAT: 
            return

        # Handle new incoming server session with tombstone protection against reconnect loops
        if self.config["role"] == "server" and sid not in self.sessions and cmd == CMD_DATA:
            self.sessions[sid] = {
                "sid": sid, "writer": None, "buffer": {}, "exp_seq": 0,
                "last_act": time.monotonic(), "addr": addr, "seq_out": 0,
                "connecting": True, "pending_pkts": [], "closed": False
            }
            asyncio.create_task(self.create_server_session(sid, addr))
            
        if sid in self.sessions:
            sess = self.sessions[sid]
            sess["last_act"] = time.monotonic()
            
            if sess.get("closed"):
                return # Ignore trailing packets for closed sessions

            if cmd == CMD_DATA:
                if sess.get("connecting"):
                    if len(sess["pending_pkts"]) < self.tuner.reorder_window_limit:
                        sess["pending_pkts"].append((seq, pay))
                else:
                    self.push_to_reorder(sess, seq, pay)
            elif cmd == CMD_CLOSE:
                self.close_session(sid)

    def push_to_reorder(self, sess, seq, data):
        if sess.get("closed"):
            return

        buf = sess["buffer"]
        exp = sess["exp_seq"]
        
        # Unsigned 32-bit modular arithmetic distance calculation
        diff = (seq - exp) & 0xFFFFFFFF
        
        # Drop if sequence number is behind exp_seq (diff >= 2^31)
        if diff >= 0x80000000:
            return
        
        # Drop if packet sequence exceeds reorder window limit
        if diff > self.tuner.reorder_window_limit:
            return

        buf[seq] = data
        now = time.monotonic()
        if "gap_time" not in sess:
            sess["gap_time"] = now

        # Unblock stream stalls on unrecoverable packet gaps after 5 seconds timeout
        if sess["exp_seq"] not in buf and (now - sess["gap_time"] > 5.0):
            if buf:
                # Find sequence number closest to exp_seq in modular space
                closest_seq = min(buf.keys(), key=lambda s: (s - sess["exp_seq"]) & 0xFFFFFFFF)
                sess["exp_seq"] = closest_seq
                sess["gap_time"] = now
                logger.warning(f"[Reorder] Gap timeout on session {sess['sid']}, skipping to seq {sess['exp_seq']}")

        while sess["exp_seq"] in buf:
            chunk = buf.pop(sess["exp_seq"])
            sess["gap_time"] = time.monotonic()
            writer = sess.get("writer")
            if writer and not writer.is_closing():
                try:
                    writer.write(chunk)
                except Exception as e:
                    logger.debug(f"[TCP] Write error: {e}")
                    self.close_session(sess.get("sid"))
                    break
            sess["exp_seq"] = (sess["exp_seq"] + 1) & 0xFFFFFFFF

    async def gc_loop(self):
        while True:
            await asyncio.sleep(5)
            now = time.monotonic()
            
            stale_fec = [gid for gid, g in self.fec_groups.items() if now - g["time"] > 3.0]
            for gid in stale_fec: 
                self.fec_groups.pop(gid, None)
            
            # Fast cleanup for closed sessions (30s) and long-idle sessions (300s)
            stale_sess = [
                sid for sid, s in self.sessions.items() 
                if now - s["last_act"] > (30.0 if s.get("closed") else 300.0)
            ]
            for sid in stale_sess: 
                logger.debug(f"[GC] Removing session {sid}")
                self.sessions.pop(sid, None)

    async def heartbeat_loop(self):
        while True:
            await asyncio.sleep(20)
            if self.server_addr:
                msg = struct.pack(CMD_HDR, CMD_HEARTBEAT, 0, 0)
                self.send_via_tunnel(msg, self.server_addr)

    async def dns_refresh_loop(self):
        host = self.config["tunnel"]["host"]
        port = int(self.config["tunnel"]["port"])
        while True:
            await asyncio.sleep(60)
            try:
                info = await asyncio.to_thread(socket.getaddrinfo, host, port, socket.AF_INET)
                valid_ips = [item[4] for item in info]
                
                if self.server_addr not in valid_ips:
                    self.server_addr = valid_ips[0] if valid_ips else None
                    if self.server_addr:
                        logger.info(f"[DDNS] Target IP updated/switched: {self.server_addr}")
            except Exception as e:
                logger.debug(f"[DDNS] Refresh failed: {e}")

    async def create_server_session(self, sid, client_addr):
        sess = self.sessions.get(sid)
        if not sess or sess.get("closed"):
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.config["target"]["host"], int(self.config["target"]["port"])),
                timeout=10.0
            )
            sess["writer"] = writer
            sess["connecting"] = False
            
            pending = sess.pop("pending_pkts", [])
            for p_seq, p_pay in pending:
                self.push_to_reorder(sess, p_seq, p_pay)

            asyncio.create_task(self.pipe_tcp_to_udp(sid, reader, client_addr))
        except Exception as e:
            logger.debug(f"[Server] Target connection failed: {e}")
            # Mark session closed with tombstone to suppress reconnection loops from trailing data
            sess["closed"] = True
            sess["connecting"] = False
            sess.pop("pending_pkts", None)
            msg = struct.pack(CMD_HDR, CMD_CLOSE, sid, 0)
            self.send_via_tunnel(msg, client_addr)

    async def pipe_tcp_to_udp(self, sid, reader, addr):
        try:
            while True:
                data = await reader.read(4096)
                if not data: 
                    break
                sess = self.sessions.get(sid)
                if not sess or sess.get("closed"): 
                    break
                
                msg = struct.pack(CMD_HDR, CMD_DATA, sid, sess["seq_out"]) + data
                sent_ok = self.send_via_tunnel(msg, addr)
                sess["seq_out"] = (sess["seq_out"] + 1) & 0xFFFFFFFF
                sess["last_act"] = time.monotonic()
                
                if not sent_ok:
                    # Apply backpressure delay if OS UDP buffer overflows
                    await asyncio.sleep(0.002)
                else:
                    # Cooperative yield to prevent event loop starvation under high TCP throughput
                    await asyncio.sleep(0)
        except (ConnectionError, OSError):
            pass
        finally:
            self.close_session(sid)

    def close_session(self, sid):
        sess = self.sessions.get(sid)
        if sess and not sess.get("closed"):
            sess["closed"] = True
            writer = sess.get("writer")
            if writer and not writer.is_closing(): 
                try:
                    writer.close()
                except Exception: pass
            
            msg = struct.pack(CMD_HDR, CMD_CLOSE, sid, 0)
            self.send_via_tunnel(msg, sess.get("addr"))

    def stop(self):
        for task in self.bg_tasks:
            task.cancel()
        for sid in list(self.sessions.keys()):
            self.close_session(sid)
        if self.transport:
            self.transport.close()

# ==================== 4. Application Entry Point ====================
async def main():
    if len(sys.argv) < 2: 
        print("Usage: python tunnel_agent.py <config.yaml>")
        sys.exit(1)
        
    with open(sys.argv[1], "r") as f: 
        config = yaml.safe_load(f)
    
    setup_logging(config.get("log_level", "info"))
    tuner = MemoryTuner(config.get("available_memory_mb", 512))
    loop = asyncio.get_running_loop()
    agent = ForwardAgent(config, tuner)
    
    stop_event = asyncio.Event()
    def shutdown():
        logger.info("[System] Shutting down...")
        stop_event.set()
        
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown)
        except (NotImplementedError, AttributeError): pass

    if config["role"] == "client":
        host, port = config["tunnel"]["host"], int(config["tunnel"]["port"])
        info = await asyncio.to_thread(socket.getaddrinfo, host, port, socket.AF_INET)
        agent.server_addr = info[0][4]
        
        async def handle_client(reader, writer):
            sid = agent.get_next_sid()
            agent.sessions[sid] = {
                "sid": sid, "writer": writer, "buffer": {}, "exp_seq": 0, 
                "last_act": time.monotonic(), "seq_out": 0, "connecting": False, "closed": False
            }
            await agent.pipe_tcp_to_udp(sid, reader, agent.server_addr)
            
        listen_host, listen_port = config["listen"]["host"], int(config["listen"]["port"])
        server = await asyncio.start_server(handle_client, listen_host, listen_port)
        
        await loop.create_datagram_endpoint(lambda: agent, local_addr=("0.0.0.0", 0))
        logger.info(f"[Client] Listening on {listen_host}:{listen_port} -> Tunneling to {host}:{port}")
        
        async with server: 
            await stop_event.wait()
            
    else:
        tunnel_host, tunnel_port = config["tunnel"]["host"], int(config["tunnel"]["port"])
        await loop.create_datagram_endpoint(lambda: agent, local_addr=(tunnel_host, tunnel_port))
        logger.info(f"[Server] Tunnel listening securely on {tunnel_host}:{tunnel_port}")
        
        await stop_event.wait()
        
    agent.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.critical(f"Fatal crash: {e}")
