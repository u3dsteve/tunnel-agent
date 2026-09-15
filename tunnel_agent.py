import asyncio
import hashlib
import logging
import os
import random
import signal
import socket
import struct
import sys
import time
import yaml
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from typing import Dict, Tuple, Optional, List, Any

# ==================== 0. System Initialization & Config ====================
logger = logging.getLogger("tunnel_agent")


def setup_logging(level_setting: str):
    level = logging.DEBUG if str(level_setting).lower() == "debug" else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)


def validate_config(config: dict):
    if not isinstance(config, dict):
        raise ValueError("Config root must be a mapping")
    if "role" not in config:
        raise ValueError("Missing mandatory config field: role")
    if config["role"] not in ("client", "server"):
        raise ValueError(f"Invalid role: {config['role']}")

    required_top = ["psk", "tunnel"]
    required_top.append("listen" if config["role"] == "client" else "target")
    for field in required_top:
        if field not in config:
            raise ValueError(f"Missing mandatory config field: {field}")

    tunnel = config.get("tunnel")
    if not isinstance(tunnel, dict) or "host" not in tunnel or "port" not in tunnel:
        raise ValueError("Tunnel host/port missing or invalid")

    if config["role"] == "server":
        target = config.get("target")
        if not isinstance(target, dict) or "host" not in target or "port" not in target:
            raise ValueError("Server target host/port missing")
    if config["role"] == "client":
        listen = config.get("listen")
        if not isinstance(listen, dict) or "host" not in listen or "port" not in listen:
            raise ValueError("Client listen host/port missing")


class MemoryTuner:
    def __init__(self, mem_mb: int):
        self.mem_mb = max(int(mem_mb), 128)
        ratio = self.mem_mb / 512.0
        self.max_streams = min(int(1024 * ratio), 8192)
        self.tcp_buf_limit = min(int(1048576 * ratio), 4194304)
        self.reorder_window_limit = 256
        self.seen_seq_ttl = 60.0
        self.seen_seq_limit = 10000


# ==================== 1. Crypto & Anti-Replay Engine ====================
class SecureTunnelCrypto:
    def __init__(self, psk: str, tuner: MemoryTuner, timestamp_tolerance: float = 60.0):
        key = hashlib.sha256(psk.encode()).digest()
        self.aead = ChaCha20Poly1305(key)
        self.tuner = tuner
        self.timestamp_tolerance = timestamp_tolerance
        self.seen_sequences: Dict[Tuple[int, int], float] = {}

    def encrypt(self, plain: bytes, seq: int) -> bytes:
        nonce = os.urandom(12)
        ts = int(time.time())
        pad_len = os.urandom(1)[0] % 16
        padding = os.urandom(pad_len)
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
            if abs(now - ts) > self.timestamp_tolerance:
                return None

            key = (ts, seq)
            if key in self.seen_sequences:
                return None
            self.seen_sequences[key] = now

            if len(self.seen_sequences) > self.tuner.seen_seq_limit:
                cutoff = now - self.timestamp_tolerance
                expired = [k for k, t in self.seen_sequences.items() if t < cutoff]
                for k in expired:
                    del self.seen_sequences[k]
                if len(self.seen_sequences) > self.tuner.seen_seq_limit:
                    keys_to_pop = list(self.seen_sequences.keys())[:1000]
                    for k in keys_to_pop:
                        del self.seen_sequences[k]

            return decrypted[13 + pad_len:]
        except Exception:
            return None


# ==================== 2. FEC Engine ====================
EXP_TABLE = [0] * 512
LOG_TABLE = [0] * 256


def _init_gf():
    poly, x = 0x11D, 1
    for i in range(255):
        EXP_TABLE[i] = EXP_TABLE[i + 255] = x
        LOG_TABLE[x] = i
        x = (x << 1) ^ (poly if (x & 0x80) else 0)


_init_gf()


def gf_mul(a, b):
    return 0 if a == 0 or b == 0 else EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]]


def gf_inv(a):
    if a == 0:
        raise ZeroDivisionError("gf_inv(0)")
    return EXP_TABLE[255 - LOG_TABLE[a]]


class OptimizedFECEngine:
    def __init__(self, k, m):
        self.k, self.m = k, m
        self.matrix = [[1 if i == j else 0 for j in range(k)] for i in range(k)]
        for j in range(m):
            row = []
            y = k + j
            for i in range(k):
                denominator = i ^ y
                row.append(gf_inv(denominator))
            self.matrix.append(row)

    def encode(self, data: bytes) -> List[bytes]:
        shard_len = (len(data) + self.k - 1) // self.k
        padded = data.ljust(shard_len * self.k, b'\x00')
        shards = [padded[i * shard_len: (i + 1) * shard_len] for i in range(self.k)]
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
        if len(received) < self.k:
            raise ValueError(f"Not enough shards: {len(received)} < {self.k}")
        for sid in received.keys():
            if not (0 <= sid < self.k + self.m):
                raise ValueError(f"Invalid shard id: {sid}")

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
                for r in range(i + 1, k):
                    if aug[r][i] != 0:
                        aug[i], aug[r] = aug[r], aug[i]
                        pivot = aug[i][i]
                        break
                if pivot == 0:
                    raise ValueError("Singular matrix in FEC decode")
            inv_p = gf_inv(pivot)
            aug[i] = [gf_mul(x, inv_p) for x in aug[i]]
            for r in range(k):
                if r != i:
                    f = aug[r][i]
                    aug[r] = [aug[r][c] ^ gf_mul(aug[i][c], f) for c in range(2 * k)]
        return [row[k:] for row in aug]


# ==================== 3. Core Forward Agent ====================
FEC_HDR = "!IBBBI"
CMD_HDR = "!BII"
CMD_DATA, CMD_CLOSE, CMD_ACK, CMD_HEARTBEAT = 1, 2, 3, 4

FEC_ENCODE_INLINE_MAX = 2048
FEC_DECODE_INLINE_MAX = 4096
FEC_DECODED_KEEPALIVE = 30.0
FEC_PENDING_TIMEOUT = 3.0
SESSION_IDLE_TIMEOUT = 1800.0
SEND_BUFFER_HARD_LIMIT = 8192


class ForwardAgent(asyncio.DatagramProtocol):
    def __init__(self, config: dict, tuner: MemoryTuner):
        self.config = config
        self.tuner = tuner
        self.timestamp_tolerance = float(config.get("timestamp_tolerance", 60.0))
        self.crypto = SecureTunnelCrypto(config["psk"], tuner, self.timestamp_tolerance)

        self.fec_k = int(config.get("fec_k", 4))
        self.fec_m = int(config.get("fec_m", 1))
        if self.fec_k <= 0 or self.fec_m < 0 or self.fec_k + self.fec_m > 255:
            raise ValueError(f"Invalid FEC parameters: k={self.fec_k}, m={self.fec_m}")
        self.fec = OptimizedFECEngine(self.fec_k, self.fec_m)

        raw_buf = int(config.get("send_buffer_size", 4096))
        if raw_buf <= 0:
            raw_buf = 4096
        if raw_buf > SEND_BUFFER_HARD_LIMIT:
            logger.warning(
                f"[Config] send_buffer_size={raw_buf} exceeds hard limit, "
                f"clamping to {SEND_BUFFER_HARD_LIMIT}"
            )
            raw_buf = SEND_BUFFER_HARD_LIMIT
        self.send_buffer_size = raw_buf
        self.send_timeout = float(config.get("send_timeout", 0.005))

        self.sessions = {}
        self.fec_groups = {}
        self.tunnel_seq = 0
        self.group_id = 0
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.server_addr = None
        self.bg_tasks: List[asyncio.Task] = []

        self.next_sid = random.randint(1, 0x7FFFFFFF)
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
        raise RuntimeError("No available stream ID (max streams reached)")

    def connection_made(self, transport):
        self.transport = transport
        self.bg_tasks.append(asyncio.create_task(self.gc_loop()))
        if self.config["role"] == "client":
            self.bg_tasks.append(asyncio.create_task(self.heartbeat_loop()))
            self.bg_tasks.append(asyncio.create_task(self.dns_refresh_loop()))

    async def send_via_tunnel(self, payload: bytes, addr=None) -> bool:
        if self.transport is None or self.transport.is_closing():
            return False

        if len(payload) > (1 << 24):
            logger.warning(f"[Send] Payload too large: {len(payload)}")
            return False

        target = addr or self.server_addr
        if not target:
            now = time.monotonic()
            if now - self._last_no_target_warning > 5.0:
                logger.warning("[Send] No target address available, dropping packet.")
                self._last_no_target_warning = now
            return False

        gid = self.group_id = (self.group_id + 1) % 0xFFFFFFFF

        if len(payload) <= FEC_ENCODE_INLINE_MAX:
            shards = self.fec.encode(payload)
        else:
            shards = await asyncio.to_thread(self.fec.encode, payload)

        buffer_ok = True
        for i, shard in enumerate(shards):
            self.tunnel_seq = (self.tunnel_seq + 1) & 0xFFFFFFFFFFFFFFFF
            fec_head = struct.pack(FEC_HDR, gid, i, self.fec_k, self.fec_m, len(payload))
            enc = self.crypto.encrypt(fec_head + shard, self.tunnel_seq)
            try:
                self.transport.sendto(enc, target)
            except (OSError, RuntimeError):
                # [FIX-7-3] RuntimeError can be raised by asyncio transports when
                # the transport was closed between the is_closing() check above
                # and this sendto() call. Catch it so a shutdown race does not
                # crash the calling coroutine.
                buffer_ok = False
        return buffer_ok

    def datagram_received(self, data, addr):
        dec = self.crypto.decrypt(data)
        if not dec or len(dec) < struct.calcsize(FEC_HDR):
            return

        gid, sid, k, m, olen = struct.unpack(FEC_HDR, dec[:struct.calcsize(FEC_HDR)])

        if k != self.fec_k or m != self.fec_m:
            return
        if sid >= k + m:
            return
        if olen > (1 << 24):
            return

        shard_data = dec[struct.calcsize(FEC_HDR):]

        g = self.fec_groups.get(gid)
        if g is None:
            g = {
                "shards": {}, "time": time.monotonic(),
                "k": k, "m": m, "olen": olen, "decoded": False
            }
            self.fec_groups[gid] = g

        if g["decoded"]:
            return

        g["shards"][sid] = shard_data

        if len(g["shards"]) >= k:
            g["decoded"] = True
            g["time"] = time.monotonic()
            shards_snapshot = dict(g["shards"])
            g["shards"] = {}
            asyncio.create_task(
                self.decode_and_process(gid, shards_snapshot, len(shard_data), olen, addr)
            )

    async def decode_and_process(self, gid, shards, slen, olen, addr):
        try:
            if slen * self.fec_k <= FEC_DECODE_INLINE_MAX:
                plain = self.fec.decode(shards, slen, olen)
            else:
                plain = await asyncio.to_thread(self.fec.decode, shards, slen, olen)
            self.process_inner_cmd(plain, addr)
        except Exception as e:
            logger.debug(f"[FEC] Decode failed for group {gid}: {e}")

    def process_inner_cmd(self, data, addr):
        if len(data) < struct.calcsize(CMD_HDR):
            return

        cmd, sid, seq = struct.unpack(CMD_HDR, data[:struct.calcsize(CMD_HDR)])
        pay = data[struct.calcsize(CMD_HDR):]

        if cmd == CMD_HEARTBEAT:
            # [FIX-7-2] Refresh only sessions whose stored peer address matches
            # the heartbeat sender. The previous version refreshed ALL sessions,
            # so one live client's heartbeat could keep dead clients' sessions
            # alive indefinitely and prevent GC from reclaiming them.
            if self.config["role"] == "server":
                now = time.monotonic()
                for sess in self.sessions.values():
                    if sess["addr"] == addr:
                        sess["last_act"] = now
            return

        if self.config["role"] == "server" and cmd == CMD_DATA and sid != 0:
            existing = self.sessions.get(sid)

            if existing is not None and seq == 0:
                logger.warning(
                    f"[Server] sid={sid} re-handshake from {addr} (old={existing['addr']}), resetting."
                )
                existing["closed"] = True
                w = existing.get("writer")
                if w and not w.is_closing():
                    try:
                        w.close()
                    except Exception:
                        pass
                self.sessions.pop(sid, None)
                existing = None

            elif existing is not None and existing["addr"] != addr:
                # [FIX-7-1] Different source IP means a different physical client.
                # We must NOT silently retarget the existing session to the new
                # peer, or return traffic could be routed to the wrong client's
                # TCP connection. Same IP + different port is the NAT-rebinding
                # case and we continue to follow the address.
                if existing["addr"][0] != addr[0]:
                    logger.warning(
                        f"[Server] sid={sid} collision across IPs "
                        f"({existing['addr']} vs {addr}), resetting session."
                    )
                    existing["closed"] = True
                    w = existing.get("writer")
                    if w and not w.is_closing():
                        try:
                            w.close()
                        except Exception:
                            pass
                    self.sessions.pop(sid, None)
                    existing = None
                else:
                    logger.debug(
                        f"[Server] sid={sid} peer addr changed: {existing['addr']} -> {addr}"
                    )
                    existing["addr"] = addr

            if existing is None:
                self.sessions[sid] = {
                    "sid": sid, "writer": None, "buffer": {}, "exp_seq": seq,
                    "last_act": time.monotonic(), "addr": addr, "seq_out": 0,
                    "connecting": True, "pending_pkts": [], "closed": False
                }
                asyncio.create_task(self.create_server_session(sid, addr))

        if sid in self.sessions:
            sess = self.sessions[sid]
            sess["last_act"] = time.monotonic()

            if sess.get("closed"):
                return

            if cmd == CMD_DATA:
                if sess.get("connecting"):
                    if len(sess["pending_pkts"]) < self.tuner.reorder_window_limit:
                        sess["pending_pkts"].append((seq, pay))
                else:
                    self.push_to_reorder(sess, seq, pay)
            elif cmd == CMD_CLOSE:
                asyncio.create_task(self.close_session(sid))

    def push_to_reorder(self, sess, seq, data):
        if sess.get("closed"):
            return

        buf = sess["buffer"]
        exp = sess["exp_seq"]
        diff = (seq - exp) & 0xFFFFFFFF

        if diff >= 0x80000000 or diff > self.tuner.reorder_window_limit:
            return

        buf[seq] = data
        now = time.monotonic()
        if "gap_time" not in sess:
            sess["gap_time"] = now

        if sess["exp_seq"] not in buf and (now - sess["gap_time"] > 5.0):
            if buf:
                closest_seq = min(buf.keys(), key=lambda s: (s - sess["exp_seq"]) & 0xFFFFFFFF)
                sess["exp_seq"] = closest_seq
                sess["gap_time"] = now
                logger.warning(f"[Reorder] Gap timeout on session {sess['sid']}, skipping to {sess['exp_seq']}")

        while sess["exp_seq"] in buf:
            chunk = buf.pop(sess["exp_seq"])
            sess["gap_time"] = time.monotonic()
            writer = sess.get("writer")
            if writer and not writer.is_closing():
                try:
                    if chunk:
                        writer.write(chunk)
                except Exception as e:
                    logger.debug(f"[TCP] Write error: {e}")
                    asyncio.create_task(self.close_session(sess.get("sid")))
                    break
            sess["exp_seq"] = (sess["exp_seq"] + 1) & 0xFFFFFFFF

    async def gc_loop(self):
        while True:
            await asyncio.sleep(5)
            now = time.monotonic()

            stale_fec = []
            for gid, g in self.fec_groups.items():
                age = now - g["time"]
                if g["decoded"] and age > FEC_DECODED_KEEPALIVE:
                    stale_fec.append(gid)
                elif not g["decoded"] and age > FEC_PENDING_TIMEOUT:
                    stale_fec.append(gid)
            for gid in stale_fec:
                self.fec_groups.pop(gid, None)

            stale_sess = [
                sid for sid, s in self.sessions.items()
                if now - s["last_act"] > (30.0 if s.get("closed") else SESSION_IDLE_TIMEOUT)
            ]
            for sid in stale_sess:
                sess = self.sessions.get(sid)
                if sess:
                    writer = sess.get("writer")
                    if writer and not writer.is_closing():
                        try:
                            writer.close()
                        except Exception:
                            pass
                logger.debug(f"[GC] Removing session {sid}")
                self.sessions.pop(sid, None)

    async def heartbeat_loop(self):
        while True:
            await asyncio.sleep(20)
            if self.server_addr:
                msg = struct.pack(CMD_HDR, CMD_HEARTBEAT, 0, 0)
                await self.send_via_tunnel(msg, self.server_addr)

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
                        logger.info(f"[DDNS] Target IP updated: {self.server_addr}")
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
            if sess.get("closed"):
                writer.close()
                return

            sess["writer"] = writer
            sess["connecting"] = False

            pending = sess.pop("pending_pkts", [])
            for p_seq, p_pay in pending:
                self.push_to_reorder(sess, p_seq, p_pay)

            asyncio.create_task(self.pipe_tcp_to_udp(sid, reader, client_addr))
        except Exception as e:
            logger.debug(f"[Server] Target connection failed: {e}")
            sess["closed"] = True
            sess["connecting"] = False
            sess.pop("pending_pkts", None)
            msg = struct.pack(CMD_HDR, CMD_CLOSE, sid, 0)
            await self.send_via_tunnel(msg, client_addr)

    async def pipe_tcp_to_udp(self, sid, reader, addr):
        consecutive_failures = 0
        send_buffer = bytearray()
        last_send_time = time.monotonic()
        max_payload = max(self.send_buffer_size, 512)

        async def flush_buffer():
            nonlocal send_buffer, last_send_time
            if not send_buffer:
                return True

            sess = self.sessions.get(sid)
            if not sess or sess.get("closed"):
                return False

            target_addr = sess.get("addr") or addr

            chunk = bytes(send_buffer[:max_payload])
            msg = struct.pack(CMD_HDR, CMD_DATA, sid, sess["seq_out"]) + chunk
            sent_ok = await self.send_via_tunnel(msg, target_addr)
            if not sent_ok:
                return False

            del send_buffer[:len(chunk)]
            last_send_time = time.monotonic()
            sess["seq_out"] = (sess["seq_out"] + 1) & 0xFFFFFFFF
            sess["last_act"] = time.monotonic()
            return True

        try:
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(32768), timeout=self.send_timeout)
                    if not data:
                        break
                    send_buffer.extend(data)
                except asyncio.TimeoutError:
                    pass

                if len(send_buffer) >= self.send_buffer_size or \
                        (send_buffer and (time.monotonic() - last_send_time) >= self.send_timeout):
                    sent_ok = await flush_buffer()
                    if not sent_ok:
                        sess_check = self.sessions.get(sid)
                        if not sess_check or sess_check.get("closed"):
                            logger.debug(f"[Pipe] Session {sid} gone, exiting.")
                            break
                        consecutive_failures += 1
                        delay = min(0.002 * (2 ** min(consecutive_failures, 6)), 0.1)
                        await asyncio.sleep(delay)
                        if consecutive_failures > 50:
                            logger.warning(f"[Pipe] Too many send failures, closing session {sid}")
                            break
                    else:
                        consecutive_failures = 0
                    await asyncio.sleep(0)

            if send_buffer:
                await flush_buffer()

        except (ConnectionError, OSError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            await self.close_session(sid)

    async def close_session(self, sid):
        sess = self.sessions.get(sid)
        if sess and not sess.get("closed"):
            sess["closed"] = True
            writer = sess.get("writer")
            if writer and not writer.is_closing():
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass
            msg = struct.pack(CMD_HDR, CMD_CLOSE, sid, 0)
            await self.send_via_tunnel(msg, sess.get("addr"))

    def stop(self):
        for task in self.bg_tasks:
            task.cancel()
        for sid in list(self.sessions.keys()):
            asyncio.create_task(self.close_session(sid))
        if self.transport:
            self.transport.close()


# ==================== 4. Application Entry Point ====================
async def main():
    if len(sys.argv) < 2:
        print("Usage: python tunnel_agent.py <config.yaml>")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        config = yaml.safe_load(f)

    validate_config(config)
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
        except (NotImplementedError, AttributeError):
            pass

    if config["role"] == "client":
        host, port = config["tunnel"]["host"], int(config["tunnel"]["port"])
        info = await asyncio.to_thread(socket.getaddrinfo, host, port, socket.AF_INET)
        agent.server_addr = info[0][4]

        async def handle_client(reader, writer):
            try:
                sid = agent.get_next_sid()
            except RuntimeError as e:
                logger.error(f"[Client] {e}")
                writer.close()
                return

            agent.sessions[sid] = {
                "sid": sid, "writer": writer, "buffer": {}, "exp_seq": 0,
                "last_act": time.monotonic(), "seq_out": 0, "connecting": False,
                "closed": False, "addr": None
            }

            handshake_msg = struct.pack(CMD_HDR, CMD_DATA, sid, 0)
            if not await agent.send_via_tunnel(handshake_msg, None):
                logger.warning(f"[Client] Handshake failed for sid={sid}, closing.")
                await agent.close_session(sid)
                return
            agent.sessions[sid]["seq_out"] += 1

            await agent.pipe_tcp_to_udp(sid, reader, None)

        await loop.create_datagram_endpoint(lambda: agent, local_addr=("0.0.0.0", 0))
        listen_host, listen_port = config["listen"]["host"], int(config["listen"]["port"])
        server = await asyncio.start_server(handle_client, listen_host, listen_port)
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
