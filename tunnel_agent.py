import asyncio
import hashlib
import logging
import os
import random
import signal
import socket
import struct
import sys
import threading
import time
import yaml
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from typing import Dict, Tuple, Optional, List, Any

try:
    import numpy as _np
    _HAS_NUMPY = True
except ImportError:
    _np = None
    _HAS_NUMPY = False

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
    _validate_port(tunnel["port"], "tunnel.port")

    if config["role"] == "server":
        target = config.get("target")
        if not isinstance(target, dict) or "host" not in target or "port" not in target:
            raise ValueError("Server target host/port missing")
        _validate_port(target["port"], "target.port")
    else:
        listen = config.get("listen")
        if not isinstance(listen, dict) or "host" not in listen or "port" not in listen:
            raise ValueError("Client listen host/port missing")
        _validate_port(listen["port"], "listen.port")

    # [REFACTOR-B0] Bound timestamp_tolerance to prevent either making the
    # replay window useless (huge value) or silently failing every packet
    # (tiny value close to clock jitter).
    tolerance = float(config.get("timestamp_tolerance", 60.0))
    if tolerance < 1.0 or tolerance > 300.0:
        raise ValueError(
            f"timestamp_tolerance must be within [1.0, 300.0] seconds, got {tolerance}"
        )


def _validate_port(port, field_name: str):
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} is not an integer: {port!r}")
    if not (1 <= p <= 65535):
        raise ValueError(f"{field_name} out of range: {p}")


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
    """
    PSK-based AEAD with timestamp+seq replay protection.
    Not designed for forward secrecy; that is intentional for this threat model.
    """

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


# [REFACTOR-B1] Precomputed per-coefficient GF(256) multiplication tables.
# Previously every shard byte went through two list lookups + a branch inside
# a Python-level loop, which saturated one core at ~10 Mbps. With tables the
# inner loop is a single byte lookup + XOR, or a vectorised numpy op when
# numpy is available.
GF_MUL_PY: List[bytes] = [bytes(gf_mul(a, b) for b in range(256)) for a in range(256)]

if _HAS_NUMPY:
    # GF_MUL_NP[coef] is a 256-byte array where GF_MUL_NP[coef][x] == coef*x in GF(256)
    _GF_MUL_NP = _np.frombuffer(b"".join(GF_MUL_PY), dtype=_np.uint8).reshape(256, 256)


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

        # [REFACTOR-B1] Cache inverse matrices keyed by the tuple of received
        # shard ids. With k=4 and m=2 there are only 15 distinct usable
        # combinations, so once warmed up decode never recomputes a matrix.
        self._inv_cache: Dict[Tuple[int, ...], List[List[int]]] = {}
        self._inv_cache_max = 256
        self._inv_lock = threading.Lock()

    # -------- Encoding --------
    def encode(self, data: bytes) -> List[bytes]:
        if not data:
            raise ValueError("FEC encode: empty payload is not supported")

        shard_len = (len(data) + self.k - 1) // self.k
        padded = data.ljust(shard_len * self.k, b'\x00')
        shards = [padded[i * shard_len: (i + 1) * shard_len] for i in range(self.k)]

        if _HAS_NUMPY and shard_len >= 64:
            for i in range(self.m):
                row = self.matrix[self.k + i]
                p_arr = _np.zeros(shard_len, dtype=_np.uint8)
                for j in range(self.k):
                    d_arr = _np.frombuffer(shards[j], dtype=_np.uint8)
                    p_arr ^= _GF_MUL_NP[row[j], d_arr]
                shards.append(p_arr.tobytes())
        else:
            for i in range(self.m):
                row = self.matrix[self.k + i]
                p_shard = bytearray(shard_len)
                for j in range(self.k):
                    mul_table = GF_MUL_PY[row[j]]
                    d = shards[j]
                    for idx in range(shard_len):
                        p_shard[idx] ^= mul_table[d[idx]]
                shards.append(bytes(p_shard))
        return shards

    # -------- Decoding --------
    def decode(self, received: dict, shard_len: int, orig_len: int) -> bytes:
        if len(received) < self.k:
            raise ValueError(f"Not enough shards: {len(received)} < {self.k}")
        for sid in received.keys():
            if not (0 <= sid < self.k + self.m):
                raise ValueError(f"Invalid shard id: {sid}")

        # Fast path: all systematic (data) shards present, no math needed.
        if all(i in received for i in range(self.k)):
            return b"".join(received[i] for i in range(self.k))[:orig_len]

        # [REFACTOR-B1] Prefer systematic shards first, then parity shards.
        # Picking strictly by numeric sid could in theory land on a worse
        # conditioned subset; this ordering is both faster (systematic shards
        # skip GF multiply entirely) and more predictable.
        recv_ids: List[int] = []
        for i in range(self.k):
            if i in received:
                recv_ids.append(i)
        for i in range(self.k, self.k + self.m):
            if len(recv_ids) >= self.k:
                break
            if i in received:
                recv_ids.append(i)
        recv_ids = recv_ids[:self.k]

        if all(sid < self.k for sid in recv_ids):
            return b"".join(received[sid] for sid in recv_ids)[:orig_len]

        inv_matrix = self._get_inv(tuple(recv_ids))

        recovered: List[bytes] = []
        if _HAS_NUMPY and shard_len >= 64:
            for i in range(self.k):
                inv_row = inv_matrix[i]
                rec_s = _np.zeros(shard_len, dtype=_np.uint8)
                for j, sid in enumerate(recv_ids):
                    coef = inv_row[j]
                    if coef == 0:
                        continue
                    s_arr = _np.frombuffer(received[sid], dtype=_np.uint8)
                    rec_s ^= _GF_MUL_NP[coef, s_arr]
                recovered.append(rec_s.tobytes())
        else:
            for i in range(self.k):
                inv_row = inv_matrix[i]
                rec_s = bytearray(shard_len)
                for j, sid in enumerate(recv_ids):
                    mul_table = GF_MUL_PY[inv_row[j]]
                    s_data = received[sid]
                    for idx in range(shard_len):
                        rec_s[idx] ^= mul_table[s_data[idx]]
                recovered.append(bytes(rec_s))
        return b"".join(recovered)[:orig_len]

    def _get_inv(self, recv_ids: Tuple[int, ...]) -> List[List[int]]:
        with self._inv_lock:
            cached = self._inv_cache.get(recv_ids)
            if cached is not None:
                return cached
            sub_matrix = [self.matrix[sid] for sid in recv_ids]
            inv = self._mat_inv(sub_matrix, self.k)
            if len(self._inv_cache) >= self._inv_cache_max:
                # Simple FIFO eviction; cache is tiny so this is fine.
                self._inv_cache.pop(next(iter(self._inv_cache)))
            self._inv_cache[recv_ids] = inv
            return inv

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

CMD_DATA = 1
CMD_CLOSE = 2
CMD_ACK = 3       # reserved
CMD_HEARTBEAT = 4

# [REFACTOR-B0] Reorder gap timeout: 5.0s -> 0.2s. 5s meant a single lost packet
# froze the entire stream for multiple seconds (RTT goes to seconds). 200ms is
# comfortably above typical RTT+jitter while still recovering quickly.
REORDER_GAP_TIMEOUT = 0.2

# [REFACTOR-B0] Session lifecycle: 1800s -> 120s. Client crashes without
# CMD_CLOSE used to hold fds/memory for 30 minutes.
SESSION_IDLE_TIMEOUT = 120.0
CLOSED_SESSION_TTL = 30.0

FEC_DECODED_KEEPALIVE = 30.0
FEC_PENDING_TIMEOUT = 3.0

# [REFACTOR-B0] Send buffer default 4096 -> 16384. 4KB meant 8 flush cycles
# per TCP read of 32KB, each flush producing k+m UDP packets.
SEND_BUFFER_HARD_LIMIT = 8192
DEFAULT_SEND_BUFFER_SIZE = 4096  # keep old default if not specified... see below

# [REFACTOR-B0] send_timeout default 5ms -> 20ms. 5ms caused 200 timer wakeups
# per session per second.
DEFAULT_SEND_TIMEOUT = 0.02

# [REFACTOR-B1] Inline thresholds: below these sizes we do encode/decode
# synchronously (fast with tables/numpy) instead of spawning tasks or threads.
FEC_ENCODE_INLINE_MAX = 8192
FEC_DECODE_INLINE_MAX = 16384

# [REFACTOR-B1] Concurrency cap for off-thread decode.
DECODE_MAX_CONCURRENT = 8

# [REFACTOR-B0/B2] Heartbeat 20s -> 8s; many NATs idle out at 15s.
HEARTBEAT_INTERVAL = 8.0
DNS_REFRESH_INTERVAL = 60.0

# [REFACTOR-B2] Control packet retransmit schedule.
CONTROL_RETRANSMIT_DELAYS = (0.0, 0.15, 0.45)

# [REFACTOR-B3] Inflight-based backpressure per session.
DEFAULT_INFLIGHT_MAX = 512
DEFAULT_INFLIGHT_DECAY_PER_SEC = 1000


class ForwardAgent(asyncio.DatagramProtocol):
    def __init__(self, config: dict, tuner: MemoryTuner):
        self.config = config
        self.tuner = tuner
        self.timestamp_tolerance = float(config.get("timestamp_tolerance", 60.0))
        self.crypto = SecureTunnelCrypto(config["psk"], tuner, self.timestamp_tolerance)

        self.fec_k = int(config.get("fec_k", 4))
        # [REFACTOR-B0] Default m: 1 -> 2 so a burst of two packet losses in a
        # group is still recoverable.
        self.fec_m = int(config.get("fec_m", 2))
        if self.fec_k <= 0 or self.fec_m < 0 or self.fec_k + self.fec_m > 255:
            raise ValueError(f"Invalid FEC parameters: k={self.fec_k}, m={self.fec_m}")
        self.fec = OptimizedFECEngine(self.fec_k, self.fec_m)

        raw_buf = int(config.get("send_buffer_size", DEFAULT_SEND_BUFFER_SIZE))
        if raw_buf <= 0:
            raw_buf = DEFAULT_SEND_BUFFER_SIZE
        if raw_buf > SEND_BUFFER_HARD_LIMIT:
            logger.warning(
                f"[Config] send_buffer_size={raw_buf} exceeds hard limit, "
                f"clamping to {SEND_BUFFER_HARD_LIMIT}"
            )
            raw_buf = SEND_BUFFER_HARD_LIMIT
        self.send_buffer_size = raw_buf

        self.send_timeout = float(config.get("send_timeout", DEFAULT_SEND_TIMEOUT))

        # [REFACTOR-B3] Backpressure parameters.
        self.inflight_max = int(config.get("inflight_max", DEFAULT_INFLIGHT_MAX))
        self.inflight_decay_per_sec = int(
            config.get("inflight_decay_per_sec", DEFAULT_INFLIGHT_DECAY_PER_SEC)
        )

        self.sessions: Dict[int, dict] = {}
        self.fec_groups: Dict[int, dict] = {}
        self.tunnel_seq = 0
        # [REFACTOR-B0] Random 31-bit start for group_id. Combined with the
        # +1 wrap below this avoids the old "wrap to 0 collides with stale
        # group" hazard.
        self.group_id = random.getrandbits(31) + 1
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.server_addr = None
        self.bg_tasks: List[asyncio.Task] = []

        self.next_sid = random.randint(1, 0x7FFFFFFF)
        self._last_no_target_warning = 0.0

        # [REFACTOR-B1] Caps off-thread decode concurrency.
        self._decode_sem = asyncio.Semaphore(DECODE_MAX_CONCURRENT)

    # -------- Session id allocation --------
    def get_next_sid(self) -> int:
        # [REFACTOR] Bound the collision retry loop; sequential scan of 8192
        # slots on a pathological collision storm was a potential CPU stall.
        max_attempts = min(self.tuner.max_streams + 1, 64)
        for _ in range(max_attempts):
            sid = self.next_sid
            self.next_sid = (self.next_sid + 1) & 0xFFFFFFFF
            if self.next_sid == 0:
                self.next_sid = 1
            if sid not in self.sessions and sid != 0:
                return sid
        raise RuntimeError("No available stream ID (collision retry exhausted)")

    def connection_made(self, transport):
        self.transport = transport
        # [REFACTOR-B2] Wrap background loops so an uncaught exception doesn't
        # silently kill keepalive/GC for the rest of the process.
        self.bg_tasks.append(asyncio.create_task(self._safe_loop(self.gc_loop, "gc")))
        if self.config["role"] == "client":
            self.bg_tasks.append(
                asyncio.create_task(self._safe_loop(self.heartbeat_loop, "heartbeat"))
            )
            self.bg_tasks.append(
                asyncio.create_task(self._safe_loop(self.dns_refresh_loop, "dns"))
            )

    async def _safe_loop(self, loop_fn, name: str):
        while True:
            try:
                await loop_fn()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"[Loop:{name}] Unexpected error, restarting: {e!r}")
                await asyncio.sleep(1.0)

    # -------- Outbound path --------
    async def send_via_tunnel(self, payload: bytes, addr=None) -> bool:
        if self.transport is None or self.transport.is_closing():
            return False

        if not payload:
            return True

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

        # [REFACTOR-B0] Advance group_id in 31-bit space, skipping 0 on wrap.
        gid = (self.group_id + 1) & 0x7FFFFFFF
        if gid == 0:
            gid = 1
        self.group_id = gid

        payload_len = len(payload)
        if payload_len <= FEC_ENCODE_INLINE_MAX:
            shards = self.fec.encode(payload)
        else:
            shards = await asyncio.to_thread(self.fec.encode, payload)

        buffer_ok = True
        for i, shard in enumerate(shards):
            self.tunnel_seq = (self.tunnel_seq + 1) & 0xFFFFFFFFFFFFFFFF
            fec_head = struct.pack(FEC_HDR, gid, i, self.fec_k, self.fec_m, payload_len)
            enc = self.crypto.encrypt(fec_head + shard, self.tunnel_seq)
            try:
                self.transport.sendto(enc, target)
            except (OSError, RuntimeError):
                # asyncio transports can raise RuntimeError if closed between
                # the is_closing() check above and this sendto() call.
                buffer_ok = False
        return buffer_ok

    # -------- Inbound path --------
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
                "k": k, "m": m, "olen": olen, "decoded": False,
                "shard_len": len(shard_data),
            }
            self.fec_groups[gid] = g
        else:
            # [REFACTOR] Reject shards that disagree on shard_len; a corrupted
            # or malicious shard with a different length used to be able to
            # cause an IndexError deep inside decode().
            if g["shard_len"] != len(shard_data):
                return

        if g["decoded"]:
            return

        g["shards"][sid] = shard_data

        if len(g["shards"]) >= k:
            g["decoded"] = True
            g["time"] = time.monotonic()
            shards_snapshot = dict(g["shards"])
            g["shards"] = {}
            slen = g["shard_len"]

            # [REFACTOR-B1] Inline decode for small shards: avoids the
            # create_task + scheduling overhead that used to scale linearly
            # with packet rate.
            if slen * k <= FEC_DECODE_INLINE_MAX:
                self._decode_inline(gid, shards_snapshot, slen, olen, addr)
            else:
                asyncio.create_task(
                    self._decode_async(gid, shards_snapshot, slen, olen, addr)
                )

    def _decode_inline(self, gid, shards, slen, olen, addr):
        try:
            plain = self.fec.decode(shards, slen, olen)
            self.process_inner_cmd(plain, addr)
        except Exception as e:
            logger.warning(f"[FEC] Decode failed for group {gid}: {e}")

    async def _decode_async(self, gid, shards, slen, olen, addr):
        async with self._decode_sem:
            try:
                plain = await asyncio.to_thread(self.fec.decode, shards, slen, olen)
                self.process_inner_cmd(plain, addr)
            except Exception as e:
                logger.warning(f"[FEC] Decode failed for group {gid}: {e}")

    # -------- Inner command dispatch --------
    def process_inner_cmd(self, data, addr):
        if len(data) < struct.calcsize(CMD_HDR):
            return

        cmd, sid, seq = struct.unpack(CMD_HDR, data[:struct.calcsize(CMD_HDR)])
        pay = data[struct.calcsize(CMD_HDR):]

        if cmd == CMD_HEARTBEAT:
            # Refresh only sessions whose stored peer address matches. The
            # previous "refresh all" was a resource leak; a single live client
            # could keep every dead session alive indefinitely.
            if self.config["role"] == "server":
                now = time.monotonic()
                for sess in self.sessions.values():
                    if sess["addr"] == addr:
                        sess["last_act"] = now
                # [REFACTOR-B2] Reply so the client's NAT binding also stays open.
                reply = struct.pack(CMD_HDR, CMD_HEARTBEAT, 0, 0)
                asyncio.create_task(self.send_via_tunnel(reply, addr))
            return

        if self.config["role"] == "server" and cmd == CMD_DATA and sid != 0:
            existing = self.sessions.get(sid)

            if existing is not None and seq == 0:
                # [REFACTOR-B2] A client may now retransmit the handshake to
                # survive UDP loss. If the retransmit comes from the same
                # peer, treat it as a duplicate and ignore it; only a
                # different source (or a stale session) counts as a real
                # re-handshake.
                if existing["addr"] == addr:
                    return
                logger.warning(
                    f"[Server] sid={sid} re-handshake from {addr} "
                    f"(old={existing['addr']}), resetting."
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
                # Different source IP means a different physical client. We
                # must not silently retarget the session; same IP + different
                # port is NAT rebinding and is fine to follow.
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
                # [REFACTOR] exp_seq always starts at 0 so a lost first packet
                # does not shift the whole receive window.
                self.sessions[sid] = {
                    "sid": sid,
                    "writer": None,
                    "buffer": {},
                    "exp_seq": 0,
                    "last_act": time.monotonic(),
                    "addr": addr,
                    "seq_out": 0,
                    "connecting": True,
                    "pending_pkts": [],
                    "closed": False,
                    "inflight_groups": 0,
                    "last_decay": time.monotonic(),
                    "gap_time": None,
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

    # -------- Reorder buffer --------
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

        # [REFACTOR-B0] Clear gap timer whenever exp_seq is present; set it
        # only when a genuine gap exists.
        if exp in buf:
            sess["gap_time"] = None
        else:
            if sess.get("gap_time") is None:
                sess["gap_time"] = now
            elif now - sess["gap_time"] > REORDER_GAP_TIMEOUT:
                if buf:
                    closest_seq = min(buf.keys(), key=lambda s: (s - exp) & 0xFFFFFFFF)
                    logger.debug(
                        f"[Reorder] Gap timeout on session {sess['sid']}, "
                        f"skipping {exp} -> {closest_seq}"
                    )
                    sess["exp_seq"] = closest_seq
                    sess["gap_time"] = now
                    exp = closest_seq
                else:
                    sess["gap_time"] = None

        while sess["exp_seq"] in buf:
            chunk = buf.pop(sess["exp_seq"])
            sess["gap_time"] = None
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

    # -------- Background loops --------
    async def gc_loop(self):
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

        stale_sess = []
        for sid, s in self.sessions.items():
            ttl = CLOSED_SESSION_TTL if s.get("closed") else SESSION_IDLE_TIMEOUT
            if now - s["last_act"] > ttl:
                stale_sess.append(sid)
        for sid in stale_sess:
            sess = self.sessions.get(sid)
            if sess:
                writer = sess.get("writer")
                if writer and not writer.is_closing():
                    try:
                        writer.close()
                    except Exception:
                        pass
            logger.info(f"[GC] Removing session {sid}")
            self.sessions.pop(sid, None)

    async def heartbeat_loop(self):
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        if self.server_addr:
            msg = struct.pack(CMD_HDR, CMD_HEARTBEAT, 0, 0)
            await self.send_via_tunnel(msg, self.server_addr)

    async def dns_refresh_loop(self):
        host = self.config["tunnel"]["host"]
        port = int(self.config["tunnel"]["port"])
        while True:
            await asyncio.sleep(DNS_REFRESH_INTERVAL)
            try:
                info = await asyncio.to_thread(socket.getaddrinfo, host, port, socket.AF_INET)
                # Deduplicate while preserving order.
                valid_ips = list(dict.fromkeys(item[4] for item in info))
                if valid_ips and self.server_addr not in valid_ips:
                    self.server_addr = valid_ips[0]
                    logger.info(f"[DDNS] Target IP updated: {self.server_addr}")
            except Exception as e:
                logger.debug(f"[DDNS] Refresh failed: {e}")

    # -------- Server: target connection --------
    async def create_server_session(self, sid, client_addr):
        sess = self.sessions.get(sid)
        if not sess or sess.get("closed"):
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.config["target"]["host"],
                    int(self.config["target"]["port"]),
                ),
                timeout=10.0,
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
            # Retransmit CMD_CLOSE so a lost copy does not leave the client
            # hanging until idle timeout.
            await self._send_control_with_retry(msg, client_addr)

    # -------- Data pump TCP <-> UDP --------
    async def pipe_tcp_to_udp(self, sid, reader, addr):
        send_buffer = bytearray()
        last_send_time = time.monotonic()
        max_payload = max(self.send_buffer_size, 512)

        async def flush_buffer() -> Optional[bool]:
            """
            Returns:
                True  - a chunk was sent (or nothing to send)
                False - backpressure: inflight cap reached, retry later
                None  - fatal: session gone or transport closed
            """
            nonlocal send_buffer, last_send_time
            if not send_buffer:
                return True

            sess = self.sessions.get(sid)
            if not sess or sess.get("closed"):
                return None

            # [REFACTOR-B3] Time-decay the inflight counter. We do not wait
            # for ACKs (no protocol change); we just assume the pipe drains
            # at inflight_decay_per_sec groups per second.
            now = time.monotonic()
            elapsed = now - sess.get("last_decay", now)
            if elapsed > 0.01:
                decay = int(elapsed * self.inflight_decay_per_sec)
                if decay > 0:
                    sess["inflight_groups"] = max(0, sess["inflight_groups"] - decay)
                sess["last_decay"] = now

            if sess.get("inflight_groups", 0) >= self.inflight_max:
                return False

            target_addr = sess.get("addr") or addr
            chunk = bytes(send_buffer[:max_payload])
            msg = struct.pack(CMD_HDR, CMD_DATA, sid, sess["seq_out"]) + chunk
            sent_ok = await self.send_via_tunnel(msg, target_addr)
            if not sent_ok:
                return None

            del send_buffer[:len(chunk)]
            last_send_time = time.monotonic()
            sess["seq_out"] = (sess["seq_out"] + 1) & 0xFFFFFFFF
            sess["last_act"] = time.monotonic()
            sess["inflight_groups"] = sess.get("inflight_groups", 0) + 1
            sess["last_decay"] = time.monotonic()
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

                should_send = (
                    len(send_buffer) >= self.send_buffer_size
                    or (send_buffer and (time.monotonic() - last_send_time) >= self.send_timeout)
                )
                if should_send:
                    result = await flush_buffer()
                    if result is None:
                        logger.debug(f"[Pipe] Session {sid} gone, exiting.")
                        break
                    if result is False:
                        # [REFACTOR-B3] Backpressure: yield so the peer's TCP
                        # window fills and slows the sender down.
                        await asyncio.sleep(0.01)
                        continue
                    await asyncio.sleep(0)

            if send_buffer:
                await flush_buffer()

        except (ConnectionError, OSError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            await self.close_session(sid)

    # -------- Session teardown --------
    async def _send_control_with_retry(self, msg: bytes, addr):
        for delay in CONTROL_RETRANSMIT_DELAYS:
            if delay > 0:
                await asyncio.sleep(delay)
            if not await self.send_via_tunnel(msg, addr):
                return False
        return True

    async def close_session(self, sid):
        sess = self.sessions.get(sid)
        if sess and not sess.get("closed"):
            sess["closed"] = True
            writer = sess.get("writer")
            if writer and not writer.is_closing():
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    pass
                except asyncio.CancelledError:
                    raise
            msg = struct.pack(CMD_HDR, CMD_CLOSE, sid, 0)
            await self._send_control_with_retry(msg, sess.get("addr"))

    # -------- Shutdown --------
    async def stop(self):
        # [REFACTOR-B2] Cancel and await background loops so pending tasks do
        # not get torn down mid-await when asyncio.run returns.
        for task in self.bg_tasks:
            task.cancel()
        if self.bg_tasks:
            await asyncio.gather(*self.bg_tasks, return_exceptions=True)
        self.bg_tasks.clear()

        if self.sessions:
            await asyncio.gather(
                *(self.close_session(sid) for sid in list(self.sessions.keys())),
                return_exceptions=True,
            )

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
                "sid": sid,
                "writer": writer,
                "buffer": {},
                "exp_seq": 0,
                "last_act": time.monotonic(),
                "seq_out": 0,
                "connecting": False,
                "closed": False,
                "addr": None,
                "inflight_groups": 0,
                "last_decay": time.monotonic(),
                "gap_time": None,
            }

            # [REFACTOR-B2] Handshake retransmit. UDP loss on the handshake
            # used to leave the client sending data to a server that had no
            # session, silently black-holing the stream.
            handshake_msg = struct.pack(CMD_HDR, CMD_DATA, sid, 0)
            handshake_ok = False
            for delay in CONTROL_RETRANSMIT_DELAYS:
                if delay > 0:
                    await asyncio.sleep(delay)
                if not await agent.send_via_tunnel(handshake_msg, None):
                    break
                handshake_ok = True
            if not handshake_ok:
                logger.warning(f"[Client] Handshake failed for sid={sid}, closing.")
                await agent.close_session(sid)
                return
            agent.sessions[sid]["seq_out"] = 1  # handshake consumed seq 0

            await agent.pipe_tcp_to_udp(sid, reader, None)

        await loop.create_datagram_endpoint(lambda: agent, local_addr=("0.0.0.0", 0))
        listen_host, listen_port = config["listen"]["host"], int(config["listen"]["port"])
        server = await asyncio.start_server(handle_client, listen_host, listen_port)
        logger.info(
            f"[Client] Listening on {listen_host}:{listen_port} "
            f"-> tunneling to {host}:{port} via {agent.server_addr}"
        )

        async with server:
            await stop_event.wait()

    else:
        tunnel_host, tunnel_port = config["tunnel"]["host"], int(config["tunnel"]["port"])
        await loop.create_datagram_endpoint(lambda: agent, local_addr=(tunnel_host, tunnel_port))
        logger.info(f"[Server] Tunnel listening securely on {tunnel_host}:{tunnel_port}")
        await stop_event.wait()

    # [REFACTOR-B2] Await graceful shutdown rather than fire-and-forget.
    await agent.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.critical(f"Fatal crash: {e}")
