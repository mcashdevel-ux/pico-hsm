import trng, hashlib, ubinascii, time, sys, machine, ujson

# HSM: mints in-RAM (volatile) keys from silicon entropy on boot.
# Keys are NEVER written to flash; destroyed on power-loss.
#
# v1.5.0: TRNG uses adaptive bit selection — profiles the ADC at boot and
# selects the highest-entropy bits dynamically. On health failure it
# re-profiles (up to 3 attempts) before falling back to degraded mode.

def _mint_key(margin=4, retries=3):
    """Mint a 256-bit key from TRNG; fall back to degraded mode on health failure.

    The adaptive TRNG re-profiles the ADC on each retry, so each attempt
    uses a potentially different bit set. Only if all retries fail does it
    fall back to the degraded (chip-ID-derived) key.
    """
    for _ in range(retries):
        try:
            return trng.key256(margin), False
        except Exception:
            pass
    # Degraded fallback: derive from chip ID + ADC noise (unhealthy but functional)
    seed = machine.unique_id() + bytes(range(32))
    for _ in range(256):
        seed += bytes([machine.ADC(4).read_u16() & 0xFF])
    return hashlib.sha256(b'degraded-fallback:' + seed).digest(), True

_KEY, _DEGRADED = _mint_key()

# AES-256 encryption key (minted from TRNG, expanded once at boot).
_AES_KEY = None
_AES_RK = None
_AES_FP = None
try:
    import aes as _aes
    _AES_KEY, _aes_deg = _mint_key()
    _AES_RK = _aes.expand_key(_AES_KEY)
    _AES_FP = ubinascii.hexlify(hashlib.sha256(b'pico-hsm-aes:' + _AES_KEY).digest()).decode()
except Exception:
    _aes = None

# Factory-programmed 64-bit chip ID — unique per RP2040, survives reflash.
_DEVICE_ID = ubinascii.hexlify(machine.unique_id()).decode()

_VERSION = 'pico-hsm/1.6.3'
_COMMANDS = ('WHO', 'PING', 'CHALLENGE <hex>', 'SEED <n>',
             'AES_ENC <hex32>', 'AES_DEC <hex32>',
             'AES_CTR <hex_nonce32> <hex_data>', 'AES_KEY',
             'TRNG', 'TRNG_REPROFILE', 'TRNG_WATCHDOG [ON|OFF|<ms>]',
             'RATE_LIMIT [STATUS|RESET]', 'JSON [ON|OFF]',
             'AUDIT [N|CLEAR]', 'ENC [ON <hex>|OFF|STATUS]',
             'SEED_STREAM <total> [<chunk>]', 'HELP', 'VERSION')

_JSON_MODE = False


def _resp(ok, cmd, **kw):
    """Build a structured response dict."""
    d = {"ok": ok, "cmd": cmd}
    d.update(kw)
    return d


def _format(resp):
    """Format a structured response dict as text or JSON."""
    if _JSON_MODE:
        return ujson.dumps(resp)
    # Text protocol: flatten to space-separated KEY VALUE pairs
    if not resp["ok"]:
        return "ERR " + resp.get("error", "unknown")
    cmd = resp["cmd"]
    if cmd == "PING":
        return "PONG " + str(resp["ts"])
    if cmd == "WHO":
        return ("ID openhands-pico-hsm DEVICE " + resp["device"] +
                " FINGERPRINT " + resp["fingerprint"] +
                " STATUS" + (" DEGRADED" if resp.get("degraded") else ""))
    if cmd == "CHALLENGE":
        return "RESPONSE " + resp["response"]
    if cmd == "SEED":
        return "SEED " + resp["seed"]
    if cmd == "AES_ENC":
        return "AES_CT " + resp["ct"]
    if cmd == "AES_DEC":
        return "AES_PT " + resp["pt"]
    if cmd == "AES_CTR":
        return "AES_OUT " + resp["out"]
    if cmd == "AES_KEY":
        return "AES_KEY_FP " + resp["fingerprint"]
    if cmd == "TRNG":
        return resp["status"]
    if cmd == "TRNG_REPROFILE":
        return "OK reprofile " + ("pass" if resp["passed"] else "fail")
    if cmd == "TRNG_WATCHDOG":
        return ("WATCHDOG %s interval=%dms failures=%d reprofiles=%d trend=%s" % (
            "RUNNING" if resp["running"] else "STOPPED",
            resp["interval_ms"], resp["failures"], resp["reprofiles"],
            "DECLINING" if resp["trend_declining"] else "stable"))
    if cmd == "JSON":
        return "OK json " + ("on" if resp["enabled"] else "off")
    if cmd == "RATE_LIMIT":
        s = resp["status"]
        if s["lockout_active"]:
            return ("RATE_LIMIT LOCKED remaining=%dms lockout=%dms requests=%d/%d window=%dms" % (
                s["lockout_remaining_ms"], s["current_lockout_ms"],
                s["requests_in_window"], s["max_per_window"], s["window_ms"]))
        return ("RATE_LIMIT OK requests=%d/%d window=%dms" % (
            s["requests_in_window"], s["max_per_window"], s["window_ms"]))
    if cmd == "AUDIT":
        entries = resp["entries"]
        if not entries:
            return "AUDIT empty entries=%d/%d" % (0, resp["capacity"])
        lines = ["AUDIT entries=%d/%d" % (resp["count"], resp["capacity"])]
        for e in entries:
            lines.append("  %s %s ch=%s %s" % (
                e["ts"], e["cmd"], e["ch_hash"], e["result"]))
        return "\n".join(lines)
    if cmd == "ENC":
        s = resp.get("status", {})
        if s.get("active"):
            return "ENC ACTIVE counter=%d rx_counter=%d" % (
                s["tx_counter"], s["rx_counter"])
        return "ENC OFF"
    if cmd == "ENC_MSG":
        return "ENC_MSG %d %s" % (resp["counter"], resp["response"])
    if cmd == "SEED_STREAM":
        lines = ["SEED_STREAM total=%d chunk=%d chunks=%d" % (
            resp["total_bytes"], resp["chunk_size"], resp["chunk_count"])]
        for c in resp["chunks"]:
            lines.append(c)
        return "\n".join(lines)
    if cmd == "VERSION":
        return "VERSION " + resp["version"] + " micropython-" + resp["mpy"]
    if cmd == "HELP":
        return "COMMANDS " + " ".join(resp["commands"])
    return "ERR " + resp.get("error", "unknown")

def _hmac_sha256(key, msg):
    block = 64
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    k = key + b'\x00' * (block - len(key))
    o = bytes(b ^ 0x5c for b in k)
    i = bytes(b ^ 0x36 for b in k)
    inner = hashlib.sha256(i + msg).digest()
    return hashlib.sha256(o + inner).digest()

def _fingerprint():
    return ubinascii.hexlify(hashlib.sha256(b'pico-hsm-v1:' + _KEY).digest()).decode()

def _parse_hex(hx):
    try:
        return ubinascii.unhexlify(hx)
    except Exception:
        return None

# ── Rate limiting / lockout ─────────────────────────────────────────────── #
# Sliding-window rate limiter on CHALLENGE and SEED to slow brute-force
# attacks. Tracks recent request timestamps; if the count in the window
# exceeds the threshold, enters a lockout with exponential backoff.
_RATE_WINDOW_MS = 10000        # sliding window length
_RATE_MAX_IN_WINDOW = 10       # max requests per window before lockout
_RATE_LOCKOUT_BASE_MS = 2000   # base lockout (doubles each violation)
_RATE_LOCKOUT_MAX_MS = 60000   # cap at 60 seconds
_RATE_TRACK_CMDS = ('CHALLENGE', 'SEED')

_rate_timestamps = []          # recent request ticks_ms
_rate_lockout_until = 0        # ticks_ms when lockout expires
_rate_lockout_ms = 0           # current lockout duration (for backoff)


def _rate_check(cmd):
    """Check rate limit for a command. Returns (ok, retry_after_ms)."""
    global _rate_lockout_until, _rate_lockout_ms
    now = time.ticks_ms()
    # If in lockout, reject
    if _rate_lockout_until > 0:
        remaining = time.ticks_diff(_rate_lockout_until, now)
        if remaining > 0:
            return False, remaining
        # Lockout expired — reset
        _rate_lockout_until = 0
        _rate_lockout_ms = 0
    # Prune timestamps outside the window
    cutoff = time.ticks_add(now, -_RATE_WINDOW_MS)
    _rate_timestamps[:] = [t for t in _rate_timestamps
                           if time.ticks_diff(t, cutoff) > 0]
    # Check count
    if len(_rate_timestamps) >= _RATE_MAX_IN_WINDOW:
        # Enter lockout with exponential backoff
        if _rate_lockout_ms == 0:
            _rate_lockout_ms = _RATE_LOCKOUT_BASE_MS
        else:
            _rate_lockout_ms = min(_rate_lockout_ms * 2, _RATE_LOCKOUT_MAX_MS)
        _rate_lockout_until = time.ticks_add(now, _rate_lockout_ms)
        _rate_timestamps[:] = []  # reset window
        return False, _rate_lockout_ms
    # Record this request
    _rate_timestamps.append(now)
    return True, 0


def _rate_status():
    """Return rate limiter status dict."""
    now = time.ticks_ms()
    remaining = 0
    if _rate_lockout_until > 0:
        remaining = max(0, time.ticks_diff(_rate_lockout_until, now))
    return {
        'lockout_active': remaining > 0,
        'lockout_remaining_ms': remaining,
        'current_lockout_ms': _rate_lockout_ms,
        'requests_in_window': len(_rate_timestamps),
        'max_per_window': _RATE_MAX_IN_WINDOW,
        'window_ms': _RATE_WINDOW_MS,
    }


def _rate_reset():
    """Reset rate limiter state (clears lockout and history)."""
    global _rate_lockout_until, _rate_lockout_ms
    _rate_timestamps[:] = []
    _rate_lockout_until = 0
    _rate_lockout_ms = 0


# ── Audit log (in-RAM ring buffer) ─────────────────────────────────────── #
# Records CHALLENGE events for post-incident forensics. Stores timestamp +
# challenge hash (SHA-256 of the challenge, NOT the raw challenge or response)
# to protect the volatile key — an attacker reading the log cannot verify the
# key from hashes alone. In-RAM only (lost on power-off), consistent with the
# volatile-key design; flash persistence deferred (wear-leveling + key-leak
# tradeoff needs threat analysis first).
_AUDIT_MAX = 64
_audit_log = []
_audit_head = 0  # index of oldest entry


def _audit_record(cmd, challenge_bytes, result):
    """Record a challenge event in the audit ring buffer."""
    global _audit_head
    entry = {
        'ts': time.ticks_ms(),
        'cmd': cmd,
        'ch_hash': ubinascii.hexlify(
            hashlib.sha256(challenge_bytes).digest()[:8]).decode(),
        'result': result,  # 'ok', 'rate-limited', 'bad-hex'
    }
    if len(_audit_log) < _AUDIT_MAX:
        _audit_log.append(entry)
    else:
        _audit_log[_audit_head] = entry
        _audit_head = (_audit_head + 1) % _AUDIT_MAX


def _audit_get(n=10):
    """Return the last n audit entries (newest first)."""
    if not _audit_log:
        return []
    total = len(_audit_log)
    if n > total:
        n = total
    if total < _AUDIT_MAX:
        # Not yet wrapped — linear, newest at end
        return list(reversed(_audit_log[-n:]))
    # Wrapped — start from head-1 (newest) going back
    result = []
    idx = (_audit_head - 1) % _AUDIT_MAX
    for _ in range(n):
        result.append(_audit_log[idx])
        idx = (idx - 1) % _AUDIT_MAX
    return result


def _audit_clear():
    """Wipe the audit log."""
    global _audit_head
    _audit_log[:] = []
    _audit_head = 0


# ── Encrypted serial protocol (AES-CTR transport) ─────────────────────── #
# After ENC ON <nonce>, all subsequent commands are encrypted with AES-CTR
# using a session key derived from the challenge-response exchange:
#
#   1. Host sends CHALLENGE <nonce> → gets RESPONSE <hmac(key, nonce)>
#   2. session_key = SHA-256(b"enc-session:" + nonce + hmac_response)
#   3. Host sends ENC ON <nonce_hex> → Pico derives the same session_key
#   4. In encrypted mode:
#      Host → Pico:  ENC_MSG <counter> <ciphertext_hex>
#      Pico → Host:  ENC_RESP <counter> <ciphertext_hex>
#      ciphertext = AES-CTR(session_key, counter_as_nonce, plaintext)
#   5. ENC OFF exits encrypted mode
#
# Security properties:
#   ✅ Confidentiality against late-joining eavesdroppers (missed handshake)
#   ✅ Replay protection (counter tracked, replays rejected)
#   ❌ Confidentiality against from-start eavesdroppers (saw the handshake)
#   ❌ Message authentication (session key is derivable from observed traffic)
#
# For full confidentiality against a from-start eavesdropper, a pre-shared
# key or asymmetric key exchange (ECDH) would be needed — both require
# either flash storage (breaks volatile-key design) or ECC hardware (RP2040
# lacks it). This is a pragmatic partial improvement for the USB CDC threat
# model (physical access to the cable).
_ENC_SESSION_KEY = None
_ENC_ACTIVE = False
_ENC_COUNTER = 0
_ENC_LAST_RX_COUNTER = -1  # -1 = no message received yet


def _enc_derive_session_key(nonce_bytes):
    """Derive a session key from a challenge nonce and the volatile key.

    session_key = SHA-256(b"enc-session:" + nonce + hmac(key, nonce))
    The host can compute the same key because it received hmac(key, nonce)
    from the CHALLENGE response. The Pico recomputes hmac(key, nonce) here.
    """
    hmac_resp = _hmac_sha256(_KEY, nonce_bytes)
    return hashlib.sha256(b'enc-session:' + nonce_bytes + hmac_resp).digest()


def _enc_ctr_nonce(counter):
    """Build a 16-byte AES-CTR nonce from a message counter (big-endian)."""
    return counter.to_bytes(16, 'big')


def _enc_encrypt(plaintext_bytes, counter):
    """AES-CTR encrypt the plaintext using the session key."""
    if _aes is None or _ENC_SESSION_KEY is None:
        return None
    rk = _aes.expand_key(_ENC_SESSION_KEY)
    nonce = _enc_ctr_nonce(counter)
    return _aes.ctr_xcrypt(rk, nonce, plaintext_bytes)


def _enc_decrypt(ciphertext_bytes, counter):
    """AES-CTR decrypt (identical to encrypt for CTR mode)."""
    return _enc_encrypt(ciphertext_bytes, counter)


def _enc_reset():
    """Clear encrypted session state."""
    global _ENC_SESSION_KEY, _ENC_ACTIVE, _ENC_COUNTER, _ENC_LAST_RX_COUNTER
    _ENC_SESSION_KEY = None
    _ENC_ACTIVE = False
    _ENC_COUNTER = 0
    _ENC_LAST_RX_COUNTER = -1


def handle(line):
    global _JSON_MODE
    global _ENC_SESSION_KEY, _ENC_ACTIVE, _ENC_COUNTER, _ENC_LAST_RX_COUNTER
    line = line.strip()
    if not line:
        return ''
    if line.startswith('CHALLENGE '):
        ok, retry = _rate_check('CHALLENGE')
        if not ok:
            _audit_record('CHALLENGE', line[10:].encode(), 'rate-limited')
            return _format(_resp(False, 'CHALLENGE', error='rate-limited',
                                 retry_after_ms=retry))
        ch = _parse_hex(line[10:].strip())
        if ch is None:
            _audit_record('CHALLENGE', line[10:].encode(), 'bad-hex')
            return _format(_resp(False, 'CHALLENGE', error='bad-hex'))
        mac = _hmac_sha256(_KEY, ch)
        _audit_record('CHALLENGE', ch, 'ok')
        return _format(_resp(True, 'CHALLENGE',
                             response=ubinascii.hexlify(mac).decode()))
    if line.startswith('SEED '):
        ok, retry = _rate_check('SEED')
        if not ok:
            return _format(_resp(False, 'SEED', error='rate-limited',
                                 retry_after_ms=retry))
        try:
            n = int(line[5:].strip())
        except Exception:
            return _format(_resp(False, 'SEED', error='bad-count'))
        if n < 1 or n > 256:
            return _format(_resp(False, 'SEED', error='count-range-1-256'))
        try:
            raw = trng.raw_entropy(n)
        except Exception:
            return _format(_resp(False, 'SEED', error='trng-unhealthy'))
        return _format(_resp(True, 'SEED',
                             seed=ubinascii.hexlify(raw).decode()))
    if line == 'SEED_STREAM' or line.startswith('SEED_STREAM '):
        ok, retry = _rate_check('SEED')
        if not ok:
            return _format(_resp(False, 'SEED_STREAM', error='rate-limited',
                                 retry_after_ms=retry))
        parts = line[12:].strip().split() if len(line) > 12 else []
        if len(parts) < 1 or len(parts) > 2:
            return _format(_resp(False, 'SEED_STREAM',
                                 error='usage: SEED_STREAM <total> [<chunk>]'))
        try:
            total = int(parts[0])
        except Exception:
            return _format(_resp(False, 'SEED_STREAM', error='bad-total'))
        chunk_size = 64
        if len(parts) == 2:
            try:
                chunk_size = int(parts[1])
            except Exception:
                return _format(_resp(False, 'SEED_STREAM',
                                     error='bad-chunk'))
        if total < 1 or total > 8192:
            return _format(_resp(False, 'SEED_STREAM',
                                 error='total-range-1-8192'))
        if chunk_size < 1 or chunk_size > 256:
            return _format(_resp(False, 'SEED_STREAM',
                                 error='chunk-range-1-256'))
        chunks = []
        remaining = total
        while remaining > 0:
            n = min(chunk_size, remaining)
            try:
                raw = trng.raw_entropy(n)
            except Exception:
                return _format(_resp(False, 'SEED_STREAM',
                                     error='trng-unhealthy'))
            chunks.append(ubinascii.hexlify(raw).decode())
            remaining -= n
        return _format(_resp(True, 'SEED_STREAM',
                             total_bytes=total, chunk_size=chunk_size,
                             chunk_count=len(chunks), chunks=chunks))
    if line.startswith('AES_ENC '):
        if _aes is None:
            return _format(_resp(False, 'AES_ENC', error='no-aes-module'))
        pt = _parse_hex(line[8:].strip())
        if pt is None:
            return _format(_resp(False, 'AES_ENC', error='bad-hex'))
        if len(pt) != 16:
            return _format(_resp(False, 'AES_ENC', error='block-size-16'))
        ct = _aes.encrypt_block(_AES_RK, pt)
        return _format(_resp(True, 'AES_ENC',
                             ct=ubinascii.hexlify(ct).decode()))
    if line.startswith('AES_DEC '):
        if _aes is None:
            return _format(_resp(False, 'AES_DEC', error='no-aes-module'))
        ct = _parse_hex(line[8:].strip())
        if ct is None:
            return _format(_resp(False, 'AES_DEC', error='bad-hex'))
        if len(ct) != 16:
            return _format(_resp(False, 'AES_DEC', error='block-size-16'))
        pt = _aes.decrypt_block(_AES_RK, ct)
        return _format(_resp(True, 'AES_DEC',
                             pt=ubinascii.hexlify(pt).decode()))
    if line.startswith('AES_CTR '):
        if _aes is None:
            return _format(_resp(False, 'AES_CTR', error='no-aes-module'))
        parts = line[8:].strip().split(None, 1)
        if len(parts) == 0:
            return _format(_resp(False, 'AES_CTR', error='usage: AES_CTR <hex_nonce32> <hex_data>'))
        nonce = _parse_hex(parts[0])
        if nonce is None:
            return _format(_resp(False, 'AES_CTR', error='bad-hex'))
        if len(nonce) != 16:
            return _format(_resp(False, 'AES_CTR', error='nonce-size-16'))
        data = _parse_hex(parts[1]) if len(parts) > 1 else b''
        if data is None:
            return _format(_resp(False, 'AES_CTR', error='bad-hex'))
        out = _aes.ctr_xcrypt(_AES_RK, nonce, data)
        return _format(_resp(True, 'AES_CTR',
                             out=ubinascii.hexlify(out).decode()))
    if line == 'AES_KEY':
        if _aes is None:
            return _format(_resp(False, 'AES_KEY', error='no-aes-module'))
        return _format(_resp(True, 'AES_KEY', fingerprint=_AES_FP))
    if line == 'TRNG':
        try:
            return _format(_resp(True, 'TRNG', status=trng.status_str()))
        except Exception as e:
            return _format(_resp(False, 'TRNG', error=str(e)))
    if line == 'TRNG_REPROFILE':
        try:
            ok = trng.reprofile()
            return _format(_resp(True, 'TRNG_REPROFILE', passed=ok))
        except Exception as e:
            return _format(_resp(False, 'TRNG_REPROFILE', error=str(e)))
    if line == 'TRNG_WATCHDOG':
        try:
            wd = trng.watchdog_status()
            return _format(_resp(True, 'TRNG_WATCHDOG',
                                 running=wd['running'],
                                 interval_ms=wd['interval_ms'],
                                 failures=wd['failures'],
                                 reprofiles=wd['reprofiles'],
                                 trend_declining=wd['trend_declining']))
        except Exception as e:
            return _format(_resp(False, 'TRNG_WATCHDOG', error=str(e)))
    if line.startswith('TRNG_WATCHDOG '):
        arg = line[14:].strip().upper()
        try:
            if arg == 'ON':
                ok = trng.start_watchdog()
                return _format(_resp(True, 'TRNG_WATCHDOG',
                                     running=True, interval_ms=trng._wd_interval_ms,
                                     failures=0, reprofiles=trng._wd_reprofiles,
                                     trend_declining=False))
            elif arg == 'OFF':
                trng.stop_watchdog()
                return _format(_resp(True, 'TRNG_WATCHDOG',
                                     running=False, interval_ms=trng._wd_interval_ms,
                                     failures=trng._wd_failures,
                                     reprofiles=trng._wd_reprofiles,
                                     trend_declining=False))
            else:
                ms = int(arg)
                trng.stop_watchdog()
                ok = trng.start_watchdog(interval_ms=ms)
                return _format(_resp(True, 'TRNG_WATCHDOG',
                                     running=ok, interval_ms=ms,
                                     failures=0, reprofiles=trng._wd_reprofiles,
                                     trend_declining=False))
        except Exception as e:
            return _format(_resp(False, 'TRNG_WATCHDOG', error=str(e)))
    if line == 'RATE_LIMIT' or line == 'RATE_LIMIT STATUS':
        return _format(_resp(True, 'RATE_LIMIT', status=_rate_status()))
    if line == 'RATE_LIMIT RESET':
        _rate_reset()
        return _format(_resp(True, 'RATE_LIMIT', status=_rate_status()))
    if line == 'AUDIT CLEAR':
        _audit_clear()
        return _format(_resp(True, 'AUDIT', entries=[], count=0,
                             capacity=_AUDIT_MAX))
    if line == 'AUDIT' or line == 'AUDIT STATUS':
        entries = _audit_get(10)
        return _format(_resp(True, 'AUDIT', entries=entries,
                             count=len(_audit_log), capacity=_AUDIT_MAX))
    if line.startswith('AUDIT '):
        try:
            n = int(line[6:].strip())
        except Exception:
            n = 10
        if n < 1:
            n = 1
        if n > _AUDIT_MAX:
            n = _AUDIT_MAX
        entries = _audit_get(n)
        return _format(_resp(True, 'AUDIT', entries=entries,
                             count=len(_audit_log), capacity=_AUDIT_MAX))
    # ── Encrypted transport ──
    if line == 'ENC OFF':
        _enc_reset()
        return _format(_resp(True, 'ENC', status={'active': False}))
    if line == 'ENC' or line == 'ENC STATUS':
        return _format(_resp(True, 'ENC', status={
            'active': _ENC_ACTIVE,
            'tx_counter': _ENC_COUNTER,
            'rx_counter': _ENC_LAST_RX_COUNTER,
        }))
    if line.startswith('ENC ON'):
        if _aes is None:
            return _format(_resp(False, 'ENC', error='no-aes-module'))
        parts = line.split(None, 2)
        if len(parts) < 3:
            return _format(_resp(False, 'ENC', error='usage: ENC ON <hex_nonce>'))
        nonce = _parse_hex(parts[2])
        if nonce is None:
            return _format(_resp(False, 'ENC', error='bad-hex'))
        if len(nonce) < 8:
            return _format(_resp(False, 'ENC', error='nonce-too-short'))
        _ENC_SESSION_KEY = _enc_derive_session_key(nonce)
        _ENC_ACTIVE = True
        _ENC_COUNTER = 0
        _ENC_LAST_RX_COUNTER = -1
        return _format(_resp(True, 'ENC', status={
            'active': True, 'tx_counter': 0, 'rx_counter': -1}))
    if line.startswith('ENC_MSG '):
        if not _ENC_ACTIVE:
            return _format(_resp(False, 'ENC_MSG', error='not-active'))
        if _aes is None:
            return _format(_resp(False, 'ENC_MSG', error='no-aes-module'))
        parts = line[8:].strip().split(None, 1)
        if len(parts) < 2:
            return _format(_resp(False, 'ENC_MSG',
                                 error='usage: ENC_MSG <counter> <hex_ct>'))
        try:
            rx_counter = int(parts[0])
        except Exception:
            return _format(_resp(False, 'ENC_MSG', error='bad-counter'))
        if rx_counter <= _ENC_LAST_RX_COUNTER:
            return _format(_resp(False, 'ENC_MSG', error='replay-detected'))
        ct = _parse_hex(parts[1])
        if ct is None:
            return _format(_resp(False, 'ENC_MSG', error='bad-hex'))
        pt = _enc_decrypt(ct, rx_counter)
        if pt is None:
            return _format(_resp(False, 'ENC_MSG', error='decrypt-failed'))
        _ENC_LAST_RX_COUNTER = rx_counter
        inner_cmd = pt.decode('utf-8', 'replace').strip()
        # Execute the decrypted command, then encrypt the response
        inner_resp = handle(inner_cmd)
        resp_bytes = inner_resp.encode('utf-8')
        tx_counter = _ENC_COUNTER
        _ENC_COUNTER += 1
        enc_resp = _enc_encrypt(resp_bytes, tx_counter)
        if enc_resp is None:
            return _format(_resp(False, 'ENC_MSG', error='encrypt-failed'))
        return _format(_resp(True, 'ENC_MSG',
                             counter=tx_counter,
                             response=ubinascii.hexlify(enc_resp).decode()))
    if line == 'JSON' or line == 'JSON OFF':
        _JSON_MODE = False
        return _format(_resp(True, 'JSON', enabled=False))
    if line == 'JSON ON':
        _JSON_MODE = True
        return _format(_resp(True, 'JSON', enabled=True))
    if line == 'WHO':
        return _format(_resp(True, 'WHO', device=_DEVICE_ID,
                             fingerprint=_fingerprint(),
                             degraded=_DEGRADED))
    if line == 'PING':
        return _format(_resp(True, 'PING', ts=time.ticks_ms()))
    if line == 'VERSION':
        return _format(_resp(True, 'VERSION', version=_VERSION,
                             mpy=sys.version.split(';')[0].strip()))
    if line == 'HELP':
        return _format(_resp(True, 'HELP', commands=list(_COMMANDS)))
    return _format(_resp(False, 'UNKNOWN', error='unknown-cmd'))
