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
             'JSON [ON|OFF]', 'HELP', 'VERSION')

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

def handle(line):
    global _JSON_MODE
    line = line.strip()
    if not line:
        return ''
    if line.startswith('CHALLENGE '):
        ch = _parse_hex(line[10:].strip())
        if ch is None:
            return _format(_resp(False, 'CHALLENGE', error='bad-hex'))
        mac = _hmac_sha256(_KEY, ch)
        return _format(_resp(True, 'CHALLENGE',
                             response=ubinascii.hexlify(mac).decode()))
    if line.startswith('SEED '):
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
