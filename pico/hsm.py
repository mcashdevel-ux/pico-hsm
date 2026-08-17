import trng, hashlib, ubinascii, time, sys, machine

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

_VERSION = 'pico-hsm/1.6.0'
_COMMANDS = ('WHO', 'PING', 'CHALLENGE <hex>', 'SEED <n>',
             'AES_ENC <hex32>', 'AES_DEC <hex32>',
             'AES_CTR <hex_nonce32> <hex_data>', 'AES_KEY',
             'TRNG', 'TRNG_REPROFILE', 'TRNG_WATCHDOG [ON|OFF|<ms>]',
             'HELP', 'VERSION')

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
    line = line.strip()
    if not line:
        return ''
    if line.startswith('CHALLENGE '):
        ch = _parse_hex(line[10:].strip())
        if ch is None:
            return 'ERR bad-hex'
        mac = _hmac_sha256(_KEY, ch)
        return 'RESPONSE ' + ubinascii.hexlify(mac).decode()
    if line.startswith('SEED '):
        try:
            n = int(line[5:].strip())
        except Exception:
            return 'ERR bad-count'
        if n < 1 or n > 256:
            return 'ERR count-range-1-256'
        try:
            raw = trng.raw_entropy(n)
        except Exception:
            return 'ERR trng-unhealthy'
        return 'SEED ' + ubinascii.hexlify(raw).decode()
    if line.startswith('AES_ENC '):
        if _aes is None:
            return 'ERR no-aes-module'
        pt = _parse_hex(line[8:].strip())
        if pt is None:
            return 'ERR bad-hex'
        if len(pt) != 16:
            return 'ERR block-size-16'
        ct = _aes.encrypt_block(_AES_RK, pt)
        return 'AES_CT ' + ubinascii.hexlify(ct).decode()
    if line.startswith('AES_DEC '):
        if _aes is None:
            return 'ERR no-aes-module'
        ct = _parse_hex(line[8:].strip())
        if ct is None:
            return 'ERR bad-hex'
        if len(ct) != 16:
            return 'ERR block-size-16'
        pt = _aes.decrypt_block(_AES_RK, ct)
        return 'AES_PT ' + ubinascii.hexlify(pt).decode()
    if line.startswith('AES_CTR '):
        if _aes is None:
            return 'ERR no-aes-module'
        parts = line[8:].strip().split(None, 1)
        if len(parts) == 0:
            return 'ERR usage: AES_CTR <hex_nonce32> <hex_data>'
        nonce = _parse_hex(parts[0])
        if nonce is None:
            return 'ERR bad-hex'
        if len(nonce) != 16:
            return 'ERR nonce-size-16'
        data = _parse_hex(parts[1]) if len(parts) > 1 else b''
        if data is None:
            return 'ERR bad-hex'
        out = _aes.ctr_xcrypt(_AES_RK, nonce, data)
        return 'AES_OUT ' + ubinascii.hexlify(out).decode()
    if line == 'AES_KEY':
        if _aes is None:
            return 'ERR no-aes-module'
        return 'AES_KEY_FP ' + _AES_FP
    if line == 'TRNG':
        try:
            return trng.status_str()
        except Exception as e:
            return 'ERR ' + str(e)
    if line == 'TRNG_REPROFILE':
        try:
            ok = trng.reprofile()
            return 'OK reprofile ' + ('pass' if ok else 'fail')
        except Exception as e:
            return 'ERR ' + str(e)
    if line == 'TRNG_WATCHDOG':
        try:
            wd = trng.watchdog_status()
            return ('WATCHDOG %s interval=%dms failures=%d reprofiles=%d trend=%s' % (
                "RUNNING" if wd['running'] else "STOPPED",
                wd['interval_ms'], wd['failures'], wd['reprofiles'],
                "DECLINING" if wd['trend_declining'] else "stable"))
        except Exception as e:
            return 'ERR ' + str(e)
    if line.startswith('TRNG_WATCHDOG '):
        arg = line[14:].strip().upper()
        try:
            if arg == 'ON':
                ok = trng.start_watchdog()
                return 'OK watchdog ' + ('started' if ok else 'already-running')
            elif arg == 'OFF':
                trng.stop_watchdog()
                return 'OK watchdog stopped'
            else:
                # Try parsing as interval in ms
                ms = int(arg)
                trng.stop_watchdog()
                ok = trng.start_watchdog(interval_ms=ms)
                return 'OK watchdog interval=%dms %s' % (ms, 'started' if ok else 'failed')
        except Exception as e:
            return 'ERR ' + str(e)
    if line == 'WHO':
        status = ' DEGRADED' if _DEGRADED else ''
        return ('ID openhands-pico-hsm DEVICE ' + _DEVICE_ID +
                ' FINGERPRINT ' + _fingerprint() + ' STATUS' + status)
    if line == 'PING':
        return 'PONG ' + str(time.ticks_ms())
    if line == 'VERSION':
        return 'VERSION ' + _VERSION + ' micropython-' + sys.version.split(';')[0].strip()
    if line == 'HELP':
        return 'COMMANDS ' + ' '.join(_COMMANDS)
    return 'ERR unknown-cmd'
