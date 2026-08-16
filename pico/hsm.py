import trng, hashlib, ubinascii, time, sys, machine

# HSM: mints an in-RAM (volatile) HMAC key from silicon entropy on boot.
# Key is NEVER written to flash; destroyed on power-loss.
_KEY = trng.key256()

# Factory-programmed 64-bit chip ID — unique per RP2040, survives reflash.
# Acts as a persistent device serial number so the host can detect
# substitution. It is NOT a secret (anyone with USB access can read it).
_DEVICE_ID = ubinascii.hexlify(machine.unique_id()).decode()

_VERSION = 'pico-hsm/1.2.0'
_COMMANDS = ('WHO', 'PING', 'CHALLENGE <hex>', 'SEED <n>', 'HELP', 'VERSION')

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

def handle(line):
    line = line.strip()
    if not line:
        return ''
    if line.startswith('CHALLENGE '):
        hx = line[10:].strip()
        try:
            ch = ubinascii.unhexlify(hx)
        except Exception:
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
        raw = trng.raw_entropy(n)
        return 'SEED ' + ubinascii.hexlify(raw).decode()
    if line == 'WHO':
        return ('ID openhands-pico-hsm DEVICE ' + _DEVICE_ID +
                ' FINGERPRINT ' + _fingerprint())
    if line == 'PING':
        return 'PONG ' + str(time.ticks_ms())
    if line == 'VERSION':
        return 'VERSION ' + _VERSION + ' micropython-' + sys.version.split(';')[0].strip()
    if line == 'HELP':
        return 'COMMANDS ' + ' '.join(_COMMANDS)
    return 'ERR unknown-cmd'
