import trng, hashlib, ubinascii, time, sys

# HSM: mints an in-RAM (volatile) HMAC key from silicon entropy on boot.
# Key is NEVER written to flash; destroyed on power-loss.
_KEY = trng.key256()

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
    if line.startswith('CHALLENGE '):
        hx = line[10:].strip()
        try:
            ch = ubinascii.unhexlify(hx)
        except Exception:
            return 'ERR bad-hex'
        mac = _hmac_sha256(_KEY, ch)
        return 'RESPONSE ' + ubinascii.hexlify(mac).decode()
    if line == 'WHO':
        return 'ID openhands-pico-hsm FINGERPRINT ' + _fingerprint()
    if line == 'PING':
        return 'PONG ' + str(time.ticks_ms())
    return 'ERR unknown-cmd'

print('HSM ready. Commands: CHALLENGE <hex> | WHO | PING')
print('ID openhands-pico-hsm FINGERPRINT ' + _fingerprint())
try:
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        print(handle(line))
except KeyboardInterrupt:
    pass
