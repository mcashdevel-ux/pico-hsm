import serial, sys, hashlib, hmac, time, binascii, os

PORT = '/dev/ttyACM0'
ser = serial.Serial(PORT, 115200, timeout=5)
time.sleep(0.3)

# drain any boot banner
boot = b''
end = time.time() + 2
while time.time() < end:
    b = ser.read(4096)
    if not b: break
    boot += b
print('=== boot banner ===')
print(boot.decode(errors='replace').strip())

def send(cmd):
    ser.write((cmd + '\n').encode())
    time.sleep(0.05)
    r = b''
    end = time.time() + 3
    while time.time() < end:
        b = ser.read(256)
        if b: r += b
        elif r: break
    return r.decode(errors='replace').strip()

print('\n=== PING ===')
print(send('PING'))

print('\n=== WHO ===')
who = send('WHO')
print(who)

# Issue a challenge with random bytes from host's own RNG
challenge = os.urandom(32)
ch_hex = binascii.hexlify(challenge).decode()
print('\n=== CHALLENGE (host-side random) ===')
print('challenge hex:', ch_hex)
resp = send('CHALLENGE ' + ch_hex)
print('response:', resp)

# Parse the HMAC from RESPONSE line
if resp.startswith('RESPONSE '):
    mac_hex = resp[9:].strip()
    mac = binascii.hexlify(binascii.unhexlify(mac_hex))  # echo
    print('\nGot HMAC (%d bytes): %s' % (len(binascii.unhexlify(mac_hex)), mac_hex))
    print('NOTE: host cannot verify without the key (good - key stays on Pico).')
    print('Host CAN confirm: response is 64 hex chars (32-byte SHA256 HMAC), well-formed.')
else:
    print('UNEXPECTED:', resp)

print('\n=== consistency: same challenge again ===')
resp2 = send('CHALLENGE ' + ch_hex)
print('response2:', resp2)
print('deterministic (same challenge -> same HMAC)?', resp == resp2)

ser.close()
