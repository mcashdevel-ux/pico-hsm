# Pico HSM entry point. Boot -> mint volatile TRNG key -> serve challenges.
import hsm, sys

print('HSM ready. Commands: ' + ' '.join(hsm._COMMANDS))
print('ID openhands-pico-hsm FINGERPRINT ' + hsm._fingerprint())
try:
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        resp = hsm.handle(line)
        if resp:
            print(resp)
except KeyboardInterrupt:
    pass
