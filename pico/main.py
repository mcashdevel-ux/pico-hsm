# Pico HSM entry point. Boot -> mint volatile TRNG key -> serve challenges.
import hsm, sys, trng

# Start the entropy watchdog on RP2040 core 1. It continuously monitors ADC
# entropy quality and triggers re-profiling on degradation.
trng.start_watchdog(interval_ms=5000)

print('HSM ready. Commands: ' + ' '.join(hsm._COMMANDS))
status = ' DEGRADED (TRNG unhealthy)' if hsm._DEGRADED else ''
print('ID openhands-pico-hsm FINGERPRINT ' + hsm._fingerprint() + status)
if hsm._aes is not None:
    print('AES ready. FINGERPRINT ' + hsm._AES_FP)
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
