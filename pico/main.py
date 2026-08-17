# Pico HSM entry point. Boot -> mint volatile TRNG key -> serve challenges.
import hsm, sys, trng, machine

# ── LED status indicator (hardware timer, no extra thread) ────────────── #
# Onboard LED (GP25) shows HSM health at a glance:
#   solid ON   — healthy and ready
#   fast blink — degraded (TRNG unhealthy, using fallback key)
#
# Uses machine.Timer (hardware interrupt) so it doesn't conflict with the
# watchdog thread on RP2040 core 1 (only one _thread allowed on core 1).
_led = machine.Pin("LED", machine.Pin.OUT)
_led.on()                          # healthy at boot
_blink = [False]                   # mutable flag (interrupt-safe read)

def _led_tick(_t):
    if _blink[0]:
        _led.toggle()

_tim = machine.Timer()
_tim.init(period=200, mode=machine.Timer.PERIODIC, callback=_led_tick)


def _update_led():
    """Sync LED to current HSM/TRNG health state."""
    if hsm._DEGRADED:
        _blink[0] = True           # fast blink
    else:
        _blink[0] = False          # stop blinking
        _led.on()                  # solid on = healthy


# Start the entropy watchdog on RP2040 core 1. It continuously monitors ADC
# entropy quality and triggers re-profiling on degradation.
trng.start_watchdog(interval_ms=5000)

_update_led()
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
        _update_led()
except KeyboardInterrupt:
    pass
