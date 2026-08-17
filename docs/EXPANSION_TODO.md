# Expansion TODO

Ideas and future directions for the pico-hsm project.

## TRNG / entropy

- [ ] **DMA ADC sampling.** The native C module currently polls the ADC in a
  tight loop. Using the RP2040 DMA controller to stream ADC samples to a
  buffer would free the CPU and allow higher sampling rates.
- [ ] **Multiple entropy sources.** Combine the floating-pin ADC noise with
  other sources: the ring oscillator (`ROSC.RANDOM` — needs a custom
  MicroPython build to enable it), the temperature sensor, or an external
  noise diode on a second ADC channel. XOR-mixing independent sources
  increases the overall min-entropy.
- [ ] **NIST SP 800-90B validation.** The current health gate is a screen,
  not certification. Running the source through the full 90B conditional
  test suite would give a formal entropy estimate.
- [ ] **Continuous health monitoring in C.** The watchdog currently runs in
  Python on core 1. Moving it to C (or into the native module) would
  reduce its CPU footprint and allow tighter monitoring intervals.
- [x] **Repetition-count and adaptive-proportion tests.** Added the two NIST
  800-90B §4.4 continuous health tests to both the full health gate
  (`_health_check`) and the watchdog's lightweight check (`_lightweight_health`).
  The repetition-count test detects stuck sources (run of identical samples
  exceeds `2*ceil(log2(n))+1`); the adaptive-proportion test tracks the first
  sample's value through a 512-sample window and fails if it appears >12 times
  (NIST α=2^-20). Results reported in `TRNG` status as `WATCHDOG_NIST`.
  13 host-side pytest tests in `test_nist_health.py` (no hardware needed).

## HSM / security

- [ ] **Persistent key option.** Store an encrypted HMAC key in flash,
  sealed by a PIN or a physical button press (BOOTSEL). This would make the
  key recoverable across reboots without keeping it in plaintext. Trade-off:
  loses the "ephemeral by design" property, so make it opt-in.
- [ ] **Secure element integration (ATECC608A).** Add a hardware secure
  element over I2C for non-extractable keys, true device authentication
  (not just chip ID), and certified RNG. This would close the anti-spoofing
  gap documented in the README.
- [x] **Encrypted serial protocol.** Added an AES-CTR transport encryption
  layer. After a challenge-response exchange, the host derives a session key
  (`SHA-256(b"enc-session:" + nonce + hmac(key, nonce))`) and sends
  `ENC ON <nonce_hex>`; the Pico derives the same key. Subsequent commands
  use `ENC_MSG <counter> <ciphertext_hex>` → `ENC_MSG <counter> <ciphertext_hex>`
  with AES-CTR. Replay protection via monotonically-increasing counters.
  `ENC OFF` exits encrypted mode; `ENC STATUS` shows current state.
  Security properties: ✅ confidentiality against late-joining eavesdroppers
  (missed the handshake), ✅ replay protection, ❌ confidentiality against
  from-start eavesdroppers (saw the plaintext handshake — full confidentiality
  requires ECDH or a pre-shared key, both incompatible with the volatile-key
  design on RP2040). 26 host-side pytest tests in `test_enc_protocol.py`.
- [x] **Rate limiting / lockout.** Added a sliding-window rate limiter on
  CHALLENGE and SEED endpoints. Tracks request timestamps in a 10-second
  window; if more than 10 requests arrive, enters a lockout with exponential
  backoff (2s base, doubling, capped at 60s). `RATE_LIMIT STATUS` shows
  current state; `RATE_LIMIT RESET` clears it. Non-tracked commands (WHO,
  PING, VERSION, etc.) are unaffected by lockout. 16 host-side pytest tests
  in `test_rate_limit.py`.
- [x] **Audit log on flash.** Implemented as an in-RAM ring buffer (64-entry
  capacity) storing timestamp + SHA-256 challenge hash (not the raw challenge
  or response — protects the volatile key). Records every CHALLENGE event
  (ok / rate-limited / bad-hex) for post-incident forensics. `AUDIT [N]`
  shows the last N entries (newest first); `AUDIT CLEAR` wipes the log.
  In-RAM only (lost on power-off), consistent with the volatile-key design;
  flash persistence deferred (wear-leveling + key-leak tradeoff needs threat
  analysis). 21 host-side pytest tests in `test_audit_log.py`.

## Performance / firmware

- [x] **Benchmark native module.** Measured: native `fresh_entropy(32)` =
  32.6 ms, Python DRBG `generate(256)` = 25.9 ms (12 × HMAC at 2.2 ms each),
  total `raw_entropy(256)` = 74.7 ms. The native C path (ADC → health → VN
  debias) is ~100× faster than the original Python-only pipeline; the remaining
  bottleneck was the Python HMAC-DRBG, now eliminated (see next item).
- [x] **Move HMAC-DRBG to native C.** `trng_native.seed()` runs the full
  pipeline (ADC → health → VN debias → SHA-256 → HMAC-DRBG) in C.
  `raw_entropy()` now calls `trng_native.seed()` directly when the native
  module is available (commit b430de6), falling back to the Python DRBG.
- [ ] **Core 1 dedicated to TRNG.** Pin the native TRNG collection to
  core 1 (via `_thread` or the SDK's `core1_launch`) so it never contends
  with the serial REPL on core 0.
- [ ] **Custom MicroPython firmware.** Build a custom MicroPython firmware
  with `ROSC.RANDOM` enabled, `machine.ADC` DMA support, and the native
  modules compiled in (vs. loaded as .mpy). This gives maximum performance
  and access to hardware features the stock build doesn't expose.

## Protocol / interface

- [ ] **USB HID interface.** In addition to the CDC serial port, expose a
  HID interface so the Pico works without a serial driver (useful on
  locked-down hosts and mobile devices).
- [ ] **WebUSB support.** Make the Pico accessible from a browser via
  WebUSB, enabling a web-based HSM dashboard without installing software.
- [ ] **Bulk SEED mode.** Instead of one SEED command returning up to 256
  bytes, add a streaming mode that continuously outputs entropy over serial
  for high-throughput applications (e.g., seeding a cluster of servers).
- [x] **JSON mode.** Added `JSON ON` / `JSON OFF` commands that toggle JSON
  output mode. When enabled, all responses are JSON objects
  (`{"ok": true, "cmd": "PING", "ts": 12345}`) instead of text lines, for
  easy parsing in non-Python hosts. The text protocol remains the default.
  `handle()` refactored to build structured response dicts via `_resp()` /
  `_format()`. 17 host-side pytest tests in `test_json_mode.py`.

## Testing / CI

- [ ] **Test the native module on hardware.** After the Pico is physically
  reset, copy `trng_native.mpy`, verify SEED speedup, and run the NIST
  statistical suite on native-module output.
- [x] **CI pipeline.** GitHub Actions runs pytest (skips without hardware)
  and lints C code with cppcheck (`.github/workflows/ci.yml`).
- [x] **Cross-platform host client.** `hsm_client.py._detect_port()` now
  auto-detects the serial port on Linux (`/dev/ttyACM*`), macOS
  (`/dev/cu.usbmodem*`), and Windows (`COM*` via pyserial comports).

## Documentation

- [ ] **Architecture diagram.** Add a visual showing the TRNG pipeline,
  the dual-core design (core 0 = serial REPL, core 1 = watchdog), and the
  native module integration point.
- [ ] **Threat model document.** Formalize the security claims and
  non-claims into a dedicated threat model document.
