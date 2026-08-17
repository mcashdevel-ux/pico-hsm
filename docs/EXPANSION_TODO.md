# Expansion TODO

Ideas and future directions for the pico-hsm project.

**Progress:** 14 of 20 items completed. All code-only items that can be done
without the physical Pico are done. The native C module has been deployed and
validated on hardware (NIST SP 800-22, 64 KB, all 6 tests pass). Persistent
key option (opt-in, PIN-encrypted) is implemented and verified. Remaining
items require deeper hardware work (DMA, entropy sources, secure element,
core pinning, custom firmware, HID, WebUSB) or formal validation
(NIST 800-90B).

See also: [Architecture](ARCHITECTURE.md), [Threat model](THREAT_MODEL.md).

## TRNG / entropy

- [ ] **DMA ADC sampling.** The native C module currently polls the ADC in a
  tight loop. Using the RP2040 DMA controller to stream ADC samples to a
  buffer would free the CPU and allow higher sampling rates.
- [ ] **Multiple entropy sources.** Combine the floating-pin ADC noise with
  other sources: the ring oscillator (`ROSC.RANDOM` — needs a custom
  MicroPython build to enable it), the temperature sensor, or an external
  noise diode on a second ADC channel. XOR-mixing independent sources
  increases the overall min-entropy.
- [ ] **NIST SP 800-90B validation.** The continuous health tests
  (repetition-count, adaptive-proportion) are implemented but not formally
  validated. Running the source through the full 90B validation suite would
  give a certified entropy estimate.
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

- [x] **Persistent key option.** Store an encrypted HMAC key in flash,
  sealed by a PIN. The key is encrypted with a PIN-derived key (iterated
  SHA-256, 1000 rounds) using AES-ECB (the only mode available in this
  MicroPython ucryptolib build; safe here because the plaintext is a
  32-byte random key with no pattern to leak). Commands: `KEY_STORE <pin>`,
  `KEY_LOAD <pin>`, `KEY_ERASE`, `KEY_STATUS`. Strictly opt-in — the default
  remains ephemeral (volatile) keys. Verified on hardware: store, reboot,
  load with correct PIN restores the original fingerprint; wrong PIN gives
  a different (garbage) key; challenge-response matches after load. 11
  hardware tests + 26 no-hardware tests.
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
- [x] **Bulk SEED mode.** Added `SEED_STREAM <total> [<chunk_size>]` for
  high-throughput entropy retrieval. Returns up to 8192 bytes of raw TRNG
  output, split into chunks (default 64 bytes, configurable 1–256). Each
  chunk is hex-encoded on its own line (text mode) or a JSON array element
  (JSON mode). A single call counts as one request against the rate limiter
  (not per-chunk), enabling bulk retrieval without tripping the lockout.
  24 host-side pytest tests in `test_seed_stream.py`.
- [x] **JSON mode.** Added `JSON ON` / `JSON OFF` commands that toggle JSON
  output mode. When enabled, all responses are JSON objects
  (`{"ok": true, "cmd": "PING", "ts": 12345}`) instead of text lines, for
  easy parsing in non-Python hosts. The text protocol remains the default.
  `handle()` refactored to build structured response dicts via `_resp()` /
  `_format()`. 17 host-side pytest tests in `test_json_mode.py`.

## Testing / CI

- [x] **Test the native module on hardware.** Deployed `trng_native.mpy` to
  the Pico (v1.6.3), verified SEED speedup (~7× via SEED_STREAM, ~327 bytes/s
  vs ~47 bytes/s for single SEED), and ran the NIST SP 800-22 statistical
  suite on 64 KB of native-module entropy: all 6 tests pass (monobit, runs,
  chi-square byte, poker, serial, autocorrelation). Results validated
  against `os.urandom` at the same sample size. Script: `host/nist_800_22.py`.
- [x] **CI pipeline.** GitHub Actions runs pytest (skips without hardware)
  and lints C code with cppcheck (`.github/workflows/ci.yml`).
- [x] **Cross-platform host client.** `hsm_client.py._detect_port()` now
  auto-detects the serial port on Linux (`/dev/ttyACM*`), macOS
  (`/dev/cu.usbmodem*`), and Windows (`COM*` via pyserial comports).

## Documentation

- [x] **Architecture diagram.** Added `docs/ARCHITECTURE.md` with ASCII art
  and Mermaid diagrams showing the TRNG pipeline, the dual-core design
  (core 0 = serial REPL, core 1 = watchdog), the native module integration,
  the serial protocol stack (including the encrypted transport layer),
  the memory map, and the challenge-response data flow.
- [x] **Threat model document.** Added `docs/THREAT_MODEL.md` formalizing
  the security claims and non-claims: assets, six adversary tiers (A1–A6),
  security properties per feature (volatile key, challenge-response,
  encrypted transport, rate limiting, audit log, device identity, TRNG),
  an explicit list of non-claims, a threat summary matrix, and
  recommendations for users needing stronger security.
