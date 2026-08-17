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
- [ ] **Repetition-count and adaptive-proportion tests.** Add the two NIST
  90B continuous health tests to the watchdog for runtime failure detection
  that matches the certification standard.

## HSM / security

- [ ] **Persistent key option.** Store an encrypted HMAC key in flash,
  sealed by a PIN or a physical button press (BOOTSEL). This would make the
  key recoverable across reboots without keeping it in plaintext. Trade-off:
  loses the "ephemeral by design" property, so make it opt-in.
- [ ] **Secure element integration (ATECC608A).** Add a hardware secure
  element over I2C for non-extractable keys, true device authentication
  (not just chip ID), and certified RNG. This would close the anti-spoofing
  gap documented in the README.
- [ ] **Encrypted serial protocol.** The current protocol is plaintext.
  Add a transport-layer encryption (e.g., X3DH + AES-CTR using the Pico's
  AES module) so challenges and responses are confidential on the wire.
- [ ] **Rate limiting / lockout.** Add a failed-attempt counter with
  exponential backoff or a cooldown period to slow brute-force attacks
  on the CHALLENGE endpoint.
- [ ] **Audit log on flash.** Store recent CHALLENGE/RESPONSE pairs in a
  ring buffer in flash for post-incident forensics. Needs wear-leveling
  awareness (RP2040 flash has ~100k erase cycles).

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
- [ ] **JSON mode.** Add a JSON output mode alongside the current text
  protocol for easier parsing in non-Python hosts.

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
