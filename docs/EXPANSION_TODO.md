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

- [ ] **Benchmark native module.** Measure actual SEED speedup with the
  native C module (target: <1s for 32 bytes, vs ~20s in Python). Not yet
  benchmarked because the first version crashed the Pico (writing to clock
  registers). The fixed version (ADC CS/RESULT only) is built but untested.
- [ ] **Move HMAC-DRBG to native C.** The DRBG is currently in Python.
  Moving it to C (alongside the already-native collect/health/debias path)
  would eliminate the last Python bottleneck in the SEED pipeline.
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
- [ ] **CI pipeline.** Set up GitHub Actions to run the pytest suite
  (tests skip gracefully when no board is connected) and lint the C code
  with `cppcheck`.
- [ ] **Cross-platform host client.** The `hsm_client.py` assumes Linux
  (`/dev/ttyACM0`). Add auto-detection for macOS (`/dev/cu.usbmodem*`)
  and Windows (`COM*`).

## Documentation

- [ ] **Architecture diagram.** Add a visual showing the TRNG pipeline,
  the dual-core design (core 0 = serial REPL, core 1 = watchdog), and the
  native module integration point.
- [ ] **Threat model document.** Formalize the security claims and
  non-claims into a dedicated threat model document.
