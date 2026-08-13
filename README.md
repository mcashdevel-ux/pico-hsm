# pico-hsm

<!--
  MANDATORY-WARNING — DO NOT REMOVE OR MODIFY.
  This warning is required by the repo owner. Any edit to README.md MUST keep
  this ⚠️ blockquote block at the top of the file, verbatim, AND keep the
  matching "This is not a persistent key vault" bullet in the Limitations
  section. Never delete, weaken, or move it below the fold.
-->
> ⚠️ **WARNING — do not use this for reusable, long-lived secrets.** The HMAC
> key is **volatile**: it is minted fresh on every boot and destroyed on
> power-loss. Unplug the board and the key is gone forever — unrecoverable,
> because it was random and never stored. The `WHO` fingerprint and the HMAC
> key are **different every boot**. Anything you sealed with a previous boot's
> key (an encrypted vault, a long-term token, a stored credential) **cannot be
> decrypted or verified after a reboot.** This is by design. If you need a
> reusable token or a key you can recover later, **do not use this project** —
> use a persistent HSM or KMS instead. This device is an **ephemeral,
> physical-presence** oracle, not a persistent key vault.


A **hardware True Random Number Generator (TRNG)** and a **physical-presence
HSM** running on a Raspberry Pi Pico (RP2040) under MicroPython.

The RP2040 is not used as a compute offload (a host PC is ~100× faster). It is
used for the two things a normal Linux host *cannot* do:

1. **Produce true silicon entropy** — the host's `os.urandom()` is a software
   PRNG seeded by entropy. The Pico harvests physical Johnson/thermal noise
   from a floating ADC pin, measures the actual min-entropy, and condenses it
   into 256-bit keys.
2. **Enforce physical presence** — the HSM's HMAC key exists only in volatile
   RAM on the board. To produce a valid HMAC you must physically hold the
   powered Pico. Unplug it and the key is gone.

## How it works

### TRNG (`trng.py`)

- **Entropy source:** GP26 configured as a floating high-impedance ADC input
  (ADC channel 0). The unconnected pin picks up thermal/Johnson noise.
- **Characterized, not assumed:** the noisy bits (bits 4–9 of the 16-bit ADC
  reading) are isolated, and the min-entropy is *measured* per board via a
  most-common-value estimate. On the reference board this measured
  **H_min ≈ 3.73 bits/sample** (40/64 distinct 6-bit values).
- **Key generation:** collect `ceil(256 / H_min) × margin` noisy samples (4×
  safety margin → ~276 samples), then SHA-256 condense to a 256-bit key.
- **What was tried and rejected:** the RP2040 `ROSC.RANDOM` register reads
  `0x0` under this MicroPython config (no free-running ring oscillator); the
  internal temperature ADC (channel 4) low bits are stuck. Neither is used.

### HSM (`hsm.py`)

- On boot, `trng.key256()` mints a **volatile HMAC key in RAM**. It is never
  written to flash and is destroyed on power-loss.
- A line-based protocol is served over the USB CDC serial port:

  | Command            | Response                                          |
  |--------------------|---------------------------------------------------|
  | `WHO`              | `ID openhands-pico-hsm FINGERPRINT <sha256(key)>` |
  | `PING`             | `PONG <ticks_ms>`                                 |
  | `CHALLENGE <hex>`  | `RESPONSE <hex HMAC-SHA256(key, challenge)>`      |

- HMAC-SHA256 is implemented from scratch (RFC 2104) because MicroPython has no
  `hmac` module. It was verified **bit-exact** against the host's stdlib
  `hmac`.

### Host client (`hsm_client.py`)

A minimal `pyserial` client that opens the Pico's serial port, drains the boot
banner, and exercises `PING`, `WHO`, and `CHALLENGE`. The host never sees the
key — only its fingerprint — which is the whole point.

## Repository layout

```
trng.py          # hardware entropy harvester + 256-bit key generator (runs on Pico)
hsm.py           # volatile HMAC-key HSM + serial protocol (runs on Pico)
main.py          # boot entry: import hsm
hsm_client.py    # host-side demo client (pyserial)
```

## Reproduce

### On the Pico (MicroPython ≥ 1.20, RP2040)

```bash
mpremote connect /dev/ttyACM0 cp trng.py :trng.py
mpremote connect /dev/ttyACM0 cp hsm.py  :hsm.py
mpremote connect /dev/ttyACM0 cp main.py :main.py
mpremote connect /dev/ttyACM0 reset
```

Leave **GP26 unconnected** so it floats.

### On the host (Python 3 + pyserial)

```bash
pip install pyserial mpremote
python3 hsm_client.py
```

Expected: a `WHO` fingerprint, a 32-byte HMAC response to a random challenge,
and confirmation that the same challenge produces the same HMAC within a
session.

## Verified results

See [`TEST_RESULTS.md`](TEST_RESULTS.md) for the full measurement and test
record, including:

- HMAC bit-exact match vs. Python stdlib `hmac`.
- Three boots → three fingerprints (fresh volatile key per boot).
- Determinism within a session (same challenge → same HMAC).

## Limitations & honest notes

- This is a **weak** TRNG by silicon-RNG standards — a single floating ADC pin
  is no substitute for a dedicated noise diode or a hardened TRNG IP. The
  min-entropy is measured and a safety margin is applied, but the output has
  not been put through a full NIST SP800-22 / SP800-90B test suite. Use it for
  key derivation / tokenization, not as a certified cryptographic RNG.
- The serial protocol is plaintext and unauthenticated beyond the HMAC itself;
  pair it with a trusted transport if you need confidentiality.
- The board must be physically present and powered; that is the feature, not a
  bug.

## License

MIT
