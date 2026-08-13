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

## Setup

### Hardware

- **Raspberry Pi Pico** (RP2040) — the original Pico or Pico H. A Pico W also
  works; only the ADC is used.
- **USB data cable** (many cheap cables are charge-only — if `/dev/ttyACM0`
  never appears, suspect the cable first).
- **GP26 left unconnected.** This pin (ADC channel 0) is the entropy source;
  it must float. Do not wire it to anything, not even ground.

### Flash MicroPython firmware

The Pico ships with a blank flash. Install MicroPython once:

1. Download the official RP2040 UF2 from
   <https://micropython.org/download/RPI_PICO/> (use `RPI_PICO` for the
   original Pico, or `RPI_PICO_W` for the Pico W).
2. Hold **BOOTSEL** while plugging the board into USB. It mounts as a mass
   storage drive (`RPI-RP2`).
3. Copy the `.uf2` file onto that drive. The board reboots automatically and
   the drive disappears — MicroPython is now running.

### Host software

```bash
pip install mpremote pyserial
```

`mpremote` is the official MicroPython remote-control tool (file transfer,
reset, REPL). `pyserial` is needed by `hsm_client.py`.

### Verify the board

```bash
# should list Raspberry Pi (vendor 2e8a, product 0005)
lsusb | grep 2e8a

# the CDC serial device should appear
ls /dev/ttyACM*
```

Confirm the firmware responds:

```bash
mpremote connect /dev/ttyACM0 version
```

Expected output similar to:
```
MicroPython v1.23.0 on 2024-06-02; Raspberry Pi Pico with RP2040
```

On Linux, if the serial port is not writable, add your user to the `dialout`
group (`sudo usermod -aG dialout $USER`) and re-login, or just run the client
with `sudo`.

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

## Applications

The core properties — true silicon entropy + a volatile key that demands
physical presence — open up several use cases that a software-only solution
cannot offer:

- **Physical two-factor unseal for a secrets vault.** Store encrypted secrets
  in any backend (a database, a file, a cloud KMS). To decrypt, the caller must
  present a challenge to the Pico and receive a valid HMAC response; the HMAC
  output (or a key derived from it) is the unseal key. Without the powered
  board, the vault is inaccessible even if the host is fully compromised. This
  is the canonical HSM use case scaled down to a $4 board.

- **Tamper-evident audit logging / "dead man's switch".** A service commits a
  periodic `CHALLENGE`→`RESPONSE` pair to its audit log alongside the board's
  `WHO` fingerprint. If the board is unplugged, the fingerprint changes on the
  next boot and the log stream gains a verifiable discontinuity — a cheap
  hardware attestation that the box was physically present and powered
  throughout.

- **Boot-time key derivation / seed entropy for a headless host.** A Raspberry
  Pi or server with no hardware RNG can pull a fresh 256-bit seed from the Pico
  at boot (`trng.key256()`) to seed its own CSPRNG or derive per-boot secrets.
  The host gets true entropy it could not generate on its own.

- **One-time / ephemeral session keys.** Because the key is destroyed on
  power-loss and never persisted, the Pico can mint per-session HMAC keys for
  short-lived tokens, API request signing, or challenge-handshake
  authentication. Rotate the key by power-cycling the board — no key-management
  ceremony required.

- **"Proof you're holding it" interactive challenge.** A CI pipeline, a deploy
  script, or a destructive operation can gate on a live `CHALLENGE`/
  `RESPONSE` round-trip, forcing an operator to physically tap the Pico (e.g.
  hold a button or just keep it plugged in) before a high-risk action proceeds.
  This turns the board into a hardware confirmation prompt.

- **Teaching / prototyping HSM concepts.** The whole stack — entropy
  characterization, key minting, HMAC challenge/response, the physical-presence
  security model — is under 200 lines of readable MicroPython. It is a good
  starting point for learning how real HSMs and TEEs justify their threat
  models, and for prototyping protocol ideas before committing to dedicated
  hardware.

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
