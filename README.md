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

> A **hardware True Random Number Generator (TRNG)** and a **physical-presence
> HSM** on a Raspberry Pi Pico (RP2040), in under 200 lines of MicroPython.

The RP2040 is not used as a compute offload (a host PC is ~100× faster). It is
used for the two things a normal Linux host *cannot* do:

1. **Produce true silicon entropy.** The host's `os.urandom()` is a software
   PRNG seeded by entropy. The Pico harvests physical Johnson/thermal noise
   from a floating ADC pin, *measures* the actual min-entropy, and condenses it
   into 256-bit keys.
2. **Enforce physical presence.** The HSM's HMAC key exists only in volatile
   RAM on the board. To produce a valid HMAC you must physically hold the
   powered Pico. Unplug it and the key is gone.

## Table of contents

- [Demo](#demo)
- [Programmatic usage](#programmatic-usage)
- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Setup](#setup)
- [Reproduce](#reproduce)
- [Testing](#testing)
- [Verified results](#verified-results)
- [Applications](#applications)
- [Limitations & honest notes](#limitations--honest-notes)
- [Changelog](#changelog)
- [License](#license)

## Demo

Real output captured from a Pico running this code, driven by
`host/hsm_client.py` over `/dev/ttyACM0`:

```
=== PING ===
629849

=== WHO ===
ID openhands-pico-hsm FINGERPRINT 40852620331f5d8111de55799f3bed5738d4c1bda2adf3f0b2dde386042b56c4

=== CHALLENGE (host-side random) ===
challenge hex: 2337bc72f3886f431a6a40864a7a33da75ce46d80f52a630cfec3401fc29caf
response: c32a32c6f88bd9087e8c673622f9c2c9e70a1748ae5a3d5d4d28c49ae7cade3f
Got HMAC (32 bytes)
NOTE: host cannot verify without the key (good - key stays on Pico).

=== SEED 32 ===
raw entropy (32 bytes): cfb493d59c35cb01898a1ed279a6c05299e43b6d4a91bda1f363e436206128e1

=== consistency: same challenge again ===
deterministic (same challenge -> same HMAC)? True

=== VERSION ===
VERSION pico-hsm/1.1.0 micropython-3.4.0
```

The `WHO` fingerprint is `sha256(b'pico-hsm-v1:' + key)` — a stable identifier
for this session's key that reveals nothing about the key itself. The same
challenge yields the same HMAC within a session; power-cycle the board and you
get a brand-new fingerprint and unrelated HMACs.

## Programmatic usage

`host/hsm_client.py` exports the `PicoHSM` class for use as a library:

```python
from hsm_client import PicoHSM

with PicoHSM("/dev/ttyACM0") as hsm:
    print(hsm.who())                      # ID ... FINGERPRINT <hex>
    print(hsm.fingerprint())              # just the hex fingerprint
    print(hsm.ping())                     # tick count (int)
    mac = hsm.challenge(b"deadbeef")      # -> 32-byte HMAC-SHA256 (bytes)
    raw = hsm.seed(32)                    # -> 32 bytes of raw TRNG entropy
    print(hsm.version())                  # VERSION pico-hsm/1.1.0 ...
    print(hsm.help())                     # COMMANDS WHO PING ...
```

The port defaults to `$PICO_HSM_PORT` or `/dev/ttyACM0`. `challenge()` accepts
either `bytes` or a hex string; `seed(n)` returns raw bytes (1–256).

## How it works

### TRNG — `pico/trng.py`

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

### HSM — `pico/hsm.py`

- On boot, `trng.key256()` mints a **volatile HMAC key in RAM**. It is never
  written to flash and is destroyed on power-loss.
- `hsm.py` is a pure library: it defines `handle(line)` and the key, but does
  not run a REPL loop. `main.py` is the entry point that prints the boot banner
  and serves the serial protocol. This separation lets `hsm` be imported for
  testing without blocking.
- A line-based protocol is served over the USB CDC serial port:

  | Command           | Response                                          |
  |-------------------|---------------------------------------------------|
  | `WHO`             | `ID openhands-pico-hsm FINGERPRINT <sha256(key)>` |
  | `PING`            | `PONG <ticks_ms>`                                 |
  | `CHALLENGE <hex>` | `RESPONSE <hex HMAC-SHA256(key, challenge)>`      |
  | `SEED <n>`        | `SEED <hex>` — *n* raw TRNG bytes (1–256)         |
  | `HELP`            | `COMMANDS <space-separated command list>`         |
  | `VERSION`         | `VERSION pico-hsm/<ver> micropython-<ver>`        |

- HMAC-SHA256 is implemented from scratch (RFC 2104) because MicroPython has no
  `hmac` module. It was verified **bit-exact** against the host's stdlib
  `hmac`.
- `SEED <n>` exposes the TRNG directly: it calls `trng.raw_entropy(n)` to
  return *n* bytes of raw (uncondensed) silicon entropy, hex-encoded. This is
  the same entropy source used for key minting, but without SHA-256 condensing
  — useful for seeding host-side CSPRNGs or statistical testing.

### Host client — `host/hsm_client.py`

A `pyserial` client that opens the Pico's serial port, soft-resets the board
to ensure a clean boot, drains the boot banner, and provides a `PicoHSM` class
with typed methods for every protocol command. It can be used as a library
(see [Programmatic usage](#programmatic-usage)) or run directly as a demo CLI
(`python3 host/hsm_client.py [--port /dev/ttyACM0]`). The host never sees the
key — only its fingerprint — which is the whole point.

`host/trng_stats.py` pulls raw entropy via repeated `SEED` calls and runs three
lightweight statistical suites (monobit, runs, chi-square on byte distribution)
as a quick sanity check that the entropy source hasn't degraded.

## Repository layout

Files are split by **where they run**: `pico/` for the board, `host/` for the
controlling PC, `docs/` for reference material. When deployed to the Pico the
files are flattened to its root (see [Reproduce](#reproduce)).

```
pico-hsm/
├── pico/              # runs ON the Pico (RP2040, MicroPython)
│   ├── trng.py        # hardware entropy harvester + 256-bit key generator
│   ├── hsm.py         # volatile HMAC-key HSM library + handle() protocol
│   └── main.py        # boot entry: banner + serial REPL loop (imports hsm)
├── host/              # runs on the controlling PC (Python 3)
│   ├── hsm_client.py  # PicoHSM library + demo CLI
│   └── trng_stats.py  # TRNG statistical test suite (monobit/runs/chi-square)
├── tests/             # pytest integration tests (skip if no board)
│   ├── conftest.py    # session-scoped PicoHSM fixture + skip logic
│   └── test_hsm.py    # 16 tests across 7 command classes
├── docs/
│   └── TEST_RESULTS.md
├── pytest.ini
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
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
pip install -r requirements.txt   # pyserial + pytest
# or manually:
pip install mpremote pyserial pytest
```

`mpremote` is the official MicroPython remote-control tool (file transfer,
reset, REPL). `pyserial` is needed by `hsm_client.py`. `pytest` runs the
test suite.

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

Assuming the [Setup](#setup) steps are done. From the repo root:

### 1. Deploy the code to the Pico

```bash
mpremote connect /dev/ttyACM0 cp pico/trng.py :trng.py
mpremote connect /dev/ttyACM0 cp pico/hsm.py  :hsm.py
mpremote connect /dev/ttyACM0 cp pico/main.py :main.py
mpremote connect /dev/ttyACM0 reset
```

The files are flattened onto the Pico's root; `main.py` imports `hsm`, which
imports `trng`. Leave **GP26 unconnected** so it floats.

### 2. Run the host client

```bash
python3 host/hsm_client.py
```

Expected: a `WHO` fingerprint, a 32-byte HMAC response to a random challenge,
32 bytes of raw TRNG entropy via `SEED`, and confirmation that the same
challenge produces the same HMAC within a session.

### 3. Run the TRNG statistical test

```bash
python3 host/trng_stats.py --bytes 4096
```

Pulls 4096 bytes of raw entropy via `SEED` and runs monobit, runs, and
chi-square tests. Sample output:

```
[PASS] Monobit: ones=16555  zeros=16213  proportion=0.505219  threshold=0.011049
[PASS] Runs: transitions=16376  expected=16383.5  z_score=-0.0829
[PASS] Chi-square (bytes): chi2=238.62  df=255  critical_p01=310  ...
All tests PASSED — TRNG output looks random.
```

## Testing

The repo includes a pytest integration suite in `tests/`:

```bash
# from the repo root (board must be connected)
python3 -m pytest -v
```

The 16 tests cover all protocol commands — PING (returns int, increasing),
WHO (format, fingerprint stability), CHALLENGE (length, determinism, distinct
inputs, hex-string input), SEED (length, non-determinism, range errors),
VERSION, HELP, and error handling (unknown command, bad seed count).

Tests connect to a real Pico via `$PICO_HSM_PORT` (default `/dev/ttyACM0`).
If no board is detected, all tests are **skipped** automatically — the suite
can run in CI without hardware.

## Verified results

See [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) for the full measurement and
test record, including:

- HMAC bit-exact match vs. Python stdlib `hmac`.
- Three boots → three fingerprints (fresh volatile key per boot).
- Determinism within a session (same challenge → same HMAC).
- TRNG statistical tests (monobit, runs, chi-square) — all pass on 4096 bytes.
- 16/16 pytest integration tests pass against real hardware.

## Applications

The core properties — true silicon entropy + a volatile key that demands
physical presence — open up several use cases that a software-only solution
cannot offer:

- **Physical two-factor unseal for a *session*.** Store encrypted secrets
  in any backend (a database, a file, a cloud KMS). Within a powered session,
  a caller presents a challenge to the Pico and receives a valid HMAC; the
  HMAC output (or a key derived from it) is the unseal key. Without the powered
  board the vault is inaccessible even if the host is fully compromised. This
  is a **per-session** pattern: once the board is unplugged the session key is
  gone, so you re-establish a fresh session next time rather than recovering
  the old key. This is the canonical HSM use case scaled down to a $4 board —
  but see the warning above; it does **not** give you a reusable, recoverable
  unseal key.

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

- **This is not a persistent key vault.** The HMAC key is minted fresh on every
  boot and destroyed on power-loss; the fingerprint and key are different every
  boot (see the warning at the top of this README). Anything sealed with a
  previous boot's key cannot be decrypted or verified after a reboot. If you
  need a reusable token or a recoverable long-term key, use a persistent HSM
  or KMS — this device deliberately cannot provide that.
- This is a **weak** TRNG by silicon-RNG standards — a single floating ADC pin
  is no substitute for a dedicated noise diode or a hardened TRNG IP. The
  min-entropy is measured and a safety margin is applied, but the output has
  not been put through a full NIST SP800-22 / SP800-90B test suite. Use it for
  key derivation / tokenization, not as a certified cryptographic RNG.
- The serial protocol is plaintext and unauthenticated beyond the HMAC itself;
  pair it with a trusted transport if you need confidentiality.
- The board must be physically present and powered; that is the feature, not a
  bug.

## Changelog

### v1.1.0

- **SEED `<n>` command** — returns *n* bytes (1–256) of raw TRNG entropy,
  hex-encoded. Exposes `trng.raw_entropy(n)` over the serial protocol for
  seeding host-side CSPRNGs or statistical testing.
- **HELP command** — lists all available commands.
- **VERSION command** — returns the firmware version string and MicroPython
  version.
- **`hsm.py` refactored to a pure library.** The REPL loop moved to
  `main.py`; `hsm.py` now only defines `handle()` and the key. This makes
  `hsm` importable for testing without blocking on `sys.stdin.readline()`.
- **`host/hsm_client.py` refactored into an importable `PicoHSM` class** with
  typed methods (`ping`, `who`, `fingerprint`, `challenge`, `seed`, `version`,
  `help`) and a `--port` CLI argument. Supports context-manager usage and
  `$PICO_HSM_PORT` env var.
- **`host/trng_stats.py`** — new TRNG statistical test script (monobit, runs,
  chi-square).
- **`tests/`** — new pytest integration suite (16 tests, skip if no board).
- **`requirements.txt`** added.

### v1.0.0

Initial release: TRNG entropy harvester, volatile HMAC-key HSM, `WHO`/`PING`/
`CHALLENGE` protocol, demo host client.

## License

MIT
