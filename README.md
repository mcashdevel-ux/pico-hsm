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
> HSM** with **persistent device identity** on a Raspberry Pi Pico (RP2040),
> in MicroPython.

The RP2040 is not used as a compute offload (a host PC is ~100× faster). It is
used for the three things a normal Linux host *cannot* do:

1. **Produce true silicon entropy.** The host's `os.urandom()` is a software
   PRNG seeded by entropy. The Pico harvests physical Johnson/thermal noise
   from a floating ADC pin, *measures* the actual min-entropy, and condenses it
   into 256-bit keys.
2. **Enforce physical presence.** The HSM's HMAC key exists only in volatile
   RAM on the board. To produce a valid HMAC you must physically hold the
   powered Pico. Unplug it and the key is gone.
3. **Provide persistent device identity.** Every RP2040 has a factory-
   programmed 64-bit chip ID that survives reboots and reflashes. The `WHO`
   command exposes it, so the host can verify it is talking to **the same
   physical board** it was provisioned with — not an impostor running the same
   open-source firmware. (See [Device identity](#device-identity) for what this
   does and does not protect against.)

## Table of contents

- [Demo](#demo)
- [Programmatic usage](#programmatic-usage)
- [How it works](#how-it-works)
- [Device identity](#device-identity)
- [Repository layout](#repository-layout)
- [Setup](#setup)
- [Reproduce](#reproduce)
- [Testing](#testing)
- [Verified results](#verified-results)
- [Applications](#applications)
- [Limitations & honest notes](#limitations--honest-notes)
- [Architecture (diagrams)](docs/ARCHITECTURE.md)
- [Threat model (formal)](docs/THREAT_MODEL.md)
- [Roadmap & expansion TODO](#roadmap--expansion-todo)
- [Changelog](#changelog)
- [License](#license)

## Demo

Real output captured from a Pico running this code, driven by
`host/hsm_client.py` over `/dev/ttyACM0`:

```
=== PING ===
53506

=== WHO ===
ID openhands-pico-hsm DEVICE e6605481db5f6734 FINGERPRINT d088a715a19896a68950e4e6aad6f262b52b0f7c719a6d1c571e8b41e54f8e86
device ID: e6605481db5f6734

=== CHALLENGE (host-side random) ===
challenge hex: 3d52b838222beed96c415b67395a4ec03cd39c6fe512570aa2b65fca067d8146
response: c5847d01217ba79458aac50771eaf92295ad84b2de6ec8f828700fb2c5244f76
Got HMAC (32 bytes)
NOTE: host cannot verify without the key (good - key stays on Pico).

=== SEED 32 ===
raw entropy (32 bytes): 47de541fb37c91f30a6c594ade8451748c195b92ba61ac134074d47efcf4c16a

=== consistency: same challenge again ===
deterministic (same challenge -> same HMAC)? True

=== VERSION ===
VERSION pico-hsm/1.7.0 micropython-3.4.0
```

The `WHO` response now includes a **DEVICE** field — the factory-programmed
64-bit chip ID (`machine.unique_id()`), unique per RP2040 and persistent across
reboots and reflashes. The **FINGERPRINT** (`sha256(b'pico-hsm-v1:' + key)`) is
a stable identifier for this session's volatile key that reveals nothing about
the key itself — it changes every boot. The same challenge yields the same HMAC
within a session; power-cycle the board and you get a brand-new fingerprint and
unrelated HMACs, but the **same** device ID.

The host can register the device ID at provisioning time and check it on every
connection to detect board substitution (see [Device identity](#device-identity)).

## Programmatic usage

`host/hsm_client.py` exports the `PicoHSM` class for use as a library:

```python
from hsm_client import PicoHSM

with PicoHSM("/dev/ttyACM0") as hsm:
    print(hsm.device_id())               # chip ID — stable, persistent (e6605481db5f6734)
    print(hsm.who())                     # ID ... DEVICE <hex> FINGERPRINT <hex>
    print(hsm.fingerprint())             # just the hex fingerprint (changes per boot)
    print(hsm.ping())                    # tick count (int)
    mac = hsm.challenge(b"deadbeef")     # -> 32-byte HMAC-SHA256 (bytes)
    raw = hsm.seed(32)                   # -> 32 bytes of raw TRNG entropy
    print(hsm.version())                 # VERSION pico-hsm/1.7.0 ...
    print(hsm.help())                    # COMMANDS WHO PING ...
    # Persistent key (opt-in, v1.7.0):
    hsm.key_store("myPin")               # encrypt + save key to flash
    # ...reboot Pico...
    fp = hsm.key_load("myPin")           # decrypt + load; returns fingerprint
    hsm.key_erase()                      # delete from flash
    print(hsm.key_status())              # {'persistent': False, 'degraded': False}
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
- **Pipeline (NIST SP 800-90A-inspired):**
  `ADC noise → health gate → von-Neumann debias → HMAC-DRBG (SHA-256) → keys`
  - **Health gate** screens each raw capture *before* it seeds the DRBG: bit
    balance must be 0.45–0.55, byte-level min-entropy ≥ 6.0 bits, and lag-1
    serial correlation ≤ 0.30. A degraded capture is rejected — no key is
    minted from a bad source.
  - **Von-Neumann extractor** removes residual per-bit bias (01→0, 10→1,
    00/11 discarded) before the DRBG consumes the bits.
  - **HMAC-DRBG** (NIST SP 800-90A, SHA-256) is the cryptographic extractor.
    It is reseeded with fresh TRNG entropy on every generation, giving
    backtracking resistance — compromise of one key never reveals earlier or
    later keys. This replaces the original naive SHA-256 condense.
  - **Continuous health testing (NIST SP 800-90B §4.4):** the repetition-count
    and adaptive-proportion tests run on every entropy block (in the health
    gate) and in the core-1 watchdog's lightweight check. The repetition-count
    test detects stuck sources (excessive runs of identical samples); the
    adaptive-proportion test tracks a specific value through a 512-sample
    window and fails if it appears >12 times (NIST α=2⁻²⁰). Results are
    reported in `TRNG` status as `WATCHDOG_NIST rc_max=X/Y ap_max=X/Y
    healthy=YES`.
- **Validated:** the source passes the full **NIST SP 800-22** statistical
  suite (9/9 tests at α=0.01) on a 12,800-byte sample — see
  [Verified results](#verified-results). The original (pre-DRBG) pipeline also
  passed 9/9, confirming the ADC source is sound independent of the extractor.
- **What was tried and rejected:** the RP2040 `ROSC.RANDOM` register reads
  `0x0` under this MicroPython config (no free-running ring oscillator); the
  internal temperature ADC (channel 4) low bits are stuck. Neither is used.
- **Native C acceleration (v1.6.0):** the entire hot path (ADC sampling,
  health gate, VN debias, SHA-256, HMAC-DRBG) is also implemented as a
  native C module (`pico/native/trng_native.c`). When `trng_native.mpy` is
  present on the Pico's filesystem, `trng.py` automatically uses it for
  ~100x speedup (SEED drops from ~20s to under 1s). The Python pipeline
  remains as a transparent fallback. See
  [`pico/native/README.md`](pico/native/README.md) for build instructions.

### HSM — `pico/hsm.py`

- On boot, `trng.key256()` mints a **volatile HMAC key in RAM**. It is never
  written to flash by default and is destroyed on power-loss.
- At the same time, the RP2040's factory chip ID (`machine.unique_id()`) is
  read and stored as a **persistent device identifier**. Unlike the key, it
  survives reboots and reflashes — it is burned into silicon at manufacturing
  time. This gives the host a way to distinguish *this specific board* from
  any other board running the same firmware (see [Device identity](#device-identity)).
- **Opt-in persistent key (v1.7.0):** `KEY_STORE <pin>` encrypts the current
  HMAC key with a PIN-derived key (iterated SHA-256, AES-ECB) and writes it
  to flash (`pico_hsm_key.enc`). On reboot, `KEY_LOAD <pin>` decrypts and
  restores the key so the fingerprint stays stable across power cycles.
  This is strictly opt-in — the default remains a fresh volatile key per boot.
  See [Limitations](#limitations--honest-notes) for the security trade-offs.
- `hsm.py` is a pure library: it defines `handle(line)`, the key, and the
  device ID, but does not run a REPL loop. `main.py` is the entry point that
  prints the boot banner and serves the serial protocol. This separation lets
  `hsm` be imported for testing without blocking.
- A line-based protocol is served over the USB CDC serial port:

  | Command           | Response                                          |
  |-------------------|---------------------------------------------------|
  | `WHO`             | `ID openhands-pico-hsm DEVICE <chip_id> FINGERPRINT <sha256(key)>` |
  | `PING`            | `PONG <ticks_ms>`                                 |
  | `CHALLENGE <hex>` | `RESPONSE <hex HMAC-SHA256(key, challenge)>`      |
  | `SEED <n>`        | `SEED <hex>` — *n* raw TRNG bytes (1–256)         |
  | `SEED_STREAM <total> [<chunk>]` | `SEED_STREAM ...` — bulk entropy (1–8192B) |
  | `AES_ENC <hex32>` | `AES_ENC <hex32>` — encrypt one 16-byte block     |
  | `AES_DEC <hex32>` | `AES_DEC <hex32>` — decrypt one 16-byte block     |
  | `AES_CTR <hex_nonce32> <hex_data>` | `AES_CTR <hex_data>` — CTR mode   |
  | `AES_KEY`         | `AES_KEY_FP <fingerprint>` — AES key fingerprint  |
  | `TRNG`            | `TRNG <status>` — health, entropy, watchdog       |
  | `JSON [ON|OFF]`   | `OK json on|off` — toggle JSON output mode        |
  | `RATE_LIMIT [STATUS|RESET]` | `RATE_LIMIT OK|LOCKED ...` — rate limiter |
  | `AUDIT [N|CLEAR]` | `AUDIT entries=N/CAP ...` — challenge audit log     |
  | `ENC [ON <hex>|OFF|STATUS]` | `ENC ACTIVE|OFF ...` — transport encryption |
  | `ENC_MSG <ctr> <hex_ct>` | `ENC_MSG <ctr> <hex_ct>` — encrypted command  |
  | `KEY_STORE <pin>` | `OK key-stored` — persist HMAC key (encrypted)   |
  | `KEY_LOAD <pin>` | `OK key-loaded fingerprint=...` — load from flash |
  | `KEY_ERASE`       | `OK key-erased` — delete persistent key           |
  | `KEY_STATUS`      | `KEY_STATUS persistent=yes|no degraded=yes|no`    |
  | `HELP`            | `COMMANDS <space-separated command list>`         |
  | `VERSION`         | `VERSION pico-hsm/<ver> micropython-<ver>`        |

  In JSON mode (enabled with `JSON ON`), all responses are JSON objects:
  `{"ok": true, "cmd": "PING", "ts": 12345}`. Errors return
  `{"ok": false, "cmd": "...", "error": "..."}`. The text protocol remains
  the default; `JSON OFF` (or bare `JSON`) restores it.

  The `DEVICE` field in `WHO` is the RP2040's factory chip ID
  (`machine.unique_id()`), a 16-hex-char persistent identifier. The
  `FINGERPRINT` is `sha256(b'pico-hsm-v1:' + key)` — volatile, changes per boot.

- HMAC-SHA256 is implemented from scratch (RFC 2104) because MicroPython has no
  `hmac` module. It was verified **bit-exact** against the host's stdlib
  `hmac`.
- `SEED <n>` exposes the TRNG directly: it calls `trng.raw_entropy(n)` to
  return *n* bytes of TRNG output via the HMAC-DRBG (reseeded with fresh TRNG
  entropy on every call), hex-encoded. This is the same entropy source and
  extractor used for key minting — useful for seeding host-side CSPRNGs or
  statistical testing.
- `SEED_STREAM <total> [<chunk_size>]` is the bulk variant: up to 8192 bytes
  in one call, split into chunks (default 64 bytes, configurable 1–256). A
  single call counts as one rate-limiter request, enabling high-throughput
  entropy retrieval.
- **AES operations** (`AES_ENC`, `AES_DEC`, `AES_CTR`, `AES_KEY`) provide
  single-block and CTR-mode encryption using a volatile AES key (separate
  from the HMAC key), minted from the same TRNG. `AES_KEY` returns the key's
  fingerprint (not the key itself).
- **Rate limiting** (`RATE_LIMIT`) applies a sliding 10-second window to
  CHALLENGE, SEED, and SEED_STREAM; exceeding 10 requests triggers lockout
  with exponential backoff (2s base, doubling, capped at 60s).
- **Audit log** (`AUDIT`) records every CHALLENGE event in a 64-entry ring
  buffer with timestamp and challenge hash (not the raw challenge, to protect
  the volatile key). In-RAM only — lost on power-off, consistent with the
  volatile-key design.
- **Encrypted transport** (`ENC ON`, `ENC_MSG`, `ENC OFF`) wraps the protocol
  in AES-CTR with a session key derived from the challenge-response exchange.
  Replay-protected via monotonic counters. See
  [Threat model](docs/THREAT_MODEL.md) for the security properties.
- **Persistent key** (`KEY_STORE`, `KEY_LOAD`, `KEY_ERASE`, `KEY_STATUS`) is
  an opt-in feature that persists the otherwise-volatile HMAC key in flash,
  encrypted with a PIN-derived key (iterated SHA-256, 1000 rounds, AES-ECB).
  On reboot, `KEY_LOAD <pin>` decrypts and restores the key so the
  fingerprint stays stable across power cycles. The default remains ephemeral
  (volatile) keys; persistence must be explicitly enabled.

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

## Device identity

The `WHO` response includes the RP2040's factory-programmed 64-bit chip ID
(`machine.unique_id()`) in the `DEVICE` field. This ID is:

- **Unique per chip** — set at manufacturing, no two RP2040s share it.
- **Persistent** — survives reboots, power cycles, and reflashes. It's in the
  silicon, not flash.
- **Public, not secret** — anyone with USB access can read it. It's a serial
  number, like a car's VIN.

### Detecting board substitution

Register the chip ID at provisioning time, then check it on every connection:

```python
from hsm_client import PicoHSM

REGISTERED_DEVICE = "e6605481db5f6734"   # captured once from your board

with PicoHSM() as hsm:
    if hsm.device_id() != REGISTERED_DEVICE:
        raise SystemExit("WRONG BOARD — refusing to proceed")
    # only now trust the fingerprint + HMACs for this session
```

This catches the most likely attack: an attacker plugs in **their own** Pico
with the same open-source firmware. Their chip ID won't match, so the host
rejects the session before any HMAC is trusted.

### What it does NOT prevent

The chip ID is readable, not secret. An attacker who has had physical access to
your specific Pico can learn its ID, then flash custom firmware onto their own
Pico that hardcodes your ID. The substitution would then be undetectable. This
is the fundamental limitation of using a public identifier for authentication.
For cryptographic protection against device substitution, a secure element (e.g.
ATECC608A) with a non-extractable key is required — the RP2040 alone cannot
provide this.

| Threat | Chip ID check | Secure element |
|-------|---------------|----------------|
| Random/stock-firmware Pico swap | **blocked** | blocked |
| Attacker read your ID, spoofed it in custom firmware | not blocked | **blocked** |
| Key extraction from board | n/a (volatile by default; opt-in flash key is PIN-encrypted) | **blocked** (non-extractable) |

## Repository layout

Files are split by **where they run**: `pico/` for the board, `host/` for the
controlling PC, `docs/` for reference material. When deployed to the Pico the
files are flattened to its root (see [Reproduce](#reproduce)).

```
pico-hsm/
├── pico/              # runs ON the Pico (RP2040, MicroPython)
│   ├── trng.py        # hardware entropy harvester + 256-bit key generator
│   ├── hsm.py         # volatile HMAC-key HSM library + handle() protocol
│   ├── main.py        # boot entry: banner + serial REPL loop (imports hsm)
│   └── native/        # C source for native MicroPython modules
│       ├── aes.c      # AES-256 block cipher (compiled into firmware)
│       ├── trng_native.c  # TRNG pipeline in C (standalone .mpy)
│       └── README.md  # build instructions for native modules
├── host/              # runs on the controlling PC (Python 3)
│   ├── hsm_client.py  # PicoHSM library + demo CLI
│   └── trng_stats.py  # TRNG statistical test suite (monobit/runs/chi-square)
├── tests/             # pytest integration tests (skip if no board)
│   ├── conftest.py    # session-scoped PicoHSM fixture + skip logic
│   ├── test_hsm.py    # 28 tests: 7 base classes + 11 persistent-key (hw)
│   ├── test_hsm_aes_host.py  # 15 tests: AES + TRNG commands (serial)
│   ├── test_persist_key.py   # 26 persistent-key tests (no hardware needed)
│   ├── test_nist_health.py   # 13 NIST 90B tests (no hardware needed)
│   ├── test_json_mode.py    # 17 JSON mode tests (no hardware needed)
│   ├── test_rate_limit.py   # 16 rate limiter tests (no hardware needed)
│   ├── test_audit_log.py   # 21 audit log tests (no hardware needed)
│   ├── test_enc_protocol.py # 26 encrypted transport tests (no hardware)
│   ├── test_seed_stream.py  # 24 bulk SEED streaming tests (no hardware)
│   └── test_hsm_aes.py       # mpremote script (runs on Pico, not pytest)
├── docs/
│   ├── ARCHITECTURE.md     # system architecture (diagrams, pipeline, memory)
│   ├── THREAT_MODEL.md     # formal threat model (adversaries, security claims)
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
# Optional: native C TRNG accelerator (~100x faster SEED)
mpremote connect /dev/ttyACM0 cp pico/native/trng_native.mpy :trng_native.mpy
mpremote connect /dev/ttyACM0 reset
```

The files are flattened onto the Pico's root; `main.py` imports `hsm`, which
imports `trng`. `trng.py` auto-detects `trng_native.mpy` at import time and
uses it when present. Leave **GP26 unconnected** so it floats.

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

The 186 tests cover all protocol commands — PING (returns int, increasing),
WHO (format with DEVICE + FINGERPRINT, device ID stability, fingerprint
stability), CHALLENGE (length, determinism, distinct inputs, hex-string
input), SEED (length, non-determinism, range errors), SEED_STREAM (bulk
entropy, chunk sizes, rate limiting, JSON mode), VERSION, HELP, and error
handling (unknown command, bad seed count), plus AES (key fingerprint
stability, encrypt/decrypt round-trip, CTR mode round-trip, error cases)
and TRNG status/reprofile/watchdog commands, NIST SP 800-90B continuous
health tests (repetition-count, adaptive-proportion), JSON output mode,
rate limiting / lockout, audit log, encrypted transport (AES-CTR
session establishment, encrypt/decrypt round-trips, replay protection),
and persistent key management (store/load/erase/status, PIN derivation,
wrong-PIN detection, challenge after load, overwrite).

Tests connect to a real Pico via `$PICO_HSM_PORT` (auto-detected on Linux,
macOS, and Windows). If no board is detected, all tests are **skipped**
automatically — the suite can run in CI without hardware.

## Verified results

See [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) for the full measurement and
test record, including:

- HMAC bit-exact match vs. Python stdlib `hmac`.
- Three boots → three fingerprints (fresh volatile key per boot).
- Determinism within a session (same challenge → same HMAC).
- TRNG statistical tests (monobit, runs, chi-square) — all pass on 4096 bytes.
- **NIST SP 800-22** deep suite (9 tests) — **9/9 pass** at α=0.01 on a
  12,800-byte sample, for both the original and the new DRBG pipeline.
- 43/43 hardware integration tests pass against real hardware (v1.7.0):
  28 core (`test_hsm.py` — 17 base + 11 persistent-key) + 15 AES/TRNG
  (`test_hsm_aes_host.py`); 186 total tests (143 no-hardware + 43 hardware);
  143 run without hardware, 43 skip without a board.
- Chip ID stable across reboots (e6605481db5f6734); fingerprint changes per boot.

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

- **Device-authenticated sessions.** The persistent chip ID lets the host bind
  a session to a *specific physical board*, not just "any powered Pico." At
  provisioning time the host records the chip ID; on every subsequent
  connection it verifies the `WHO` response matches before trusting the
  session's HMACs. This catches board substitution — an attacker who plugs in
  their own Pico with identical open-source firmware is rejected, because their
  chip ID differs. It does **not** stop a determined attacker who has read your
  chip ID and custom-flashed a spoofing board (the ID is a public serial
  number, not a secret), but it raises the bar from "trivial" to "requires
  targeted preparation with prior physical access" (see
  [Device identity](#device-identity)).

- **Teaching / prototyping HSM concepts.** The whole stack — entropy
  characterization, key minting, HMAC challenge/response, the physical-presence
  security model — is a compact, readable MicroPython codebase (the HSM core
  is `hsm.py`, the TRNG pipeline is `trng.py`). It is a good
  starting point for learning how real HSMs and TEEs justify their threat
  models, and for prototyping protocol ideas before committing to dedicated
  hardware.

## Limitations & honest notes

- **This is not a persistent key vault (by default).** The HMAC key is minted
  fresh on every boot and destroyed on power-loss; the fingerprint and key are
  different every boot (see the warning at the top of this README). Anything
  sealed with a previous boot's key cannot be decrypted or verified after a
  reboot. If you need a reusable token or a recoverable long-term key, use a
  persistent HSM or KMS — this device deliberately defaults to volatile keys.
  An **opt-in** persistent key mode is available (`KEY_STORE <pin>`,
  `KEY_LOAD <pin>`, `KEY_ERASE`, `KEY_STATUS`) that encrypts the key with a
  PIN-derived key and stores it in flash, but this is a convenience feature,
  not a hardened key vault: AES-ECB is used (the only mode in this MicroPython
  build), PIN derivation is iterated SHA-256 (not bcrypt/argon2), and a wrong
  PIN produces a garbage key with no integrity check. For production-grade
  persistent keys, use a real HSM.
- This is a **weak** TRNG by silicon-RNG standards — a single floating ADC pin
  is no substitute for a dedicated noise diode or a hardened TRNG IP. The
  min-entropy is measured and a safety margin is applied. The source passes the
  full **NIST SP 800-22** suite (9/9 tests, see [Verified results](#verified-results)).
  NIST SP 800-90B continuous health tests (repetition-count and
  adaptive-proportion, §4.4) run on every entropy block and in the watchdog,
  but the source has not been through formal **NIST SP 800-90B entropy-source
  validation**. Use it for key derivation / tokenization; for a certified
  cryptographic RNG use a validated hardware entropy source.
- The serial protocol is plaintext by default; use `ENC ON <nonce_hex>` to
  enable optional AES-CTR transport encryption (confidential against
  late-joining eavesdroppers, replay-protected, but not authenticated and
  not confidential against a from-start eavesdropper who saw the plaintext
  handshake — see [Encrypted transport](docs/THREAT_MODEL.md#encrypted-transport-aes-ctr)
  in the threat model).
- **The chip ID is a serial number, not a secret.** Anyone with USB access can
  read `machine.unique_id()`. The device-identity check catches a casual board
  swap (attacker's own Pico, stock firmware) but not a targeted spoof (attacker
  read your chip ID, custom-flashed their board to report it). For
  cryptographic anti-substitution, a secure element with a non-extractable key
  (e.g. ATECC608A) is required. See [Device identity](#device-identity).
- The board must be physically present and powered; that is the feature, not a
  bug.

For a formal breakdown of adversaries, security properties, and non-claims,
see the [Threat model](docs/THREAT_MODEL.md) and
[Architecture](docs/ARCHITECTURE.md) documents.

## Roadmap & expansion TODO

Future improvements, grouped by area. See [`docs/EXPANSION_TODO.md`](docs/EXPANSION_TODO.md)
for the full list with details.

**Completed (v1.7.0):**
- ~~SHA-256 / HMAC-DRBG in native C~~ ✅ (v1.6.2)
- ~~NIST SP 800-90B continuous health tests~~ ✅ (v1.6.3)
- ~~JSON output mode~~ ✅ (v1.6.3)
- ~~Rate limiting / lockout~~ ✅ (v1.6.3)
- ~~Audit log (CHALLENGE forensics)~~ ✅ (v1.6.3)
- ~~Encrypted serial protocol (AES-CTR)~~ ✅ (v1.6.3)
- ~~Bulk SEED mode~~ ✅ (v1.6.3)
- ~~Architecture diagram + threat model~~ ✅ (v1.6.3)
- ~~NIST SP 800-22 hardware validation~~ ✅ (v1.6.3)
- ~~Persistent key option (encrypted in flash, opt-in)~~ ✅ (v1.7.0)

**Remaining (require hardware or significant effort):**
- **TRNG / entropy:** DMA ADC sampling, multiple entropy sources (ring
  oscillator), NIST SP 800-90B formal validation, continuous health monitoring
  in C
- **HSM / security:** Secure element integration (ATECC608A over I²C)
- **Platform:** Core 1 dedicated to TRNG, custom MicroPython firmware
  (ROSC.RANDOM, DMA, compiled-in native modules)
- **Interface:** USB HID interface, WebUSB support
- **Testing:** Test the native module on hardware

## Changelog

### v1.7.0

- **Persistent key option (opt-in).** Added an opt-in feature to persist the
  otherwise-volatile HMAC key in flash, encrypted with a PIN-derived key.
  This breaks the "ephemeral by design" default, so it is strictly opt-in —
  the default remains a fresh random key on every boot.
  - **PIN derivation:** 1000-round iterated SHA-256 (lightweight PBKDF).
    Not bcrypt/argon2 (the RP2040 has no hardware acceleration for those),
    but adequate for a hobbyist device with a long PIN.
  - **Encryption:** AES-ECB (the only mode available in this MicroPython
    `ucryptolib` build). Safe here because the plaintext is a 32-byte random
    key with no pattern to leak — ECB's weakness (pattern leakage) does not
    apply to a single random block.
  - **Commands:** `KEY_STORE <pin>` encrypts and saves the current key;
    `KEY_LOAD <pin>` decrypts and loads it (returns the new fingerprint);
    `KEY_ERASE` deletes the flash blob; `KEY_STATUS` reports whether a
    persistent key exists.
  - **Wrong PIN:** AES-ECB decryption succeeds (no integrity check), producing
    a garbage key. The host can detect this by comparing fingerprints.
  - **Hardware verified:** store → reboot → load with correct PIN restores
    the original fingerprint; wrong PIN gives a different key;
    challenge-response matches after load; erase clears the flash blob.
  - **Tests:** 26 no-hardware tests (`test_persist_key.py`) + 11 hardware
    tests (`test_hsm.py::TestPersistKey`). Full suite: 186 tests
    (143 no-hardware + 43 hardware).
- **Client methods.** Added `key_store(pin)`, `key_load(pin)`, `key_erase()`,
  `key_status()` to `hsm_client.py`.
- **Version bump:** 1.6.3 → 1.7.0.

### v1.6.3

- **Architecture & threat model docs.** Added `docs/ARCHITECTURE.md`
  (ASCII + Mermaid diagrams of the TRNG pipeline, dual-core design,
  protocol stack, memory map) and `docs/THREAT_MODEL.md` (six adversary
  tiers, security properties per feature, explicit non-claims, threat
  matrix).
- **Bulk SEED mode.** Added `SEED_STREAM <total> [<chunk_size>]` for
  high-throughput entropy retrieval. Returns up to 8192 bytes of raw TRNG
  output in chunks (default 64 bytes, configurable 1–256). Each chunk is
  hex-encoded on its own line. A single call counts as one rate-limiter
  request. 24 host-side pytest tests in `test_seed_stream.py`.
- **Encrypted serial protocol.** AES-CTR transport encryption layer.
  After a challenge-response exchange, both sides derive a session key
  (`SHA-256(b"enc-session:" + nonce + hmac(key, nonce))`). `ENC ON
  <nonce_hex>` activates the session; subsequent commands use
  `ENC_MSG <counter> <ciphertext_hex>` → `ENC_MSG <counter>
  <ciphertext_hex>` with AES-CTR. Replay protection via monotonically-
  increasing counters. `ENC OFF` exits; `ENC STATUS` shows state.
  Confidentiality against late-joining eavesdroppers; replay-protected.
  26 host-side pytest tests in `test_enc_protocol.py`.
- **Audit log.** In-RAM ring buffer (64-entry capacity) records every
  CHALLENGE event (ok / rate-limited / bad-hex) with timestamp + SHA-256
  challenge hash (not the raw challenge/response — protects the volatile
  key). `AUDIT [N]` shows the last N entries (newest first);
  `AUDIT CLEAR` wipes the log. In-RAM only (lost on power-off), consistent
  with the volatile-key design; flash persistence deferred. 21 host-side
  pytest tests in `test_audit_log.py`.
- **Rate limiting / lockout.** Added a sliding-window rate limiter on
  CHALLENGE and SEED endpoints. Tracks request timestamps in a 10-second
  window; if more than 10 requests arrive, enters a lockout with exponential
  backoff (2s base, doubling, capped at 60s). `RATE_LIMIT STATUS` shows
  current state; `RATE_LIMIT RESET` clears it. Non-tracked commands (WHO,
  PING, etc.) are unaffected. 16 host-side pytest tests in `test_rate_limit.py`.
- **JSON output mode.** Added `JSON ON` / `JSON OFF` commands that toggle
  JSON output mode. When enabled, all responses are JSON objects
  (`{"ok": true, "cmd": "PING", "ts": 12345}`) instead of text lines, for
  easy parsing in non-Python hosts. The text protocol remains the default.
  17 host-side pytest tests in `test_json_mode.py`.
- **NIST SP 800-90B continuous health tests.** Added the repetition-count and
  adaptive-proportion tests (§4.4) to both the full health gate and the
  watchdog's lightweight check. The repetition-count test detects stuck
  sources (excessive runs of identical samples); the adaptive-proportion test
  tracks a specific value through a 512-sample window and fails if it appears
  >12 times (NIST α=2^-20). Results reported in `TRNG` status as
  `WATCHDOG_NIST rc_max=X/Y ap_max=X/Y healthy=YES`.
- **Host-side NIST tests.** 13 pytest tests in `test_nist_health.py` —
  uniform random passes, stuck source fails, biased source fails, threshold
  scaling. No hardware needed (stubs MicroPython modules).

### v1.6.2

- **Native C DRBG fast path.** `raw_entropy()` now calls
  `trng_native.seed()` directly when the native module is available, running
  the full pipeline (ADC → health → VN debias → HMAC-DRBG) in C. Eliminates
  the ~26 ms Python HMAC overhead per `raw_entropy(256)` call (35% of total).
  Falls back to Python DRBG if the native module is unavailable.
- **Non-blocking serial client.** Fixed `hsm_client._send()` — was blocking
  5 s per command due to `serial.Serial(timeout=5)`. Now uses `timeout=1` +
  `in_waiting` non-blocking polling. Full demo completes in <30 s (was timing
  out).
- **AES pytest suite.** Added 15 tests for AES_ENC/AES_DEC/AES_CTR/AES_KEY
  and TRNG commands via the serial protocol (`test_hsm_aes_host.py`).
- **Cross-platform port detection.** `hsm_client._detect_port()` auto-detects
  the serial port on Linux, macOS, and Windows.
- **GitHub Actions CI.** Pytest (skips without hardware) + cppcheck lint.
- **Stale version check fix.** `test_hsm_aes.py` hardcoded v1.5.0; updated to
  v1.6.x.

### v1.6.1

- **LED status indicator.** The onboard LED (GP25) now shows HSM health at a
  glance: **solid ON** = healthy and ready, **fast blink** = degraded (TRNG
  unhealthy, using fallback key). Uses a hardware timer interrupt (no extra
  thread — RP2040 MicroPython only supports one core-1 thread, already used
  by the entropy watchdog).
- **ADC register offset fix (native module).** The native C module was
  reading the ADC FCS register (offset 0x08) instead of ADC RESULT (offset
  0x04), causing all ADC reads to return zero. Fixed — `collect_raw` and
  `fresh_entropy` now produce real entropy.
- **ADC channel selection fix (native module).** `adc_read_raw()` now writes
  `EN | AINSEL=0 | START_ONCE` directly on every read, ensuring channel 0
  (GP26) is always selected. Previously, MicroPython's temperature sensor
  reads could leave AINSEL pointing at channel 4.
- **Host client robustness.** `hsm_client.py` now sends Ctrl-C before Ctrl-D
  to properly exit raw REPL mode (left by `mpremote exec` sessions) before
  soft-resetting. Banner draining also handles the multi-line boot banner
  (ID + AES ready lines) correctly.
- **Verified on hardware.** SEED 32 bytes: 0.000s (native) vs ~20s (Python
  fallback). CHALLENGE deterministic. NIST entropy tests pass on 512 bytes.

### v1.6.0

- **Native C TRNG accelerator (major).** The entire TRNG hot path (ADC
  sampling, health gate, von-Neumann debiasing, SHA-256, HMAC-DRBG) is
  implemented as a native MicroPython dynamic module (`trng_native.c`)
  that produces a standalone `.mpy` file. When present on the Pico's
  filesystem, `trng.py` automatically uses the C path instead of the
  Python per-sample loop, giving an estimated ~100x speedup for SEED
  (from ~20s to under 1s for 32 bytes).
  - **No firmware rebuild required.** The module uses MicroPython's
    `py/dynruntime.h` dynamic native module system, producing a `.mpy`
    that can be copied to the Pico like any Python file.
  - **Integer-only health check.** The C health gate uses integer
    arithmetic (integer sqrt, fixed-point comparisons) instead of float
    math, avoiding the `libm` dependency entirely.
  - **Safe ADC access.** The C code reads only the ADC CS/RESULT registers
    directly (MicroPython's `machine.ADC` already enables the ADC at boot).
    It does NOT touch clock or reset registers, which would crash the chip.
  - **Transparent fallback.** If the `.mpy` is absent or the C path raises,
    `trng.py` falls through to the existing Python pipeline. The `TRNG`
    status command reports `NATIVE YES` or `NATIVE NO`.
  - The Python pipeline is unchanged and remains the reference
    implementation. See [`pico/native/README.md`](pico/native/README.md)
    for build instructions.

### v1.5.0

- **Cryptographic TRNG upgrade (major).** The TRNG pipeline now follows
  NIST SP 800-90A:
  `ADC noise → health gate → von-Neumann debias → HMAC-DRBG (SHA-256) → keys`.
  - **HMAC-DRBG** (NIST SP 800-90A, SHA-256) replaces the original naive
    SHA-256 condense as the cryptographic extractor. It is reseeded with fresh
    TRNG entropy on every generation, giving backtracking resistance —
    compromise of one key never reveals earlier or later keys. `raw_entropy()`
    also routes through the DRBG, so `SEED` now returns DRBG output (reseeded
    per call) rather than raw condensed bytes.
  - **Von-Neumann extractor** removes residual per-bit bias (01→0, 10→1,
    00/11 discarded) before the DRBG consumes the bits.
  - **Strict health gate** replaces the old 0.5-bit min-entropy floor. Each
    raw capture is screened before seeding: bit balance must be 0.45–0.55,
    byte-level min-entropy ≥ 6.0 bits, lag-1 serial correlation ≤ 0.30. A
    degraded capture is rejected — no key is minted from a bad source.
  - HMAC-SHA256 is implemented from scratch (the MicroPython build has no
    `hmac` module), reusing the same RFC 2104 pattern already in `hsm.py`.
- **NIST SP 800-22 validation.** The entropy source was validated against the
  full NIST SP 800-22 statistical suite (9 tests): **9/9 pass** at α=0.01 on
  a 12,800-byte sample. Validated for both the original pipeline and the new
  DRBG pipeline, confirming the ADC source is sound independent of the
  extractor. See [Verified results](#verified-results).
- **Public API unchanged.** `key256()`, `raw_entropy()`, and `measure()`
  keep the same signatures, so `hsm.py` needs no changes.
- **Code size:** `trng.py` grew from ~30 lines to 226 (the DRBG + debiaser +
  health gate). Total firmware is now under 300 lines.
- **Reproducibility:** the new pipeline was incorporated from the
  [`trng-crypt`](https://github.com/mcashdevel-ux/trng-crypt) repo, which
  provided the von-Neumann debiaser, HMAC-DRBG, and the NIST SP 800-22 test
  harness.

### v1.2.0

- **Persistent device identity (major).** The project's security model expands
  from two pillars (true entropy + physical presence) to three: the `WHO`
  response now includes a `DEVICE <chip_id>` field with the RP2040's
  factory-programmed 64-bit chip ID (`machine.unique_id()`), persistent across
  reboots and reflashes. This is a fundamental shift — the board now has a
  *stable identity* that the host can verify, not just a volatile key. It
  enables [device-authenticated sessions](#device-identity): register the chip
  ID at provisioning time, check it on every connection, and reject a
  substituted board before trusting any HMAC.
- **Honest limitation.** The chip ID is a public serial number, not a secret.
  It catches a casual board swap but not a targeted spoof. Full cryptographic
  anti-substitution would require a secure element (ATECC608A). The README's
  new [Device identity](#device-identity) section and [Limitations](#limitations--honest-notes)
  document this trade-off explicitly.
- **`PicoHSM.device_id()`** — new host client method returning the 16-hex-char
  chip ID.
- Test suite: new `test_device_id_stable` test (17 total, all pass).

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
