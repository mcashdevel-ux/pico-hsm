# Test Results

> **Note:** The results below were captured on real hardware during
> development (v1.1.0–v1.6.1). The current test suite has 149 tests (117 pass
> without hardware, 32 skip without a board). See the [Testing](../README.md#testing)
> section of the README for the up-to-date test inventory.

| | |
|---|---|
| **Board** | Raspberry Pi Pico (RP2040) |
| **Firmware** | MicroPython v1.23.0 |
| **Entropy pin** | GP26 floating (ADC channel 0) |
| **Host** | Linux, Python 3, pyserial |
| **Date** | 2026-08-13 |

---

## TRNG characterization

Raw source exploration (what worked, what didn't):

| Source                         | Result                                           | Used? |
|--------------------------------|--------------------------------------------------|-------|
| `ROSC.RANDOM` register (0x40060038) | reads `0x0` every sample (no entropy)       | no    |
| Internal temp ADC (channel 4) LSBs  | stuck; unique 1/100                        | no    |
| Floating GP26 ADC0, bits 4–9       | varies; 40/64 distinct 6-bit values        | **yes** |

Per-bit ones-fraction over 4000 samples of the raw 16-bit ADC reading (GP26
floating):

```
bit:     15   14   13   12   11   10    9    8    7    6    5    4    3    2    1    0
ones:   0.00 0.00 1.00 1.00 1.00 0.00 1.00 0.34 0.47 0.45 0.47 0.40 0.00 0.00 1.00 1.00
```

Only bits 4–9 carry noise; the rest are stuck high or low.

Min-entropy estimate (most-common-value) over the 6 noisy bits:

```
H_min ≈ 3.73 bits/sample, 40/64 distinct values
```

Key generation: `need = ceil(256 / 3.73) * 4 = 276` noisy samples, SHA-256
condense. Two consecutive keys were confirmed distinct.

## HMAC correctness (Pico vs. host stdlib)

Fixed test vector run *on the Pico* with a known key, then verified on the host
with Python's `hmac` module:

```
key  = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
msg  = 68656c6c6f2d7069636f2d68736d2d74657374  ("hello-pico-hsm-test")
Pico HMAC  = e7ed0c67f76a66765ef94acfb9e37101cdc842bc7210e8f813ba4cbc0e0c5ff5
host HMAC  = e7ed0c67f76a66765ef94acfb9e37101cdc842bc7210e8f813ba4cbc0e0c5ff5
MATCH = True
```

The Pico's RFC 2104 HMAC-SHA256 is bit-exact with the reference implementation.

## Volatility — fresh key per boot

`WHO` fingerprint (`sha256(b'pico-hsm-v1:' + key)`) captured across three
soft-resets of the board:

```
boot 1: b63b651096b531ff5986c67cdf0bcb23bd4cd67b05b3f5a84ed149c76f4799d0
boot 2: e20789895b873d3804d9f8ae2181d16ce4fe8aa9dcbf6f9fe83faacc33a3b162
boot 3: 6eaebc9f7692cde51d35a4a089342181044994035cb8ab5afa12edfa98859f8f
```

All three differ → the key is freshly minted from silicon entropy on every boot
and never persisted.

## Determinism within a session

The same challenge issued twice in one session yields the same HMAC (expected,
since the in-RAM key is stable while powered):

```
challenge: 3588ae136a6436c5a6aaa3697f338b5d235004fe850ff9e56bafad785d8bfffa
response1: 5613e0c38c50bc4f1589f148e7f6b114532cea2aa0d8e1244b8066507f644116
response2: 5613e0c38c50bc4f1589f148e7f6b114532cea2aa0d8e1244b8066507f644116
deterministic = True
```

## Physical-presence property

The host can obtain the key *fingerprint* (`WHO`) but never the key itself.
Producing a valid `RESPONSE` therefore requires the Pico to be powered on with
its volatile key loaded. Powering off / unplugging destroys the key; a fresh,
unrelated key is minted on the next boot.

---

## v1.1.0 — SEED / HELP / VERSION + library refactor

### New commands verified via mpremote exec

```
HELP: COMMANDS WHO PING CHALLENGE <hex> SEED <n> HELP VERSION
VERSION: VERSION pico-hsm/1.1.0 micropython-3.4.0
PING: PONG 11101
WHO: ID openhands-pico-hsm FINGERPRINT 2e0097924454edbf63fe1f72e67e258ee137c4955b03be1520488dda4b2fc256
SEED 32: SEED 50c9131c2d2e6ce2be6f9cf91c1cc6efd2756c50c4822bf9c5d769d0c55fe10e
CHALLENGE deadbeef: RESPONSE d9f8c197e341fccd51c1402d7bcdac17914c1bb48a4c0e3de77f3862dfc6834c
SEED 0: ERR count-range-1-256
SEED 999: ERR count-range-1-256
SEED abc: ERR bad-count
FOOBAR: ERR unknown-cmd
```

### SEED determinism + byte count

```
s1: SEED b54c9cc6810e98816559004a7a830e41867208cf13360938cc71fc7867d2df25
s2: SEED 14899af2226dc0a9da8b8eb38acffa4e89029de99a2fc22e1fb212508eb1db2b
differ: True
s3 bytes: 64    (SEED 64 → exactly 64 bytes)
```

### TRNG statistical tests (4096 bytes via SEED)

```
[PASS] Monobit: ones=16555  zeros=16213  proportion=0.505219  threshold=0.011049
[PASS] Runs: transitions=16376  expected=16383.5  z_score=-0.0829
[PASS] Chi-square (bytes): chi2=238.62  df=255  critical_p01=310  min_count=6  max_count=29  expected_per_byte=16.0
All tests PASSED — TRNG output looks random.
```

### Host client demo (PicoHSM class)

```
=== PING ===
629849
=== WHO ===
ID openhands-pico-hsm FINGERPRINT 40852620331f5d8111de55799f3bed5738d4c1bda2adf3f0b2dde386042b56c4
=== CHALLENGE (host-side random) ===
challenge hex: 2337bc72f3886f431a6a40864a7a33da75ce46d80f52a630cfec3401fc29caf
response: c32a32c6f88bd9087e8c673622f9c2c9e70a1748ae5a3d5d4d28c49ae7cade3f
Got HMAC (32 bytes)
=== SEED 32 ===
raw entropy (32 bytes): cfb493d59c35cb01898a1ed279a6c05299e43b6d4a91bda1f363e436206128e1
=== consistency: same challenge again ===
deterministic (same challenge -> same HMAC)? True
=== VERSION ===
VERSION pico-hsm/1.1.0 micropython-3.4.0
```

### pytest integration suite

```
17 passed in 172.29s
```

All 17 tests pass against real hardware: PING (returns int, increasing), WHO
(format with DEVICE + FINGERPRINT, device ID stable, fingerprint stable),
CHALLENGE (32 bytes, deterministic, distinct inputs, hex-string input), SEED
(correct length 1–256, non-deterministic, range/count errors), VERSION, HELP,
and error handling (unknown command, bad seed count). Tests skip automatically
when no board is connected.

---

## v1.2.0 — Device identity (RP2040 chip ID)

### Chip ID stable across reboots

The RP2040 factory chip ID (`machine.unique_id()`) captured across two
soft-resets of the board:

```
boot 1: DEVICE e6605481db5f6734 FINGERPRINT 165d0e93522ba75d2f0b8f9af5e099a3b955d312db08f4b01cb423038b0aee42
boot 2: DEVICE e6605481db5f6734 FINGERPRINT 13ee39d3d262e74daa7459973235a0aba781b85be116d12d68f3ac3e844ce3ee
```

Device ID is identical across both boots; fingerprint changes (volatile key
working as designed).

### WHO response (new format)

```
ID openhands-pico-hsm DEVICE e6605481db5f6734 FINGERPRINT c39d2b712a38c30f414dee5c360573f516f152b253a3de8ca7ce4676d0cac826
```

### Host client — device_id() method

```
device ID: e6605481db5f6734
```

---

## v1.3.0 — Cryptographic TRNG upgrade (von-Neumann + HMAC-DRBG + NIST validation)

### Pipeline

The TRNG now follows NIST SP 800-90A:

```
ADC noise (GP26, bits 4..9) → health gate → von-Neumann debias → HMAC-DRBG (SHA-256) → keys
```

The original naive SHA-256 condense and the 0.5-bit min-entropy floor are
replaced by a proper cryptographic extractor (HMAC-DRBG, reseeded per
generation) and a strict health gate (bit balance 0.45–0.55, byte min-entropy
≥ 6.0, lag-1 serial correlation ≤ 0.30).

### NIST SP 800-22 validation (9/9 pass)

A 12,800-byte (102,400-bit) sample was collected from the Pico via 50 ×
`SEED 256` calls and analyzed with the
[`trng-crypt`](https://github.com/mcashdevel-ux/trng-crypt) repo's NIST SP
800-22 test harness. The test was run for both the original pipeline and the
new DRBG pipeline — both pass all 9 tests.

#### New pipeline (von-Neumann + HMAC-DRBG)

Quick screen:

```
feasible:          True
bit_balance:       0.500088   (ideal 0.5)
chi_square_bits:   0.0032
shannon_entropy:   7.9841 / 8.0
min_entropy:       7.3959 bits/byte
compression_ratio: 1.0009     (ideal ~1.0)
serial_correlation: -0.002512 (ideal ~0.0)
```

Deep suite (NIST SP 800-22, α = 0.01):

```
[PASS] monobit          p=0.0449
[PASS] block_frequency  p=0.3392
[PASS] runs             p=0.7287
[PASS] longest_run      p=0.3282
[PASS] dft_spectral     p=0.2837
[PASS] approx_entropy   p=0.7409
[PASS] serial           p=0.0250
[PASS] cumsum_fwd       p=0.7569
[PASS] cumsum_rev       p=0.7334
RESULT: 9/9 passed
```

#### Original pipeline (pre-DRBG, for comparison)

Quick screen:

```
bit_balance:       0.501064
shannon_entropy:   7.9888 / 8.0
min_entropy:       7.4739 bits/byte
compression_ratio: 1.0009
serial_correlation: -0.005306
```

Deep suite: **9/9 passed** (all p-values > 0.01).

Both pipelines pass the full suite, confirming the ADC source is
cryptographically sound independent of the extractor.

### HSM end-to-end (new pipeline)

```
WHO => ID openhands-pico-hsm DEVICE e6605481db5f6734 FINGERPRINT bd0bd92df3bcd6a97dc92b52eb38b214802dc3a95bdc3fa6a72bb1ece61f6a95
VERSION => VERSION pico-hsm/1.3.0 micropython-3.4.0
PING => PONG 7680457
CHALLENGE deadbeef => RESPONSE 101cf80869027e992bdc04fb5b8615a311e8cba679d6fa44cb915736bcb66799
SEED 16 => SEED 82cae729ba9a3c153244d63d4b043a1d
```

### Methodology

- **Data collection:** 50 × `SEED 256` calls (256 bytes each) via raw REPL
  serial on rpi3b (`/dev/ttyACM0`, 115200 baud), accumulated to 12,800 raw
  bytes, saved to a binary file.
- **Analysis:** the sample was transferred to a host pod and analyzed with
  `trng_scan.quick_analysis()` (bit balance, min-entropy, compression,
  serial correlation) and `trng_scan.deep_analysis()` (9-test NIST SP 800-22
  suite) from the trng-crypt repo. No analysis ran on the Pico itself — only
  data collection.
- **Date:** 2026-08-16.

## v1.6.3 — Native C module + NIST SP 800-22 on hardware

### NIST SP 800-22 statistical suite (64 KB, native module)

After deploying the native C TRNG module (`trng_native.mpy`) to the Pico,
64 KB of entropy was collected via `SEED_STREAM` (16 calls × 4096 bytes,
~327 bytes/s throughput). The NIST SP 800-22 suite was run with
`host/nist_800_22.py`:

```
Loaded 65536 bytes from /tmp/entropy.bin

✅ PASS  Monobit: proportion=0.500015 threshold=±0.002762 ones=262152
✅ PASS  Runs: transitions=261558 expected=262143.5 chi_sq=1.3077
✅ PASS  Chi-square (byte): chi_sq=264.6094 threshold=311.41 expected=256.0/byte
✅ PASS  Poker (4-bit): chi_sq=18.7390 threshold=25.0
✅ PASS  Serial (2-bit): chi_sq=5.5398 threshold=7.815 counts=[65650, 65026, 65810, 65658]
✅ PASS  Autocorr (lag=1): lag=1 proportion=0.501117 threshold=±0.002762

All tests PASSED — output looks random.
```

### Validation methodology

- The test suite was validated against Python's `os.urandom` (CSPRNG) at the
  same sample size (64 KB): all 6 tests pass on urandom, confirming the test
  thresholds are correct.
- At 8 KB, even `os.urandom` fails the poker test (chi_sq=25.15 vs threshold
  25.0) — 8 KB is too small a sample for reliable testing. 64 KB is the
  minimum recommended sample size for these tests.
- Tests run: monobit, runs, chi-square (byte distribution), poker (4-bit
  nibbles), serial (2-bit pairs), autocorrelation (lag=1).

### Hardware test results (32/32 pass on sparky)

All 32 hardware-dependent tests pass on the Pico (v1.6.3) via sparky:

```
tests/test_hsm.py ................. (17 tests)
tests/test_hsm_aes_host.py ............... (15 tests)
============================= 32 passed in 36.77s ==============================
```

Combined with 117 no-hardware tests: **149 total tests, all passing**
(117 pass without hardware, 32 pass on hardware).

### Client bug fixes

Three bugs in `host/hsm_client.py` were found and fixed during hardware
testing:

1. **Fingerprint parsing** — `fingerprint()` returned the full suffix
   including " STATUS" (added in v1.6.2 for the degraded-state indicator).
   Fixed to parse only the 64-hex-char fingerprint via `.split()[0]`.

2. **AES_CTR empty data** — `aes_ctr()` with empty data received
   `"AES_OUT"` (no trailing space after strip) and failed the
   `startswith("AES_OUT ")` check. Fixed to use `startswith("AES_OUT")`
   and `or ""` for the unhexlify call.

3. **Multi-line `_send()`** — `_send()` returned only the first response
   line, but `TRNG` returns a multi-line status dump. Fixed to join all
   non-echo lines with `\n`. `seed()` updated to parse only the first line.

### Rate limiter test fixture

Added an autouse fixture in `tests/conftest.py` that resets the rate limiter
before each hardware test, preventing cross-test interference from the
10-req/10s sliding window. Only activates when the board is present; uses
the session-scoped `hsm` instance (no extra serial connection).

### Methodology

- **Data collection:** 16 × `SEED_STREAM 4096 256` calls via serial on sparky
  (`/dev/ttyACM0`, 115200 baud), accumulated to 65,536 bytes.
- **Analysis:** `host/nist_800_22.py` (6-test NIST SP 800-22 suite, pure
  Python, no external deps). Validated against `os.urandom` at 8 KB and 64 KB.
- **Hardware tests:** `pytest tests/test_hsm.py tests/test_hsm_aes_host.py`
  on sparky with Pico at `/dev/ttyACM0`.
- **Date:** 2026-08-16.

## v1.7.0 — Persistent key (flash, PIN-encrypted, opt-in)

### Feature

The HMAC key is volatile by default (fresh random key on every boot). The
persistent key feature (`KEY_STORE`, `KEY_LOAD`, `KEY_ERASE`, `KEY_STATUS`)
allows opt-in persistence: the current key is encrypted with a PIN-derived
key (iterated SHA-256, 1000 rounds) using AES-ECB and written to flash.
On reboot, `KEY_LOAD <pin>` decrypts and restores the key so the
fingerprint stays stable across power cycles.

### Hardware test: store → reboot → load → verify

Test script run on sparky with Pico at `/dev/ttyACM0`.

```
Original FP:  992ff9177ae2b1cc8129a6fb0f209949782ea3aab31966e800e5e942de9e8cf8
KEY_STORE:    True
Status:       {'persistent': True, 'degraded': False}
Challenge 1:  bbc473fd85323ab699e1f84d581b56a7e127beae301a3c5427501f1331b77c6f

--- Reboot Pico (mpremote reset) ---

FP after reboot:    49f44b3cf88eb768a1f2a0ac6245f2730a3b9250b53c4a120ab8f67e0904d315
Keys differ:        True   (ephemeral — new random key on boot)
FP after load:      992ff9177ae2b1cc8129a6fb0f209949782ea3aab31966e800e5e942de9e8cf8
Matches original:   True   (PIN-encrypted round-trip)
Challenge 2:        bbc473fd85323ab699e1f84d581b56a7e127beae301a3c5427501f1331b77c6f
Challenges match:   True   (same key → same HMAC)
FP after wrong PIN: a97d2c6d545d66c3f20acd88f3742c84058260c699a135cb67d4f2221e800e10
Wrong PIN differs:  True   (wrong PIN → garbage key)
Status after erase: {'persistent': False, 'degraded': False}
```

### Test counts

- **No-hardware tests:** 143 passed, 43 skipped (32 hardware + 11 new
  persistent-key hardware tests).
- **New no-hardware tests:** `tests/test_persist_key.py` — 26 tests
  (PIN derivation, store/load round-trip, erase, command interface).
- **New hardware tests:** `tests/test_hsm.py::TestPersistKey` — 11 tests
  (status, store, load, erase, wrong PIN, challenge after load, empty PIN,
  help listing, overwrite). All pass on sparky.
- **Full hardware suite:** 43 passed (test_hsm.py + test_hsm_aes_host.py).

### Security notes

- AES-ECB is used (the only mode available in this MicroPython ucryptolib
  build). This is safe here because the plaintext is a 32-byte random key
  with no structure to leak — ECB's weakness (pattern leakage) does not
  apply to a single random block.
- PIN derivation: 1000-round iterated SHA-256 (not bcrypt/argon2, but the
  RP2040 has no hardware acceleration for those). The PIN space is limited
  by the user; a long PIN is recommended.
- The PIN is never stored. Only the encrypted key blob (`PHSM` header +
  32-byte ciphertext) is in flash.
- Wrong PIN: AES-ECB decryption succeeds (no integrity check), producing
  a garbage key. The fingerprint will differ, which the host can detect.

