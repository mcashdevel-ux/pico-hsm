# Test Results

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
