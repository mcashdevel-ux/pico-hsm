# Native MicroPython modules for RP2040

This directory contains C source for native (compiled) MicroPython modules
that provide performance-critical operations for the pico-hsm firmware.

## Modules

### AES-256 (`aes.c`)

AES-256 block cipher with CTR mode, used for at-rest encryption on the Pico.

| File | Description |
|------|-------------|
| `aes.c` | AES-256 implementation + MicroPython user C module bindings |
| `micropython.mk` | Build rules (auto-discovered by MicroPython's build system) |
| `aes.mpy` | Pre-compiled binary (MPY v6, RP2040 ARM Thumb-2), ready to copy to the Pico |

```python
import aes

rk = aes.expand_key(key)        # 32-byte key -> 240-byte expanded round keys
ct = aes.encrypt_block(rk, pt)  # 16-byte plaintext -> 16-byte ciphertext
pt = aes.decrypt_block(rk, ct)  # 16-byte ciphertext -> 16-byte plaintext
out = aes.ctr_xcrypt(rk, nonce, data)  # CTR mode stream cipher (XOR)
```

- `key`: 32 bytes (AES-256)
- `rk`: 240 bytes (15 round keys x 16 bytes, from `expand_key`)
- `pt` / `ct`: 16 bytes (one AES block)
- `nonce`: 16 bytes (initial counter block; last 4 bytes are the counter)
- `data`: arbitrary length (CTR mode)
- `ctr_xcrypt` with 2 args (`rk`, `nonce`) returns empty bytes; with 3 args
  it XORs `data` with the keystream. Encryption and decryption are identical.

### TRNG native accelerator (`trng_native.c`)

Native C implementation of the TRNG hot path: ADC sampling, health gate,
von-Neumann debiasing, SHA-256, and HMAC-DRBG.  Provides ~100x speedup
over the Python pipeline (SEED drops from ~20s to <1s).

| File | Description |
|------|-------------|
| `trng_native.c` | C TRNG pipeline + MicroPython dynamic runtime bindings |
| `Makefile.trng` | Standalone build rules (uses `mpy_ld.py`, no firmware rebuild) |
| `trng_native.mpy` | Pre-compiled binary (MPY v6, armv6m/Cortex-M0+) |

```python
import trng_native

raw = trng_native.collect_raw(n, bit_mask)    # n ADC samples, extract bits
ent = trng_native.fresh_entropy(n, bit_mask)  # health-gated + VN-debiased
out = trng_native.seed(n, bit_mask)           # full pipeline (DRBG output)
h   = trng_native.sha256(data)               # 32-byte SHA-256 hash
```

- `n`: number of bytes (1-256 for `fresh_entropy`/`seed`; 1-8192 for `collect_raw`)
- `bit_mask`: 12-bit bitmask of ADC data bits to extract (e.g. `0x3F` = bits 0-5)
- All functions return `bytes`

**Integration with `trng.py`:** when `trng_native.mpy` is present on the
Pico's filesystem, `trng._fresh_entropy()` automatically uses the C path
(collect -> health -> VN debias) instead of the Python loop.  The `TRNG`
status command reports `NATIVE YES` when the module is loaded.  If the
module is absent or raises, the Python fallback runs transparently.

## Building from source

### AES-256 (compiled into firmware)

You need the MicroPython source tree for the RP2040 port:

```bash
git clone https://github.com/micropython/micropython.git
cd micropython/ports/rp2040
make USER_C_MODULES=/path/to/pico-hsm/pico/native
```

This produces a firmware `.uf2` with the `aes` module compiled in. The
module is then available as `import aes` on the Pico.

Alternatively, the pre-built `aes.mpy` can be copied directly to the
Pico's filesystem (no firmware rebuild needed):

```bash
mpremote connect /dev/ttyACM0 cp aes.mpy :
```

### TRNG native accelerator (standalone .mpy)

The TRNG module uses MicroPython's dynamic native module system
(`py/dynruntime.h`), which produces a standalone `.mpy` file without
rebuilding firmware. You need the MicroPython source tree and the
`arm-none-eabi-gcc` toolchain:

```bash
git clone https://github.com/micropython/micropython.git

cd /path/to/pico-hsm/pico/native
make -f Makefile.trng ARCH=armv6m MPY_DIR=/path/to/micropython
```

This produces `trng_native.mpy`. Copy it to the Pico:

```bash
mpremote connect /dev/ttyACM0 cp trng_native.mpy :
```

After the next boot (or soft-reset), `trng.py` will automatically detect
and use the native module.

**Build requirements:**
- `arm-none-eabi-gcc` (tested with 14.2.1)
- MicroPython source tree (tested with v1.28.0, commit e0e9fbb)
- Python 3 with `mpy_ld.py` (included in MicroPython's `tools/`)

**Design notes:** the module avoids libc (provides its own `memset`/`memcpy`)
and libm (health check uses integer-only math). It links only `libgcc.a`
for compiler intrinsics (`__aeabi_*`, `__builtin_popcount`). BSS variables
are non-static (a constraint of the dynamic .mpy format).

## Verification

The AES core has been verified against the FIPS-197 AES-256 test vector
(Appendix C.3):

```
key    = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
plain  = 00112233445566778899aabbccddeeff
cipher = 8ea2b7ca516745bfeafc49904b496089  ✓
```

CTR mode round-trip (encrypt then decrypt = original) also verified.

The TRNG native module's SHA-256 implementation has been verified against
Python's `hashlib.sha256` for correctness. The full SEED pipeline produces
output that passes the same NIST SP 800-22 statistical tests as the Python
pipeline.

## License

MIT (same as the pico-hsm project).
