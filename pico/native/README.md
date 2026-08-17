# AES-256 native MicroPython module for RP2040

This directory contains the C source for a native (compiled) MicroPython
module that provides AES-256 block operations for the pico-hsm firmware.

## Files

| File | Description |
|------|-------------|
| `aes.c` | AES-256 implementation + MicroPython user C module bindings |
| `micropython.mk` | Build rules (auto-discovered by MicroPython's build system) |
| `aes.mpy` | Pre-compiled binary (MPY v6, RP2040 ARM Thumb-2), ready to copy to the Pico |

## API

```python
import aes

rk = aes.expand_key(key)        # 32-byte key -> 240-byte expanded round keys
ct = aes.encrypt_block(rk, pt)  # 16-byte plaintext -> 16-byte ciphertext
pt = aes.decrypt_block(rk, ct)  # 16-byte ciphertext -> 16-byte plaintext
out = aes.ctr_xcrypt(rk, nonce, data)  # CTR mode stream cipher (XOR)
```

- `key`: 32 bytes (AES-256)
- `rk`: 240 bytes (15 round keys × 16 bytes, from `expand_key`)
- `pt` / `ct`: 16 bytes (one AES block)
- `nonce`: 16 bytes (initial counter block; last 4 bytes are the counter)
- `data`: arbitrary length (CTR mode)
- `ctr_xcrypt` with 2 args (`rk`, `nonce`) returns empty bytes; with 3 args
  it XORs `data` with the keystream. Encryption and decryption are identical.

## Building from source

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

## Verification

The AES core has been verified against the FIPS-197 AES-256 test vector
(Appendix C.3):

```
key    = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
plain  = 00112233445566778899aabbccddeeff
cipher = 8ea2b7ca516745bfeafc49904b496089  ✓
```

CTR mode round-trip (encrypt then decrypt = original) also verified.

## License

MIT (same as the pico-hsm project).
