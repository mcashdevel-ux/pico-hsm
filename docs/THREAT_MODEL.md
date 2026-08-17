# Threat Model

This document formalizes the security claims and non-claims of pico-hsm.
It is intended to help users understand what the system protects against,
what it does not, and why.

## Scope

Pico-hsm is a Raspberry Pi Pico (RP2040) running MicroPython firmware that
provides:

1. A volatile HMAC-SHA256 key for challenge-response authentication
2. An opt-in persistent key mode (v1.7.0) that encrypts the key with a
   PIN and stores it in flash
3. A TRNG (true random number generator) for entropy seeding
4. A serial protocol over USB CDC for host communication
5. Optional AES-CTR transport encryption
6. Rate limiting, audit logging, and device identity

This is a **hobbyist / educational HSM**, not a certified cryptographic
module. It is not FIPS 140-2/3 validated, not Common Criteria evaluated,
and not intended for production secrets or regulated environments.

## Assets

| Asset | Location | Lifetime | Exposure |
|-------|----------|----------|----------|
| **HMAC key** (`_KEY`) | RP2040 RAM | Volatile (destroyed on power-loss) | Never transmitted; only `sha256(key)` fingerprint is sent |
| **Persistent key blob** (`pico_hsm_key.enc`) | RP2040 flash | Persistent (opt-in, v1.7.0) | Encrypted (AES-ECB, PIN-derived key); never readable without PIN |
| **AES key** (`_AES_KEY`) | RP2040 RAM | Volatile | Used for AES operations; never transmitted |
| **Encrypted session key** | RP2040 RAM + host memory | Volatile (per-session) | Derived from HMAC key + nonce; host can compute it |
| **Chip ID** (`machine.unique_id()`) | RP2040 silicon | Persistent (factory) | Public — anyone with USB access can read it |
| **Entropy output** (SEED/SEED_STREAM) | Generated on demand | Transmitted then gone | Exposed to whoever requests it (rate-limited) |
| **Audit log** | RP2040 RAM | Volatile (64-entry ring buffer) | Queryable via `AUDIT` command |

## Adversary model

We consider the following adversaries, in increasing order of capability:

### A1: Casual observer (no physical access)

An adversary who can observe network traffic **after** the host-Pico link.
**Out of scope.** The USB cable is a direct physical connection; there is no
network component.

### A2: Late-joining USB eavesdropper

An adversary who taps the USB cable **after** the challenge-response handshake
has already occurred. They see encrypted traffic but did not observe the
plaintext handshake.

**Protected by:** AES-CTR encrypted transport (`ENC ON`). The session key
is derived from the HMAC key and a nonce; the eavesdropper missed the
challenge-response exchange that would let them derive it.

### A3: From-start USB eavesdropper

An adversary who taps the USB cable **from boot** and observes all traffic,
including the plaintext challenge-response handshake.

**NOT fully protected.** The encrypted transport session key is:
```
session_key = SHA-256(b"enc-session:" + nonce + hmac(key, nonce))
```
The eavesdropper saw both `nonce` and `hmac(key, nonce)` in the plaintext
CHALLENGE/RESPONSE exchange, so they can derive `session_key` and decrypt
all subsequent `ENC_MSG` traffic.

**Why this is accepted:** Full confidentiality against a from-start
eavesdropper requires either:
- **ECDH key exchange** — the RP2040 lacks ECC hardware; a pure-Python ECC
  implementation would be too slow and too error-prone for a security device.
- **A pre-shared key** — this contradicts the volatile-key design (the key
  is minted fresh on every boot and never stored in flash).

The encrypted transport is a **partial** improvement: it protects against
late-joining eavesdroppers (A2) and provides replay protection, but does
not provide end-to-end confidentiality against A3. For the USB CDC threat
model (physical access to the cable), A3 is the strongest realistic
adversary, and the limitation is documented honestly.

### A4: Physical access attacker (read-only)

An adversary with physical access to the Pico who can read the USB port,
issue commands, and observe responses, but **cannot modify the firmware**
or open the chip.

**Protected against:**
- **Key extraction:** The HMAC key is never transmitted; only `sha256(key)`.
  The attacker cannot recover the key from the fingerprint (one-way hash).
- **Replay attacks:** Rate limiting + audit logging + encrypted transport
  replay protection (monotonic counters) reject repeated challenges.
- **Brute-force CHALLENGE:** Rate limiter caps at 10 requests / 10 seconds,
  then exponential backoff (2s → 4s → 8s → ... → 60s cap).
- **Board swap with stock firmware:** The chip ID check catches a different
  Pico running the same open-source firmware (different chip ID).

**NOT protected against:**
- **Entropy exhaustion:** An attacker with USB access can call SEED repeatedly
  (within rate limits) and drain entropy. This is by design — entropy is a
  public resource.
- **Audit log tampering:** An attacker with USB access can issue `AUDIT CLEAR`.
  This is a known trade-off (the audit log is for forensics, not tamper-proofing).
- **Persistent key brute-force (if opt-in):** If `KEY_STORE` has been used,
  an attacker with USB access can attempt `KEY_LOAD <pin>` repeatedly. The
  rate limiter applies to CHALLENGE/SEED, not KEY_LOAD, so there is no
  lockout on PIN guesses. The PIN space depends on the user's choice; a
  long PIN is required. A wrong PIN produces a garbage key (different
  fingerprint), which the host can detect, but the device itself does not
  reject it.

### A5: Physical access attacker (firmware modification)

An adversary who can **reflash the Pico** with custom firmware.

**NOT protected against.** This is the fundamental limitation of a
non-secure-element design:
- The attacker can flash firmware that hardcodes a known key, exfiltrates the
  key over USB, or logs all commands.
- The attacker can read the target Pico's chip ID, then flash their own Pico
  with firmware that reports that ID — defeating the board-substitution check.
- If a persistent key blob (`pico_hsm_key.enc`) exists in flash, the attacker
  can copy it off and brute-force the PIN offline (the KDF is 1000-round
  iterated SHA-256, not a memory-hard function). A long PIN is the only
  mitigation.

**Mitigation:** Use a secure element (e.g., ATECC608A) with a non-extractable
key for cryptographic anti-substitution. The RP2040 alone cannot provide this.
See the EXPANSION_TODO "Secure element integration" item.

### A6: Physical access attacker (chip-level)

An adversary who can **decap the RP2040** and read SRAM with invasive
techniques (electron microscopy, focused ion beam, etc.).

**Out of scope.** No software-only mitigation exists against invasive
physical attacks on a non-hardened MCU.

## Security properties by feature

### Volatile HMAC key (default)

| Property | Status | Notes |
|----------|--------|-------|
| Key confidentiality (no USB tap) | ✅ Protected | Key never leaves RAM; only fingerprint transmitted |
| Key confidentiality (power-loss) | ✅ Protected | Destroyed on power-loss; cannot be recovered |
| Key persistence across reboots | ❌ By design | Volatile by default — not a persistent key vault |
| Backtracking resistance | ✅ Protected | HMAC-DRBG reseeded every generation; prior keys don't reveal later ones |

### Persistent key (opt-in, v1.7.0)

| Property | Status | Notes |
|----------|--------|-------|
| Key confidentiality (no flash access) | ✅ Protected | Encrypted blob in flash; PIN never stored |
| Key persistence across reboots | ✅ Provided | `KEY_LOAD <pin>` restores the original key |
| PIN brute-force (online, USB) | ⚠️ Partial | No lockout on KEY_LOAD; wrong PIN gives garbage key (detectable by fingerprint mismatch) |
| PIN brute-force (offline, flash dump) | ❌ Not protected | KDF is 1000-round iterated SHA-256 (not memory-hard); flash blob can be copied and brute-forced |
| Ciphertext integrity | ❌ Not provided | AES-ECB has no MAC; wrong PIN produces silent garbage |
| Flash wear-out | ⚠️ Low risk | `KEY_STORE` writes 36 bytes; RP2040 flash rated ~100k erase cycles per sector |

### Challenge-response authentication

| Property | Status | Notes |
|----------|--------|-------|
| Replay protection (no enc) | ⚠️ Partial | Rate limiter throttles; audit log records; no nonce-binding |
| Replay protection (with enc) | ✅ Protected | Monotonic counter rejects replays |
| Man-in-the-middle | ❌ Not protected | No key confirmation beyond HMAC; MITM can relay |
| Key-in-the-middle | ❌ Not protected | Attacker who saw handshake can derive session key |

### Encrypted transport (AES-CTR)

| Property | Status | Notes |
|----------|--------|-------|
| Confidentiality vs late eavesdropper (A2) | ✅ Protected | Session key derived from missed handshake |
| Confidentiality vs from-start eavesdropper (A3) | ❌ Not protected | Handshake was plaintext; session key derivable |
| Message authentication | ❌ Not protected | No MAC; ciphertext can be modified (CTR malleability) |
| Replay protection | ✅ Protected | Monotonic rx counter; replays rejected |
| Forward secrecy | ❌ Not protected | Single session key; no ratchet |

### Rate limiting

| Property | Status | Notes |
|----------|--------|-------|
| Brute-force CHALLENGE | ✅ Protected | 10 req/10s → exponential backoff (max 60s) |
| Brute-force SEED drain | ⚠️ Partial | Rate-limited but not prevented; entropy is public |
| Lockout recovery | ✅ Automatic | Backoff resets after window clears |
| Administrator bypass | ✅ Supported | `RATE_LIMIT RESET` clears lockout |

### Audit log

| Property | Status | Notes |
|----------|--------|-------|
| Forensic record of challenges | ✅ Provided | 64-entry ring buffer with timestamp, hash, result |
| Tamper resistance | ❌ Not provided | `AUDIT CLEAR` is available to any USB user |
| Persistence across reboots | ❌ Not provided | Volatile (in RAM); destroyed on power-loss |

### Device identity (chip ID)

| Property | Status | Notes |
|----------|--------|-------|
| Unique per chip | ✅ Factory-guaranteed | No two RP2040s share a chip ID |
| Persistent across reboots | ✅ In silicon | Survives reflashes, power cycles |
| Secret (unforgeable) | ❌ Public | Anyone with USB can read it; not a secret |
| Anti-substitution (stock firmware) | ✅ Effective | Different chip → rejected |
| Anti-substitution (custom firmware) | ❌ Defeated | Attacker can spoof chip ID in custom firmware |

### TRNG / entropy

| Property | Status | Notes |
|----------|--------|-------|
| Source quality | ⚠️ Measured, not certified | H_min ≈ 3.73 bits/sample; passes NIST SP 800-22 (9/9) |
| Continuous health monitoring | ✅ Provided | Watchdog (core 1) + NIST SP 800-90B health tests |
| NIST SP 800-90B validation | ❌ Not done | Continuous tests run, but not formally validated/certified |
| Backtracking resistance | ✅ Protected | HMAC-DRBG reseeded every generation |

## Security non-claims

The following are **explicitly NOT claimed**:

1. **This is NOT a certified HSM.** No FIPS 140, no Common Criteria, no
   NIST CAVP validation. It is an educational project.

2. **This is NOT a persistent key vault by default.** The key is volatile and
   changes every boot. Anything sealed with a previous boot's key cannot be
   decrypted or verified after a reboot. An **opt-in** persistent key mode
   (`KEY_STORE <pin>`, `KEY_LOAD <pin>`, `KEY_ERASE`, `KEY_STATUS`) exists
   (v1.7.0), but it is a convenience feature, not a hardened key vault: the
   KDF is iterated SHA-256 (not memory-hard), AES-ECB provides no integrity
   check, and an attacker with flash access can brute-force the PIN offline.
   For production-grade persistent keys, use a real HSM.

3. **This does NOT provide confidentiality against a from-start eavesdropper.**
   The encrypted transport protects against late-joining eavesdroppers and
   provides replay protection, but the session key is derivable from the
   observed plaintext handshake.

4. **This does NOT provide message authentication.** The encrypted transport
   uses AES-CTR without a MAC. Ciphertext can be modified (CTR malleability).
   For authenticated encryption, an AEAD (e.g., AES-GCM or ChaCha20-Poly1305)
   would be needed — not currently implemented.

5. **This does NOT prevent device substitution with custom firmware.** The
   chip ID is public and forgeable in custom firmware. A secure element with
   a non-extractable key is required for cryptographic anti-substitution.

6. **This is NOT a strong TRNG by silicon-RNG standards.** A single floating
   ADC pin is no substitute for a dedicated noise diode or hardened TRNG IP.
   The min-entropy is measured with a safety margin, and the source passes
   NIST SP 800-22. NIST SP 800-90B continuous health tests (repetition-count
   and adaptive-proportion) run on every entropy block, but the source has not
   been through formal NIST SP 800-90B entropy-source validation.

7. **The audit log is NOT tamper-proof.** Any USB user can clear it with
   `AUDIT CLEAR`. It is a forensic aid, not a security boundary.

8. **The rate limiter does NOT prevent entropy drain.** It throttles but
   does not stop an attacker from requesting entropy (within rate limits).
   Entropy is a public resource by design.

## Threat summary matrix

| Threat | Adversary | Mitigation | Status |
|--------|-----------|------------|--------|
| Key extraction via USB | A4 | Key never transmitted; fingerprint only | ✅ Protected |
| Key recovery after power-loss | A4 | Volatile (RAM only) | ✅ Protected |
| Persistent key flash extraction | A5 | Encrypted (AES-ECB, PIN-derived) | ⚠️ Partial (offline PIN brute-force possible) |
| Persistent key PIN brute-force (online) | A4 | Wrong PIN gives garbage key (detectable) | ⚠️ Partial (no lockout on KEY_LOAD) |
| Replay challenge (no enc) | A4 | Rate limiter + audit log | ⚠️ Partial |
| Replay challenge (with enc) | A2, A4 | Monotonic counter | ✅ Protected |
| Late-join eavesdrop | A2 | AES-CTR transport | ✅ Protected |
| From-start eavesdrop | A3 | — | ❌ Not protected |
| Ciphertext modification | A2, A3 | — (no MAC) | ❌ Not protected |
| Brute-force CHALLENGE | A4 | Rate limiter + lockout | ✅ Protected |
| Board swap (stock firmware) | A4 | Chip ID check | ✅ Protected |
| Board swap (custom firmware) | A5 | — (needs secure element) | ❌ Not protected |
| Firmware modification | A5 | — (needs secure boot) | ❌ Not protected |
| Audit log tampering | A4 | — | ❌ Not protected |
| Entropy drain | A4 | Rate limiter (throttle only) | ⚠️ Partial |
| Invasive physical attack | A6 | — (out of scope) | ❌ Out of scope |

## Recommendations

For users who need stronger security than pico-hsm provides:

1. **Persistent keys:** Pico-hsm's opt-in persistent key mode (v1.7.0) is a
   convenience feature, not a hardened key vault — the KDF is not memory-hard,
   there is no lockout on PIN guesses, and the flash blob can be brute-forced
   offline. For production-grade persistent keys, use a real HSM (YubiHSM 2,
   Nitrokey HSM 2) or a cloud KMS.

2. **Confidential transport:** Use a host-side transport like SSH or TLS
   if the Pico is accessed remotely. The encrypted transport is a partial
   improvement for the direct-USB case only.

3. **Anti-substitution:** Add an ATECC608A secure element over I²C for a
   non-extractable key and cryptographic device identity.

4. **Certified RNG:** Use a validated hardware entropy source (e.g.,
   OneRNG, Infineon RNG) for production cryptographic RNG. Pico-hsm's TRNG
   is educational-grade.

5. **Tamper resistance:** For physical tamper protection, use a potted
   enclosure with tamper-detection switches wired to an interrupt. The
   RP2040 itself has no tamper-resistant hardware.
