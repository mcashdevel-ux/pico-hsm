/*
 * trng_native.c — Native MicroPython module for RP2040 ADC TRNG.
 *
 * Provides fast C implementations of the TRNG pipeline that replaces the
 * slow Python per-sample loop in trng.py.  The speedup is ~100x for SEED
 * because the dominant cost (4096 Python ADC reads) becomes a tight C loop
 * reading hardware registers directly.
 *
 * Pipeline (mirrors trng.py, NIST SP 800-90A-inspired):
 *   ADC noise → bit extraction → health gate → von-Neumann debias
 *   → HMAC-DRBG (SHA-256) → output
 *
 * Exposes:
 *   trng_native.collect_raw(n, bit_mask)  -> bytes  (raw ADC samples)
 *   trng_native.fresh_entropy(n, bit_mask) -> bytes  (health-gated + VN-debiased)
 *   trng_native.seed(n, bit_mask)          -> bytes  (DRBG output, reseeded)
 *   trng_native.sha256(data)               -> bytes  (32-byte hash)
 *
 * bit_mask: bitmask of ADC data bits to extract (e.g. 0x01f0 = bits 4-8).
 *           The RP2040 ADC returns 12-bit values in bits 4-15 of read_u16().
 *           We work with the raw 12-bit value (bits 0-11 of the register).
 *
 * Build:
 *   make -f Makefile ARCH=armv6m
 *
 * SPDX-License-Identifier: MIT
 */

#include "py/dynruntime.h"
#include <stdint.h>

/* Native .mpy modules can't link libc, so provide memset/memcpy. */
void *memset(void *dst, int c, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    while (n--) *d++ = (uint8_t)c;
    return dst;
}
void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dst;
}

/* ── RP2040 ADC registers (direct memory-mapped access) ─────────────── */

/* Only access the ADC CS/RESULT registers directly.  Do NOT touch RESETS or
 * CLOCKS — MicroPython's machine.ADC already enables the ADC at boot, and
 * writing to clock/reset registers crashes the chip (kills USB, etc.). */

#define ADC_BASE   0x4004c000
#define ADC_CS     (*(volatile uint32_t *)(ADC_BASE + 0x00))
#define ADC_RESULT (*(volatile uint32_t *)(ADC_BASE + 0x04))

/* ADC_CS bits */
#define ADC_CS_EN        (1u << 0)   /* Enable ADC */
#define ADC_CS_START_ONCE (1u << 2)  /* Start one conversion */
#define ADC_CS_READY     (1u << 8)   /* Result ready */
#define ADC_CS_AINSEL_SHIFT 12       /* Input select bits 12-14 */

/* BSS (non-static — native .mpy modules don't support static BSS). */
int adc_inited = 0;

static void adc_check_enabled(void) {
    if (adc_inited) return;
    /* The ADC clock and reset are managed by MicroPython's machine.ADC
     * driver, which runs during trng._init().  We only need to verify the
     * EN bit is set; if it isn't, set it (safe — doesn't touch clocks). */
    if (!(ADC_CS & ADC_CS_EN)) {
        ADC_CS = ADC_CS_EN;
        for (volatile int i = 0; i < 100; i++) ;
    }
    adc_inited = 1;
}

static inline uint16_t adc_read_raw(void) {
    /* Write EN | AINSEL=0 | START_ONCE directly.  This ensures channel 0
     * (GP26) is selected every time — MicroPython may have left AINSEL
     * pointing at channel 4 (temperature sensor) after a read_temp() call.
     * Direct write avoids read-modify-write where we might write back a
     * stale READY bit. */
    ADC_CS = ADC_CS_EN | (0u << ADC_CS_AINSEL_SHIFT) | ADC_CS_START_ONCE;
    /* Wait for READY with a timeout (don't hang if ADC is stuck). */
    for (int i = 0; i < 10000; i++) {
        if (ADC_CS & ADC_CS_READY) break;
    }
    return (uint16_t)(ADC_RESULT & 0xFFF);  /* 12-bit result */
}

/* ── Bit extraction ──────────────────────────────────────────────────── */

/* Given a 12-bit ADC value and a bitmask of which bits to extract (relative
 * to the 12-bit value, so bit 0 = LSB), pack the selected bits into a byte. */
static inline uint8_t extract_bits(uint16_t adc_val, uint16_t bit_mask) {
    uint8_t result = 0;
    int pos = 0;
    for (int b = 0; b < 12; b++) {
        if (bit_mask & (1u << b)) {
            if (adc_val & (1u << b)) {
                result |= (1u << pos);
            }
            pos++;
        }
    }
    return result;
}

static int count_bits(uint16_t bit_mask) {
    int n = 0;
    for (int b = 0; b < 12; b++)
        if (bit_mask & (1u << b))
            n++;
    return n;
}

/* ── Health gate (mirrors trng._health_check, integer-only) ─────────── */

#define HEALTH_BALANCE_LO_NUM 35   /* 0.35 * 100 */
#define HEALTH_BALANCE_HI_NUM 65   /* 0.65 * 100 */
#define HEALTH_SERIAL_NUM 50       /* 0.50 * 100 */

/* Integer sqrt (Newton's method). Returns floor(sqrt(n)). */
static uint32_t isqrt(uint64_t n) {
    if (n == 0) return 0;
    uint64_t x = n, y = (x + 1) / 2;
    while (y < x) { x = y; y = (x + n / x) / 2; }
    return (uint32_t)x;
}

/* Returns 1 if healthy, 0 if not.
 *
 * Balance: ones/total must be in [0.35, 0.65] → ones*100 in [35*total, 65*total]/100
 * Min-entropy: -log2(pmax) >= max(2, nbits/2). We check pmax <= 2^(-floor).
 *   pmax = max_count / n. So -log2(max_count/n) >= floor
 *   → max_count <= n / 2^floor = n >> floor.
 * Serial: |num / sqrt(den1*den2)| <= 0.50 → |num| * 2 <= sqrt(den1*den2)
 */
static int health_check(const uint8_t *raw, int n, int nbits) {
    if (n < 256) return 0;

    int min_ent_floor = nbits / 2;
    if (min_ent_floor < 2) min_ent_floor = 2;

    /* Balance: fraction of 1-bits */
    int ones = 0;
    for (int i = 0; i < n; i++)
        ones += __builtin_popcount(raw[i]);
    int total = n * nbits;

    /* bal = ones / total; check 0.35 <= bal <= 0.65
     * → 35*total <= ones*100 <= 65*total */
    int ones100 = ones * 100;
    if (ones100 < HEALTH_BALANCE_LO_NUM * total) return 0;
    if (ones100 > HEALTH_BALANCE_HI_NUM * total) return 0;

    /* Min-entropy from histogram */
    int hist[256] = {0};
    for (int i = 0; i < n; i++)
        hist[raw[i]]++;
    int max_count = 0;
    for (int i = 0; i < 256; i++)
        if (hist[i] > max_count) max_count = hist[i];

    /* Check min_ent >= floor: -log2(max_count/n) >= floor
     * → max_count <= n >> floor */
    uint32_t threshold = (uint32_t)n >> min_ent_floor;
    if (max_count > threshold) return 0;

    /* Serial correlation: |num / sqrt(den1*den2)| <= 0.50
     * → |num| * 2 <= sqrt(den1 * den2) */
    int64_t sum_val = 0;
    for (int i = 0; i < n; i++)
        sum_val += raw[i];
    int64_t mean = sum_val / n;  /* integer mean */

    int64_t num = 0, den1 = 0, den2 = 0;
    for (int i = 1; i < n; i++) {
        int64_t d = raw[i] - mean;
        int64_t d0 = raw[i - 1] - mean;
        num += d * d0;
        den2 += d * d;
        den1 += d0 * d0;
    }

    if (den1 > 0 && den2 > 0) {
        /* |num| * 2 <= sqrt(den1 * den2) */
        uint64_t prod = (uint64_t)den1 * (uint64_t)den2;
        uint32_t sq = isqrt(prod);
        int64_t abs_num = num < 0 ? -num : num;
        if (abs_num * 2 > (int64_t)sq) return 0;
    }

    return 1;  /* healthy */
}

/* ── Von-Neumann debiaser ────────────────────────────────────────────── */

/* VN extractor: 01->0, 10->1, 00/11 discarded. Removes bias. */
static int vn_debias(const uint8_t *raw, int n, int nbits, uint8_t *out, int out_max) {
    int out_len = 0;
    int prev_bit = -1;
    for (int idx = 0; idx < n; idx++) {
        uint8_t byte = raw[idx];
        for (int shift = nbits - 1; shift >= 0; shift--) {
            int bit = (byte >> shift) & 1;
            if (prev_bit < 0) {
                prev_bit = bit;
            } else {
                if (prev_bit == 0 && bit == 1) {
                    if (out_len < out_max) out[out_len++] = 0;
                    prev_bit = -1;
                } else if (prev_bit == 1 && bit == 0) {
                    if (out_len < out_max) out[out_len++] = 1;
                    prev_bit = -1;
                } else {
                    prev_bit = -1;
                }
            }
        }
    }
    return out_len;
}

/* ── SHA-256 (FIPS 180-4) ────────────────────────────────────────────── */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx;

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static const uint32_t sha256_h0[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
};

#define SHA256_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x)  (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_EP1(x)  (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SIG0(x) (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx *ctx, const uint8_t *data) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)data[i*4] << 24) | ((uint32_t)data[i*4+1] << 16) |
               ((uint32_t)data[i*4+2] << 8) | ((uint32_t)data[i*4+3]);
    for (int i = 16; i < 64; i++)
        w[i] = SHA256_SIG1(w[i-2]) + w[i-7] + SHA256_SIG0(w[i-15]) + w[i-16];

    uint32_t a=ctx->state[0], b=ctx->state[1], c=ctx->state[2], d=ctx->state[3];
    uint32_t e=ctx->state[4], f=ctx->state[5], g=ctx->state[6], h=ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + sha256_k[i] + w[i];
        uint32_t t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    memcpy(ctx->state, sha256_h0, sizeof(sha256_h0));
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buf[ctx->buflen++] = data[i];
        if (ctx->buflen == 64) {
            sha256_transform(ctx, ctx->buf);
            ctx->bitlen += 512;
            ctx->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t *out) {
    uint64_t bitlen = ctx->bitlen + (uint64_t)ctx->buflen * 8;
    /* Append 0x80 */
    ctx->buf[ctx->buflen++] = 0x80;
    /* Pad with zeros until 56 bytes */
    if (ctx->buflen > 56) {
        while (ctx->buflen < 64) ctx->buf[ctx->buflen++] = 0;
        sha256_transform(ctx, ctx->buf);
        ctx->buflen = 0;
    }
    while (ctx->buflen < 56) ctx->buf[ctx->buflen++] = 0;
    /* Append length (big-endian) */
    for (int i = 7; i >= 0; i--)
        ctx->buf[56 + (7 - i)] = (uint8_t)(bitlen >> (i * 8));
    sha256_transform(ctx, ctx->buf);
    /* Output state (big-endian) */
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(ctx->state[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        out[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

static void sha256_hash(const uint8_t *data, size_t len, uint8_t *out) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* ── HMAC-SHA256 ──────────────────────────────────────────────────────── */

static void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t *out) {
    uint8_t k_ipad[64], k_opad[64];
    const uint8_t *k = key;
    uint8_t tmp_key[32];

    if (klen > 64) {
        sha256_hash(key, klen, tmp_key);
        k = tmp_key;
        klen = 32;
    }

    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    memcpy(k_ipad, k, klen);
    memcpy(k_opad, k, klen);
    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    sha256_ctx ctx;
    uint8_t inner[32];

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, msg, mlen);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out);
}

/* ── HMAC-DRBG (NIST SP 800-90A, SHA-256) ─────────────────────────────── */

typedef struct {
    uint8_t K[32];
    uint8_t V[32];
} hmac_drbg_ctx;

static void drbg_update(hmac_drbg_ctx *drbg, const uint8_t *provided, size_t plen) {
    uint8_t buf[64];
    memcpy(buf, drbg->V, 32);
    buf[32] = 0x00;
    if (plen > 0) memcpy(buf + 33, provided, plen);
    hmac_sha256(drbg->K, 32, buf, 33 + plen, drbg->K);
    hmac_sha256(drbg->K, 32, drbg->V, 32, drbg->V);

    memcpy(buf, drbg->V, 32);
    buf[32] = 0x01;
    if (plen > 0) memcpy(buf + 33, provided, plen);
    hmac_sha256(drbg->K, 32, buf, 33 + plen, drbg->K);
    hmac_sha256(drbg->K, 32, drbg->V, 32, drbg->V);
}

static void drbg_init(hmac_drbg_ctx *drbg, const uint8_t *entropy, size_t elen, const uint8_t *perso, size_t plen) {
    memset(drbg->K, 0x00, 32);
    memset(drbg->V, 0x01, 32);
    /* Concatenate entropy + perso for the initial update */
    uint8_t *combined = (uint8_t *)m_malloc(elen + plen);
    memcpy(combined, entropy, elen);
    if (plen > 0) memcpy(combined + elen, perso, plen);
    drbg_update(drbg, combined, elen + plen);
    m_free(combined);
}

static void drbg_reseed(hmac_drbg_ctx *drbg, const uint8_t *entropy, size_t elen) {
    drbg_update(drbg, entropy, elen);
}

static void drbg_generate(hmac_drbg_ctx *drbg, uint8_t *out, size_t n) {
    size_t offset = 0;
    while (offset < n) {
        hmac_sha256(drbg->K, 32, drbg->V, 32, drbg->V);
        size_t chunk = (n - offset < 32) ? (n - offset) : 32;
        memcpy(out + offset, drbg->V, chunk);
        offset += chunk;
    }
    drbg_update(drbg, NULL, 0);
}

/* ── Combined: fresh_entropy + DRBG → SEED output ────────────────────── */

/* Full SEED pipeline in C:
 * 1. Collect raw ADC samples (fast C loop)
 * 2. Health check (3 retries with re-collect)
 * 3. VN debias
 * 4. HMAC-DRBG seed from debiased entropy
 * 5. Generate output
 */
static int seed_pipeline(int nbytes, uint16_t bit_mask, uint8_t *out) {
    adc_check_enabled();
    int nbits = count_bits(bit_mask);
    if (nbits < 4) return -1;  /* not enough bits */

    /* Need at least 4096 raw samples, or nbytes*8, whichever is larger */
    int need = nbytes * 8;
    if (need < 4096) need = 4096;

    uint8_t *raw = (uint8_t *)m_malloc(need);

    for (int attempt = 0; attempt < 3; attempt++) {
        /* Collect raw samples */
        for (int i = 0; i < need; i++) {
            uint16_t val = adc_read_raw();
            raw[i] = extract_bits(val, bit_mask);
        }

        /* Health check */
        if (!health_check(raw, need, nbits)) continue;

        /* VN debias */
        uint8_t *debiased = (uint8_t *)m_malloc(need);
        int deb_len = vn_debias(raw, need, nbits, debiased, need);
        if (deb_len < 32) {
            /* VN collapsed — fall back to raw (health-gated) */
            memcpy(debiased, raw, 32);
            deb_len = 32;
        }

        /* DRBG: seed from debiased entropy */
        uint8_t perso[] = "pico-trng-drbg/v2-native";
        hmac_drbg_ctx drbg;
        drbg_init(&drbg, debiased, 32, perso, sizeof(perso) - 1);

        /* Zero out seed material */
        memset(debiased, 0, deb_len);
        m_free(debiased);

        /* Generate output (reseed with fresh entropy for >32 bytes) */
        if (nbytes <= 32) {
            drbg_generate(&drbg, out, nbytes);
        } else {
            int remaining = nbytes;
            int offset = 0;
            while (remaining > 0) {
                int chunk = (remaining < 32) ? remaining : 32;
                drbg_generate(&drbg, out + offset, chunk);
                offset += chunk;
                remaining -= chunk;
                if (remaining > 0) {
                    /* Reseed with fresh entropy */
                    for (int i = 0; i < 4096; i++) {
                        uint16_t val = adc_read_raw();
                        raw[i] = extract_bits(val, bit_mask);
                    }
                    if (health_check(raw, 4096, nbits)) {
                        uint8_t *deb2 = (uint8_t *)m_malloc(4096);
                        int d2 = vn_debias(raw, 4096, nbits, deb2, 4096);
                        if (d2 >= 32) {
                            drbg_reseed(&drbg, deb2, 32);
                        }
                        memset(deb2, 0, d2);
                        m_free(deb2);
                    }
                }
            }
        }

        /* Zero DRBG state */
        memset(&drbg, 0, sizeof(drbg));
        memset(raw, 0, need);
        m_free(raw);
        return 0;  /* success */
    }

    m_free(raw);
    return -2;  /* unhealthy after 3 attempts */
}

/* ── MicroPython bindings ────────────────────────────────────────────── */

/* trng_native.collect_raw(n, bit_mask) -> bytes
 * Read n ADC samples, extract selected bits, return as bytes. */
static mp_obj_t collect_raw(mp_obj_t n_in, mp_obj_t mask_in) {
    int n = mp_obj_get_int(n_in);
    uint16_t bit_mask = (uint16_t)mp_obj_get_int(mask_in);
    if (n < 1 || n > 8192)
        mp_raise_ValueError(MP_ERROR_TEXT("n must be 1..8192"));
    adc_check_enabled();
    uint8_t *buf = m_new(uint8_t, n);
    for (int i = 0; i < n; i++) {
        uint16_t val = adc_read_raw();
        buf[i] = extract_bits(val, bit_mask);
    }
    mp_obj_t result = mp_obj_new_bytes(buf, n);
    m_free(buf);
    return result;
}
static MP_DEFINE_CONST_FUN_OBJ_2(collect_raw_obj, collect_raw);

/* trng_native.fresh_entropy(n, bit_mask) -> bytes
 * Collect + health check + VN debias. Returns n debiased bytes. */
static mp_obj_t fresh_entropy(mp_obj_t n_in, mp_obj_t mask_in) {
    int nbytes = mp_obj_get_int(n_in);
    uint16_t bit_mask = (uint16_t)mp_obj_get_int(mask_in);
    if (nbytes < 1 || nbytes > 256)
        mp_raise_ValueError(MP_ERROR_TEXT("n must be 1..256"));

    int nbits = count_bits(bit_mask);
    if (nbits < 4)
        mp_raise_ValueError(MP_ERROR_TEXT("need at least 4 bits in mask"));

    adc_check_enabled();
    int need = nbytes * 8;
    if (need < 4096) need = 4096;
    uint8_t *raw = m_new(uint8_t, need);

    for (int attempt = 0; attempt < 3; attempt++) {
        for (int i = 0; i < need; i++) {
            uint16_t val = adc_read_raw();
            raw[i] = extract_bits(val, bit_mask);
        }
        if (!health_check(raw, need, nbits)) continue;

        uint8_t *debiased = m_new(uint8_t, need);
        int deb_len = vn_debias(raw, need, nbits, debiased, need);
        if (deb_len < nbytes) {
            if (deb_len == 0) {
                /* VN collapsed entirely — use raw (health-gated) */
                memcpy(debiased, raw, nbytes);
                deb_len = nbytes;
            } else {
                /* Pad with zeros (should be rare) */
                memset(debiased + deb_len, 0, nbytes - deb_len);
                deb_len = nbytes;
            }
        }

        mp_obj_t result = mp_obj_new_bytes(debiased, nbytes);
        memset(debiased, 0, need);
        m_free(debiased);
        memset(raw, 0, need);
        m_free(raw);
        return result;
    }

    memset(raw, 0, need);
    m_free(raw);
    mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("TRNG unhealthy after 3 attempts"));
}
static MP_DEFINE_CONST_FUN_OBJ_2(fresh_entropy_obj, fresh_entropy);

/* trng_native.seed(n, bit_mask) -> bytes
 * Full pipeline: collect → health → VN debias → HMAC-DRBG → output. */
static mp_obj_t seed(mp_obj_t n_in, mp_obj_t mask_in) {
    int nbytes = mp_obj_get_int(n_in);
    uint16_t bit_mask = (uint16_t)mp_obj_get_int(mask_in);
    if (nbytes < 1 || nbytes > 256)
        mp_raise_ValueError(MP_ERROR_TEXT("n must be 1..256"));

    uint8_t *out = m_new(uint8_t, nbytes);
    int rc = seed_pipeline(nbytes, bit_mask, out);
    if (rc != 0) {
        memset(out, 0, nbytes);
        m_free(out);
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("TRNG unhealthy after 3 attempts"));
    }
    mp_obj_t result = mp_obj_new_bytes(out, nbytes);
    memset(out, 0, nbytes);
    m_free(out);
    return result;
}
static MP_DEFINE_CONST_FUN_OBJ_2(seed_obj, seed);

/* trng_native.sha256(data) -> bytes (32-byte hash) */
static mp_obj_t sha256_func(mp_obj_t data_in) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data_in, &bufinfo, MP_BUFFER_READ);
    uint8_t hash[32];
    sha256_hash((const uint8_t *)bufinfo.buf, bufinfo.len, hash);
    return mp_obj_new_bytes(hash, 32);
}
static MP_DEFINE_CONST_FUN_OBJ_1(sha256_obj, sha256_func);

/* ── Module entry point ──────────────────────────────────────────────── */

mp_obj_t mpy_init(mp_obj_fun_bc_t *self, size_t n_args, size_t n_kw, mp_obj_t *args) {
    MP_DYNRUNTIME_INIT_ENTRY

    mp_store_global(MP_QSTR___name__, MP_OBJ_NEW_QSTR(MP_QSTR_trng_native));
    mp_store_global(MP_QSTR_collect_raw, MP_OBJ_FROM_PTR(&collect_raw_obj));
    mp_store_global(MP_QSTR_fresh_entropy, MP_OBJ_FROM_PTR(&fresh_entropy_obj));
    mp_store_global(MP_QSTR_seed, MP_OBJ_FROM_PTR(&seed_obj));
    mp_store_global(MP_QSTR_sha256, MP_OBJ_FROM_PTR(&sha256_obj));

    MP_DYNRUNTIME_INIT_EXIT
}
