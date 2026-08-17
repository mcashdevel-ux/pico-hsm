/*
 * aes.c — AES-256 native MicroPython module for RP2040 (Pico).
 *
 * Exposes:
 *   aes.expand_key(key)          -> expanded round keys (240 bytes)
 *   aes.encrypt_block(rk, pt)    -> 16-byte ciphertext
 *   aes.decrypt_block(rk, ct)    -> 16-byte plaintext
 *   aes.ctr_xcrypt(rk, nonce, data) -> stream cipher output
 *
 * key:   32 bytes (AES-256)
 * rk:    240 bytes (15 round keys × 16 bytes)
 * pt/ct: 16 bytes (one AES block)
 * nonce: 16 bytes (initial counter block)
 * data:  arbitrary length
 *
 * Build:
 *   cd micropython/ports/rp2040
 *   make USER_C_MODULES=../../../../pico-hsm/pico/native/aes.c
 *
 * SPDX-License-Identifier: MIT
 */

#include "py/runtime.h"
#include "py/objstr.h"
#include <string.h>

/* ── AES-256 constants ───────────────────────────────────────────────── */

#define NK   8    /* 256-bit key = 8 × 32-bit words                    */
#define NR   14   /* AES-256 has 14 rounds                              */
#define NB   4    /* block = 4 × 32-bit words = 16 bytes               */
#define RK_LEN (NB * (NR + 1))  /* 60 words = 240 bytes                */

/* Forward S-box (FIPS 197) */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

/* Inverse S-box */
static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

/* Round constants for key expansion */
static const uint8_t rcon[15] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,
    0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,
};

/* ── Core AES operations (work on byte arrays) ───────────────────────── */

static inline uint8_t xtime(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) r ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return r;
}

/* Key expansion: 32-byte key -> 240-byte expanded key */
static void aes256_expand_key(const uint8_t *key, uint8_t *rk) {
    memcpy(rk, key, 32);
    uint8_t temp[4];
    int i = NK;  /* start at word 8 */
    int rcon_idx = 1;
    while (i < RK_LEN) {
        memcpy(temp, rk + (i - 1) * 4, 4);
        if (i % NK == 0) {
            /* RotWord */
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2];
            temp[2] = temp[3]; temp[3] = t;
            /* SubWord */
            temp[0] = sbox[temp[0]]; temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]]; temp[3] = sbox[temp[3]];
            /* Rcon */
            temp[0] ^= rcon[rcon_idx++];
        } else if (i % NK == 4) {
            /* SubWord only (NK == 8) */
            temp[0] = sbox[temp[0]]; temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]]; temp[3] = sbox[temp[3]];
        }
        for (int j = 0; j < 4; j++)
            rk[i * 4 + j] = rk[(i - NK) * 4 + j] ^ temp[j];
        i++;
    }
}

/* SubBytes */
static void sub_bytes(uint8_t *s) {
    for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
}

static void inv_sub_bytes(uint8_t *s) {
    for (int i = 0; i < 16; i++) s[i] = inv_sbox[s[i]];
}

/* ShiftRows */
static void shift_rows(uint8_t *s) {
    uint8_t t;
    /* row 1: shift left 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    /* row 2: shift left 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* row 3: shift left 3 (= shift right 1) */
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void inv_shift_rows(uint8_t *s) {
    uint8_t t;
    /* row 1: shift right 1 */
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    /* row 2: shift right 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* row 3: shift right 3 (= shift left 1) */
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

/* MixColumns */
static void mix_columns(uint8_t *s) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = s + c * 4;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        col[1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        col[2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        col[3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

static void inv_mix_columns(uint8_t *s) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = s + c * 4;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = gmul(a0,0x0e) ^ gmul(a1,0x0b) ^ gmul(a2,0x0d) ^ gmul(a3,0x09);
        col[1] = gmul(a0,0x09) ^ gmul(a1,0x0e) ^ gmul(a2,0x0b) ^ gmul(a3,0x0d);
        col[2] = gmul(a0,0x0d) ^ gmul(a1,0x09) ^ gmul(a2,0x0e) ^ gmul(a3,0x0b);
        col[3] = gmul(a0,0x0b) ^ gmul(a1,0x0d) ^ gmul(a2,0x09) ^ gmul(a3,0x0e);
    }
}

/* AddRoundKey (column-major: state[col][row], rk byte offset = round*16 + col*4 + row) */
static void add_round_key(uint8_t *s, const uint8_t *rk, int round) {
    const uint8_t *k = rk + round * 16;
    for (int i = 0; i < 16; i++) s[i] ^= k[i];
}

/* Encrypt one 16-byte block */
static void aes256_encrypt(const uint8_t *rk, const uint8_t *pt, uint8_t *ct) {
    uint8_t s[16];
    memcpy(s, pt, 16);
    add_round_key(s, rk, 0);
    for (int round = 1; round < NR; round++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, rk, round);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, rk, NR);
    memcpy(ct, s, 16);
}

/* Decrypt one 16-byte block */
static void aes256_decrypt(const uint8_t *rk, const uint8_t *ct, uint8_t *pt) {
    uint8_t s[16];
    memcpy(s, ct, 16);
    add_round_key(s, rk, NR);
    for (int round = NR - 1; round >= 1; round--) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, rk, round);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, rk, 0);
    memcpy(pt, s, 16);
}

/* ── MicroPython bindings ────────────────────────────────────────────── */

static mp_obj_t aes_expand_key(mp_obj_t key_in) {
    size_t klen;
    const char *kbuf = mp_obj_str_get_data(key_in, &klen);
    if (klen != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("key must be 32 bytes (AES-256)"));
    }
    uint8_t rk[RK_LEN * 4];
    aes256_expand_key((const uint8_t *)kbuf, rk);
    return mp_obj_new_bytes(rk, RK_LEN * 4);
}
static MP_DEFINE_CONST_FUN_OBJ_1(aes_expand_key_obj, aes_expand_key);

static mp_obj_t aes_encrypt_block(mp_obj_t rk_in, mp_obj_t pt_in) {
    size_t rklen, ptlen;
    const char *rkbuf = mp_obj_str_get_data(rk_in, &rklen);
    const char *ptbuf = mp_obj_str_get_data(pt_in, &ptlen);
    if (rklen != RK_LEN * 4) {
        mp_raise_ValueError(MP_ERROR_TEXT("round keys must be 240 bytes"));
    }
    if (ptlen != 16) {
        mp_raise_ValueError(MP_ERROR_TEXT("block must be 16 bytes"));
    }
    uint8_t ct[16];
    aes256_encrypt((const uint8_t *)rkbuf, (const uint8_t *)ptbuf, ct);
    return mp_obj_new_bytes(ct, 16);
}
static MP_DEFINE_CONST_FUN_OBJ_2(aes_encrypt_block_obj, aes_encrypt_block);

static mp_obj_t aes_decrypt_block(mp_obj_t rk_in, mp_obj_t ct_in) {
    size_t rklen, ctlen;
    const char *rkbuf = mp_obj_str_get_data(rk_in, &rklen);
    const char *ctbuf = mp_obj_str_get_data(ct_in, &ctlen);
    if (rklen != RK_LEN * 4) {
        mp_raise_ValueError(MP_ERROR_TEXT("round keys must be 240 bytes"));
    }
    if (ctlen != 16) {
        mp_raise_ValueError(MP_ERROR_TEXT("block must be 16 bytes"));
    }
    uint8_t pt[16];
    aes256_decrypt((const uint8_t *)rkbuf, (const uint8_t *)ctbuf, pt);
    return mp_obj_new_bytes(pt, 16);
}
static MP_DEFINE_CONST_FUN_OBJ_2(aes_decrypt_block_obj, aes_decrypt_block);

static mp_obj_t aes_ctr_xcrypt(size_t n_args, const mp_obj_t *args) {
    size_t rklen, nlen, dlen;
    const char *rkbuf = mp_obj_str_get_data(args[0], &rklen);
    const char *nbuf  = mp_obj_str_get_data(args[1], &nlen);
    const char *dbuf  = (n_args >= 3) ? mp_obj_str_get_data(args[2], &dlen) : NULL;
    if (rklen != RK_LEN * 4) {
        mp_raise_ValueError(MP_ERROR_TEXT("round keys must be 240 bytes"));
    }
    if (nlen != 16) {
        mp_raise_ValueError(MP_ERROR_TEXT("nonce must be 16 bytes"));
    }
    if (n_args < 3) dlen = 0;

    uint8_t *out = m_new(uint8_t, dlen > 0 ? dlen : 1);
    uint8_t counter[16];
    memcpy(counter, nbuf, 16);
    const uint8_t *rk = (const uint8_t *)rkbuf;

    size_t offset = 0;
    while (offset < dlen) {
        uint8_t ks[16];
        aes256_encrypt(rk, counter, ks);
        size_t chunk = (dlen - offset < 16) ? (dlen - offset) : 16;
        for (size_t i = 0; i < chunk; i++)
            out[offset + i] = ((const uint8_t *)dbuf)[offset + i] ^ ks[i];
        offset += chunk;
        /* Increment counter (big-endian, last 4 bytes for simplicity) */
        for (int i = 15; i >= 12; i--) {
            if (++counter[i] != 0) break;
        }
    }
    return mp_obj_new_bytes(out, dlen);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(aes_ctr_xcrypt_obj, 2, 3, aes_ctr_xcrypt);

/* ── Module table ────────────────────────────────────────────────────── */

static const mp_rom_map_elem_t aes_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__),       MP_ROM_QSTR(MP_QSTR_aes) },
    { MP_ROM_QSTR(MP_QSTR_expand_key),     MP_ROM_PTR(&aes_expand_key_obj) },
    { MP_ROM_QSTR(MP_QSTR_encrypt_block),  MP_ROM_PTR(&aes_encrypt_block_obj) },
    { MP_ROM_QSTR(MP_QSTR_decrypt_block),  MP_ROM_PTR(&aes_decrypt_block_obj) },
    { MP_ROM_QSTR(MP_QSTR_ctr_xcrypt),     MP_ROM_PTR(&aes_ctr_xcrypt_obj) },
};
static MP_DEFINE_CONST_DICT(aes_module_globals, aes_module_globals_table);

const mp_obj_module_t aes_user_cmodule = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&aes_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR_aes, aes_user_cmodule);
