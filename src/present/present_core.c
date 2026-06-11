#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <omp.h> // Library tambahan untuk Multithreading

/* ── S-box, Inverse S-box, and Permutations ──────────────────────── */
static const uint8_t SBOX[16] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};
static const uint8_t INV_SBOX[16] = {0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};

static uint64_t player(uint64_t state) {
    uint64_t out = 0;
    for (int i = 0; i < 64; i++) {
        int dest = (i == 63) ? 63 : (i * 16) % 63;
        if ((state >> (63 - i)) & 1) out |= (uint64_t)1 << (63 - dest);
    }
    return out;
}

static uint64_t inv_player(uint64_t state) {
    uint64_t out = 0;
    for (int i = 0; i < 64; i++) {
        int dest = (i == 63) ? 63 : (i * 4) % 63;
        if ((state >> (63 - i)) & 1) out |= (uint64_t)1 << (63 - dest);
    }
    return out;
}

/* ── Key Schedule ────────────────────────────────────────────────── */
static void generate_round_keys(const uint8_t *key_bytes, uint64_t *round_keys) {
    uint64_t khi = 0, klo = 0;
    for (int i = 0; i < 8; i++) khi = (khi << 8) | key_bytes[i];
    klo = ((uint64_t)key_bytes[8] << 8) | key_bytes[9];
    klo <<= 48;

    for (int r = 0; r <= 31; r++) {
        round_keys[r] = khi;
        uint16_t lo16 = (uint16_t)(klo >> 48);
        uint64_t full_hi = khi;
        uint16_t full_lo = lo16;

        uint64_t tmp_lo = full_hi & 0x7FFFF;
        uint64_t rr_hi = (full_hi >> 19) | ((uint64_t)full_lo << 45);
        uint16_t rr_lo = (uint16_t)((full_hi >> 3) & 0xFFFF);

        uint8_t top4 = (uint8_t)(rr_hi >> 60);
        rr_hi = (rr_hi & UINT64_C(0x0FFFFFFFFFFFFFFF)) | ((uint64_t)SBOX[top4] << 60);
        uint64_t rc = (uint64_t)(r + 1) & 0x1F;
        rr_hi ^= (rc << 15);

        khi = rr_hi;
        klo = (uint64_t)rr_lo << 48;
    }
}

/* ── Public API: Encrypt Bulk ────────────────────────────────────── */
void present_encrypt_bulk(const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext, size_t len) {
    uint64_t round_keys[32];
    generate_round_keys(key, round_keys);

    /* Mengerahkan semua core CPU untuk membagi beban iterasi ini */
    #pragma omp parallel for
    for (size_t i = 0; i < len; i += 8) {
        uint64_t block = 0;
        for (int b = 0; b < 8; b++) block = (block << 8) | plaintext[i + b];

        for (int r = 0; r < 31; r++) {
            block ^= round_keys[r];
            uint64_t out = 0;
            for (int j = 0; j < 16; j++) {
                uint8_t nibble = (block >> (60 - j * 4)) & 0xF;
                out |= (uint64_t)SBOX[nibble] << (60 - j * 4);
            }
            block = player(out);
        }
        block ^= round_keys[31];

        for (int b = 7; b >= 0; b--) {
            ciphertext[i + b] = block & 0xFF;
            block >>= 8;
        }
    }
}

/* ── Public API: Decrypt Bulk ────────────────────────────────────── */
void present_decrypt_bulk(const uint8_t *key, const uint8_t *ciphertext, uint8_t *plaintext, size_t len) {
    uint64_t round_keys[32];
    generate_round_keys(key, round_keys);

    /* Mengerahkan semua core CPU untuk membagi beban iterasi ini */
    #pragma omp parallel for
    for (size_t i = 0; i < len; i += 8) {
        uint64_t block = 0;
        for (int b = 0; b < 8; b++) block = (block << 8) | ciphertext[i + b];

        block ^= round_keys[31];
        for (int r = 30; r >= 0; r--) {
            block = inv_player(block);
            uint64_t out = 0;
            for (int j = 0; j < 16; j++) {
                uint8_t nibble = (block >> (60 - j * 4)) & 0xF;
                out |= (uint64_t)INV_SBOX[nibble] << (60 - j * 4);
            }
            block = out;
            block ^= round_keys[r];
        }

        for (int b = 7; b >= 0; b--) {
            plaintext[i + b] = block & 0xFF;
            block >>= 8;
        }
    }
}
