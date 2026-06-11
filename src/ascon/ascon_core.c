/*
 * ASCON-128 AEAD Implementation
 * Reference: NIST Lightweight Cryptography Standard (2023)
 * Adapted for Green Cryptography Index research benchmark
 *
 * ASCON-128:
 *   - Key:   128-bit (16 bytes)
 *   - Nonce: 128-bit (16 bytes)
 *   - Tag:   128-bit (16 bytes)
 *   - Rate:  64-bit (8 bytes per permutation round)
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ── ASCON constants ─────────────────────────────────────────── */
#define ASCON_128_IV   UINT64_C(0x80400c0600000000)
#define ROUNDS_A       12
#define ROUNDS_B       6
#define RATE           8   /* bytes */

typedef struct {
    uint64_t x0, x1, x2, x3, x4;
} ascon_state_t;

/* ── Round constants ─────────────────────────────────────────── */
static const uint64_t RC[12] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

/* ── Utility ─────────────────────────────────────────────────── */
static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t load64_be(const uint8_t *b) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] <<  8) | ((uint64_t)b[7]);
}

static inline void store64_be(uint8_t *b, uint64_t v) {
    b[0] = (v >> 56); b[1] = (v >> 48); b[2] = (v >> 40); b[3] = (v >> 32);
    b[4] = (v >> 24); b[5] = (v >> 16); b[6] = (v >>  8); b[7] = v;
}

/* ── ASCON permutation ───────────────────────────────────────── */
static void ascon_permutation(ascon_state_t *s, int rounds) {
    int start = 12 - rounds;
    for (int i = start; i < 12; i++) {
        /* Add round constant */
        s->x2 ^= RC[i];

        /* Substitution layer (5-bit S-box applied bitsliced) */
        s->x0 ^= s->x4; s->x4 ^= s->x3; s->x2 ^= s->x1;
        uint64_t t0 = s->x0, t1 = s->x1, t2 = s->x2, t3 = s->x3, t4 = s->x4;
        s->x0 = t0 ^ (~t1 & t2);
        s->x1 = t1 ^ (~t2 & t3);
        s->x2 = t2 ^ (~t3 & t4);
        s->x3 = t3 ^ (~t4 & t0);
        s->x4 = t4 ^ (~t0 & t1);
        s->x1 ^= s->x0; s->x0 ^= s->x4; s->x3 ^= s->x2; s->x2 = ~s->x2;

        /* Linear diffusion layer */
        s->x0 ^= rotr64(s->x0, 19) ^ rotr64(s->x0, 28);
        s->x1 ^= rotr64(s->x1, 61) ^ rotr64(s->x1, 39);
        s->x2 ^= rotr64(s->x2,  1) ^ rotr64(s->x2,  6);
        s->x3 ^= rotr64(s->x3, 10) ^ rotr64(s->x3, 17);
        s->x4 ^= rotr64(s->x4,  7) ^ rotr64(s->x4, 41);
    }
}

/* ── ASCON-128 Encrypt (AEAD) ────────────────────────────────── */
/*
 * Output layout: [ciphertext (mlen bytes)] [tag (16 bytes)]
 * output buffer must be at least mlen + 16 bytes.
 */
void encrypt_ascon128(
    const uint8_t *key,        /* 16 bytes */
    const uint8_t *nonce,      /* 16 bytes */
    const uint8_t *plaintext,  /* mlen bytes */
    uint8_t       *output,     /* mlen + 16 bytes */
    size_t         mlen)
{
    ascon_state_t s;

    /* ── Initialization ──────────────────────────────────────── */
    uint64_t K0 = load64_be(key);
    uint64_t K1 = load64_be(key + 8);
    uint64_t N0 = load64_be(nonce);
    uint64_t N1 = load64_be(nonce + 8);

    s.x0 = ASCON_128_IV;
    s.x1 = K0; s.x2 = K1;
    s.x3 = N0; s.x4 = N1;
    ascon_permutation(&s, ROUNDS_A);
    s.x3 ^= K0; s.x4 ^= K1;

    /* ── Associated data (empty — no AD in this benchmark) ───── */
    s.x4 ^= 1ULL;   /* domain separation for empty AD */

    /* ── Plaintext processing (absorb + squeeze) ─────────────── */
    size_t i = 0;
    while (i + RATE <= mlen) {
        uint64_t p = load64_be(plaintext + i);
        s.x0 ^= p;
        store64_be(output + i, s.x0);
        ascon_permutation(&s, ROUNDS_B);
        i += RATE;
    }

    /* Final partial block */
    size_t rem = mlen - i;
    uint8_t buf[8] = {0};
    memcpy(buf, plaintext + i, rem);
    buf[rem] = 0x80;  /* padding */
    uint64_t p = load64_be(buf);
    s.x0 ^= p;
    uint8_t outbuf[8];
    store64_be(outbuf, s.x0);
    memcpy(output + i, outbuf, rem);

    /* ── Finalization + tag generation ───────────────────────── */
    s.x1 ^= K0; s.x2 ^= K1;
    ascon_permutation(&s, ROUNDS_A);
    s.x3 ^= K0; s.x4 ^= K1;

    /* Write 16-byte tag at end of output */
    store64_be(output + mlen,     s.x3);
    store64_be(output + mlen + 8, s.x4);
}

/* ── ASCON-128 Decrypt (AEAD) ────────────────────────────────── */
int decrypt_ascon128(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    uint8_t       *output,
    const uint8_t *tag,
    size_t         mlen)
{
    ascon_state_t s;

    uint64_t K0 = load64_be(key);
    uint64_t K1 = load64_be(key + 8);
    uint64_t N0 = load64_be(nonce);
    uint64_t N1 = load64_be(nonce + 8);

    s.x0 = ASCON_128_IV;
    s.x1 = K0; s.x2 = K1;
    s.x3 = N0; s.x4 = N1;
    ascon_permutation(&s, ROUNDS_A);
    s.x3 ^= K0; s.x4 ^= K1;

    s.x4 ^= 1ULL;

    size_t i = 0;
    while (i + RATE <= mlen) {
        uint64_t c = load64_be(ciphertext + i);
        uint64_t p = s.x0 ^ c;
        store64_be(output + i, p);
        s.x0 = c;
        ascon_permutation(&s, ROUNDS_B);
        i += RATE;
    }

    size_t rem = mlen - i;
    uint8_t buf[8] = {0};
    memcpy(buf, ciphertext + i, rem);
    buf[rem] = 0x80;
    uint64_t c_last = load64_be(buf);
    uint64_t p_last = s.x0 ^ c_last;
    uint8_t outbuf[8] = {0};
    store64_be(outbuf, p_last);
    memcpy(output + i, outbuf, rem);

    uint8_t padbuf[8] = {0};
    store64_be(padbuf, s.x0);
    memcpy(padbuf, ciphertext + i, rem);
    padbuf[rem] = 0x80;
    s.x0 = load64_be(padbuf);

    s.x1 ^= K0; s.x2 ^= K1;
    ascon_permutation(&s, ROUNDS_A);
    s.x3 ^= K0; s.x4 ^= K1;

    uint8_t expected_tag[16];
    store64_be(expected_tag,     s.x3);
    store64_be(expected_tag + 8, s.x4);

    uint8_t diff = 0;
    for (int j = 0; j < 16; j++) diff |= (expected_tag[j] ^ tag[j]);
    return (diff == 0) ? 0 : -1;
}
