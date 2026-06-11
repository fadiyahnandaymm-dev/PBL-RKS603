#include <stdint.h>
#include <string.h>

#define ROR(x,r) (((x) >> (r)) | ((x) << (64 - (r))))
#define ROL(x,r) (((x) << (r)) | ((x) >> (64 - (r))))

#define SPECK_ROUNDS 32

static void speck_expand_key(const uint64_t K[2], uint64_t rk[SPECK_ROUNDS]) {
    uint64_t b = K[0];
    uint64_t a = K[1];

    rk[0] = b;

    for (int i = 0; i < SPECK_ROUNDS - 1; i++) {
        a = (ROR(a, 8) + b) ^ i;
        b = ROL(b, 3) ^ a;
        rk[i + 1] = b;
    }
}

static void speck_encrypt_block(uint64_t *x, uint64_t *y, uint64_t rk[SPECK_ROUNDS]) {
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        *x = (ROR(*x, 8) + *y) ^ rk[i];
        *y = ROL(*y, 3) ^ *x;
    }
}

static void speck_decrypt_block(uint64_t *x, uint64_t *y, uint64_t rk[SPECK_ROUNDS]) {
    for (int i = SPECK_ROUNDS - 1; i >= 0; i--) {
        *y = ROR((*y ^ *x), 3);
        *x = ROL(((*x ^ rk[i]) - *y), 8);
    }
}

void encrypt_speck128(
    unsigned char *key,
    unsigned char *iv,
    unsigned char *input,
    unsigned char *output,
    size_t length
) {
    uint64_t round_keys[SPECK_ROUNDS];

    speck_expand_key((uint64_t*)key, round_keys);

    unsigned char current_iv[16];
    memcpy(current_iv, iv, 16);

    for(size_t i = 0; i < length; i += 16) {

        unsigned char block[16];

        for(int j = 0; j < 16; j++)
            block[j] = input[i+j] ^ current_iv[j];

        uint64_t *x = (uint64_t*)block;
        uint64_t *y = (uint64_t*)(block + 8);

        speck_encrypt_block(x, y, round_keys);

        memcpy(output + i, block, 16);
        memcpy(current_iv, block, 16);
    }
}

void decrypt_speck128(
    unsigned char *key,
    unsigned char *iv,
    unsigned char *input,
    unsigned char *output,
    size_t length
) {
    uint64_t round_keys[SPECK_ROUNDS];

    speck_expand_key((uint64_t*)key, round_keys);

    unsigned char current_iv[16];
    memcpy(current_iv, iv, 16);

    for(size_t i = 0; i < length; i += 16) {

        unsigned char block[16];
        unsigned char cipher_copy[16];

        memcpy(block, input + i, 16);
        memcpy(cipher_copy, block, 16);

        uint64_t *x = (uint64_t*)block;
        uint64_t *y = (uint64_t*)(block + 8);

        speck_decrypt_block(x, y, round_keys);

        for(int j = 0; j < 16; j++)
            block[j] ^= current_iv[j];

        memcpy(output + i, block, 16);
        memcpy(current_iv, cipher_copy, 16);
    }
}
