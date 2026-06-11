#include <mbedtls/aes.h>
#include <string.h>

// Encryption Function
void encrypt_aes128(unsigned char *key, unsigned char *iv, unsigned char *input, unsigned char *output, size_t length) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128); 
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv, input, output);
    mbedtls_aes_free(&aes);
}

// Decryption Function
void decrypt_aes128(unsigned char *key, unsigned char *iv, unsigned char *input, unsigned char *output, size_t length) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128); 
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iv, input, output);
    mbedtls_aes_free(&aes);
}
