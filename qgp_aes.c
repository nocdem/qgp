/*
 * QGP AES-256 CBC Encryption
 *
 * OpenSSL-based AES-256-CBC implementation.
 */

#include "qgp_aes.h"
#include "qgp_random.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/**
 * Calculate required buffer size for AES-256-CBC encryption
 *
 * AES-256-CBC with PKCS#7 padding requires:
 * - 16 bytes for IV (prepended)
 * - plaintext_len rounded up to next 16-byte block
 * - At least 1 byte of padding (PKCS#7 always pads)
 */
size_t qgp_aes256_encrypt_size(size_t plaintext_len) {
    // IV size + plaintext + padding
    // Padding: round up to next 16-byte block
    size_t padded_len = plaintext_len + (16 - (plaintext_len % 16));
    return 16 + padded_len;
}

/**
 * Encrypt data with AES-256-CBC
 *
 * Uses OpenSSL EVP interface for AES-256-CBC with PKCS#7 padding.
 * Generates random IV and prepends it to ciphertext.
 */
int qgp_aes256_encrypt(const uint8_t *key,
                       const uint8_t *plaintext, size_t plaintext_len,
                       uint8_t *ciphertext, size_t *ciphertext_len) {
    if (!key || !plaintext || !ciphertext || !ciphertext_len) {
        fprintf(stderr, "qgp_aes256_encrypt: NULL parameter\n");
        return -1;
    }

    if (plaintext_len == 0) {
        fprintf(stderr, "qgp_aes256_encrypt: Empty plaintext\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t iv[16];
    int len;
    int ciphertext_len_tmp = 0;
    int ret = -1;

    // Generate random IV
    if (qgp_randombytes(iv, 16) != 0) {
        fprintf(stderr, "qgp_aes256_encrypt: Failed to generate IV\n");
        goto cleanup;
    }

    // Create and initialize context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "qgp_aes256_encrypt: Failed to create context\n");
        goto cleanup;
    }

    // Initialize encryption: AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "qgp_aes256_encrypt: EVP_EncryptInit_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Prepend IV to ciphertext
    memcpy(ciphertext, iv, 16);

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext + 16, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "qgp_aes256_encrypt: EVP_EncryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    ciphertext_len_tmp = len;

    // Finalize encryption (adds PKCS#7 padding)
    if (EVP_EncryptFinal_ex(ctx, ciphertext + 16 + len, &len) != 1) {
        fprintf(stderr, "qgp_aes256_encrypt: EVP_EncryptFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    ciphertext_len_tmp += len;

    // Total ciphertext length = IV (16) + encrypted data
    *ciphertext_len = 16 + ciphertext_len_tmp;
    ret = 0;

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    // Wipe IV from stack
    memset(iv, 0, sizeof(iv));

    return ret;
}

/**
 * Decrypt data with AES-256-CBC
 *
 * Uses OpenSSL EVP interface for AES-256-CBC with PKCS#7 padding.
 * Expects IV prepended to ciphertext.
 */
int qgp_aes256_decrypt(const uint8_t *key,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       uint8_t *plaintext, size_t *plaintext_len) {
    if (!key || !ciphertext || !plaintext || !plaintext_len) {
        fprintf(stderr, "qgp_aes256_decrypt: NULL parameter\n");
        return -1;
    }

    if (ciphertext_len < 16) {
        fprintf(stderr, "qgp_aes256_decrypt: Ciphertext too short (no IV)\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t iv[16];
    int len;
    int plaintext_len_tmp = 0;
    int ret = -1;

    // Extract IV from ciphertext
    memcpy(iv, ciphertext, 16);

    // Create and initialize context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "qgp_aes256_decrypt: Failed to create context\n");
        goto cleanup;
    }

    // Initialize decryption: AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "qgp_aes256_decrypt: EVP_DecryptInit_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Decrypt ciphertext (skip first 16 bytes which is IV)
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + 16, ciphertext_len - 16) != 1) {
        fprintf(stderr, "qgp_aes256_decrypt: EVP_DecryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    plaintext_len_tmp = len;

    // Finalize decryption (removes PKCS#7 padding)
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "qgp_aes256_decrypt: EVP_DecryptFinal_ex failed (padding error?)\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    plaintext_len_tmp += len;

    *plaintext_len = plaintext_len_tmp;
    ret = 0;

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    // Wipe IV from stack
    memset(iv, 0, sizeof(iv));

    return ret;
}
