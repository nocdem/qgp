/*
 * QGP AES-256 CBC Encryption
 *
 * AES-256 encryption using OpenSSL EVP interface.
 * Replaces SDK's dap_enc_code() / dap_enc_decode() functions.
 *
 * Security:
 * - AES-256-CBC mode
 * - Random IV per encryption (prepended to ciphertext)
 * - PKCS#7 padding (automatic via OpenSSL)
 */

#ifndef QGP_AES_H
#define QGP_AES_H

#include <stdint.h>
#include <stddef.h>

/**
 * Calculate required buffer size for AES-256-CBC encryption
 *
 * @param plaintext_len Length of plaintext to encrypt
 * @return Required ciphertext buffer size (includes IV + padding)
 *
 * Formula: 16 (IV) + plaintext_len + (16 - (plaintext_len % 16))
 */
size_t qgp_aes256_encrypt_size(size_t plaintext_len);

/**
 * Encrypt data with AES-256-CBC
 *
 * @param key 32-byte AES-256 key
 * @param plaintext Input plaintext data
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer (must be >= qgp_aes256_encrypt_size(plaintext_len))
 * @param ciphertext_len Output: actual ciphertext length (includes IV)
 * @return 0 on success, -1 on error
 *
 * Format: [IV (16 bytes)] [AES-256-CBC encrypted data + PKCS#7 padding]
 */
int qgp_aes256_encrypt(const uint8_t *key,
                       const uint8_t *plaintext, size_t plaintext_len,
                       uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * Decrypt data with AES-256-CBC
 *
 * @param key 32-byte AES-256 key
 * @param ciphertext Input ciphertext (must include IV at start)
 * @param ciphertext_len Length of ciphertext (includes IV)
 * @param plaintext Output buffer (must be >= ciphertext_len - 16)
 * @param plaintext_len Output: actual plaintext length
 * @return 0 on success, -1 on error
 *
 * Expects format: [IV (16 bytes)] [AES-256-CBC encrypted data]
 */
int qgp_aes256_decrypt(const uint8_t *key,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       uint8_t *plaintext, size_t *plaintext_len);

#endif /* QGP_AES_H */
