/*
 * RFC 3394 - AES Key Wrap Algorithm
 *
 * NIST-approved key wrapping using AES encryption.
 * Used for multi-recipient encryption to wrap the DEK (Data Encryption Key).
 *
 * References:
 * - RFC 3394: https://www.rfc-editor.org/rfc/rfc3394
 * - NIST SP 800-38F: Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping
 *
 * Security: AES-256 provides 128-bit quantum security (via Grover's algorithm)
 */

#include "aes_keywrap.h"
#include "dap_enc.h"
#include "dap_enc_key.h"
#include "dap_enc_iaes.h"
#include "dap_iaes_proto.h"
#include <string.h>
#include <stdlib.h>

// RFC 3394 default initial value (integrity check)
static const uint8_t RFC3394_IV[8] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};

/**
 * RFC 3394 AES Key Wrap
 *
 * Wraps a 256-bit key using AES-256 in Key Wrap mode.
 *
 * Algorithm (from RFC 3394):
 *   Inputs:  Plaintext (P), n 64-bit values {P1, P2, ..., Pn}
 *           Key Encryption Key (KEK), 256 bits
 *   Outputs: Ciphertext (C), (n+1) 64-bit values {C0, C1, ..., Cn}
 *
 *   1. Initialize variables:
 *      Set A = IV (0xA6A6A6A6A6A6A6A6)
 *      For i = 1 to n
 *          R[i] = P[i]
 *
 *   2. Calculate intermediate values (6*n iterations):
 *      For j = 0 to 5
 *          For i=1 to n
 *              B = AES(K, A | R[i])
 *              A = MSB(64, B) ^ t where t = (n*j)+i
 *              R[i] = LSB(64, B)
 *
 *   3. Output results:
 *      Set C[0] = A
 *      For i = 1 to n
 *          C[i] = R[i]
 *
 * @param key_to_wrap: 32-byte key to wrap (DEK)
 * @param key_size: Must be 32 bytes
 * @param kek: 32-byte Key Encryption Key (from Kyber512 shared secret)
 * @param wrapped_out: Output buffer (40 bytes)
 * @return: 0 on success, -1 on error
 */
int aes256_wrap_key(const uint8_t *key_to_wrap, size_t key_size,
                   const uint8_t *kek, uint8_t *wrapped_out) {

    if (!key_to_wrap || !kek || !wrapped_out) {
        return -1;
    }

    // Only support 32-byte keys (4 × 64-bit blocks)
    if (key_size != 32) {
        return -1;
    }

    const size_t n = 4;  // Number of 64-bit blocks in key_to_wrap
    uint64_t A;          // 64-bit integrity check register
    uint64_t R[4];       // 64-bit registers for key blocks

    // Initialize A with RFC 3394 IV
    memcpy(&A, RFC3394_IV, 8);

    // Initialize R with plaintext blocks (convert to big-endian 64-bit)
    for (size_t i = 0; i < n; i++) {
        R[i] = ((uint64_t)key_to_wrap[i*8 + 0] << 56) |
               ((uint64_t)key_to_wrap[i*8 + 1] << 48) |
               ((uint64_t)key_to_wrap[i*8 + 2] << 40) |
               ((uint64_t)key_to_wrap[i*8 + 3] << 32) |
               ((uint64_t)key_to_wrap[i*8 + 4] << 24) |
               ((uint64_t)key_to_wrap[i*8 + 5] << 16) |
               ((uint64_t)key_to_wrap[i*8 + 6] << 8) |
               ((uint64_t)key_to_wrap[i*8 + 7]);
    }

    // Prepare AES-256 key (8 × uint32_t = 32 bytes)
    uint32_t aes_key[8];
    memcpy(aes_key, kek, 32);

    // SDK's AES functions expect endian-swapped key
    swap_endian(aes_key, 8);

    // Main wrapping loop: 6*n iterations (RFC 3394 Section 2.2.1)
    for (size_t j = 0; j <= 5; j++) {
        for (size_t i = 0; i < n; i++) {
            // Construct B = A | R[i] (128-bit block for AES, 4 × uint32_t)
            uint32_t B[4];
            uint32_t encrypted[4];

            // Convert A and R[i] to uint32_t array (big-endian byte order)
            B[0] = (uint32_t)((A >> 32) & 0xFFFFFFFF);
            B[1] = (uint32_t)(A & 0xFFFFFFFF);
            B[2] = (uint32_t)((R[i] >> 32) & 0xFFFFFFFF);
            B[3] = (uint32_t)(R[i] & 0xFFFFFFFF);

            // B = AES-256-ECB(KEK, B) - raw block encryption
            AES256_enc_cernelT(B, encrypted, aes_key);

            // A = MSB(64, B) ^ t where t = n*j + i + 1
            uint64_t t = n * j + i + 1;
            A = ((uint64_t)encrypted[0] << 32) | (uint64_t)encrypted[1];
            A ^= t;

            // R[i] = LSB(64, B)
            R[i] = ((uint64_t)encrypted[2] << 32) | (uint64_t)encrypted[3];
        }
    }

    // Output: C[0] = A, C[1..n] = R[1..n] (convert back to bytes, big-endian)
    wrapped_out[0] = (A >> 56) & 0xFF;
    wrapped_out[1] = (A >> 48) & 0xFF;
    wrapped_out[2] = (A >> 40) & 0xFF;
    wrapped_out[3] = (A >> 32) & 0xFF;
    wrapped_out[4] = (A >> 24) & 0xFF;
    wrapped_out[5] = (A >> 16) & 0xFF;
    wrapped_out[6] = (A >> 8) & 0xFF;
    wrapped_out[7] = A & 0xFF;

    for (size_t i = 0; i < n; i++) {
        wrapped_out[8 + i*8 + 0] = (R[i] >> 56) & 0xFF;
        wrapped_out[8 + i*8 + 1] = (R[i] >> 48) & 0xFF;
        wrapped_out[8 + i*8 + 2] = (R[i] >> 40) & 0xFF;
        wrapped_out[8 + i*8 + 3] = (R[i] >> 32) & 0xFF;
        wrapped_out[8 + i*8 + 4] = (R[i] >> 24) & 0xFF;
        wrapped_out[8 + i*8 + 5] = (R[i] >> 16) & 0xFF;
        wrapped_out[8 + i*8 + 6] = (R[i] >> 8) & 0xFF;
        wrapped_out[8 + i*8 + 7] = R[i] & 0xFF;
    }

    return 0;
}

/**
 * RFC 3394 AES Key Unwrap
 *
 * Unwraps a key encrypted with aes256_wrap_key, verifying integrity.
 *
 * Algorithm (from RFC 3394 Section 2.2.2):
 *   Inputs:  Ciphertext (C), (n+1) 64-bit values {C0, C1, ..., Cn}
 *           Key Encryption Key (KEK), 256 bits
 *   Outputs: Plaintext (P), n 64-bit values {P1, P2, ..., Pn}
 *           or error if integrity check fails
 *
 *   1. Initialize variables:
 *      A = C[0]
 *      For i = 1 to n
 *          R[i] = C[i]
 *
 *   2. Calculate intermediate values (6*n iterations, reverse order):
 *      For j = 5 to 0
 *          For i = n to 1
 *              B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
 *              A = MSB(64, B)
 *              R[i] = LSB(64, B)
 *
 *   3. Verify integrity and output results:
 *      If A == IV
 *          For i = 1 to n
 *              P[i] = R[i]
 *      Else
 *          Return error (integrity check failed)
 *
 * @param wrapped_key: 40-byte wrapped key (from aes256_wrap_key)
 * @param wrapped_size: Must be 40 bytes
 * @param kek: 32-byte Key Encryption Key
 * @param unwrapped_out: Output buffer for 32-byte unwrapped key
 * @return: 0 on success, -1 on error or integrity check failure
 */
int aes256_unwrap_key(const uint8_t *wrapped_key, size_t wrapped_size,
                     const uint8_t *kek, uint8_t *unwrapped_out) {

    if (!wrapped_key || !kek || !unwrapped_out) {
        return -1;
    }

    // Expected size: 8-byte IV + 32-byte wrapped key = 40 bytes
    if (wrapped_size != 40) {
        return -1;
    }

    const size_t n = 4;  // Number of 64-bit blocks
    uint64_t A;          // Integrity check register
    uint64_t R[4];       // Key block registers

    // Initialize A from C[0]
    A = ((uint64_t)wrapped_key[0] << 56) |
        ((uint64_t)wrapped_key[1] << 48) |
        ((uint64_t)wrapped_key[2] << 40) |
        ((uint64_t)wrapped_key[3] << 32) |
        ((uint64_t)wrapped_key[4] << 24) |
        ((uint64_t)wrapped_key[5] << 16) |
        ((uint64_t)wrapped_key[6] << 8) |
        ((uint64_t)wrapped_key[7]);

    // Initialize R from C[1..n]
    for (size_t i = 0; i < n; i++) {
        R[i] = ((uint64_t)wrapped_key[8 + i*8 + 0] << 56) |
               ((uint64_t)wrapped_key[8 + i*8 + 1] << 48) |
               ((uint64_t)wrapped_key[8 + i*8 + 2] << 40) |
               ((uint64_t)wrapped_key[8 + i*8 + 3] << 32) |
               ((uint64_t)wrapped_key[8 + i*8 + 4] << 24) |
               ((uint64_t)wrapped_key[8 + i*8 + 5] << 16) |
               ((uint64_t)wrapped_key[8 + i*8 + 6] << 8) |
               ((uint64_t)wrapped_key[8 + i*8 + 7]);
    }

    // Prepare AES-256 key and decryption key schedule
    uint32_t aes_key[8];
    uint32_t decrypt_key[60];  // Decryption key schedule (15 rounds × 4 uint32_t)

    memcpy(aes_key, kek, 32);

    // SDK's AES functions expect endian-swapped key
    swap_endian(aes_key, 8);
    Key_Shedule_for_decrypT(aes_key, decrypt_key);

    // Main unwrapping loop: 6*n iterations (reverse order)
    for (int j = 5; j >= 0; j--) {
        for (int i = n - 1; i >= 0; i--) {
            // t = n*j + i + 1
            uint64_t t = n * j + i + 1;

            // Construct B = (A ^ t) | R[i] (128-bit block, 4 × uint32_t)
            uint64_t A_xor_t = A ^ t;
            uint32_t B[4];
            uint32_t decrypted[4];

            B[0] = (uint32_t)((A_xor_t >> 32) & 0xFFFFFFFF);
            B[1] = (uint32_t)(A_xor_t & 0xFFFFFFFF);
            B[2] = (uint32_t)((R[i] >> 32) & 0xFFFFFFFF);
            B[3] = (uint32_t)(R[i] & 0xFFFFFFFF);

            // B = AES-256-DEC(KEK, B) - raw block decryption
            AES256_dec_cernelT(B, decrypted, decrypt_key);

            // A = MSB(64, B)
            A = ((uint64_t)decrypted[0] << 32) | (uint64_t)decrypted[1];

            // R[i] = LSB(64, B)
            R[i] = ((uint64_t)decrypted[2] << 32) | (uint64_t)decrypted[3];
        }
    }

    // Verify integrity: A must equal RFC3394_IV
    uint64_t expected_A;
    memcpy(&expected_A, RFC3394_IV, 8);

    if (A != expected_A) {
        // Integrity check failed - wrong KEK or corrupted data
        return -1;
    }

    // Output unwrapped key (R[0..3] converted to bytes)
    for (size_t i = 0; i < n; i++) {
        unwrapped_out[i*8 + 0] = (R[i] >> 56) & 0xFF;
        unwrapped_out[i*8 + 1] = (R[i] >> 48) & 0xFF;
        unwrapped_out[i*8 + 2] = (R[i] >> 40) & 0xFF;
        unwrapped_out[i*8 + 3] = (R[i] >> 32) & 0xFF;
        unwrapped_out[i*8 + 4] = (R[i] >> 24) & 0xFF;
        unwrapped_out[i*8 + 5] = (R[i] >> 16) & 0xFF;
        unwrapped_out[i*8 + 6] = (R[i] >> 8) & 0xFF;
        unwrapped_out[i*8 + 7] = R[i] & 0xFF;
    }

    return 0;
}
