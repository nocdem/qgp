/*
 * pqsignum - File decryption using Kyber512 KEM + AES-256
 *
 * Protocol Mode: Uses only verified SDK functions
 * - Kyber512 KEM for key decapsulation (post-quantum)
 * - AES-256 CBC for file decryption
 * - Hybrid decryption: Kyber.Decap() → session key → AES-256
 *
 * Security Model:
 * - Kyber512 private key decapsulation (768-byte ciphertext → 32-byte shared secret)
 * - AES-256 CBC decryption of file with derived key
 * - Round-trip verification mandatory
 */

#include "qgp.h"
#include "dap_enc_kyber.h"
#include "dap_cert_file.h"  // For dap_cert_file_hdr_t
#include "aes_keywrap.h"

// File format for Kyber-encrypted files (must match encrypt.c)
#define PQSIGNUM_ENC_MAGIC "PQSIGENC"
#define PQSIGNUM_ENC_VERSION_V2 0x02  // Version 2: Kyber KEM mode (no signature)
#define PQSIGNUM_ENC_VERSION_V3 0x03  // Version 3: Kyber KEM + signature (single recipient)
#define PQSIGNUM_ENC_VERSION_V4 0x04  // Version 4: Multi-recipient

// Version 2 header (backward compatibility)
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x02
    uint8_t enc_key_type;       // DAP_ENC_KEY_TYPE_KEM_KYBER512
    uint8_t reserved[2];        // Reserved
    uint32_t ciphertext_size;   // Kyber ciphertext size (768 bytes)
} __attribute__((packed)) pqsignum_enc_header_v2_t;

// Version 3 header (with signature, single recipient)
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x03
    uint8_t enc_key_type;       // DAP_ENC_KEY_TYPE_KEM_KYBER512
    uint8_t reserved[2];        // Reserved
    uint32_t ciphertext_size;   // Kyber ciphertext size (768 bytes)
    uint32_t signature_size;    // Signature size (appended after encrypted data)
} __attribute__((packed)) pqsignum_enc_header_v3_t;

// Version 4 header (multi-recipient)
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x04
    uint8_t enc_key_type;       // DAP_ENC_KEY_TYPE_KEM_KYBER512
    uint8_t recipient_count;    // Number of recipients (1-255)
    uint8_t reserved;
    uint32_t encrypted_size;    // Size of encrypted data
    uint32_t signature_size;    // Size of signature
} __attribute__((packed)) pqsignum_enc_header_v4_t;

// Recipient entry for multi-recipient encryption
typedef struct {
    uint8_t kyber_ciphertext[768];    // Kyber512 ciphertext (encapsulated shared secret)
    uint8_t wrapped_dek[40];          // AES-wrapped DEK (32-byte DEK + 8-byte IV)
} __attribute__((packed)) recipient_entry_t;

/**
 * Decrypt file using Kyber512 KEM + AES-256
 *
 * Protocol Mode decryption workflow:
 * 1. Load recipient's private Kyber512 key from certificate
 * 2. Read encrypted file: [header | kyber_ciphertext (768 bytes) | encrypted_file]
 * 3. Decapsulate: Kyber512.Decap(ciphertext, privkey) → shared_secret
 * 4. Derive AES-256 key from shared_secret
 * 5. Decrypt file with AES-256 CBC
 * 6. Save decrypted file
 *
 * @param input_file: Encrypted file (.enc)
 * @param output_file: Output decrypted file
 * @param cert_path: Path to recipient's encryption certificate (<name>-enc.dcert)
 * @return: 0 on success, non-zero on error
 */
int cmd_decrypt_file(const char *input_file, const char *output_file, const char *key_path) {
    dap_enc_key_t *enc_key = NULL;
    uint8_t *kyber_ciphertext = NULL;
    uint8_t *encrypted_data = NULL;
    uint8_t *decrypted_data = NULL;
    uint8_t *signature_data = NULL;
    dap_sign_t *signature = NULL;
    size_t encrypted_size = 0;
    size_t decrypted_size = 0;
    size_t signature_size = 0;
    uint8_t file_version = 0;
    FILE *out_fp = NULL;
    int ret = EXIT_ERROR;

    printf("Decrypting file with Kyber512 KEM + AES-256\n");
    printf("  Input file: %s\n", input_file);
    printf("  Output file: %s\n", output_file);
    printf("  Encryption key: %s\n", key_path);

    // ======================================================================
    // STEP 1: Load encryption key from PQSigNum format
    // ======================================================================

    printf("\n[1/5] Loading encryption key...\n");

    if (!file_exists(key_path)) {
        fprintf(stderr, "Error: Encryption key not found: %s\n", key_path);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }

    if (pqsignum_load_privkey(key_path, &enc_key) != 0) {
        fprintf(stderr, "Error: Failed to load encryption key\n");
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }

    // Verify it's a Kyber512 encryption key
    if (enc_key->type != DAP_ENC_KEY_TYPE_KEM_KYBER512) {
        fprintf(stderr, "Error: Key is not a Kyber512 encryption key (type: %d)\n", enc_key->type);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }

    printf("  ✓ Encryption key loaded\n");

    // ======================================================================
    // STEP 2: Read encrypted file
    // ======================================================================

    printf("\n[2/5] Reading encrypted file...\n");

    FILE *in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Read generic header (first read enough bytes to get version)
    uint8_t header_buf[32];  // Enough for both header types
    if (fread(header_buf, 1, sizeof(header_buf), in_fp) != sizeof(header_buf)) {
        fprintf(stderr, "Error: Failed to read file header\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Validate magic
    if (memcmp(header_buf, PQSIGNUM_ENC_MAGIC, 8) != 0) {
        fprintf(stderr, "Error: Invalid file format (bad magic)\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Get version
    file_version = header_buf[8];

    // Handle different versions
    uint32_t kyber_ct_size = 0;
    size_t header_size = 0;

    if (file_version == PQSIGNUM_ENC_VERSION_V2) {
        // Version 2: No signature
        pqsignum_enc_header_v2_t *hdr_v2 = (pqsignum_enc_header_v2_t*)header_buf;

        if (hdr_v2->enc_key_type != DAP_ENC_KEY_TYPE_KEM_KYBER512) {
            fprintf(stderr, "Error: File not encrypted with Kyber512 KEM\n");
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        kyber_ct_size = hdr_v2->ciphertext_size;
        header_size = sizeof(pqsignum_enc_header_v2_t);
        signature_size = 0;  // No signature in v2

        printf("  ✓ File format: Version 2 (no signature)\n");

    } else if (file_version == PQSIGNUM_ENC_VERSION_V3) {
        // Version 3: With signature (single recipient)
        pqsignum_enc_header_v3_t *hdr_v3 = (pqsignum_enc_header_v3_t*)header_buf;

        if (hdr_v3->enc_key_type != DAP_ENC_KEY_TYPE_KEM_KYBER512) {
            fprintf(stderr, "Error: File not encrypted with Kyber512 KEM\n");
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        kyber_ct_size = hdr_v3->ciphertext_size;
        signature_size = hdr_v3->signature_size;
        header_size = sizeof(pqsignum_enc_header_v3_t);

        printf("  ✓ File format: Version 3 (single recipient with signature)\n");
        printf("  ✓ Signature size: %zu bytes\n", signature_size);

    } else if (file_version == PQSIGNUM_ENC_VERSION_V4) {
        // Version 4: Multi-recipient - route to dedicated function
        fclose(in_fp);
        if (enc_key) dap_enc_key_delete(enc_key);
        return cmd_decrypt_file_multi(input_file, output_file, key_path);

    } else {
        fprintf(stderr, "Error: Unsupported file version: 0x%02x\n", file_version);
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (kyber_ct_size != 768) {
        fprintf(stderr, "Error: Invalid Kyber ciphertext size: %u (expected 768)\n", kyber_ct_size);
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("  ✓ File format validated\n");

    // Seek back to start of file and skip header
    fseek(in_fp, header_size, SEEK_SET);

    // Read Kyber ciphertext
    kyber_ciphertext = malloc(768);
    if (!kyber_ciphertext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (fread(kyber_ciphertext, 1, 768, in_fp) != 768) {
        fprintf(stderr, "Error: Failed to read Kyber ciphertext\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("  ✓ Kyber ciphertext read: 768 bytes\n");

    // Read encrypted file data
    fseek(in_fp, 0, SEEK_END);
    long file_size = ftell(in_fp);

    // Calculate encrypted data size (exclude header, kyber ct, and signature if present)
    encrypted_size = file_size - header_size - 768 - signature_size;

    fseek(in_fp, header_size + 768, SEEK_SET);
    encrypted_data = malloc(encrypted_size);
    if (!encrypted_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (fread(encrypted_data, 1, encrypted_size, in_fp) != encrypted_size) {
        fprintf(stderr, "Error: Failed to read encrypted data\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("  ✓ Encrypted data read: %zu bytes\n", encrypted_size);

    // Read signature if present (v3 files)
    if (signature_size > 0) {
        signature_data = malloc(signature_size);
        if (!signature_data) {
            fprintf(stderr, "Error: Memory allocation failed for signature\n");
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        if (fread(signature_data, 1, signature_size, in_fp) != signature_size) {
            fprintf(stderr, "Error: Failed to read signature\n");
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        printf("  ✓ Signature read: %zu bytes\n", signature_size);
        signature = (dap_sign_t*)signature_data;
    }

    fclose(in_fp);

    // ======================================================================
    // STEP 3: Decapsulate - Recover shared secret from Kyber ciphertext
    // ======================================================================

    printf("\n[3/5] Performing Kyber512 key decapsulation...\n");

    // Kyber private key is in _inheritor field
    uint8_t *privkey_bytes = enc_key->_inheritor;
    size_t privkey_size = enc_key->_inheritor_size;

    if (!privkey_bytes || privkey_size != 1632) {
        fprintf(stderr, "Error: Invalid private key (expected 1632 bytes, got %zu)\n", privkey_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ Private key accessed: 1632 bytes\n");

    // Perform decapsulation (recover shared secret)
    size_t shared_secret_size = dap_enc_kyber512_gen_alice_shared_key(
        enc_key,               // Alice's key (recipient)
        privkey_bytes,         // Alice's private key
        768,                   // Ciphertext size
        kyber_ciphertext       // Ciphertext to decapsulate
    );

    if (shared_secret_size != 32) {
        fprintf(stderr, "Error: Kyber512 decapsulation failed (expected 32 bytes, got %zu)\n", shared_secret_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ Kyber512 decapsulation successful\n");
    printf("  ✓ Shared secret recovered: 32 bytes\n");

    // enc_key now contains the 32-byte shared secret in priv_key_data
    // Extract the shared secret for AES-256 decryption
    if (!enc_key->priv_key_data || enc_key->priv_key_data_size != 32) {
        fprintf(stderr, "Error: Invalid shared secret size (expected 32 bytes, got %zu)\n",
                enc_key->priv_key_data_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    uint8_t *shared_secret = enc_key->priv_key_data;

    // ======================================================================
    // STEP 4: Decrypt with AES-256 using shared secret
    // ======================================================================

    printf("\n[4/5] Decrypting file with AES-256 CBC...\n");

    // Create AES key from shared secret (32 bytes = 256 bits)
    dap_enc_key_t *aes_key = dap_enc_key_new_generate(
        DAP_ENC_KEY_TYPE_IAES,     // AES
        NULL, 0,                    // No KEX
        shared_secret, 32,          // Use shared secret as seed
        256                         // AES-256
    );

    if (!aes_key) {
        fprintf(stderr, "Error: Failed to create AES-256 key from shared secret\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Calculate required output buffer size for AES decryption
    size_t decrypt_buf_size = dap_enc_decode_out_size(aes_key, encrypted_size, DAP_ENC_DATA_TYPE_RAW);
    if (decrypt_buf_size == 0) {
        fprintf(stderr, "Error: Failed to calculate AES decryption output size\n");
        dap_enc_key_delete(aes_key);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    decrypted_data = malloc(decrypt_buf_size);
    if (!decrypted_data) {
        fprintf(stderr, "Error: Memory allocation failed for decrypted data\n");
        dap_enc_key_delete(aes_key);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Decrypt with AES-256
    decrypted_size = dap_enc_decode(
        aes_key,                // AES key derived from shared secret
        encrypted_data,         // Input encrypted data
        encrypted_size,         // Input size
        decrypted_data,         // Output buffer
        decrypt_buf_size,       // Output buffer size
        DAP_ENC_DATA_TYPE_RAW   // Raw decryption mode
    );

    dap_enc_key_delete(aes_key);  // Delete AES key after use

    if (decrypted_size == 0) {
        fprintf(stderr, "Error: AES-256 decryption failed\n");
        fprintf(stderr, "This file may not be encrypted for your key\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ File decrypted successfully\n");
    printf("  ✓ Decrypted size: %zu bytes\n", decrypted_size);

    // ======================================================================
    // STEP 5: Verify signature (if present)
    // ======================================================================

    if (signature) {
        printf("\n[5/6] Verifying signature...\n");

        // Extract signer's public key hash from signature
        dap_chain_hash_fast_t signer_pkey_hash;
        if (dap_sign_get_pkey_hash(signature, &signer_pkey_hash)) {
            char hash_str[70];
            dap_chain_hash_fast_to_str(&signer_pkey_hash, hash_str, sizeof(hash_str));
            printf("  Signer public key hash: %s\n", hash_str);
        }

        // Verify signature against decrypted data
        if (dap_sign_verify(signature, decrypted_data, decrypted_size) == 0) {
            printf("  ✓ Signature verified successfully\n");
            printf("  ✓ File authenticity confirmed\n");
            printf("  ✓ Algorithm: %s\n", get_signature_algorithm_name(signature));
        } else {
            fprintf(stderr, "  ✗ WARNING: Signature verification FAILED\n");
            fprintf(stderr, "  ✗ File may have been tampered with or sent by wrong sender\n");
            fprintf(stderr, "  ✗ Decryption succeeded but signature is invalid\n");
            printf("\nDo you want to save the decrypted file anyway? [y/N]: ");
            char response[10];
            if (fgets(response, sizeof(response), stdin) == NULL ||
                (response[0] != 'y' && response[0] != 'Y')) {
                printf("Aborted. File not saved.\n");
                ret = EXIT_CRYPTO_ERROR;
                goto cleanup;
            }
        }
    } else {
        printf("\n[5/6] No signature present (old format or unsigned file)\n");
        printf("  ⚠ Warning: File authenticity cannot be verified\n");
    }

    // ======================================================================
    // STEP 6: Write output file
    // ======================================================================

    printf("\n[6/6] Writing decrypted file...\n");

    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", output_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (fwrite(decrypted_data, 1, decrypted_size, out_fp) != decrypted_size) {
        fprintf(stderr, "Error: Failed to write decrypted data\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fclose(out_fp);
    out_fp = NULL;

    printf("  ✓ Decrypted file written\n");

    printf("\n✓ File decrypted successfully!\n");
    printf("\nOutput file: %s\n", output_file);
    printf("  Decrypted size: %zu bytes\n", decrypted_size);

    ret = EXIT_SUCCESS;

cleanup:
    if (kyber_ciphertext) free(kyber_ciphertext);
    if (encrypted_data) free(encrypted_data);
    if (decrypted_data) {
        memset(decrypted_data, 0, decrypted_size);  // Wipe decrypted data
        free(decrypted_data);
    }
    if (signature_data) free(signature_data);  // signature points to signature_data, don't double-free
    if (out_fp) fclose(out_fp);
    if (enc_key) dap_enc_key_delete(enc_key);

    return ret;
}

/**
 * Decrypt multi-recipient file using Kyber512 KEM + AES-256
 *
 * Multi-recipient decryption workflow:
 * 1. Load recipient's private Kyber512 key
 * 2. Read file header and all recipient entries
 * 3. Try each recipient entry to find matching one:
 *    - Decapsulate Kyber ciphertext → KEK (Key Encryption Key)
 *    - Unwrap DEK using KEK
 *    - If unwrap succeeds, we found our entry
 * 4. Decrypt file with DEK using AES-256 CBC
 * 5. Verify signature
 * 6. Save decrypted file
 *
 * @param input_file: Encrypted file (.enc)
 * @param output_file: Output decrypted file
 * @param key_path: Path to recipient's encryption key
 * @return: 0 on success, non-zero on error
 */
int cmd_decrypt_file_multi(const char *input_file, const char *output_file, const char *key_path) {
    dap_enc_key_t *enc_key = NULL;
    recipient_entry_t *recipient_entries = NULL;
    uint8_t *encrypted_data = NULL;
    uint8_t *decrypted_data = NULL;
    uint8_t *signature_data = NULL;
    uint8_t *dek = NULL;
    dap_sign_t *signature = NULL;
    size_t encrypted_size = 0;
    size_t decrypted_size = 0;
    size_t signature_size = 0;
    uint8_t recipient_count = 0;
    FILE *out_fp = NULL;
    int ret = EXIT_ERROR;
    int found_entry = -1;

    printf("Decrypting multi-recipient file with Kyber512 KEM + AES-256\n");
    printf("  Input file: %s\n", input_file);
    printf("  Output file: %s\n", output_file);
    printf("  Encryption key: %s\n", key_path);

    // ======================================================================
    // STEP 1: Load encryption key
    // ======================================================================

    printf("\n[1/6] Loading encryption key...\n");

    if (!file_exists(key_path)) {
        fprintf(stderr, "Error: Encryption key not found: %s\n", key_path);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }

    if (pqsignum_load_privkey(key_path, &enc_key) != 0) {
        fprintf(stderr, "Error: Failed to load encryption key\n");
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }

    // Verify it's a Kyber512 encryption key
    if (enc_key->type != DAP_ENC_KEY_TYPE_KEM_KYBER512) {
        fprintf(stderr, "Error: Key is not a Kyber512 encryption key (type: %d)\n", enc_key->type);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }

    printf("  ✓ Encryption key loaded\n");

    // ======================================================================
    // STEP 2: Read file header
    // ======================================================================

    printf("\n[2/6] Reading file header...\n");

    FILE *in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Read v0.04 header
    pqsignum_enc_header_v4_t header;
    if (fread(&header, 1, sizeof(header), in_fp) != sizeof(header)) {
        fprintf(stderr, "Error: Failed to read file header\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Validate header
    if (memcmp(header.magic, PQSIGNUM_ENC_MAGIC, 8) != 0) {
        fprintf(stderr, "Error: Invalid file format (bad magic)\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (header.version != PQSIGNUM_ENC_VERSION_V4) {
        fprintf(stderr, "Error: Not a multi-recipient file (version: 0x%02x)\n", header.version);
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (header.enc_key_type != DAP_ENC_KEY_TYPE_KEM_KYBER512) {
        fprintf(stderr, "Error: File not encrypted with Kyber512 KEM\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    recipient_count = header.recipient_count;
    encrypted_size = header.encrypted_size;
    signature_size = header.signature_size;

    printf("  ✓ File format: Version 4 (multi-recipient)\n");
    printf("  ✓ Recipients: %u\n", recipient_count);
    printf("  ✓ Encrypted size: %zu bytes\n", encrypted_size);
    printf("  ✓ Signature size: %zu bytes\n", signature_size);

    // ======================================================================
    // STEP 3: Read all recipient entries
    // ======================================================================

    printf("\n[3/6] Reading recipient entries...\n");

    recipient_entries = calloc(recipient_count, sizeof(recipient_entry_t));
    if (!recipient_entries) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    for (int i = 0; i < recipient_count; i++) {
        if (fread(&recipient_entries[i], 1, sizeof(recipient_entry_t), in_fp) != sizeof(recipient_entry_t)) {
            fprintf(stderr, "Error: Failed to read recipient entry %d\n", i+1);
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }
    }

    printf("  ✓ Read %u recipient entries (%zu bytes each)\n", recipient_count, sizeof(recipient_entry_t));

    // ======================================================================
    // STEP 4: Try each recipient entry to find ours
    // ======================================================================

    printf("\n[4/6] Finding matching recipient entry...\n");

    // Get private key
    uint8_t *privkey_bytes = enc_key->_inheritor;
    size_t privkey_size = enc_key->_inheritor_size;

    if (!privkey_bytes || privkey_size != 1632) {
        fprintf(stderr, "Error: Invalid private key (expected 1632 bytes, got %zu)\n", privkey_size);
        fclose(in_fp);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    dek = malloc(32);
    if (!dek) {
        fprintf(stderr, "Error: Memory allocation failed for DEK\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    for (int i = 0; i < recipient_count; i++) {
        printf("  Trying recipient entry %d/%u...\n", i+1, recipient_count);

        // Decapsulate to get KEK using our private key
        size_t shared_secret_size = dap_enc_kyber512_gen_alice_shared_key(
            enc_key,               // Use Alice's key (our encryption key)
            privkey_bytes,         // Alice's private key
            768,                   // Ciphertext size
            recipient_entries[i].kyber_ciphertext  // Try this entry's ciphertext
        );

        if (shared_secret_size != 32 || !enc_key->priv_key_data) {
            printf("    ✗ Decapsulation failed\n");
            continue;
        }

        uint8_t *kek = enc_key->priv_key_data;  // KEK = shared secret

        // Try to unwrap DEK with this KEK
        if (aes256_unwrap_key(recipient_entries[i].wrapped_dek, 40, kek, dek) == 0) {
            // Success! This is our entry
            printf("    ✓ Found matching entry: %d/%u\n", i+1, recipient_count);
            found_entry = i;
            break;
        }

        printf("    ✗ DEK unwrap failed\n");
    }

    if (found_entry == -1) {
        fprintf(stderr, "Error: File not encrypted for your key\n");
        fprintf(stderr, "Tried all %u recipient entries - none matched\n", recipient_count);
        fclose(in_fp);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ DEK unwrapped successfully\n");

    // ======================================================================
    // STEP 5: Read encrypted data and signature
    // ======================================================================

    printf("\n[5/6] Reading encrypted data...\n");

    encrypted_data = malloc(encrypted_size);
    if (!encrypted_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (fread(encrypted_data, 1, encrypted_size, in_fp) != encrypted_size) {
        fprintf(stderr, "Error: Failed to read encrypted data\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("  ✓ Encrypted data read: %zu bytes\n", encrypted_size);

    // Read signature
    if (signature_size > 0) {
        signature_data = malloc(signature_size);
        if (!signature_data) {
            fprintf(stderr, "Error: Memory allocation failed for signature\n");
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        if (fread(signature_data, 1, signature_size, in_fp) != signature_size) {
            fprintf(stderr, "Error: Failed to read signature\n");
            fclose(in_fp);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        printf("  ✓ Signature read: %zu bytes\n", signature_size);
        signature = (dap_sign_t*)signature_data;
    }

    fclose(in_fp);

    // ======================================================================
    // STEP 6: Decrypt with DEK using AES-256
    // ======================================================================

    printf("\n[6/7] Decrypting file with AES-256 CBC using DEK...\n");

    // Create AES key from DEK
    dap_enc_key_t *aes_key = dap_enc_key_new_generate(
        DAP_ENC_KEY_TYPE_IAES,     // AES
        NULL, 0,                    // No KEX
        dek, 32,                    // Use DEK as seed
        256                         // AES-256
    );

    if (!aes_key) {
        fprintf(stderr, "Error: Failed to create AES-256 key from DEK\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Calculate required output buffer size for AES decryption
    size_t decrypt_buf_size = dap_enc_decode_out_size(aes_key, encrypted_size, DAP_ENC_DATA_TYPE_RAW);
    if (decrypt_buf_size == 0) {
        fprintf(stderr, "Error: Failed to calculate AES decryption output size\n");
        dap_enc_key_delete(aes_key);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    decrypted_data = malloc(decrypt_buf_size);
    if (!decrypted_data) {
        fprintf(stderr, "Error: Memory allocation failed for decrypted data\n");
        dap_enc_key_delete(aes_key);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Decrypt with AES-256
    decrypted_size = dap_enc_decode(
        aes_key,                // AES key derived from DEK
        encrypted_data,         // Input encrypted data
        encrypted_size,         // Input size
        decrypted_data,         // Output buffer
        decrypt_buf_size,       // Output buffer size
        DAP_ENC_DATA_TYPE_RAW   // Raw decryption mode
    );

    dap_enc_key_delete(aes_key);  // Delete AES key after use

    if (decrypted_size == 0) {
        fprintf(stderr, "Error: AES-256 decryption failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ File decrypted successfully\n");
    printf("  ✓ Decrypted size: %zu bytes\n", decrypted_size);

    // ======================================================================
    // STEP 7: Verify signature
    // ======================================================================

    if (signature) {
        printf("\n[7/8] Verifying signature...\n");

        // Extract signer's public key hash from signature
        dap_chain_hash_fast_t signer_pkey_hash;
        if (dap_sign_get_pkey_hash(signature, &signer_pkey_hash)) {
            char hash_str[70];
            dap_chain_hash_fast_to_str(&signer_pkey_hash, hash_str, sizeof(hash_str));
            printf("  Signer public key hash: %s\n", hash_str);
        }

        // Verify signature against decrypted data
        if (dap_sign_verify(signature, decrypted_data, decrypted_size) == 0) {
            printf("  ✓ Signature verified successfully\n");
            printf("  ✓ File authenticity confirmed\n");
            printf("  ✓ Algorithm: %s\n", get_signature_algorithm_name(signature));
        } else {
            fprintf(stderr, "  ✗ WARNING: Signature verification FAILED\n");
            fprintf(stderr, "  ✗ File may have been tampered with or sent by wrong sender\n");
            fprintf(stderr, "  ✗ Decryption succeeded but signature is invalid\n");
            printf("\nDo you want to save the decrypted file anyway? [y/N]: ");
            char response[10];
            if (fgets(response, sizeof(response), stdin) == NULL ||
                (response[0] != 'y' && response[0] != 'Y')) {
                printf("Aborted. File not saved.\n");
                ret = EXIT_CRYPTO_ERROR;
                goto cleanup;
            }
        }
    } else {
        printf("\n[7/8] No signature present\n");
    }

    // ======================================================================
    // STEP 8: Write output file
    // ======================================================================

    printf("\n[8/8] Writing decrypted file...\n");

    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", output_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (fwrite(decrypted_data, 1, decrypted_size, out_fp) != decrypted_size) {
        fprintf(stderr, "Error: Failed to write decrypted data\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fclose(out_fp);
    out_fp = NULL;

    printf("  ✓ Decrypted file written\n");

    printf("\n✓ Multi-recipient file decrypted successfully!\n");
    printf("\nOutput file: %s\n", output_file);
    printf("  Decrypted size: %zu bytes\n", decrypted_size);
    printf("  You were recipient %d/%u\n", found_entry + 1, recipient_count);

    ret = EXIT_SUCCESS;

cleanup:
    if (recipient_entries) free(recipient_entries);
    if (encrypted_data) free(encrypted_data);
    if (decrypted_data) {
        memset(decrypted_data, 0, decrypted_size);  // Wipe decrypted data
        free(decrypted_data);
    }
    if (dek) {
        memset(dek, 0, 32);  // Wipe DEK
        free(dek);
    }
    if (signature_data) free(signature_data);
    if (out_fp) fclose(out_fp);
    if (enc_key) dap_enc_key_delete(enc_key);

    return ret;
}
