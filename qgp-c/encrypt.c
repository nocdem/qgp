/*
 * pqsignum - File encryption using Kyber512 KEM + AES-256
 *
 * Protocol Mode: Uses only verified SDK functions
 * - Kyber512 KEM for key encapsulation (post-quantum)
 * - AES-256 CBC for file encryption
 * - Hybrid encryption: Kyber.Encap() → session key → AES-256
 *
 * Security Model:
 * - Kyber512 public key encapsulation (800-byte pubkey → 768-byte ciphertext)
 * - 32-byte shared secret derived via KEM
 * - AES-256 CBC encryption of file with derived key
 * - Round-trip verification mandatory
 */

#include "qgp.h"
#include "dap_enc_kyber.h"
#include "aes_keywrap.h"
#include "dap_common.h"
#include "dap_rand.h"

// File format for Kyber-encrypted files
#define PQSIGNUM_ENC_MAGIC "PQSIGENC"
#define PQSIGNUM_ENC_VERSION 0x03  // Version 3: Kyber KEM + signature (single recipient)
#define PQSIGNUM_ENC_VERSION_MULTI 0x04  // Version 4: Multi-recipient

// Version 3 header (single recipient)
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x03
    uint8_t enc_key_type;       // DAP_ENC_KEY_TYPE_KEM_KYBER512
    uint8_t reserved[2];        // Reserved
    uint32_t ciphertext_size;   // Kyber ciphertext size (768 bytes)
    uint32_t signature_size;    // Signature size (appended after encrypted data)
} __attribute__((packed)) pqsignum_enc_header_t;

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
 * Load recipient's public key from .pub file (binary or ASCII armored)
 *
 * Reads .pub file created by --export command
 * Extracts Kyber512 encryption public key (800 bytes)
 * Supports both binary and ASCII armored formats
 *
 * @param pubkey_file: Path to recipient's .pub file
 * @param pubkey_out: Output buffer for public key (caller must free)
 * @param pubkey_size_out: Output size of public key
 * @return: 0 on success, non-zero on error
 */
static int load_recipient_pubkey(const char *pubkey_file, uint8_t **pubkey_out, size_t *pubkey_size_out) {
    // Public key header structure (defined in export.c)
    typedef struct {
        char magic[8];
        uint8_t version;
        uint8_t sign_key_type;
        uint8_t enc_key_type;
        uint8_t reserved;
        uint32_t sign_pubkey_size;
        uint32_t enc_pubkey_size;
    } __attribute__((packed)) pqsignum_pubkey_header_t;

    uint8_t *bundle_data = NULL;
    size_t bundle_size = 0;
    pqsignum_pubkey_header_t header;
    char *recipient_name = NULL;

    // Check if file is ASCII armored
    if (is_armored_file(pubkey_file)) {
        printf("  Detected ASCII armored public key\n");

        // Read armored file
        char *type = NULL;
        char **headers = NULL;
        size_t header_count = 0;

        if (read_armored_file(pubkey_file, &type, &bundle_data, &bundle_size,
                             &headers, &header_count) != 0) {
            fprintf(stderr, "Error: Failed to read ASCII armored public key\n");
            return EXIT_ERROR;
        }

        // Verify type
        if (strcmp(type, "PUBLIC KEY") != 0) {
            fprintf(stderr, "Error: Expected PUBLIC KEY, got: %s\n", type);
            free(type);
            free(bundle_data);
            for (size_t i = 0; i < header_count; i++) free(headers[i]);
            free(headers);
            return EXIT_ERROR;
        }

        // Extract name from armor headers
        for (size_t i = 0; i < header_count; i++) {
            if (strncmp(headers[i], "Name: ", 6) == 0) {
                recipient_name = strdup(headers[i] + 6);
                break;
            }
        }

        // Cleanup armor metadata
        free(type);
        for (size_t i = 0; i < header_count; i++) free(headers[i]);
        free(headers);

        // Extract header from bundle
        if (bundle_size < sizeof(pqsignum_pubkey_header_t)) {
            fprintf(stderr, "Error: ASCII armored data too small for public key\n");
            free(bundle_data);
            return EXIT_ERROR;
        }

        memcpy(&header, bundle_data, sizeof(header));

    } else {
        // Binary format
        FILE *fp = fopen(pubkey_file, "rb");
        if (!fp) {
            fprintf(stderr, "Error: Cannot open recipient public key file: %s\n", pubkey_file);
            return EXIT_ERROR;
        }

        // Read header
        if (fread(&header, 1, sizeof(header), fp) != sizeof(header)) {
            fprintf(stderr, "Error: Failed to read public key file header\n");
            fclose(fp);
            return EXIT_ERROR;
        }

        // Calculate bundle size and read entire file
        bundle_size = sizeof(header) + header.sign_pubkey_size + header.enc_pubkey_size;
        bundle_data = malloc(bundle_size);
        if (!bundle_data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            fclose(fp);
            return EXIT_ERROR;
        }

        // Copy header and read rest of file
        memcpy(bundle_data, &header, sizeof(header));
        size_t remaining = bundle_size - sizeof(header);
        if (fread(bundle_data + sizeof(header), 1, remaining, fp) != remaining) {
            fprintf(stderr, "Error: Failed to read public key data\n");
            fclose(fp);
            free(bundle_data);
            return EXIT_ERROR;
        }

        fclose(fp);
    }

    // Validate header
    if (memcmp(header.magic, "PQPUBKEY", 8) != 0) {
        fprintf(stderr, "Error: Invalid public key file format (bad magic)\n");
        free(bundle_data);
        return EXIT_ERROR;
    }

    if (header.version != 0x01) {
        fprintf(stderr, "Error: Unsupported public key file version: 0x%02x\n", header.version);
        free(bundle_data);
        return EXIT_ERROR;
    }

    if (header.enc_key_type != DAP_ENC_KEY_TYPE_KEM_KYBER512) {
        fprintf(stderr, "Error: Public key does not contain Kyber512 encryption key\n");
        free(bundle_data);
        return EXIT_ERROR;
    }

    if (header.enc_pubkey_size != 800) {
        fprintf(stderr, "Error: Invalid Kyber512 public key size: %u (expected 800)\n", header.enc_pubkey_size);
        free(bundle_data);
        return EXIT_ERROR;
    }

    // Extract encryption public key from bundle
    size_t enc_pubkey_offset = sizeof(header) + header.sign_pubkey_size;
    if (enc_pubkey_offset + header.enc_pubkey_size > bundle_size) {
        fprintf(stderr, "Error: Bundle data truncated\n");
        free(bundle_data);
        return EXIT_ERROR;
    }

    uint8_t *pubkey = malloc(header.enc_pubkey_size);
    if (!pubkey) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(bundle_data);
        return EXIT_ERROR;
    }

    memcpy(pubkey, bundle_data + enc_pubkey_offset, header.enc_pubkey_size);
    free(bundle_data);

    if (recipient_name) {
        printf("✓ Loaded recipient public key: %s\n", recipient_name);
        free(recipient_name);
    } else {
        printf("✓ Loaded recipient public key\n");
    }
    printf("  Kyber512 public key: %u bytes\n", header.enc_pubkey_size);

    *pubkey_out = pubkey;
    *pubkey_size_out = header.enc_pubkey_size;
    return EXIT_SUCCESS;
}

/**
 * Encrypt and sign file using Kyber512 KEM + AES-256 + Digital Signature
 *
 * Protocol Mode encryption workflow:
 * 1. Load recipient's Kyber512 public key from .pub file
 * 2. Load sender's signing key
 * 3. Sign the plaintext file
 * 4. Generate temporary Kyber512 keypair (Bob's role in KEM)
 * 5. Encapsulate: Kyber512.Encap(recipient_pubkey) → shared_secret + ciphertext
 * 6. Derive AES-256 key from shared_secret using SHA3-256
 * 7. Encrypt file with AES-256 CBC
 * 8. Save: [header | kyber_ciphertext (768 bytes) | encrypted_file | signature]
 *
 * @param input_file: File to encrypt
 * @param output_file: Output encrypted file (.enc)
 * @param recipient_pubkey_file: Recipient's .pub file
 * @param signing_key_path: Sender's signing private key
 * @return: 0 on success, non-zero on error
 */
int cmd_encrypt_file(const char *input_file, const char *output_file, const char *recipient_pubkey_file, const char *signing_key_path) {
    uint8_t *recipient_pubkey = NULL;
    size_t recipient_pubkey_size = 0;
    dap_enc_key_t *temp_key = NULL;
    dap_enc_key_t *sign_key = NULL;
    dap_sign_t *signature = NULL;
    void *kyber_ciphertext = NULL;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    size_t plaintext_size = 0;
    size_t ciphertext_size = 0;
    size_t signature_size = 0;
    FILE *out_fp = NULL;
    int ret = EXIT_ERROR;
    char *resolved_pubkey_path = NULL;

    printf("Encrypting and signing file with Kyber512 KEM + AES-256\n");
    printf("  Input file: %s\n", input_file);
    printf("  Output file: %s\n", output_file);
    printf("  Recipient: %s\n", recipient_pubkey_file);
    printf("  Signing key: %s\n", signing_key_path);

    // ======================================================================
    // STEP 1: Resolve recipient (keyring name or file path)
    // ======================================================================

    // Check if recipient is a file that exists
    if (!file_exists(recipient_pubkey_file)) {
        // Not a file - try keyring lookup
        printf("\n[1/6] Searching keyring for '%s'...\n", recipient_pubkey_file);
        resolved_pubkey_path = keyring_find_key(recipient_pubkey_file);

        if (!resolved_pubkey_path) {
            fprintf(stderr, "Error: Recipient not found in keyring and not a valid file: %s\n", recipient_pubkey_file);
            fprintf(stderr, "To import a key: qgp --import --file <pubkey.asc> --name %s\n", recipient_pubkey_file);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        printf("  ✓ Found in keyring: %s\n", resolved_pubkey_path);
    } else {
        // Recipient is an existing file
        resolved_pubkey_path = (char*)recipient_pubkey_file;
    }

    // ======================================================================
    // STEP 2: Load recipient's public key
    // ======================================================================

    printf("\n[2/8] Loading recipient's public key...\n");
    if (load_recipient_pubkey(resolved_pubkey_path, &recipient_pubkey, &recipient_pubkey_size) != EXIT_SUCCESS) {
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // ======================================================================
    // STEP 3: Load signing key
    // ======================================================================

    printf("\n[3/8] Loading signing key...\n");
    if (!file_exists(signing_key_path)) {
        fprintf(stderr, "Error: Signing key not found: %s\n", signing_key_path);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }

    if (pqsignum_load_privkey(signing_key_path, &sign_key) != 0) {
        fprintf(stderr, "Error: Failed to load signing key\n");
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }
    printf("  ✓ Signing key loaded\n");

    // ======================================================================
    // STEP 4: Read input file (needed for signing)
    // ======================================================================

    printf("\n[4/8] Reading input file...\n");

    FILE *in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fseek(in_fp, 0, SEEK_END);
    plaintext_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);

    plaintext = malloc(plaintext_size);
    if (!plaintext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (fread(plaintext, 1, plaintext_size, in_fp) != plaintext_size) {
        fprintf(stderr, "Error: Failed to read input file\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fclose(in_fp);
    printf("  ✓ Read %zu bytes from input file\n", plaintext_size);

    // ======================================================================
    // STEP 5: Sign the plaintext file
    // ======================================================================

    printf("\n[5/8] Signing file...\n");
    signature = dap_sign_create(sign_key, plaintext, plaintext_size);
    if (!signature) {
        fprintf(stderr, "Error: Signature creation failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Verify signature (round-trip test)
    if (dap_sign_verify(signature, plaintext, plaintext_size) != 0) {
        fprintf(stderr, "Error: Signature verification failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    signature_size = dap_sign_get_size(signature);
    if (signature_size == 0) {
        fprintf(stderr, "Error: Failed to get signature size\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ File signed successfully\n");
    printf("  ✓ Signature size: %zu bytes\n", signature_size);
    printf("  ✓ Algorithm: %s\n", get_signature_algorithm_name(signature));

    // ======================================================================
    // STEP 6: Generate temporary Kyber512 keypair (Bob's role)
    // ======================================================================

    printf("\n[6/8] Generating temporary Kyber512 KEM keypair...\n");
    temp_key = dap_enc_key_new_generate(
        DAP_ENC_KEY_TYPE_KEM_KYBER512,
        NULL, 0,
        NULL, 0,
        0
    );

    if (!temp_key) {
        fprintf(stderr, "Error: Failed to generate temporary Kyber512 keypair\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ Temporary keypair generated\n");

    // ======================================================================
    // STEP 7: Encapsulate - Generate shared secret with recipient's pubkey
    // ======================================================================

    printf("\n[7/8] Performing Kyber512 key encapsulation...\n");

    size_t kyber_ct_size = dap_enc_kyber512_gen_bob_shared_key(
        temp_key,              // Bob's temporary key
        recipient_pubkey,      // Alice's (recipient's) public key
        recipient_pubkey_size, // 800 bytes
        &kyber_ciphertext      // Output: encapsulated key (768 bytes)
    );

    if (kyber_ct_size != 768 || !kyber_ciphertext) {
        fprintf(stderr, "Error: Kyber512 encapsulation failed (expected 768 bytes, got %zu)\n", kyber_ct_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ Kyber512 encapsulation successful\n");
    printf("  ✓ Ciphertext size: 768 bytes\n");
    printf("  ✓ Shared secret generated: 32 bytes\n");

    // temp_key now contains the 32-byte shared secret in its priv_key_data
    // Extract the shared secret for AES-256 encryption
    if (!temp_key->priv_key_data || temp_key->priv_key_data_size != 32) {
        fprintf(stderr, "Error: Invalid shared secret size (expected 32 bytes, got %zu)\n", temp_key->priv_key_data_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    uint8_t *shared_secret = temp_key->priv_key_data;

    // ======================================================================
    // STEP 8: Encrypt with AES-256 using shared secret
    // ======================================================================

    printf("\n[8/8] Encrypting file with AES-256 CBC...\n");

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

    // Calculate required output buffer size for AES
    size_t cipher_buf_size = dap_enc_code_out_size(aes_key, plaintext_size, DAP_ENC_DATA_TYPE_RAW);
    if (cipher_buf_size == 0) {
        fprintf(stderr, "Error: Failed to calculate AES encryption output size\n");
        dap_enc_key_delete(aes_key);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    ciphertext = malloc(cipher_buf_size);
    if (!ciphertext) {
        fprintf(stderr, "Error: Memory allocation failed for ciphertext\n");
        dap_enc_key_delete(aes_key);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Encrypt with AES-256
    ciphertext_size = dap_enc_code(
        aes_key,               // AES key derived from shared secret
        plaintext,             // Input data
        plaintext_size,        // Input size
        ciphertext,            // Output buffer
        cipher_buf_size,       // Output buffer size
        DAP_ENC_DATA_TYPE_RAW  // Raw encryption mode
    );

    dap_enc_key_delete(aes_key);  // Delete AES key after use

    if (ciphertext_size == 0) {
        fprintf(stderr, "Error: AES-256 encryption failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ File encrypted successfully\n");
    printf("  ✓ Encrypted size: %zu bytes\n", ciphertext_size);

    // ======================================================================
    // STEP 9: Write output file
    // ======================================================================

    printf("\n[9/9] Writing output file...\n");

    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", output_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write header
    pqsignum_enc_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, PQSIGNUM_ENC_MAGIC, 8);
    header.version = PQSIGNUM_ENC_VERSION;
    header.enc_key_type = (uint8_t)DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header.ciphertext_size = 768;
    header.signature_size = (uint32_t)signature_size;

    if (fwrite(&header, 1, sizeof(header), out_fp) != sizeof(header)) {
        fprintf(stderr, "Error: Failed to write header\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write Kyber ciphertext (768 bytes)
    if (fwrite(kyber_ciphertext, 1, 768, out_fp) != 768) {
        fprintf(stderr, "Error: Failed to write Kyber ciphertext\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write encrypted file data
    if (fwrite(ciphertext, 1, ciphertext_size, out_fp) != ciphertext_size) {
        fprintf(stderr, "Error: Failed to write encrypted data\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write signature (appended at end)
    uint8_t *sig_bytes = (uint8_t*)signature;
    if (fwrite(sig_bytes, 1, signature_size, out_fp) != signature_size) {
        fprintf(stderr, "Error: Failed to write signature\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fclose(out_fp);
    out_fp = NULL;

    printf("  ✓ Output file written\n");

    printf("\n✓ File encrypted and signed successfully!\n");
    printf("\nOutput file: %s\n", output_file);
    printf("  Total size: %zu bytes\n", sizeof(header) + 768 + ciphertext_size + signature_size);
    printf("  Header: %zu bytes\n", sizeof(header));
    printf("  Kyber ciphertext: 768 bytes\n");
    printf("  Encrypted data: %zu bytes\n", ciphertext_size);
    printf("  Signature: %zu bytes (%s)\n", signature_size, get_signature_algorithm_name(signature));
    printf("\nThe recipient can decrypt this file and verify it came from you.\n");

    ret = EXIT_SUCCESS;

cleanup:
    if (resolved_pubkey_path && resolved_pubkey_path != recipient_pubkey_file) {
        free(resolved_pubkey_path);  // Only free if allocated by keyring_find_key()
    }
    if (recipient_pubkey) free(recipient_pubkey);
    if (sign_key) dap_enc_key_delete(sign_key);
    if (signature) DAP_DELETE(signature);
    if (temp_key) dap_enc_key_delete(temp_key);
    if (kyber_ciphertext) free(kyber_ciphertext);
    if (plaintext) {
        memset(plaintext, 0, plaintext_size);  // Wipe plaintext
        free(plaintext);
    }
    if (ciphertext) free(ciphertext);
    if (out_fp) fclose(out_fp);

    return ret;
}

/**
 * Encrypt and sign file for multiple recipients using Kyber512 KEM + AES-256
 *
 * Multi-recipient workflow:
 * 1. Load all recipient public keys
 * 2. Load sender's signing key
 * 3. Sign the plaintext file
 * 4. Generate random 32-byte DEK (Data Encryption Key)
 * 5. Encrypt file with DEK using AES-256 CBC
 * 6. For each recipient:
 *    - Generate ephemeral Kyber512 keypair
 *    - Encapsulate: Kyber512.Encap(recipient_pubkey) → shared_secret + ciphertext
 *    - Derive KEK from shared_secret
 *    - Wrap DEK with KEK using AES Key Wrap (RFC 3394)
 *    - Store recipient entry: [kyber_ciphertext | wrapped_dek]
 * 7. Save: [header_v4 | recipient_entries | encrypted_data | signature]
 *
 * @param input_file: File to encrypt
 * @param output_file: Output encrypted file (.enc)
 * @param recipient_pubkey_files: Array of recipient .pub files or keyring names
 * @param recipient_count: Number of recipients (1-255)
 * @param signing_key_path: Sender's signing private key
 * @return: 0 on success, non-zero on error
 */
int cmd_encrypt_file_multi(const char *input_file, const char *output_file,
                           const char **recipient_pubkey_files, size_t recipient_count,
                           const char *signing_key_path) {

    // Validate recipient count
    if (recipient_count == 0 || recipient_count > 255) {
        fprintf(stderr, "Error: Invalid recipient count: %zu (must be 1-255)\n", recipient_count);
        return EXIT_ERROR;
    }

    uint8_t **recipient_pubkeys = NULL;
    size_t *recipient_pubkey_sizes = NULL;
    char **resolved_pubkey_paths = NULL;
    dap_enc_key_t *sign_key = NULL;
    dap_sign_t *signature = NULL;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *dek = NULL;
    recipient_entry_t *recipient_entries = NULL;
    FILE *out_fp = NULL;
    int ret = EXIT_ERROR;
    size_t plaintext_size = 0;
    size_t ciphertext_size = 0;
    size_t signature_size = 0;

    printf("Encrypting and signing file for %zu recipient(s) with Kyber512 KEM + AES-256\n", recipient_count);
    printf("  Input file: %s\n", input_file);
    printf("  Output file: %s\n", output_file);
    printf("  Signing key: %s\n", signing_key_path);

    // ======================================================================
    // STEP 1: Allocate arrays for recipients
    // ======================================================================

    recipient_pubkeys = calloc(recipient_count, sizeof(uint8_t*));
    recipient_pubkey_sizes = calloc(recipient_count, sizeof(size_t));
    resolved_pubkey_paths = calloc(recipient_count, sizeof(char*));
    recipient_entries = calloc(recipient_count, sizeof(recipient_entry_t));

    if (!recipient_pubkeys || !recipient_pubkey_sizes || !resolved_pubkey_paths || !recipient_entries) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // ======================================================================
    // STEP 2: Resolve and load all recipient public keys
    // ======================================================================

    printf("\n[1/7] Loading %zu recipient public key(s)...\n", recipient_count);

    for (size_t i = 0; i < recipient_count; i++) {
        printf("\nRecipient %zu/%zu: %s\n", i+1, recipient_count, recipient_pubkey_files[i]);

        // Check if recipient is a file that exists
        if (!file_exists(recipient_pubkey_files[i])) {
            // Not a file - try keyring lookup
            printf("  Searching keyring for '%s'...\n", recipient_pubkey_files[i]);
            resolved_pubkey_paths[i] = keyring_find_key(recipient_pubkey_files[i]);

            if (!resolved_pubkey_paths[i]) {
                fprintf(stderr, "Error: Recipient not found in keyring and not a valid file: %s\n",
                       recipient_pubkey_files[i]);
                fprintf(stderr, "To import a key: qgp --import --file <pubkey.asc> --name %s\n",
                       recipient_pubkey_files[i]);
                ret = EXIT_ERROR;
                goto cleanup;
            }

            printf("  ✓ Found in keyring: %s\n", resolved_pubkey_paths[i]);
        } else {
            // Recipient is an existing file
            resolved_pubkey_paths[i] = (char*)recipient_pubkey_files[i];
        }

        // Load recipient's public key
        if (load_recipient_pubkey(resolved_pubkey_paths[i],
                                 &recipient_pubkeys[i],
                                 &recipient_pubkey_sizes[i]) != EXIT_SUCCESS) {
            ret = EXIT_ERROR;
            goto cleanup;
        }
    }

    printf("\n✓ All recipient public keys loaded successfully\n");

    // ======================================================================
    // STEP 3: Load signing key
    // ======================================================================

    printf("\n[2/7] Loading signing key...\n");
    if (!file_exists(signing_key_path)) {
        fprintf(stderr, "Error: Signing key not found: %s\n", signing_key_path);
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }

    if (pqsignum_load_privkey(signing_key_path, &sign_key) != 0) {
        fprintf(stderr, "Error: Failed to load signing key\n");
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }
    printf("  ✓ Signing key loaded\n");

    // ======================================================================
    // STEP 4: Read input file
    // ======================================================================

    printf("\n[3/7] Reading input file...\n");

    FILE *in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fseek(in_fp, 0, SEEK_END);
    plaintext_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);

    plaintext = malloc(plaintext_size);
    if (!plaintext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (fread(plaintext, 1, plaintext_size, in_fp) != plaintext_size) {
        fprintf(stderr, "Error: Failed to read input file\n");
        fclose(in_fp);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fclose(in_fp);
    printf("  ✓ Read %zu bytes from input file\n", plaintext_size);

    // ======================================================================
    // STEP 5: Sign the plaintext file
    // ======================================================================

    printf("\n[4/7] Signing file...\n");
    signature = dap_sign_create(sign_key, plaintext, plaintext_size);
    if (!signature) {
        fprintf(stderr, "Error: Signature creation failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Verify signature (round-trip test)
    if (dap_sign_verify(signature, plaintext, plaintext_size) != 0) {
        fprintf(stderr, "Error: Signature verification failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    signature_size = dap_sign_get_size(signature);
    if (signature_size == 0) {
        fprintf(stderr, "Error: Failed to get signature size\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ File signed successfully\n");
    printf("  ✓ Signature size: %zu bytes\n", signature_size);
    printf("  ✓ Algorithm: %s\n", get_signature_algorithm_name(signature));

    // ======================================================================
    // STEP 6: Generate random DEK (Data Encryption Key)
    // ======================================================================

    printf("\n[5/7] Generating random 32-byte DEK (Data Encryption Key)...\n");

    dek = malloc(32);
    if (!dek) {
        fprintf(stderr, "Error: Memory allocation failed for DEK\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Generate random 32-byte DEK using SDK's random function
    if (randombytes(dek, 32) != 0) {
        fprintf(stderr, "Error: Failed to generate random DEK\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ Random DEK generated: 32 bytes\n");

    // ======================================================================
    // STEP 7: Encrypt file with DEK using AES-256 CBC
    // ======================================================================

    printf("\n[6/7] Encrypting file with AES-256 CBC using DEK...\n");

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

    // Calculate required output buffer size for AES
    size_t cipher_buf_size = dap_enc_code_out_size(aes_key, plaintext_size, DAP_ENC_DATA_TYPE_RAW);
    if (cipher_buf_size == 0) {
        fprintf(stderr, "Error: Failed to calculate AES encryption output size\n");
        dap_enc_key_delete(aes_key);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    ciphertext = malloc(cipher_buf_size);
    if (!ciphertext) {
        fprintf(stderr, "Error: Memory allocation failed for ciphertext\n");
        dap_enc_key_delete(aes_key);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Encrypt with AES-256
    ciphertext_size = dap_enc_code(
        aes_key,               // AES key derived from DEK
        plaintext,             // Input data
        plaintext_size,        // Input size
        ciphertext,            // Output buffer
        cipher_buf_size,       // Output buffer size
        DAP_ENC_DATA_TYPE_RAW  // Raw encryption mode
    );

    dap_enc_key_delete(aes_key);  // Delete AES key after use

    if (ciphertext_size == 0) {
        fprintf(stderr, "Error: AES-256 encryption failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ File encrypted successfully\n");
    printf("  ✓ Encrypted size: %zu bytes\n", ciphertext_size);

    // ======================================================================
    // STEP 8: Create recipient entries (wrap DEK for each recipient)
    // ======================================================================

    printf("\n[7/7] Creating recipient entries (wrapping DEK for each recipient)...\n");

    for (size_t i = 0; i < recipient_count; i++) {
        printf("\nRecipient %zu/%zu:\n", i+1, recipient_count);

        // Generate temporary Kyber512 keypair for this recipient
        dap_enc_key_t *temp_key = dap_enc_key_new_generate(
            DAP_ENC_KEY_TYPE_KEM_KYBER512,
            NULL, 0,
            NULL, 0,
            0
        );

        if (!temp_key) {
            fprintf(stderr, "Error: Failed to generate temporary Kyber512 keypair for recipient %zu\n", i+1);
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        // Perform Kyber512 encapsulation with recipient's public key
        void *kyber_ciphertext = NULL;
        size_t kyber_ct_size = dap_enc_kyber512_gen_bob_shared_key(
            temp_key,                   // Bob's temporary key
            recipient_pubkeys[i],       // Alice's (recipient's) public key
            recipient_pubkey_sizes[i],  // 800 bytes
            &kyber_ciphertext           // Output: encapsulated key (768 bytes)
        );

        if (kyber_ct_size != 768 || !kyber_ciphertext) {
            fprintf(stderr, "Error: Kyber512 encapsulation failed for recipient %zu\n", i+1);
            dap_enc_key_delete(temp_key);
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        printf("  ✓ Kyber512 encapsulation successful\n");

        // Extract shared secret from temp_key (KEK derivation)
        if (!temp_key->priv_key_data || temp_key->priv_key_data_size != 32) {
            fprintf(stderr, "Error: Invalid shared secret size for recipient %zu\n", i+1);
            dap_enc_key_delete(temp_key);
            free(kyber_ciphertext);
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        uint8_t *kek = temp_key->priv_key_data;  // KEK = shared secret

        // Wrap DEK with KEK using AES Key Wrap (RFC 3394)
        uint8_t wrapped_dek[40];  // 32-byte DEK + 8-byte IV
        if (aes256_wrap_key(dek, 32, kek, wrapped_dek) != 0) {
            fprintf(stderr, "Error: Failed to wrap DEK for recipient %zu\n", i+1);
            dap_enc_key_delete(temp_key);
            free(kyber_ciphertext);
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        printf("  ✓ DEK wrapped successfully (AES Key Wrap)\n");

        // Store recipient entry
        memcpy(recipient_entries[i].kyber_ciphertext, kyber_ciphertext, 768);
        memcpy(recipient_entries[i].wrapped_dek, wrapped_dek, 40);

        // Cleanup for this recipient
        dap_enc_key_delete(temp_key);
        free(kyber_ciphertext);
    }

    printf("\n✓ All recipient entries created successfully\n");

    // ======================================================================
    // STEP 9: Write output file
    // ======================================================================

    printf("\n[8/8] Writing output file...\n");

    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", output_file);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write v0.04 header
    pqsignum_enc_header_v4_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, PQSIGNUM_ENC_MAGIC, 8);
    header.version = PQSIGNUM_ENC_VERSION_MULTI;
    header.enc_key_type = (uint8_t)DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header.recipient_count = (uint8_t)recipient_count;
    header.encrypted_size = (uint32_t)ciphertext_size;
    header.signature_size = (uint32_t)signature_size;

    if (fwrite(&header, 1, sizeof(header), out_fp) != sizeof(header)) {
        fprintf(stderr, "Error: Failed to write header\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write all recipient entries
    for (size_t i = 0; i < recipient_count; i++) {
        if (fwrite(&recipient_entries[i], 1, sizeof(recipient_entry_t), out_fp) != sizeof(recipient_entry_t)) {
            fprintf(stderr, "Error: Failed to write recipient entry %zu\n", i+1);
            ret = EXIT_ERROR;
            goto cleanup;
        }
    }

    // Write encrypted file data
    if (fwrite(ciphertext, 1, ciphertext_size, out_fp) != ciphertext_size) {
        fprintf(stderr, "Error: Failed to write encrypted data\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Write signature (appended at end)
    uint8_t *sig_bytes = (uint8_t*)signature;
    if (fwrite(sig_bytes, 1, signature_size, out_fp) != signature_size) {
        fprintf(stderr, "Error: Failed to write signature\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    fclose(out_fp);
    out_fp = NULL;

    printf("  ✓ Output file written\n");

    size_t total_size = sizeof(header) + (sizeof(recipient_entry_t) * recipient_count) + ciphertext_size + signature_size;
    size_t recipient_overhead = sizeof(recipient_entry_t) * recipient_count;

    printf("\n✓ File encrypted and signed for %zu recipient(s)!\n", recipient_count);
    printf("\nOutput file: %s\n", output_file);
    printf("  Total size: %zu bytes\n", total_size);
    printf("  Header: %zu bytes\n", sizeof(header));
    printf("  Recipient entries: %zu bytes (%zu bytes × %zu recipients)\n",
           recipient_overhead, sizeof(recipient_entry_t), recipient_count);
    printf("  Encrypted data: %zu bytes\n", ciphertext_size);
    printf("  Signature: %zu bytes (%s)\n", signature_size, get_signature_algorithm_name(signature));
    printf("\nAny of the %zu recipient(s) can decrypt this file and verify it came from you.\n", recipient_count);

    ret = EXIT_SUCCESS;

cleanup:
    if (recipient_pubkeys) {
        for (size_t i = 0; i < recipient_count; i++) {
            if (recipient_pubkeys[i]) free(recipient_pubkeys[i]);
        }
        free(recipient_pubkeys);
    }
    if (recipient_pubkey_sizes) free(recipient_pubkey_sizes);
    if (resolved_pubkey_paths) {
        for (size_t i = 0; i < recipient_count; i++) {
            if (resolved_pubkey_paths[i] && resolved_pubkey_paths[i] != recipient_pubkey_files[i]) {
                free(resolved_pubkey_paths[i]);  // Only free if allocated by keyring_find_key()
            }
        }
        free(resolved_pubkey_paths);
    }
    if (sign_key) dap_enc_key_delete(sign_key);
    if (signature) DAP_DELETE(signature);
    if (plaintext) {
        memset(plaintext, 0, plaintext_size);  // Wipe plaintext
        free(plaintext);
    }
    if (dek) {
        memset(dek, 0, 32);  // Wipe DEK
        free(dek);
    }
    if (ciphertext) free(ciphertext);
    if (recipient_entries) free(recipient_entries);
    if (out_fp) fclose(out_fp);

    return ret;
}
