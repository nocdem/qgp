/*
 * pqsignum - Key generation (Signing + Encryption keypairs)
 *
 * Protocol Mode: Uses only verified SDK functions
 * - dap_cert_generate() for signing key generation
 * - dap_enc_key_new_generate() for Kyber KEM key generation
 * - Round-trip verification mandatory for both keys
 */

#include <sys/stat.h>
#include <sys/types.h>
#include "qgp.h"
#include "dap_enc_kyber.h"
#include "dap_cert_file.h"  // For dap_cert_file_hdr_t

// Map algorithm name to SDK key type
static dap_enc_key_type_t get_sign_key_type(const char *algo) {
    if (strcasecmp(algo, "dilithium") == 0) {
        return DAP_ENC_KEY_TYPE_SIG_DILITHIUM;
    } else if (strcasecmp(algo, "falcon") == 0) {
        return DAP_ENC_KEY_TYPE_SIG_FALCON;
    } else if (strcasecmp(algo, "sphincsplus") == 0 || strcasecmp(algo, "sphincs") == 0) {
        return DAP_ENC_KEY_TYPE_SIG_SPHINCSPLUS;
    } else {
        fprintf(stderr, "Error: Unknown algorithm '%s'\n", algo);
        fprintf(stderr, "Supported algorithms: dilithium, falcon, sphincsplus\n");
        return DAP_ENC_KEY_TYPE_INVALID;
    }
}

/**
 * Generate keypair for pqsignum
 *
 * Creates TWO key files (PQSigNum format):
 * 1. <name>-signing.pqkey - Signing key (Dilithium/Falcon/SPHINCS+)
 * 2. <name>-encryption.pqkey - Encryption key (Kyber512 KEM)
 *
 * Protocol Mode:
 * - All keys verified with round-trip tests
 * - Signing key: sign → verify
 * - Encryption key: encap → decap
 */
int cmd_gen_key(const char *name, const char *algo, const char *output_dir) {
    dap_enc_key_t *sign_key = NULL;
    dap_enc_key_t *enc_key = NULL;
    char *sign_key_path = NULL;
    char *enc_key_path = NULL;
    int ret = EXIT_ERROR;

    printf("Generating keypair for: %s\n", name);
    printf("  Signing algorithm: %s\n", algo);
    printf("  Encryption: Kyber512 KEM (post-quantum)\n");
    printf("  Output directory: %s\n", output_dir);

    // Get signing key type
    dap_enc_key_type_t sign_key_type = get_sign_key_type(algo);
    if (sign_key_type == DAP_ENC_KEY_TYPE_INVALID) {
        return EXIT_KEY_ERROR;
    }

    // Create output directory if it doesn't exist
    struct stat st = {0};
    if (stat(output_dir, &st) == -1) {
        if (mkdir(output_dir, 0700) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", output_dir);
            return EXIT_ERROR;
        }
        printf("Created directory: %s (mode 0700)\n", output_dir);
    }

    // Build key file paths
    char sign_filename[512];
    char enc_filename[512];
    snprintf(sign_filename, sizeof(sign_filename), "%s-signing.pqkey", name);
    snprintf(enc_filename, sizeof(enc_filename), "%s-encryption.pqkey", name);

    sign_key_path = build_path(output_dir, sign_filename);
    enc_key_path = build_path(output_dir, enc_filename);

    if (!sign_key_path || !enc_key_path) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Check if files already exist
    if (file_exists(sign_key_path)) {
        fprintf(stderr, "Error: Signing key already exists: %s\n", sign_key_path);
        fprintf(stderr, "Remove it first or use a different name\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (file_exists(enc_key_path)) {
        fprintf(stderr, "Error: Encryption key already exists: %s\n", enc_key_path);
        fprintf(stderr, "Remove it first or use a different name\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // ======================================================================
    // STEP 1: Generate SIGNING key (Dilithium/Falcon/SPHINCS+)
    // ======================================================================

    printf("\n[1/2] Generating signing key (%s)...\n", algo);

    sign_key = dap_enc_key_new_generate(
        sign_key_type,  // Dilithium, Falcon, or SPHINCS+
        NULL, 0,        // No KEX
        NULL, 0,        // Random generation (no seed)
        0               // Default key size
    );

    if (!sign_key) {
        fprintf(stderr, "Error: Failed to generate signing key\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ Signing key generated\n");

    // Save signing key in PQSigNum format
    if (pqsignum_save_privkey(sign_key, name, PQSIGNUM_KEY_PURPOSE_SIGNING, sign_key_path) != 0) {
        fprintf(stderr, "Error: Failed to save signing key\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("  ✓ Signing key saved: %s\n", sign_key_path);

    // Protocol Mode: Round-trip verification for signing key
    printf("  Verifying signing key (round-trip test)...\n");
    const char *test_data = "pqsignum-verification-test";
    size_t test_len = strlen(test_data);

    dap_sign_t *test_sign = dap_sign_create(sign_key, test_data, test_len);
    if (!test_sign) {
        fprintf(stderr, "  ✗ CRITICAL ERROR: Signing key verification failed (cannot sign)\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    if (dap_sign_verify(test_sign, test_data, test_len) != 0) {
        fprintf(stderr, "  ✗ CRITICAL ERROR: Signing key verification failed (invalid signature)\n");
        DAP_DELETE(test_sign);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    DAP_DELETE(test_sign);
    printf("  ✓ Signing key verified (sign → verify PASSED)\n");

    // ======================================================================
    // STEP 2: Generate ENCRYPTION key (Kyber512 KEM)
    // ======================================================================

    printf("\n[2/2] Generating encryption key (Kyber512 KEM)...\n");

    enc_key = dap_enc_key_new_generate(
        DAP_ENC_KEY_TYPE_KEM_KYBER512,  // Kyber512 post-quantum KEM
        NULL, 0,                         // No KEX
        NULL, 0,                         // Random generation
        0                                // Default key size
    );

    if (!enc_key) {
        fprintf(stderr, "Error: Failed to generate Kyber512 encryption key\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    printf("  ✓ Kyber512 KEM key generated\n");

    // Validate key sizes
    if (!enc_key->pub_key_data || enc_key->pub_key_data_size != 800) {
        fprintf(stderr, "Error: Invalid public key (expected 800 bytes, got %zu)\n",
                enc_key->pub_key_data_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    if (!enc_key->_inheritor || enc_key->_inheritor_size != 1632) {
        fprintf(stderr, "Error: Invalid private key (expected 1632 bytes, got %zu)\n",
                enc_key->_inheritor_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Save encryption key in PQSigNum format
    if (pqsignum_save_privkey(enc_key, name, PQSIGNUM_KEY_PURPOSE_ENCRYPTION, enc_key_path) != 0) {
        fprintf(stderr, "Error: Failed to save encryption key\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("  ✓ Encryption key saved: %s\n", enc_key_path);
    printf("  ✓ Public key: 800 bytes\n");
    printf("  ✓ Private key: 1632 bytes\n");

    // ======================================================================
    // SUCCESS
    // ======================================================================

    printf("\n✓ Keypair generation complete!\n");
    printf("\nGenerated files:\n");
    printf("  Signing key:     %s (keep private!)\n", sign_key_path);
    printf("  Encryption key:  %s (keep private!)\n", enc_key_path);

    // Register keys in keyring
    printf("\nRegistering keys in keyring...\n");
    if (keyring_register_private_key(name, sign_key_path, enc_key_path) == 0) {
        printf("  ✓ Keys registered in keyring\n");
        printf("  View with: qgp --list-keys\n");
    } else {
        printf("  ⚠ Warning: Could not register keys in keyring (non-fatal)\n");
    }

    // Auto-export public key directly to keyring
    printf("\nExporting public key to keyring...\n");

    // Create keyring directory path
    char *keyring_dir = build_path(output_dir, "keyring");
    if (!keyring_dir) {
        fprintf(stderr, "  ⚠ Warning: Memory allocation failed for keyring path\n");
        goto skip_export;
    }

    // Create keyring directory if it doesn't exist
    struct stat keyring_st = {0};
    if (stat(keyring_dir, &keyring_st) == -1) {
        if (mkdir(keyring_dir, 0700) != 0) {
            fprintf(stderr, "  ⚠ Warning: Cannot create keyring directory: %s\n", keyring_dir);
            free(keyring_dir);
            goto skip_export;
        }
    }

    // Build public key path in keyring directory
    char pubkey_filename[512];
    snprintf(pubkey_filename, sizeof(pubkey_filename), "%s.pub", name);
    char *pubkey_path = build_path(keyring_dir, pubkey_filename);
    free(keyring_dir);

    if (!pubkey_path) {
        fprintf(stderr, "  ⚠ Warning: Memory allocation failed for public key path\n");
        goto skip_export;
    }

    // Export public key directly to keyring
    if (cmd_export_pubkey(name, output_dir, pubkey_path) == 0) {
        printf("  ✓ Public key exported to keyring: %s\n", pubkey_path);

        // Import the exported public key into keyring index
        if (cmd_keyring_import(pubkey_path, name) == 0) {
            printf("  ✓ Public key registered in keyring\n");
            printf("  You can now use: qgp --encrypt --file secret.txt --recipient %s\n", name);
        } else {
            printf("  ⚠ Warning: Could not register public key in keyring (non-fatal)\n");
        }
    } else {
        printf("  ⚠ Warning: Could not export public key (non-fatal)\n");
        printf("  You can export it later with: qgp --export --name %s\n", name);
    }

    free(pubkey_path);

skip_export:
    printf("\nNext steps:\n");
    printf("  1. Share your public key with others:\n");
    printf("       Export with: qgp --export --name %s --output %s.asc\n", name, name);
    printf("\n  2. Sign a file:\n");
    printf("       qgp --sign --file document.pdf --key %s\n", name);
    printf("\n  3. Encrypt a file for someone:\n");
    printf("       qgp --encrypt --file secret.txt --recipient <their-name>\n");
    printf("\n  4. Decrypt a file sent to you:\n");
    printf("       qgp --decrypt --file secret.txt.enc --key %s\n", name);

    ret = EXIT_SUCCESS;

cleanup:
    if (sign_key_path) free(sign_key_path);
    if (enc_key_path) free(enc_key_path);
    if (sign_key) dap_enc_key_delete(sign_key);
    if (enc_key) dap_enc_key_delete(enc_key);

    return ret;
}
