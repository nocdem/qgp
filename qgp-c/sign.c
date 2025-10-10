/*
 * pqsignum - File signing
 *
 * Protocol Mode: Uses only verified SDK functions
 * - pqsignum_load_privkey() to load signing key
 * - dap_sign_create() to sign data
 * - Round-trip verification mandatory before saving signature
 */

#include "qgp.h"

int cmd_sign_file(const char *input_file, const char *key_path, const char *output_sig) {
    dap_enc_key_t *sign_key = NULL;
    uint8_t *file_data = NULL;
    size_t file_size = 0;
    dap_sign_t *signature = NULL;
    uint8_t *sig_bytes = NULL;
    size_t sig_size = 0;
    int ret = EXIT_ERROR;

    printf("Signing file...\n");
    printf("  Input file: %s\n", input_file);
    printf("  Signing key: %s\n", key_path);
    printf("  Output signature: %s\n", output_sig);

    // Check if input file exists
    if (!file_exists(input_file)) {
        fprintf(stderr, "Error: Input file not found: %s\n", input_file);
        return EXIT_ERROR;
    }

    // Check if signing key exists
    if (!file_exists(key_path)) {
        fprintf(stderr, "Error: Signing key not found: %s\n", key_path);
        return EXIT_KEY_ERROR;
    }

    // Load signing key using PQSigNum format
    printf("Loading signing key...\n");
    if (pqsignum_load_privkey(key_path, &sign_key) != 0) {
        fprintf(stderr, "Error: Failed to load signing key\n");
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }
    printf("Signing key loaded successfully\n");

    // Read file data
    printf("Reading file...\n");
    if (read_file_data(input_file, &file_data, &file_size) != 0) {
        ret = EXIT_ERROR;
        goto cleanup;
    }
    printf("File size: %zu bytes\n", file_size);

    // Sign the file using SDK
    printf("Creating signature...\n");
    signature = dap_sign_create(sign_key, file_data, file_size);
    if (!signature) {
        fprintf(stderr, "Error: Signature creation failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }
    printf("Signature created\n");

    // Protocol Mode: MANDATORY round-trip verification
    printf("Performing round-trip verification...\n");
    if (dap_sign_verify(signature, file_data, file_size) != 0) {
        fprintf(stderr, "Error: Round-trip verification FAILED\n");
        fprintf(stderr, "Signature is invalid - will not save\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }
    printf("Round-trip verification: OK\n");

    // Get signature size (dap_sign_t is already serialized format)
    sig_size = dap_sign_get_size(signature);
    if (sig_size == 0) {
        fprintf(stderr, "Error: Failed to get signature size\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Signature bytes are the struct itself
    sig_bytes = (uint8_t*)signature;

    // Write ASCII-armored signature
    printf("Writing signature...\n");

    const char *headers[10];
    size_t header_count = build_signature_headers(signature, headers, 10);

    if (write_armored_file(output_sig, "SIGNATURE",
                           sig_bytes, sig_size,
                           headers, header_count) != 0) {
        fprintf(stderr, "Error: Failed to write armored signature\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("\nFile signed successfully!\n");
    printf("  ASCII-armored signature: %s\n", output_sig);
    printf("  Algorithm: %s\n", get_signature_algorithm_name(signature));

    printf("\nTo verify:\n");
    printf("  pqsignum --verify --file %s\n", input_file);

    ret = EXIT_SUCCESS;

cleanup:
    if (file_data) {
        free(file_data);
    }
    if (signature) {
        DAP_DELETE(signature);
    }
    // sig_bytes points to signature, no separate free needed
    if (sign_key) {
        dap_enc_key_delete(sign_key);
    }

    return ret;
}
