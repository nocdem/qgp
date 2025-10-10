/*
 * pqsignum - Private Key Format (OpenPGP-style)
 *
 * PQSigNum native private key format:
 * - ASCII armored with PGP-style headers
 * - Self-contained (not dependent on Cellframe format)
 * - Version controlled and extensible
 * - Supports all post-quantum algorithms
 */

#include "qgp.h"
#include <time.h>

// Private key file format
#define PQSIGNUM_PRIVKEY_MAGIC "PQPRIV01"
#define PQSIGNUM_PRIVKEY_VERSION 0x01

// Key purpose types
#define PQSIGNUM_KEY_PURPOSE_SIGNING 0
#define PQSIGNUM_KEY_PURPOSE_ENCRYPTION 1

typedef struct {
    char magic[8];              // "PQPRIV01"
    uint8_t version;            // 0x01
    uint8_t key_type;           // DAP_ENC_KEY_TYPE_*
    uint8_t key_purpose;        // 0=signing, 1=encryption
    uint8_t reserved;
    uint32_t public_key_size;
    uint32_t private_key_size;
    uint64_t created_timestamp;
} __attribute__((packed)) pqsignum_privkey_header_t;

/**
 * Get algorithm name from key type
 */
static const char* get_algorithm_name(dap_enc_key_type_t type) {
    switch (type) {
        case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
            return "Dilithium";
        case DAP_ENC_KEY_TYPE_SIG_FALCON:
            return "Falcon";
        case DAP_ENC_KEY_TYPE_SIG_SPHINCSPLUS:
            return "SPHINCS+";
        case DAP_ENC_KEY_TYPE_KEM_KYBER512:
            return "Kyber512";
        default:
            return "Unknown";
    }
}

/**
 * Save private key to file (ASCII armored)
 *
 * @param key: DAP encryption key object
 * @param name: Key name/identifier
 * @param key_purpose: PQSIGNUM_KEY_PURPOSE_SIGNING or PQSIGNUM_KEY_PURPOSE_ENCRYPTION
 * @param output_path: Output file path
 * @return: 0 on success, non-zero on error
 */
int pqsignum_save_privkey(dap_enc_key_t *key, const char *name,
                          uint8_t key_purpose, const char *output_path) {
    if (!key || !name || !output_path) {
        fprintf(stderr, "Error: Invalid parameters for save_privkey\n");
        return -1;
    }

    // Validate key has required data
    if (!key->pub_key_data || key->pub_key_data_size == 0) {
        fprintf(stderr, "Error: Key missing public key data\n");
        return -1;
    }

    // Serialize key data
    uint64_t pub_size = 0;
    uint64_t priv_size = 0;
    uint8_t *pub_data = NULL;
    uint8_t *priv_data = NULL;
    bool needs_free = true;  // Track if we need to free serialized data

    // KEM keys (Kyber) don't have serialization callbacks - use raw data
    if (key->type == DAP_ENC_KEY_TYPE_KEM_KYBER512) {
        pub_size = key->pub_key_data_size;
        priv_size = key->_inheritor_size;
        pub_data = key->pub_key_data;
        priv_data = key->_inheritor;
        needs_free = false;  // Don't free - we're using pointers directly
    } else {
        // Signature keys - use SDK serialization
        pub_data = dap_enc_key_serialize_pub_key(key, &pub_size);
        priv_data = dap_enc_key_serialize_priv_key(key, &priv_size);
    }

    if (!pub_data || !priv_data || pub_size == 0 || priv_size == 0) {
        fprintf(stderr, "Error: Failed to serialize keys (pub=%p size=%lu, priv=%p size=%lu)\n",
                (void*)pub_data, pub_size, (void*)priv_data, priv_size);
        if (needs_free) {
            DAP_DELETE(pub_data);
            DAP_DELETE(priv_data);
        }
        return -1;
    }

    // Build header
    pqsignum_privkey_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, PQSIGNUM_PRIVKEY_MAGIC, 8);
    header.version = PQSIGNUM_PRIVKEY_VERSION;
    header.key_type = (uint8_t)key->type;
    header.key_purpose = key_purpose;
    header.reserved = 0;
    header.public_key_size = (uint32_t)pub_size;
    header.private_key_size = (uint32_t)priv_size;
    header.created_timestamp = (uint64_t)time(NULL);

    // Calculate total size
    size_t total_size = sizeof(header) + pub_size + priv_size;

    // Assemble complete binary bundle
    uint8_t *bundle = malloc(total_size);
    if (!bundle) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(pub_data);
        free(priv_data);
        return -1;
    }

    memcpy(bundle, &header, sizeof(header));
    memcpy(bundle + sizeof(header), pub_data, pub_size);
    memcpy(bundle + sizeof(header) + pub_size, priv_data, priv_size);

    // Build armor headers
    static char header_buf[10][128];
    const char *armor_headers[10];
    size_t header_count = 0;

    snprintf(header_buf[0], sizeof(header_buf[0]), "Version: pqsignum 1.0");
    armor_headers[header_count++] = header_buf[0];

    snprintf(header_buf[1], sizeof(header_buf[1]), "Name: %s", name);
    armor_headers[header_count++] = header_buf[1];

    snprintf(header_buf[2], sizeof(header_buf[2]), "Algorithm: %s",
             get_algorithm_name(key->type));
    armor_headers[header_count++] = header_buf[2];

    snprintf(header_buf[3], sizeof(header_buf[3]), "KeyType: %s",
             key_purpose == PQSIGNUM_KEY_PURPOSE_SIGNING ? "Signing" : "Encryption");
    armor_headers[header_count++] = header_buf[3];

    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", tm_info);
    snprintf(header_buf[4], sizeof(header_buf[4]), "Created: %s", time_str);
    armor_headers[header_count++] = header_buf[4];

    // Write armored file
    int ret = write_armored_file(output_path, "PRIVATE KEY", bundle, total_size,
                                 armor_headers, header_count);

    // Cleanup
    DAP_DELETE(bundle);
    if (needs_free) {
        DAP_DELETE(pub_data);
        DAP_DELETE(priv_data);
    }

    if (ret != 0) {
        fprintf(stderr, "Error: Failed to write armored private key\n");
        return -1;
    }

    return 0;
}

/**
 * Load private key from file (ASCII armored or binary)
 *
 * @param input_path: Input file path
 * @param key_out: Output DAP key object (caller must delete with dap_enc_key_delete)
 * @return: 0 on success, non-zero on error
 */
int pqsignum_load_privkey(const char *input_path, dap_enc_key_t **key_out) {
    if (!input_path || !key_out) {
        fprintf(stderr, "Error: Invalid parameters for load_privkey\n");
        return -1;
    }

    uint8_t *bundle_data = NULL;
    size_t bundle_size = 0;
    pqsignum_privkey_header_t header;

    // Check if file is ASCII armored
    if (is_armored_file(input_path)) {
        // Read armored file
        char *type = NULL;
        char **headers = NULL;
        size_t header_count = 0;

        if (read_armored_file(input_path, &type, &bundle_data, &bundle_size,
                             &headers, &header_count) != 0) {
            fprintf(stderr, "Error: Failed to read ASCII armored private key\n");
            return -1;
        }

        // Verify type
        if (strcmp(type, "PRIVATE KEY") != 0) {
            fprintf(stderr, "Error: Expected PRIVATE KEY, got: %s\n", type);
            free(type);
            free(bundle_data);
            for (size_t i = 0; i < header_count; i++) free(headers[i]);
            free(headers);
            return -1;
        }

        // Cleanup armor metadata
        free(type);
        for (size_t i = 0; i < header_count; i++) free(headers[i]);
        free(headers);

    } else {
        // Binary format
        if (read_file_data(input_path, &bundle_data, &bundle_size) != 0) {
            return -1;
        }
    }

    // Validate size
    if (bundle_size < sizeof(pqsignum_privkey_header_t)) {
        fprintf(stderr, "Error: File too small to be valid private key\n");
        free(bundle_data);
        return -1;
    }

    // Extract header
    memcpy(&header, bundle_data, sizeof(header));

    // Validate magic
    if (memcmp(header.magic, PQSIGNUM_PRIVKEY_MAGIC, 8) != 0) {
        fprintf(stderr, "Error: Invalid private key file format (bad magic)\n");
        free(bundle_data);
        return -1;
    }

    // Validate version
    if (header.version != PQSIGNUM_PRIVKEY_VERSION) {
        fprintf(stderr, "Error: Unsupported private key version: 0x%02x\n", header.version);
        free(bundle_data);
        return -1;
    }

    // Validate sizes
    size_t expected_size = sizeof(header) + header.public_key_size + header.private_key_size;
    if (bundle_size != expected_size) {
        fprintf(stderr, "Error: Invalid file size (expected %zu, got %zu)\n",
                expected_size, bundle_size);
        free(bundle_data);
        return -1;
    }

    // Extract key data
    uint8_t *pub_data = bundle_data + sizeof(header);
    uint8_t *priv_data = pub_data + header.public_key_size;

    // Create DAP key object using dap_enc_key_new() to initialize callbacks
    dap_enc_key_t *key = dap_enc_key_new((dap_enc_key_type_t)header.key_type);
    if (!key) {
        fprintf(stderr, "Error: Failed to create key object\n");
        free(bundle_data);
        return -1;
    }

    key->last_used_timestamp = header.created_timestamp;

    // Deserialize keys
    if (key->type == DAP_ENC_KEY_TYPE_KEM_KYBER512) {
        // Kyber - copy raw data
        key->pub_key_data_size = header.public_key_size;
        key->pub_key_data = malloc(header.public_key_size);
        if (!key->pub_key_data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            free(bundle_data);
            dap_enc_key_delete(key);
            return -1;
        }
        memcpy(key->pub_key_data, pub_data, header.public_key_size);

        key->_inheritor_size = header.private_key_size;
        key->_inheritor = malloc(header.private_key_size);
        if (!key->_inheritor) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            free(bundle_data);
            dap_enc_key_delete(key);
            return -1;
        }
        memcpy(key->_inheritor, priv_data, header.private_key_size);
    } else {
        // Signature keys - use SDK deserialization
        if (dap_enc_key_deserialize_pub_key(key, pub_data, header.public_key_size) != 0) {
            fprintf(stderr, "Error: Public key deserialization failed\n");
            free(bundle_data);
            dap_enc_key_delete(key);
            return -1;
        }

        if (dap_enc_key_deserialize_priv_key(key, priv_data, header.private_key_size) != 0) {
            fprintf(stderr, "Error: Private key deserialization failed\n");
            free(bundle_data);
            dap_enc_key_delete(key);
            return -1;
        }
    }

    free(bundle_data);

    *key_out = key;
    return 0;
}
