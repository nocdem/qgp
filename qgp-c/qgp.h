/*
 * pqsignum - Post-Quantum File Signing Tool
 * Copyright (c) 2025 pqsignum contributors
 *
 * A PGP-like file signing utility using Cellframe SDK
 * post-quantum cryptography (Dilithium, Falcon)
 */

#ifndef QGP_H
#define QGP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

// Cellframe SDK includes
#include "dap_common.h"
#include "dap_enc.h"
#include "dap_cert.h"
#include "dap_cert_file.h"
#include "dap_sign.h"
#include "dap_enc_key.h"
#include "dap_enc_base64.h"

// Version info
#ifndef PQSIGNUM_VERSION
#define PQSIGNUM_VERSION "1.0.0"
#endif

#ifndef BUILD_TS
#define BUILD_TS "unknown"
#endif

#ifndef BUILD_HASH
#define BUILD_HASH "unknown"
#endif

// Default paths
#define DEFAULT_KEYRING_DIR ".qgp"
#define DEFAULT_CERT_EXT ".dcert"
#define DEFAULT_SIG_EXT ".sig"
#define DEFAULT_ASC_EXT ".asc"

// Exit codes
#define EXIT_SUCCESS 0
#define EXIT_ERROR 2
#define EXIT_CRYPTO_ERROR 4
#define EXIT_KEY_ERROR 5

// Function prototypes

// Key generation (keygen.c)
int cmd_gen_key(const char *name, const char *algo, const char *output_dir);
int cmd_gen_key_from_seed(const char *name, const char *algo, const char *output_dir);
int cmd_restore_key_from_seed(const char *name, const char *algo, const char *output_dir);

// File signing (sign.c) - Always ASCII armored
int cmd_sign_file(const char *input_file, const char *key_path, const char *output_sig);

// Signature verification (verify.c)
int cmd_verify_file(const char *input_file, const char *sig_file);

// Public key export (export.c) - Always ASCII armored
int cmd_export_pubkey(const char *name, const char *key_dir, const char *output_file);

// File encryption (encrypt.c)
int cmd_encrypt_file(const char *input_file, const char *output_file, const char *recipient_pubkey_file, const char *signing_key_path);
int cmd_encrypt_file_multi(const char *input_file, const char *output_file,
                           const char **recipient_pubkey_files, size_t recipient_count,
                           const char *signing_key_path);

// File decryption (decrypt.c)
int cmd_decrypt_file(const char *input_file, const char *output_file, const char *key_path);
int cmd_decrypt_file_multi(const char *input_file, const char *output_file, const char *key_path);

// ASCII Armor (armor.c)
bool is_armored_file(const char *path);
int write_armored_file(const char *output_path, const char *type,
                       const uint8_t *data, size_t data_size,
                       const char **headers, size_t header_count);
int read_armored_file(const char *input_path, char **type_out,
                      uint8_t **data_out, size_t *data_size_out,
                      char ***headers_out, size_t *header_count_out);
const char* get_signature_algorithm_name(const dap_sign_t *signature);
size_t build_signature_headers(const dap_sign_t *signature, const char **headers, size_t max_headers);

// Keyring Management (keyring.c)
int cmd_keyring_import(const char *pubkey_file, const char *name);
int cmd_keyring_list(void);
int cmd_keyring_delete(const char *name);
char* keyring_find_key(const char *name);
char* keyring_find_private_key(const char *name, const char *key_type);
int keyring_register_private_key(const char *name, const char *signing_key_path,
                                   const char *encryption_key_path);

// Private Key Format (privkey.c)
int pqsignum_save_privkey(dap_enc_key_t *key, const char *name,
                          uint8_t key_purpose, const char *output_path);
int pqsignum_load_privkey(const char *input_path, dap_enc_key_t **key_out);

// Key purpose constants
#define PQSIGNUM_KEY_PURPOSE_SIGNING 0
#define PQSIGNUM_KEY_PURPOSE_ENCRYPTION 1

// Utilities (utils.c)
char* get_home_dir(void);
char* build_path(const char *dir, const char *filename);
bool file_exists(const char *path);
int read_file_data(const char *path, uint8_t **data, size_t *size);
int write_file_data(const char *path, const uint8_t *data, size_t size);
char* resolve_key_path(const char *key_param, const char *key_type);
char* resolve_recipient_path(const char *recipient_param);
void print_version(void);
void print_help(void);

#endif // QGP_H
