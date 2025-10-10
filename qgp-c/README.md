# QGP C Implementation

C implementation of QGP using the Cellframe SDK for post-quantum cryptographic operations.

## Building

```bash
mkdir build && cd build
cmake ..
make
```

**Requirements:**
- CMake 3.10+
- GCC or Clang
- Cellframe SDK (automatically included via git submodule)

## Binary Output

The compiled binary `qgp` is a standalone executable with all cryptographic functions statically linked.

**Size:** ~2.5 MB
**Dependencies:** None (fully static)

## Features

- Digital signatures: Dilithium, Falcon, SPHINCS+
- File encryption: Kyber512 KEM + AES-256-CBC
- Multi-recipient encryption with RFC 3394 AES Key Wrap
- Authenticated encryption (auto-signing)
- ASCII armor support (PGP-style)
- Keyring management

## Source Files

- `main.c` - CLI parsing and main entry point
- `keygen.c` - Key generation (signing + encryption)
- `sign.c` - File signing
- `verify.c` - Signature verification
- `encrypt.c` - File encryption with multi-recipient support
- `decrypt.c` - File decryption with signature verification
- `export.c` - Public key export
- `keyring.c` - Keyring management (import/list/delete)
- `armor.c` - ASCII armor encoding/decoding
- `aes_keywrap.c` - RFC 3394 AES Key Wrap implementation
- `privkey.c` - Private key loading/saving
- `utils.c` - Utility functions and help text

## SDK Integration

Uses Cellframe SDK cryptographic functions:
- `dap_enc_key_new_generate()` - Key generation
- `dap_sign_create()` / `dap_sign_verify()` - Signatures
- `dap_enc_kyber512_*()` - Kyber512 KEM
- `AES256_enc_cernelT()` / `AES256_dec_cernelT()` - AES-256 encryption

All SDK crypto libraries are statically linked into the binary.

## License

GNU General Public License v3.0
