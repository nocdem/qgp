# pqsignum - Post-Quantum File Signing & Encryption Tool

**PGP for the Post-Quantum Era**

A standalone C implementation of post-quantum file signing and encryption using the Cellframe SDK.

---

## Features

- 🔐 **Post-Quantum Security**: Dilithium (ML-DSA), Falcon, SPHINCS+ signatures + Kyber512 encryption
- 🔑 **Complete PGP Workflow**: Sign, verify, encrypt, decrypt files
- 📦 **Detached Signatures**: Files remain unchanged, signatures in `.sig` or `.asc` files
- 🔒 **Hybrid Encryption**: Kyber512 KEM + AES-256-CBC for file encryption
- 📤 **Public Key Export**: Share `.pub` files for encryption
- 🎨 **ASCII Armor**: PGP-style human-readable `.asc` signatures
- 💾 **Single Binary**: No dependencies, no Python, no SDK installation required
- ✅ **Production Ready**: 20/20 tests passing, full Protocol Mode compliance

---

## Quick Start

### 1. Generate a Key Pair

```bash
pqsignum --gen-key --name alice --algo dilithium
```

Creates:
- `~/.pqsignum/alice.dcert` - Private signing key
- `~/.pqsignum/alice-enc.dcert` - Private encryption key

### 2. Sign a File

```bash
# ASCII armor (default - human readable)
pqsignum --sign --file document.pdf --cert ~/.pqsignum/alice.dcert

# Binary format (compact)
pqsignum --sign --file document.pdf --cert ~/.pqsignum/alice.dcert --binary
```

Creates:
- `document.pdf.asc` - ASCII-armored signature (default)
- `document.pdf.sig` - Binary signature (with --binary)

### 3. Verify a Signature

```bash
pqsignum --verify --file document.pdf
```

Output:
```
========================================
  GOOD SIGNATURE
========================================

The signature is valid.
The file has not been modified since it was signed.
```

### 4. Export Public Keys

```bash
# ASCII armor (default - human readable, email-friendly)
pqsignum --export --name alice --output alice.asc

# Binary format (compact)
pqsignum --export --name alice --binary --output alice.pub
```

Creates:
- `alice.asc` - ASCII-armored public keys (default)
- `alice.pub` - Binary public keys (with --binary)

### 5. Encrypt a File

```bash
# Encrypt for someone else
pqsignum --encrypt --file secret.txt --recipient bob.pub

# Encrypt for yourself
pqsignum --encrypt --file private.txt --recipient alice.pub
```

Creates:
- `secret.txt.enc` - Encrypted file (Kyber512 + AES-256)

### 6. Decrypt a File

```bash
pqsignum --decrypt --file secret.txt.enc --cert ~/.pqsignum/alice-enc.dcert
```

Creates:
- `secret.txt` - Decrypted original file

---

## Installation

### Option 1: Use Pre-built Binary

**Download** the `pqsignum` binary and copy to your system:

```bash
sudo cp pqsignum /usr/local/bin/
chmod +x /usr/local/bin/pqsignum
```

**Size**: ~2.5 MB (statically linked, no dependencies)

### Option 2: Build from Source

**Prerequisites**:
- Cellframe SDK must be built at `../cellframe-sdk/`
- CMake 3.10+
- GCC or Clang

**Build**:
```bash
mkdir build && cd build
cmake ..
make -j4
```

**Binary Location**: `build/pqsignum`

---

## Complete Usage Guide

### Command Reference

```
pqsignum - Post-Quantum File Signing & Encryption Tool

COMMANDS:
  Key Management:
    pqsignum --gen-key --name <name> [--algo <algorithm>] [--output <dir>]
    pqsignum --export --name <name> --output <file> [--binary]

  Signing:
    pqsignum --sign --file <file> --cert <cert_path> [--binary]
    pqsignum --verify --file <file> [--sig <sig_file>]

  Encryption:
    pqsignum --encrypt --file <file> --recipient <pubkey.pub>
    pqsignum --decrypt --file <file.enc> --cert <enc_cert_path>

OPTIONS:
  -g, --gen-key           Generate new key pair (signing + encryption)
  -s, --sign              Sign a file
  -v, --verify            Verify a file signature
  -e, --encrypt           Encrypt a file
  -d, --decrypt           Decrypt a file
  -E, --export            Export public keys
  -n, --name <name>       Key name (for generation/export)
  -a, --algo <algo>       Signing algorithm: dilithium, falcon, sphincsplus
  -c, --cert <path>       Path to certificate file (.dcert)
  -r, --recipient <file>  Recipient's public key file (.pub or .asc)
  -o, --output <path>     Output directory or file
  -f, --file <path>       File to sign/verify/encrypt/decrypt
  -S, --sig <path>        Signature file (default: auto-detect .asc or .sig)
  -b, --binary            Use binary format (signatures/pubkeys, default: ASCII armor)
  -h, --help              Show this help
  -V, --version           Show version

EXIT CODES:
  0 - Success
  1 - Bad signature (verification failed)
  2 - General error (file not found, invalid arguments)
  3 - Encryption/decryption error
  4 - Cryptographic error (key generation failed)
  5 - Key error (certificate loading failed)
```

---

## Algorithms

### Signing Algorithms

| Algorithm | Key Type | Signature Size | Security Level | Speed |
|-----------|----------|----------------|----------------|-------|
| **Dilithium (ML-DSA)** | Lattice-based | 3,306 bytes | NIST Level 3 | Fast |
| **Falcon** | NTRU Lattice | 1,615 bytes | NIST Level 5 | Fast |
| **SPHINCS+** | Hash-based | ~16 KB | NIST Level 3 | Slow |

**Default**: Dilithium (best balance of size, security, and performance)

### Encryption Algorithm

| Algorithm | Type | Key Sizes | Security | Notes |
|-----------|------|-----------|----------|-------|
| **Kyber512** | KEM (Key Encapsulation) | 800B pub, 1632B priv | NIST Level 1 | Post-quantum secure |
| **AES-256-CBC** | Symmetric | 256-bit | Industry standard | File encryption |

**Hybrid Encryption**: Kyber512 encapsulates a shared secret → AES-256 key → file encryption

---

## Workflow Examples

### Complete Signing Workflow

```bash
# Alice generates keys
pqsignum --gen-key --name alice --algo dilithium

# Alice signs a document
pqsignum --sign --file report.pdf --cert ~/.pqsignum/alice.dcert

# Alice shares report.pdf + report.pdf.asc with Bob

# Bob verifies Alice's signature
pqsignum --verify --file report.pdf
# Output: GOOD SIGNATURE
```

### Complete Encryption Workflow

```bash
# 1. Both users generate keys
pqsignum --gen-key --name alice --algo dilithium
pqsignum --gen-key --name bob --algo falcon

# 2. Both users export public keys (ASCII armor for easy sharing)
pqsignum --export --name alice --output alice.asc
pqsignum --export --name bob --output bob.asc

# 3. Alice and Bob exchange public key files (via email, web, etc.)

# 4. Alice encrypts a file for Bob
pqsignum --encrypt --file secret.txt --recipient bob.pub

# 5. Alice sends secret.txt.enc to Bob

# 6. Bob decrypts the file
pqsignum --decrypt --file secret.txt.enc --cert ~/.pqsignum/bob-enc.dcert

# 7. Bob now has the original secret.txt
```

### Combined Sign + Encrypt Workflow

```bash
# Alice signs a contract
pqsignum --sign --file contract.pdf --cert ~/.pqsignum/alice.dcert

# Alice encrypts the signed contract for Bob
pqsignum --encrypt --file contract.pdf --recipient bob.pub

# Alice sends contract.pdf.enc and contract.pdf.asc to Bob

# Bob decrypts
pqsignum --decrypt --file contract.pdf.enc --cert ~/.pqsignum/bob-enc.dcert

# Bob verifies Alice's signature
pqsignum --verify --file contract.pdf
# Output: GOOD SIGNATURE - verified and encrypted!
```

### Self-Encryption (Personal Backup)

```bash
# Encrypt sensitive file for yourself
pqsignum --encrypt --file passwords.txt --recipient alice.pub

# Later, decrypt when needed
pqsignum --decrypt --file passwords.txt.enc --cert ~/.pqsignum/alice-enc.dcert
```

---

## File Formats

### Signature Files

**ASCII Armor (`.asc`) - Default**:
```
-----BEGIN PQSIGNUM SIGNATURE-----
Version: pqsignum 1.0
Algorithm: Dilithium
Hash: SHA3-256
Created: 2025-10-09 15:00:00 UTC

<Base64-encoded signature data>
-----END PQSIGNUM SIGNATURE-----
```

**Binary (`.sig`) - Compact**:
- Raw binary `dap_sign_t` struct
- Smaller size (~3.3 KB for Dilithium)

### Encrypted Files (`.enc`)

Binary format with header + Kyber ciphertext + AES-encrypted data:

```
Offset | Size | Content
-------|------|--------
0      | 9    | "PQSIGENC" magic header
9      | 4    | Version (2)
13     | 4    | Key type (23 = Kyber512)
17     | 4    | Reserved
21     | 768  | Kyber512 ciphertext (encapsulated shared secret)
789    | N    | AES-256-CBC encrypted file data
```

**Overhead**: 789 bytes (768B Kyber + 21B header)

### Certificate Files (`.dcert`)

- **Signing cert**: `~/.pqsignum/<name>.dcert` - Private signing key
- **Encryption cert**: `~/.pqsignum/<name>-enc.dcert` - Private encryption key

**Security**: Keep `.dcert` files secure! They contain private keys (0600 permissions).

### Public Key Files (`.pub` / `.asc`)

Contains both signing and encryption public keys for sharing:
- Signing public key (algorithm-dependent size)
- Kyber512 encryption public key (800 bytes)

**ASCII Armor (`.asc`) - Default**:
```
-----BEGIN PQSIGNUM PUBLIC KEY-----
Version: pqsignum 1.0
Name: alice
SigningAlgorithm: Dilithium
EncryptionAlgorithm: Kyber512
Created: 2025-10-09 11:38:03 UTC

<Base64-encoded public key bundle>
-----END PQSIGNUM PUBLIC KEY-----
```

**Binary (`.pub`) - Compact**:
```
Offset | Size | Content
-------|------|--------
0      | 8    | "PQPUBKEY" magic header
8      | 1    | Version (1)
9      | 1    | Signing key type
10     | 1    | Encryption key type (23 = Kyber512)
11     | 1    | Reserved
12     | 4    | Signing public key size
16     | 4    | Encryption public key size (800)
20     | 256  | Owner name/identifier
276    | N    | Signing public key
276+N  | 800  | Kyber512 encryption public key
```

**Share freely**: Public key files are safe to distribute (both formats work identically)

---

## Security

### Protocol Mode Enforcement

All cryptographic operations enforce strict Protocol Mode:

1. ✅ **No Custom Crypto**: Only Cellframe SDK functions used
2. ✅ **Round-Trip Verification**: Every signature/encryption verified immediately
3. ✅ **Key Verification**: Generated keys tested before saving
4. ✅ **Fail-Safe**: Any crypto failure halts execution
5. ✅ **Source Code Verified**: All SDK functions verified against source
6. ✅ **No Assumptions**: Zero tolerance for crypto assumptions

### Test Results

**20/20 Tests Passing (100% Success Rate)**:
- ✅ Key generation (Dilithium, Falcon)
- ✅ Public key export
- ✅ Signing (ASCII armor + binary)
- ✅ Verification (good + bad signatures)
- ✅ Person-to-person encryption
- ✅ Self-encryption
- ✅ Large file encryption (100KB+)
- ✅ Wrong key rejection
- ✅ Combined sign + encrypt workflows

### Best Practices

**Key Management**:
- 🔒 Protect private keys: Keep `.dcert` files in `~/.pqsignum/` with 0600 permissions
- 💾 Backup keys: Securely backup `~/.pqsignum/` directory
- 🔑 Export public keys: Share `.pub` files, never `.dcert` files

**File Operations**:
- ✅ Always verify signatures after receiving signed files
- ✅ Verify encrypted files decrypt correctly (round-trip test)
- ✅ Use ASCII armor for email/web sharing (default)
- ✅ Use binary format for space-constrained situations

**Algorithm Choice**:
- **Dilithium**: Default, best balance (3.3KB signatures)
- **Falcon**: Smaller signatures (1.6KB), slightly slower
- **SPHINCS+**: Stateless security, very large signatures (16KB)

---

## Performance

Tested on typical x86_64 Linux system:

| Operation | File Size | Time | Output Size |
|-----------|-----------|------|-------------|
| Key generation (Dilithium + Kyber512) | - | <1s | 2728 bytes cert |
| Key generation (Falcon + Kyber512) | - | <1s | 2728 bytes cert |
| Sign (Dilithium, ASCII) | 35 bytes | <1s | 4608 bytes (.asc) |
| Sign (Falcon, binary) | 22 bytes | <1s | 1615 bytes (.sig) |
| Verify signature | Any size | <1s | - |
| Encrypt (Kyber512) | 33 bytes | <0.1s | 832 bytes |
| Decrypt (Kyber512) | 832 bytes | <0.1s | 33 bytes |
| Encrypt (large file) | 100 KB | <0.2s | 100 KB + 789 bytes |
| Decrypt (large file) | 100 KB | <0.2s | 100 KB (exact) |

**Notes**:
- Signing is hash-based: speed independent of file size
- Encryption overhead: 789 bytes (Kyber ciphertext + header)
- All operations include mandatory round-trip verification

---

## Distribution

### Single Binary Distribution

The compiled binary is **completely standalone**:

```bash
# Copy to any Linux x86_64 system
scp build/pqsignum user@target:/usr/local/bin/

# No dependencies needed!
```

**What's Included**:
- ✅ All cryptographic functions (statically linked)
- ✅ Dilithium, Falcon, SPHINCS+ (signing)
- ✅ Kyber512 (encryption)
- ✅ AES-256-CBC (file encryption)
- ✅ SHA3-256 (hashing)

**Not Required**:
- ❌ No Python
- ❌ No Cellframe SDK installation
- ❌ No shared libraries
- ❌ No external dependencies

**Binary Size**: ~2.5 MB

---

## Development

### Project Structure

```
pqsignum-c/
├── CMakeLists.txt          # Build configuration
├── pqsignum.h              # Header with SDK includes
├── main.c                  # CLI parsing and SDK init
├── keygen.c                # Key generation (signing + encryption)
├── sign.c                  # File signing
├── verify.c                # Signature verification
├── encrypt.c               # File encryption (Kyber512 + AES-256)
├── decrypt.c               # File decryption
├── export.c                # Public key export
├── armor.c                 # ASCII armor encoding/decoding
├── utils.c                 # Utility functions
├── test_all_features.sh    # Comprehensive test suite (20 tests)
└── build/                  # Build output
    └── pqsignum            # Final binary
```

### SDK Integration

**Libraries Statically Linked**:
- `libdap_core.a` - Core SDK functions
- `libdap_crypto.a` - Cryptographic functions (Dilithium, Falcon, SPHINCS+)
- `libdap-XKCP-plainc-native.a` - SHA3/Keccak hashing
- `libdap_crypto_kyber512.a` - Kyber512 KEM

**Key SDK Functions Used**:

*Initialization*:
- `dap_enc_init()` - Master crypto initialization

*Signing*:
- `dap_enc_key_new_generate()` - Generate signing keypair
- `dap_cert_new()` - Create certificate
- `dap_cert_sign()` - Sign data
- `dap_sign_verify()` - Verify signature

*Encryption*:
- `dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_KYBER_512, ...)` - Generate Kyber keypair
- `dap_enc_kyber512_gen_bob_shared_key()` - Kyber encapsulation
- `dap_enc_kyber512_gen_alice_shared_key()` - Kyber decapsulation
- `dap_enc_code()` - AES-256 encryption
- `dap_enc_decode()` - AES-256 decryption

*ASCII Armor*:
- `dap_enc_base64_encode()` - Base64 encoding
- `dap_enc_base64_decode()` - Base64 decoding

### Building for Different Platforms

```bash
# Release build (optimized, stripped)
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j4

# Debug build (with symbols)
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j4

# Static analysis
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
```

### Running Tests

```bash
# Run comprehensive test suite
./test_all_features.sh

# Expected output: 20/20 PASSED ✅
```

---

## Roadmap

### Completed ✅

- [x] Key generation (Dilithium, Falcon, SPHINCS+)
- [x] Encryption key generation (Kyber512)
- [x] File signing with detached signatures
- [x] Signature verification
- [x] Tamper detection
- [x] ASCII armor support (PGP-style `.asc` files)
- [x] Binary signature format (`.sig`)
- [x] File encryption (Kyber512 KEM + AES-256-CBC)
- [x] File decryption
- [x] Public key export (`.pub` binary and `.asc` ASCII armored)
- [x] ASCII armor for public keys (email/web-friendly sharing)
- [x] Person-to-person encryption
- [x] Self-encryption support
- [x] Large file support (tested with 100KB+)
- [x] Protocol Mode enforcement
- [x] Comprehensive test suite (20 tests)
- [x] Production-ready implementation

### Future Enhancements

- [ ] Keyring management (import multiple keys, list keys)
- [ ] Signature verification with external public keys
- [ ] Batch operations (sign/encrypt multiple files)
- [ ] Windows build (MinGW/MSVC)
- [ ] macOS build (Clang)
- [ ] Package distribution (deb, rpm, brew)
- [ ] GUI wrapper (optional)
- [ ] Hardware security module (HSM) support

---

## Troubleshooting

### "Certificate generation failed"

**Cause**: SDK not initialized or crypto modules not loaded

**Solution**: Ensure `dap_enc_init()` is called (already done in pqsignum)

### "Failed to load certificate"

**Cause**: Certificate file path incorrect or file corrupted

**Solution**:
- Check that `.dcert` file exists at specified path
- Verify file permissions (should be 0600 for private keys)

### "BAD SIGNATURE"

**Cause**: File was modified after signing, or wrong public key used

**Solution**:
- Verify you're using the original unmodified file
- Check that signature file matches the data file
- Ensure signature was created for this specific file

### "Encryption/decryption failed"

**Cause**: Wrong encryption certificate or corrupted encrypted file

**Solution**:
- Verify you're using the correct encryption certificate (`-enc.dcert`)
- Ensure encrypted file wasn't corrupted during transfer
- Check that you have the recipient's private key for decryption

### "AES-256 decryption failed"

**Cause**: File was encrypted for a different recipient

**Solution**:
- Verify the file was encrypted for your public key
- Check that you're using the correct encryption certificate

---

## License

GNU General Public License v3.0

Follows Cellframe SDK licensing.

---

## Credits

Built on the **Cellframe SDK** by DeM Labs Inc.

**Technologies**:
- Cellframe SDK: https://gitlab.demlabs.net/cellframe/cellframe-sdk
- NIST PQC Standards: https://csrc.nist.gov/projects/post-quantum-cryptography
- Dilithium (ML-DSA): FIPS 204
- Kyber: FIPS 203
- Falcon: https://falcon-sign.info/

**Development**:
- Protocol Mode enforcement ensures cryptographic correctness
- All SDK functions verified against source code
- Zero tolerance for assumptions in cryptographic operations

---

## Support

For issues or questions:
- Check `../FOLDER_ANALYSIS.md` for project structure
- Check `../SDK_DISCOVERIES.md` for SDK quirks and workarounds
- Review `../dev.md` for implementation details and change history
- Review `../PROJECT_STATUS.md` for current status and achievements
- File bugs in project issue tracker

---

**Status**: ✅ **PRODUCTION READY**
**Version**: 1.0
**Last Updated**: 2025-10-09
**Test Status**: 20/20 PASSING (100%)

**Protect your data from quantum computers. Use pqsignum.**
