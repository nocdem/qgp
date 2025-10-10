# QGP - Quantum-Safe File Signing & Encryption

**Post-quantum cryptographic tool for file signing, verification, and encryption.**

QGP uses NIST-standardized post-quantum algorithms to protect files against quantum computer attacks.

## Features

- ✅ **Digital Signatures**: Dilithium, Falcon, SPHINCS+
- ✅ **File Encryption**: Kyber512 KEM + AES-256-CBC
- ✅ **Multi-Recipient Encryption**: Encrypt for multiple recipients
- ✅ **Authenticated Encryption**: Files are automatically signed when encrypted
- ✅ **ASCII Armor**: PGP-style format for signatures and keys

## Quick Start

```bash
# Generate keys
qgp --gen-key --name alice

# Sign a file
qgp --sign --file document.pdf --key alice

# Verify signature
qgp --verify --file document.pdf

# Encrypt for recipient
qgp --encrypt --file secret.txt --recipient bob --key alice

# Decrypt file
qgp --decrypt --file secret.txt.enc --key bob
```

## Installation

### From Source

```bash
# Clone with submodules (includes Cellframe SDK)
git clone --recurse-submodules https://github.com/nocdem/qgp.git
cd qgp/qgp-c
mkdir build && cd build
cmake ..
make
sudo make install
```

**Requirements:**
- Linux (Debian/Ubuntu tested)
- CMake 3.10+
- GCC or Clang

**Note:** The `--recurse-submodules` flag is required to download the Cellframe SDK dependency.

## Algorithms

### Signatures
- **Dilithium (ML-DSA)** - FIPS 204, default choice
- **Falcon** - Compact signatures
- **SPHINCS+** - Hash-based, conservative

### Encryption
- **Kyber512 KEM** - FIPS 203
- **AES-256-CBC** - Bulk encryption

## Security

QGP protects against:
- ✅ Quantum computer attacks
- ✅ File tampering
- ✅ Impersonation
- ✅ Eavesdropping

## License

GNU General Public License v3.0

## Links

- **Issues**: https://github.com/nocdem/qgp/issues
- **NIST Post-Quantum Cryptography**: https://csrc.nist.gov/projects/post-quantum-cryptography
