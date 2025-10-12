# QGP - Quantum Good Privacy

Post-quantum cryptographic tool for file signing, verification, and encryption using NIST-standardized algorithms.

## Features

- **Digital Signatures**: Dilithium, Falcon, SPHINCS+
- **File Encryption**: Kyber512 KEM + AES-256-CBC
- **Multi-Recipient Encryption**: Encrypt for multiple recipients simultaneously
- **BIP39 Key Backup**: 24-word recovery phrases for key restoration
- **Authenticated Encryption**: Files are automatically signed when encrypted
- **ASCII Armor**: PGP-style format for signatures and keys

## Build

```bash
# Clone repository with Cellframe SDK submodule
git clone --recurse-submodules https://github.com/nocdem/qgp.git
cd qgp

# Build Cellframe SDK
cd cellframe-sdk
git submodule update --init --recursive
mkdir build && cd build
cmake ..
make
cd ../..

# Build QGP
cd qgp-c
mkdir build && cd build
cmake ..
make
sudo make install
```

**Requirements**: Linux, CMake 3.10+, GCC/Clang

## Usage

### Key Generation

```bash
# Generate keypair with BIP39 recovery phrase
qgp --gen-key --name alice

# Save the 24-word recovery phrase shown!

# Restore keys from recovery phrase
qgp --restore --name alice
```

### Signing

```bash
# Sign file
qgp --sign --file document.pdf --key alice

# Verify signature
qgp --verify --file document.pdf
```

### Encryption

```bash
# Encrypt for one recipient
qgp --encrypt --file secret.txt --recipient bob --key alice

# Encrypt for multiple recipients
qgp --encrypt --file secret.txt \
  --recipient bob \
  --recipient charlie \
  --recipient diana \
  --key alice

# Decrypt
qgp --decrypt --file secret.txt.enc --key bob
```

### Keyring Management

```bash
# List keys
qgp --list

# Import public key
qgp --import --file bob.asc --name bob

# Export public key
qgp --export --name alice --output alice.asc
```

## Algorithms

**Signatures**: Dilithium (ML-DSA) FIPS 204, Falcon, SPHINCS+
**Encryption**: Kyber512 (ML-KEM) FIPS 203, AES-256-CBC
**Key Derivation**: BIP39, PBKDF2-HMAC-SHA512, SHAKE256

## License

GNU General Public License v3.0
