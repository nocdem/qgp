# QGP (Quantum Good Privacy)

Post-quantum cryptographic tool for file signing, encryption, and keyring management.

## Quick Start

```bash
# Linux/macOS
mkdir build && cd build
cmake .. && make

# Windows (automated)
curl -o build_windows.bat https://raw.githubusercontent.com/nocdem/qgp/main/build_windows.bat
build_windows.bat
```

## Build Requirements

**Linux/macOS:**
- CMake 3.10+, GCC/Clang, OpenSSL dev libraries
- Debian/Ubuntu: `sudo apt-get install cmake gcc libssl-dev`

**Windows:**
- Git, CMake 3.10+, Visual Studio Build Tools
- See automated script output for installation links

## Features

- **Post-Quantum Crypto**: Dilithium3 signatures + Kyber512 KEM + AES-256-GCM
- **Multi-Recipient**: Encrypt for up to 255 recipients
- **BIP39 Recovery**: Generate/restore keys from 24-word mnemonic
- **Keyring**: Name-based operations (`--key alice` instead of paths)

## Usage

```bash
# Generate key with recovery seed
qgp --gen-key --name alice --from-seed

# Restore from 24-word mnemonic (interactive)
qgp --restore --name alice

# Restore from seed file
qgp --restore --name alice --file seed.txt

# Sign and verify
qgp --sign --file doc.pdf --key alice
qgp --verify --file doc.pdf

# Encrypt (single/multi-recipient)
qgp --encrypt --file secret.txt --recipient bob --key alice
qgp --encrypt --file secret.txt -r alice -r bob -r charlie --key alice

# Decrypt
qgp --decrypt --file secret.txt.enc --key bob

# Keyring
qgp --list-keys
qgp --import --file alice.pub --name alice
```

## Technical Details

**Cryptography:** Vendored pq-crystals (Dilithium3, Kyber512) + OpenSSL (AES-GCM, SHAKE256)
**Binary Size:** ~2.5 MB standalone executable
**Platforms:** Linux, Windows, macOS (auto-detected at build time)
**Random Source:** `getrandom()` (Linux), `BCryptGenRandom()` (Windows), `/dev/urandom` (macOS)

## License

GNU General Public License v3.0
