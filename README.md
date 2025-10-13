# QGP (Quantum Good Privacy)

Post-quantum cryptographic tool for file signing, encryption, and keyring management. Built with vendored pq-crystals implementations (Kyber512, Dilithium3) and OpenSSL.

## Building

QGP supports Linux, Windows, and macOS. Platform-specific random number generation and file system operations are automatically selected at build time.

### Linux Build

#### Prerequisites

Install build dependencies:

```bash
# Debian/Ubuntu
sudo apt-get install cmake gcc libssl-dev

# Fedora/RHEL
sudo dnf install cmake gcc openssl-devel

# Arch Linux
sudo pacman -S cmake gcc openssl
```

**Requirements:**
- CMake 3.10+
- GCC or Clang
- OpenSSL development libraries

#### Build Steps

```bash
mkdir build && cd build
cmake ..
make
```

The binary will be created at `build/qgp`.

**Build Process:**
- CMake configures the build system
- Platform detection (Linux/Windows/macOS)
- Vendored cryptography is automatically compiled (Kyber512, Dilithium3)
- All libraries are statically linked into the binary
- Build time: ~30 seconds on modern hardware

### Windows Build

#### Prerequisites

**Option A: Visual Studio (Recommended)**
- Visual Studio 2019 or later
- CMake 3.10+
- OpenSSL for Windows (install via vcpkg or pre-built binaries)

**Option B: MinGW**
- MinGW-w64
- CMake 3.10+
- OpenSSL for Windows

#### Install OpenSSL (vcpkg)

```cmd
# Install vcpkg
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat

# Install OpenSSL
vcpkg install openssl:x64-windows
```

#### Build Steps (Visual Studio)

```cmd
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -DCMAKE_TOOLCHAIN_FILE=path\to\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build . --config Release
```

The binary will be created at `build\Release\qgp.exe`.

#### Build Steps (MinGW)

```cmd
mkdir build
cd build
cmake .. -G "MinGW Makefiles"
cmake --build .
```

### macOS Build

#### Prerequisites

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake openssl
```

#### Build Steps

```bash
mkdir build && cd build
cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl
make
```

### Cross-Platform Differences

| Platform | Random Source | Home Directory | Path Separator |
|----------|--------------|----------------|----------------|
| Linux    | getrandom() or /dev/urandom | $HOME | / |
| Windows  | BCryptGenRandom() (CNG) | %USERPROFILE% | \\ |
| macOS    | /dev/urandom | $HOME | / |

### Installation (Optional)

```bash
# Install to /usr/local/bin
sudo make install

# Or copy manually
sudo cp build/qgp /usr/local/bin/

# Verify installation
qgp --version
```

## Binary Output

The compiled binary `qgp` is a standalone executable with all cryptographic functions statically linked.

**Size:** ~2.5 MB
**Runtime Dependencies:** OpenSSL (libcrypto), libc, pthread
**Cryptographic Implementation:** Vendored pq-crystals (statically linked)

## Features

- **Post-Quantum Signatures**: Dilithium3 (ML-DSA-65, FIPS 204), Falcon, SPHINCS+
- **Post-Quantum Encryption**: Kyber512 KEM (NIST Level 1) + AES-256-CBC
- **Multi-Recipient Encryption**: RFC 3394 AES Key Wrap for secure group encryption
- **Authenticated Encryption**: Automatic signing during encryption (encrypt-then-sign)
- **BIP39 Seed Support**: Mnemonic-based key generation and restoration (12/15/18/21/24 words)
- **ASCII Armor**: PGP-style armored signatures and keys
- **Keyring Management**: Import, list, delete keys with name resolution
- **Name-Based Operations**: Use key names instead of full paths (`--key alice`, `--recipient bob`)

## Usage Examples

```bash
# Generate keypair with BIP39 mnemonic (automatic recovery seed)
qgp --gen-key --name alice --from-seed

# Restore keys from BIP39 mnemonic
qgp --restore --name alice

# Sign a file
qgp --sign --file document.pdf --key alice

# Verify signature
qgp --verify --file document.pdf --sig document.pdf.sig

# Encrypt for single recipient
qgp --encrypt --file secret.txt --recipient bob --key alice

# Encrypt for multiple recipients
qgp --encrypt --file secret.txt --recipient alice --recipient bob --recipient charlie --key alice

# Decrypt file
qgp --decrypt --file secret.txt.enc --key bob

# Keyring operations
qgp --import --file alice.pub --name alice
qgp --list-keys
qgp --delete-key --name alice
```

## Architecture

### Platform Abstraction Layer
- `qgp_platform.h` - Cross-platform API definitions
- `qgp_platform_linux.c` - Linux implementation (getrandom, /dev/urandom, mkdir, $HOME)
- `qgp_platform_windows.c` - Windows implementation (BCryptGenRandom, _mkdir, %USERPROFILE%)

Platform detection at build time automatically selects correct implementation.

### Cryptographic Independence Layer
- `qgp_types.h/c` - Core QGP data structures (keys, signatures, hashes)
- `qgp_key.c` - Key memory management and serialization
- `qgp_signature.c` - Signature structure management
- `qgp_dilithium.c` - Dilithium3 signature operations
- `qgp_kyber.c` - Kyber512 KEM operations
- `qgp_aes.c` - AES-256 encryption/decryption
- `qgp_random.c` - Cryptographically secure random number generation (uses platform layer)
- `qgp_utils_standalone.c` - Hash and Base64 utilities (OpenSSL)

### Application Layer
- `main.c` - CLI parsing and command dispatch
- `keygen.c` - Key generation (signing + encryption pairs)
- `sign.c` / `verify.c` - File signing and verification
- `encrypt.c` / `decrypt.c` - File encryption/decryption with multi-recipient support
- `export.c` - Public key export (ASCII armor + binary)
- `keyring.c` - Keyring management (import/list/delete)
- `armor.c` - ASCII armor encoding/decoding (PGP-style)
- `aes_keywrap.c` - RFC 3394 AES Key Wrap for multi-recipient encryption
- `privkey.c` - Private key file I/O
- `utils.c` - Utility functions, help text, path resolution

### BIP39 Mnemonic System
- `bip39.h/c` - BIP39 mnemonic generation and validation
- `bip39_wordlist.h` - Official 2048-word BIP39 English wordlist
- `bip39_pbkdf2.c` - PBKDF2-HMAC-SHA512 seed derivation
- `seed_derivation.c` - QGP-specific SHAKE256 seed derivation
- `kyber_deterministic.c` - Deterministic Kyber512 key generation from seed

### Vendored Cryptography
- `crypto/kyber512/` - Kyber512 KEM from pq-crystals (includes FIPS202/SHAKE256)
- `crypto/dilithium/` - Dilithium3 signatures from pq-crystals

Both implementations are compiled directly into the binary with no external dependencies.

## Version

Current version: **1.2.x** (auto-incrementing patch version based on git commit count)

Check version: `qgp --version`

## License

GNU General Public License v3.0
