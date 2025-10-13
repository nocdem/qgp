# Windows Build Instructions for QGP

**Branch:** `winport`
**Latest Commit:** 88dbbfa
**Status:** Ready for Windows testing

## What Was Fixed

### Phase 1: Platform Abstraction Layer ✅
- Created `qgp_platform.h` with unified API
- Implemented `qgp_platform_windows.c` (Windows CNG, _mkdir, GetFileAttributesA)
- Implemented `qgp_platform_linux.c` (getrandom, mkdir, stat, access)
- Refactored all application code to use platform abstraction

### Phase 2: Application Code Refactoring ✅
- Refactored `utils.c` - Removed POSIX dependencies
- Refactored `keygen.c` - Replaced mkdir/stat with platform abstraction
- Refactored `keyring.c` - Updated directory management
- All platform-specific code isolated in two files

### Phase 3: MSVC Compiler Compatibility ✅
- Created `qgp_compiler.h` with cross-platform macros
- Fixed `__attribute__((packed))` → PACK_STRUCT_BEGIN/END
- Mapped `strcasecmp` → `_stricmp` for MSVC
- Removed unnecessary `unistd.h` includes
- Fixed Dilithium3 CMake (added MSVC flags: /W3, /O2)
- Fixed Kyber512 CMake (wrapped GCC flags in if(NOT MSVC))

### Phase 4: POSIX Compatibility Layer ✅
- Implemented `win32/getopt.h` + `win32/getopt.c` (POSIX getopt for Windows)
- Implemented `win32/dirent.h` + `win32/dirent.c` (POSIX directory functions)
- Updated CMakeLists.txt to include Windows-specific sources
- Added win32/ to Windows include paths

## Prerequisites

1. **Visual Studio Build Tools 2022** (already installed)
2. **vcpkg** (for OpenSSL)
3. **CMake** (version 3.10+)

## Installation Steps

### 1. Install vcpkg (if not already installed)

```cmd
cd C:\
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat
```

### 2. Install OpenSSL via vcpkg

```cmd
cd C:\vcpkg
vcpkg install openssl:x64-windows
vcpkg integrate install
```

### 3. Pull Latest Code

```cmd
cd C:\qgp
git fetch origin
git checkout winport
git pull origin winport
```

**Expected output:**
- Should pull commits f5cd5c7 (MSVC compatibility) and 88dbbfa (POSIX layer)

### 4. Clean Previous Build

```cmd
cd C:\qgp
rmdir /S /Q build
mkdir build
cd build
```

### 5. Configure with CMake

```cmd
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
```

**Expected output:**
```
-- The C compiler identification is MSVC
-- Platform: Windows
-- OpenSSL found: 3.x.x
-- Configuring done
-- Generating done
```

### 6. Build

```cmd
cmake --build . --config Release
```

**Expected output:**
```
Building Custom Rule C:/qgp/crypto/dilithium/CMakeLists.txt
  dilithium.vcxproj -> C:\qgp\build\crypto\dilithium\Release\dilithium.lib
Building Custom Rule C:/qgp/crypto/kyber512/CMakeLists.txt
  kyber512.vcxproj -> C:\qgp\build\crypto\kyber512\Release\kyber512.lib
Building Custom Rule C:/qgp/CMakeLists.txt
  [compilation of all .c files]
  qgp.vcxproj -> C:\qgp\build\Release\qgp.exe
Build succeeded.
```

### 7. Test the Binary

```cmd
cd C:\qgp\build\Release
qgp.exe --version
```

**Expected output:**
```
qgp version 1.2.24
Build date: 2025-10-13
Git commit: 88dbbfa

Post-quantum file signing and encryption tool
Signatures: Dilithium3 (ML-DSA-65, FIPS 204)
Encryption: Kyber512 KEM + AES-256-CBC (public key encryption)
```

## Testing Commands

### Basic Functionality Tests

```cmd
cd C:\qgp\build\Release

REM Test key generation
qgp.exe --gen-key --name test-windows

REM Test file signing
echo "Hello from Windows" > test.txt
qgp.exe --sign --file test.txt --key test-windows

REM Test signature verification
qgp.exe --verify --file test.txt

REM Test encryption (self-encryption)
qgp.exe --encrypt --file test.txt --recipient test-windows --key test-windows

REM Test decryption
qgp.exe --decrypt --file test.txt.enc --key test-windows

REM Test keyring listing
qgp.exe --list-keys

REM Test help
qgp.exe --help
```

### Cross-Platform Compatibility Tests

**On Windows:**
1. Generate keys and encrypt a file
2. Copy encrypted file to Linux

**On Linux:**
1. Import Windows public key
2. Decrypt the file
3. Verify signature

This tests that the file formats are truly cross-platform.

## Known Warnings (Safe to Ignore)

The following warnings are expected and safe:

1. **C4244: conversion from 'uint64_t' to 'uint8_t'**
   - Source: Dilithium and Kyber crypto libraries
   - Reason: Intentional narrowing conversions in crypto algorithms
   - Impact: None (these are part of the reference implementations)

2. **C4267: conversion from 'size_t' to 'uint16_t'**
   - Source: Signature size calculations
   - Reason: Size values known to fit in uint16_t
   - Impact: None (signature sizes are validated)

3. **C4996: 'strncpy'/'strcpy'/'strtok' unsafe**
   - Reason: MSVC security warnings for C standard library functions
   - Impact: None (buffer sizes are properly managed)
   - Future: Can be suppressed with /D_CRT_SECURE_NO_WARNINGS if desired

## Troubleshooting

### Error: "Cannot find OpenSSL"
```cmd
cd C:\vcpkg
vcpkg install openssl:x64-windows
vcpkg integrate install
```
Then re-run cmake configure.

### Error: "cl: command not found"
Make sure you're using the **Visual Studio Developer Command Prompt** or **x64 Native Tools Command Prompt**.

### Error: "CMake version too old"
Download and install CMake 3.10 or newer from https://cmake.org/download/

### Build succeeds but binary doesn't run
Make sure you're running the binary from `build\Release\qgp.exe`, not `build\qgp.exe`.

## What's Different on Windows

1. **Random Number Generation:** Uses Windows CNG (`BCryptGenRandom`) instead of Linux `getrandom()`
2. **File Paths:** Uses `%USERPROFILE%` instead of `$HOME`, backslashes instead of forward slashes
3. **Directory Operations:** Uses `_mkdir()` and `GetFileAttributesA()` instead of POSIX `mkdir()` and `stat()`
4. **Command Line Parsing:** Uses included getopt implementation instead of system getopt
5. **Directory Listing:** Uses included dirent implementation (wraps FindFirstFile/FindNextFile)

## File Format Compatibility

**All file formats are cross-platform compatible:**
- Private keys (`.pqkey`) - Binary format, big-endian
- Public keys (`.asc`, `.pub`) - ASCII armor or binary
- Signatures (`.asc`, `.sig`) - ASCII armor or binary
- Encrypted files (`.enc`) - Binary format

Files created on Windows can be decrypted/verified on Linux and vice versa.

## Performance Expectations

- **Key Generation:** ~100-200ms (both platforms)
- **Signing:** ~5-10ms per file (both platforms)
- **Verification:** ~5-10ms per file (both platforms)
- **Encryption:** Depends on file size (~100 MB/s)
- **Decryption:** Depends on file size (~100 MB/s)

## Next Steps After Successful Build

1. Run the test suite (all commands above)
2. Test cross-platform compatibility (encrypt on Windows, decrypt on Linux)
3. Test with large files (>100 MB)
4. Test multi-recipient encryption
5. Test BIP39 key generation (`--gen-key --from-seed --name alice`)
6. Test BIP39 key restoration (`--restore --name alice`)

## Reporting Issues

If the build fails or tests don't work, please provide:
1. Full cmake configure output
2. Full build output
3. QGP version (`qgp.exe --version`)
4. Windows version
5. Visual Studio Build Tools version

Post issues to: https://github.com/nocdem/qgp/issues

## Success Criteria

✅ Build completes without errors
✅ Binary runs and shows version
✅ Key generation works
✅ Sign/verify works
✅ Encrypt/decrypt works
✅ Keyring operations work
✅ Files are compatible with Linux version

---

**Last Updated:** 2025-10-13
**Branch:** winport
**Commit:** 88dbbfa
**Status:** Ready for Windows testing
