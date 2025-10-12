# QGP SDK Independence Migration Plan
## Dilithium + Kyber512 Focus

**Branch:** `feature/sdk-independence`
**Target:** Remove Cellframe SDK dependency for core operations
**Scope:** Dilithium (signatures) + Kyber512 (encryption) only
**Timeline:** 6-8 weeks
**Effort:** 250-320 hours

---

## Strategy: Minimal Viable Independence

Focus on the **two algorithms we actually use**:
- **Dilithium3 (ML-DSA)** - Default signing algorithm
- **Kyber512 (ML-KEM)** - Encryption algorithm

**Falcon and SPHINCS+ will be removed** (can be added back later if needed).

---

## Current Dependency Assessment

### Dilithium + Kyber512 SDK Usage

**Files using SDK for these algorithms:**
1. `keygen.c` - Key generation for both algorithms
2. `encrypt.c` - Kyber512 encapsulation
3. `decrypt.c` - Kyber512 decapsulation
4. `sign.c` - Dilithium signature creation
5. `verify.c` - Dilithium signature verification
6. `utils.c` - Hashing, memory utilities

**SDK Functions to Replace:**
```c
// Kyber512
dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_KEM_KYBER512, ...)
dap_enc_kyber512_key_new()
dap_enc_kyber512_gen_bob_shared_key()

// Dilithium
dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, ...)
dap_sign_create()
dap_sign_verify()
dap_sign_get_size()

// Utilities
dap_enc_code() / dap_enc_decode()  // AES-256
dap_hash_fast()  // SHA3
randombytes()  // Random
DAP_NEW_Z / DAP_DELETE  // Memory macros
```

---

## Upstream Libraries

### 1. Dilithium (ML-DSA) - FIPS 204
**Source:** https://github.com/pq-crystals/dilithium
**License:** CC0 (Public Domain) or Apache 2.0
**NIST Status:** FIPS 204 approved ✅
**Files Needed:** `ref/` directory (~15 files, ~5,000 LOC)

**API:**
```c
int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);
int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);
```

**Key Sizes:**
- Public key: 1,952 bytes
- Private key: 4,000 bytes
- Signature: ~3,293 bytes (variable)

### 2. Kyber512 (ML-KEM) - FIPS 203
**Source:** https://github.com/pq-crystals/kyber
**License:** CC0 (Public Domain) or Apache 2.0
**NIST Status:** FIPS 203 approved ✅
**Files Needed:** `ref/` directory (~20 files, ~4,000 LOC)

**API:**
```c
int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```

**Key Sizes:**
- Public key: 800 bytes
- Private key: 1,632 bytes
- Ciphertext: 768 bytes
- Shared secret: 32 bytes

### 3. AES-256 CBC
**Source:** OpenSSL libcrypto (already available on most systems)
**License:** Apache 2.0
**Alternative:** mbedTLS (if OpenSSL unavailable)

### 4. SHA3 / SHAKE256
**Source:** XKCP (already in project for BIP39!)
**Location:** `qgp-c/sha3/` (already have it)
**No changes needed** ✅

### 5. Random Bytes
**Source:** `/dev/urandom` (Linux/Unix) or OpenSSL `RAND_bytes()`
**Fallback:** System `getrandom()` syscall

---

## Migration Phases

### Phase 0: Preparation (Week 0)
**Goal:** Set up infrastructure

**Tasks:**
1. ✅ Create feature branch `feature/sdk-independence`
2. Create test corpus:
   - Generate reference keys with current SDK version
   - Generate reference signatures
   - Generate reference encrypted files
   - Save for cross-validation testing
3. Document current file formats byte-by-byte
4. Set up parallel build option (SDK vs upstream)

**Estimated Effort:** 10-15 hours
**Deliverable:** Test corpus + documentation

---

### Phase 1: Foundation Layer (Weeks 1-2)
**Goal:** Replace utilities (AES, random, memory, SHA3)

#### Task 1.1: Memory Macros Replacement
**Change:**
```c
// Before:
DAP_NEW_Z(type)              → calloc(1, sizeof(type))
DAP_NEW_Z_SIZE(type, size)   → calloc(size, sizeof(type))
DAP_DELETE(ptr)              → free(ptr)

// After: Standard C
ptr = calloc(1, sizeof(*ptr));
free(ptr);
```

**Files:** All source files
**Effort:** 2-3 hours (global find/replace)

#### Task 1.2: Random Number Generation
**Create:** `qgp-c/qgp_random.c`

```c
#include <stdio.h>
#include <sys/random.h>  // Linux getrandom()

int qgp_randombytes(uint8_t *buf, size_t len) {
    // Use getrandom() syscall (Linux 3.17+)
    ssize_t ret = getrandom(buf, len, 0);
    if (ret < 0 || (size_t)ret != len) {
        // Fallback to /dev/urandom
        FILE *fp = fopen("/dev/urandom", "rb");
        if (!fp) return -1;
        size_t n = fread(buf, 1, len, fp);
        fclose(fp);
        return (n == len) ? 0 : -1;
    }
    return 0;
}
```

**Effort:** 4-6 hours

#### Task 1.3: AES-256 CBC with OpenSSL
**Create:** `qgp-c/qgp_aes.c`

```c
#include <openssl/evp.h>
#include <openssl/rand.h>

// Encrypt with AES-256-CBC
int qgp_aes256_encrypt(const uint8_t *key, const uint8_t *plaintext,
                       size_t plaintext_len, uint8_t *ciphertext,
                       size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t iv[16];
    RAND_bytes(iv, 16);  // Generate random IV

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext + 16, &len, plaintext, plaintext_len);
    int ciphertext_len_tmp = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + 16 + len, &len);
    ciphertext_len_tmp += len;

    // Prepend IV to ciphertext
    memcpy(ciphertext, iv, 16);
    *ciphertext_len = ciphertext_len_tmp + 16;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Decrypt with AES-256-CBC
int qgp_aes256_decrypt(const uint8_t *key, const uint8_t *ciphertext,
                       size_t ciphertext_len, uint8_t *plaintext,
                       size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Extract IV from ciphertext
    uint8_t iv[16];
    memcpy(iv, ciphertext, 16);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + 16, ciphertext_len - 16);
    int plaintext_len_tmp = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len_tmp += len;

    *plaintext_len = plaintext_len_tmp;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
```

**Effort:** 15-20 hours (including buffer size handling, error cases)

#### Task 1.4: Update encrypt.c / decrypt.c
Replace `dap_enc_code()` / `dap_enc_decode()` calls with `qgp_aes256_*()`.

**Effort:** 10-15 hours

**Phase 1 Total:** 31-44 hours

**Testing:**
- Encrypt file with SDK AES, decrypt with OpenSSL AES
- Encrypt file with OpenSSL AES, decrypt with SDK AES
- Verify file integrity with sha256sum

---

### Phase 2: Kyber512 Migration (Weeks 3-4)
**Goal:** Replace Kyber512 with upstream ML-KEM

#### Task 2.1: Integrate Upstream Kyber
**Action:** Add pq-crystals/kyber as git submodule or vendor into tree

```bash
cd qgp-c
mkdir -p crypto/kyber512
cd crypto/kyber512
# Copy ref/ implementation from pq-crystals/kyber
```

**Files to vendor:**
- `api.h`
- `cbd.c/.h`
- `indcpa.c/.h`
- `kem.c/.h`
- `ntt.c/.h`
- `params.h`
- `poly.c/.h`
- `polyvec.c/.h`
- `reduce.c/.h`
- `symmetric-shake.c` (uses SHAKE256)
- `verify.c/.h`

**Effort:** 6-8 hours

#### Task 2.2: Create QGP Kyber Wrapper
**Create:** `qgp-c/qgp_kyber.c` and `qgp_kyber.h`

```c
// qgp_kyber.h
#ifndef QGP_KYBER_H
#define QGP_KYBER_H

#include <stdint.h>
#include <stddef.h>

#define QGP_KYBER512_PUBLICKEYBYTES  800
#define QGP_KYBER512_SECRETKEYBYTES  1632
#define QGP_KYBER512_CIPHERTEXTBYTES 768
#define QGP_KYBER512_BYTES           32

// Generate Kyber512 keypair
int qgp_kyber512_keypair(uint8_t *pk, uint8_t *sk);

// Generate Kyber512 keypair deterministically from seed
int qgp_kyber512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

// Encapsulation: Generate shared secret and ciphertext
int qgp_kyber512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

// Decapsulation: Recover shared secret from ciphertext
int qgp_kyber512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
```

```c
// qgp_kyber.c
#include "qgp_kyber.h"
#include "crypto/kyber512/kem.h"
#include "qgp_random.h"

int qgp_kyber512_keypair(uint8_t *pk, uint8_t *sk) {
    return pqcrystals_kyber512_ref_keypair(pk, sk);
}

int qgp_kyber512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    // Deterministic key generation from seed
    // Use seed to derive randomness for keypair generation
    // (replaces SDK's dap_enc_key_new_generate with seed parameter)
    return pqcrystals_kyber512_ref_keypair_derand(pk, sk, seed);
}

int qgp_kyber512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return pqcrystals_kyber512_ref_enc(ct, ss, pk);
}

int qgp_kyber512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return pqcrystals_kyber512_ref_dec(ss, ct, sk);
}
```

**Effort:** 12-16 hours

#### Task 2.3: Update keygen.c for Kyber
Replace SDK Kyber key generation with upstream.

**Before:**
```c
enc_key = dap_enc_key_new_generate(
    DAP_ENC_KEY_TYPE_KEM_KYBER512,
    NULL, 0, NULL, 0, 0
);
```

**After:**
```c
uint8_t kyber_pk[800];
uint8_t kyber_sk[1632];
qgp_kyber512_keypair(kyber_pk, kyber_sk);

// For BIP39 deterministic generation:
qgp_kyber512_keypair_derand(kyber_pk, kyber_sk, encryption_seed);
```

**Effort:** 10-15 hours

#### Task 2.4: Update encrypt.c for Kyber Encapsulation
Replace SDK's `dap_enc_kyber512_gen_bob_shared_key()`.

**Before:**
```c
size_t kyber_ct_size = dap_enc_kyber512_gen_bob_shared_key(
    temp_key,
    recipient_pubkey,
    recipient_pubkey_size,
    &kyber_ciphertext
);
```

**After:**
```c
uint8_t kyber_ct[768];
uint8_t shared_secret[32];
qgp_kyber512_enc(kyber_ct, shared_secret, recipient_pubkey);
```

**Effort:** 15-20 hours

#### Task 2.5: Update decrypt.c for Kyber Decapsulation
Replace SDK's Kyber decapsulation.

**Before:**
```c
size_t shared_secret_size = dap_enc_kyber512_gen_alice_shared_key(
    enc_key,
    kyber_ciphertext,
    768,
    &shared_secret
);
```

**After:**
```c
uint8_t shared_secret[32];
qgp_kyber512_dec(shared_secret, kyber_ciphertext, kyber_sk);
```

**Effort:** 15-20 hours

**Phase 2 Total:** 58-79 hours

**Testing:**
- Generate Kyber keys with SDK, encrypt with upstream
- Generate Kyber keys with upstream, encrypt with SDK
- Cross-decryption testing
- BIP39 deterministic key generation compatibility
- Multi-recipient encryption compatibility

---

### Phase 3: Dilithium Migration (Weeks 5-6)
**Goal:** Replace Dilithium with upstream ML-DSA

#### Task 3.1: Integrate Upstream Dilithium
**Action:** Vendor pq-crystals/dilithium reference implementation

```bash
cd qgp-c
mkdir -p crypto/dilithium3
cd crypto/dilithium3
# Copy ref/ implementation from pq-crystals/dilithium
```

**Files to vendor:**
- `api.h`
- `ntt.c/.h`
- `packing.c/.h`
- `params.h`
- `poly.c/.h`
- `polyvec.c/.h`
- `reduce.c/.h`
- `rounding.c/.h`
- `sign.c/.h`
- `symmetric-shake.c`

**Effort:** 6-8 hours

#### Task 3.2: Create QGP Dilithium Wrapper
**Create:** `qgp-c/qgp_dilithium.c` and `qgp_dilithium.h`

```c
// qgp_dilithium.h
#ifndef QGP_DILITHIUM_H
#define QGP_DILITHIUM_H

#include <stdint.h>
#include <stddef.h>

#define QGP_DILITHIUM3_PUBLICKEYBYTES  1952
#define QGP_DILITHIUM3_SECRETKEYBYTES  4000
#define QGP_DILITHIUM3_BYTES           3293  // Max signature size

// Generate Dilithium3 keypair
int qgp_dilithium3_keypair(uint8_t *pk, uint8_t *sk);

// Generate Dilithium3 keypair deterministically from seed
int qgp_dilithium3_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

// Create signature
int qgp_dilithium3_sign(uint8_t *sig, size_t *siglen,
                        const uint8_t *msg, size_t msglen,
                        const uint8_t *sk);

// Verify signature
int qgp_dilithium3_verify(const uint8_t *sig, size_t siglen,
                          const uint8_t *msg, size_t msglen,
                          const uint8_t *pk);

#endif
```

```c
// qgp_dilithium.c
#include "qgp_dilithium.h"
#include "crypto/dilithium3/sign.h"

int qgp_dilithium3_keypair(uint8_t *pk, uint8_t *sk) {
    return pqcrystals_dilithium3_ref_keypair(pk, sk);
}

int qgp_dilithium3_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    // Deterministic key generation from seed
    return pqcrystals_dilithium3_ref_keypair_derand(pk, sk, seed);
}

int qgp_dilithium3_sign(uint8_t *sig, size_t *siglen,
                        const uint8_t *msg, size_t msglen,
                        const uint8_t *sk) {
    return pqcrystals_dilithium3_ref_signature(sig, siglen, msg, msglen, sk);
}

int qgp_dilithium3_verify(const uint8_t *sig, size_t siglen,
                          const uint8_t *msg, size_t msglen,
                          const uint8_t *pk) {
    return pqcrystals_dilithium3_ref_verify(sig, siglen, msg, msglen, pk);
}
```

**Effort:** 12-16 hours

#### Task 3.3: Update keygen.c for Dilithium
Replace SDK Dilithium key generation.

**Before:**
```c
sign_key = dap_enc_key_new_generate(
    DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
    NULL, 0,
    signing_seed, 32,  // For BIP39
    0
);
```

**After:**
```c
uint8_t dilithium_pk[1952];
uint8_t dilithium_sk[4000];

// Random generation:
qgp_dilithium3_keypair(dilithium_pk, dilithium_sk);

// BIP39 deterministic:
qgp_dilithium3_keypair_derand(dilithium_pk, dilithium_sk, signing_seed);
```

**Effort:** 10-15 hours

#### Task 3.4: Update sign.c
Replace SDK's `dap_sign_create()`.

**Before:**
```c
dap_sign_t *signature = dap_sign_create(sign_key, file_data, file_size);
size_t sig_size = dap_sign_get_size(signature);
```

**After:**
```c
uint8_t signature[QGP_DILITHIUM3_BYTES];
size_t siglen;
qgp_dilithium3_sign(signature, &siglen, file_data, file_size, dilithium_sk);
```

**Effort:** 15-20 hours

#### Task 3.5: Update verify.c
Replace SDK's `dap_sign_verify()`.

**Before:**
```c
int result = dap_sign_verify(signature, file_data, file_size);
```

**After:**
```c
int result = qgp_dilithium3_verify(signature, siglen, file_data, file_size, dilithium_pk);
```

**Effort:** 15-20 hours

**Phase 3 Total:** 58-79 hours

**Testing:**
- Sign with SDK, verify with upstream
- Sign with upstream, verify with SDK
- ASCII armor compatibility
- BIP39 deterministic signing compatibility
- Large file signing (10MB+)

---

### Phase 4: Cleanup & Integration (Weeks 7-8)
**Goal:** Remove SDK completely, finalize build system

#### Task 4.1: Remove SDK References
**Actions:**
1. Remove all `#include "dap_*.h"` headers
2. Remove SDK from CMakeLists.txt
3. Remove SDK git submodule
4. Update .gitmodules

**Effort:** 6-8 hours

#### Task 4.2: Update CMakeLists.txt
**New dependencies:**
```cmake
# OpenSSL for AES
find_package(OpenSSL REQUIRED)
target_link_libraries(qgp OpenSSL::Crypto)

# Include upstream crypto
add_subdirectory(crypto/kyber512)
add_subdirectory(crypto/dilithium3)

# QGP crypto wrappers
add_library(qgp_crypto
    qgp_kyber.c
    qgp_dilithium.c
    qgp_aes.c
    qgp_random.c
)
target_link_libraries(qgp qgp_crypto kyber512 dilithium3)
```

**Effort:** 8-12 hours

#### Task 4.3: Update Build Documentation
Update README.md with new build instructions (no SDK required!).

**Effort:** 2-4 hours

#### Task 4.4: Comprehensive Testing
**Test Matrix:**
- ✅ Key generation (random + BIP39)
- ✅ Key restoration from BIP39
- ✅ Signing + verification
- ✅ Encryption + decryption (single recipient)
- ✅ Multi-recipient encryption
- ✅ ASCII armor
- ✅ Keyring operations
- ✅ Cross-validation: SDK ↔ Upstream
- ✅ File format compatibility

**Effort:** 30-40 hours

#### Task 4.5: Performance Benchmarking
Compare SDK vs upstream performance:
- Key generation speed
- Signing speed
- Verification speed
- Encryption speed
- Decryption speed
- Binary size

**Effort:** 8-10 hours

**Phase 4 Total:** 54-74 hours

---

## Total Effort Summary

| Phase | Effort (hours) |
|-------|---------------|
| Phase 0: Preparation | 10-15 |
| Phase 1: Foundation | 31-44 |
| Phase 2: Kyber512 | 58-79 |
| Phase 3: Dilithium | 58-79 |
| Phase 4: Cleanup | 54-74 |
| **TOTAL** | **211-291 hours** |

**Timeline:** 6-8 weeks (full-time) or 12-16 weeks (part-time)

---

## Simplified Architecture

### Before (SDK-dependent):
```
QGP Application
    ↓
Cellframe SDK (500MB)
    ↓
[Dilithium, Kyber, Falcon, SPHINCS+, AES, SHA3, ...]
    ↓
System Libraries
```

### After (SDK-independent):
```
QGP Application
    ↓
QGP Crypto Wrappers (thin layer)
    ↓
├─ pq-crystals/dilithium (5MB)
├─ pq-crystals/kyber (4MB)
├─ OpenSSL (AES, SHA3)
└─ System (random)
```

**Size Reduction:** 500MB → 9MB (~98% smaller)

---

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Backward compatibility breaks | CRITICAL | Extensive cross-validation testing |
| BIP39 deterministic keygen breaks | HIGH | Test with saved mnemonics |
| Performance regression | MEDIUM | Benchmark each phase |
| Build complexity increases | LOW | Well-documented CMake |

---

## Success Criteria

**Must achieve 100% on all:**
- ✅ Existing `.pqkey` files still load
- ✅ Existing `.sig` files still verify
- ✅ Existing `.enc` files still decrypt
- ✅ BIP39 mnemonic restoration produces identical keys
- ✅ All CLI commands work identically
- ✅ Cross-validation: SDK-generated files work with upstream code
- ✅ Cross-validation: Upstream-generated files work with SDK code
- ✅ Build completes without SDK
- ✅ Binary size reduced
- ✅ No performance regressions (within 5%)

---

## Next Steps

1. **Approve this focused plan** (Dilithium + Kyber only)
2. **Phase 0: Generate test corpus** with current SDK version
3. **Begin Phase 1: Foundation layer** (AES, random, utilities)
4. **Weekly progress reviews**

**Branch:** `feature/sdk-independence` (already created ✅)

---

**Questions for User:**
1. Timeline preference: Full-time (6-8 weeks) or part-time (12-16 weeks)?
2. Should we remove Falcon/SPHINCS+ support entirely or keep as "deprecated"?
3. Approval to proceed with Phase 0 (test corpus generation)?
