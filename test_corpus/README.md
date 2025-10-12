# QGP SDK Independence Test Corpus

**Purpose:** Reference files generated with Cellframe SDK version for backward compatibility validation during SDK independence migration.

**Generated:** 2025-10-12
**SDK Version:** Cellframe SDK develop branch (commit: 1fc3be5)
**QGP Commit:** 6c7e30a (before SDK independence migration)
**Branch:** feature/sdk-independence

---

## Directory Structure

```
test_corpus/
├── keys/               # Test keypairs (private keys, public keys)
├── signatures/         # Test signatures (ASCII armor only)
├── encrypted/          # Test encrypted files (single & multi-recipient)
├── metadata/           # Checksums and documentation
├── test_document.txt   # Original plaintext test file
└── README.md          # This file
```

---

## Test Keys

### 1. sdk_test_random (Randomly Generated)
**Type:** Random key generation (no BIP39)
**Algorithm:** Dilithium3 (signing) + Kyber512 (encryption)

**Files:**
- `keys/sdk_test_random-signing.pqkey` - Private signing key (5.6 KB)
- `keys/sdk_test_random-encryption.pqkey` - Private encryption key (3.5 KB)
- `keys/sdk_test_random.pub` - Public keys bundle (2.9 KB, ASCII armor)

**SHA256 Checksums:**
```
80855a950c35be1fe5dfd333e4ee71a844a2f0f332cadccdc0a651f4acf3ff72  sdk_test_random-signing.pqkey
a57d8e15036bd1bc9bcf79e2a37723f17a3e0b9016e4f47c40bf0b61a65b27ba  sdk_test_random-encryption.pqkey
721f60f763507d0b2af6f7362419a493f63c3296382dc981c1d3a6384c947bb1  sdk_test_random.pub
```

---

### 2. sdk_test_bip39 (BIP39-Based Deterministic)
**Type:** BIP39 mnemonic-based key generation
**Algorithm:** Dilithium3 (signing) + Kyber512 (encryption)
**Passphrase:** None (empty)

**BIP39 Mnemonic (24 words):**
```
blue quiz aware mule solar rotate swamp dutch tiger bacon student zero
body trophy stairs tobacco scorpion traffic spider tourist ostrich chapter survey draft
```

**Files:**
- `keys/sdk_test_bip39-signing.pqkey` - Private signing key (5.6 KB)
- `keys/sdk_test_bip39-encryption.pqkey` - Private encryption key (3.5 KB)
- `keys/sdk_test_bip39.pub` - Public keys bundle (2.9 KB, ASCII armor)
- `keys/sdk_test_bip39_mnemonic.txt` - BIP39 mnemonic for restoration

**SHA256 Checksums:**
```
7fc3b84ff60c21c264efb7afbed9dda3100d5ac799fb3884509d22432fb0ce3c  sdk_test_bip39-signing.pqkey
6470e09c4e0eb45666b998f41b8296cf789fed9d615f3eb792e652ce841c1210  sdk_test_bip39-encryption.pqkey
186e5debe036198601c4d9755292c5ee5859bd569ae8df0865be559383459bcc  sdk_test_bip39.pub
```

**Key Derivation:**
```
BIP39 Mnemonic (24 words)
  ↓ PBKDF2-HMAC-SHA512 (2048 iterations, salt="mnemonic")
Master Seed (512 bits)
  ↓ SHAKE256 (domain-separated)
  ├─→ Signing Seed (256 bits) → Dilithium3 keypair (deterministic)
  └─→ Encryption Seed (256 bits) → Kyber512 keypair (deterministic)
```

---

## Test Document

**File:** `test_document.txt`
**Content:** "This is a test document for SDK independence migration validation."
**Size:** 67 bytes
**SHA256:** `f420fdefaa8ef44098b5f9ad26aad64cdf09a64e07b4b8db6cd966fb2fa443ba`

---

## Test Signatures (ASCII Armor)

### 1. sdk_test_random.asc
**Signed by:** sdk_test_random (random key)
**File signed:** test_document.txt
**Algorithm:** Dilithium3
**Format:** ASCII Armored (.asc)
**Size:** 4.6 KB
**SHA256:** `a9e0f2c678e195e8192b1c88e08c7ed3dafce5629a35ab5f481ba37f3ba3ab4b`

**Verification:**
```bash
qgp --verify --file test_document.txt --signature signatures/sdk_test_random.asc
```

### 2. sdk_test_bip39.asc
**Signed by:** sdk_test_bip39 (BIP39-based key)
**File signed:** test_document.txt
**Algorithm:** Dilithium3
**Format:** ASCII Armored (.asc)
**Size:** 4.6 KB
**SHA256:** `5646a90826202cfd66a79295ae67b4c9a7c84914d4c12442bb4527e1503d434d`

**Verification:**
```bash
qgp --verify --file test_document.txt --signature signatures/sdk_test_bip39.asc
```

---

## Test Encrypted Files

### 1. single_recipient.enc
**Encrypted for:** sdk_test_random
**Encrypted by:** sdk_test_bip39 (signed)
**File encrypted:** test_document.txt
**Encryption:** Kyber512 KEM + AES-256 CBC
**Recipients:** 1
**Size:** 4.1 KB (4,174 bytes)
**SHA256:** `3b00a57aefee57e220c463e3b24e0bf939ff4d90b5fbabe03c2798e78dedd6ca`

**File Structure:**
```
[Header: 20 bytes]
  - Magic: "PQSIGENC" (8 bytes)
  - Version: 0x03 (single recipient)
  - Encryption type: Kyber512
  - Ciphertext size: 768 bytes
  - Signature size: 3306 bytes

[Kyber Ciphertext: 768 bytes]
  - Encapsulated shared secret for recipient

[Encrypted Data: 80 bytes]
  - AES-256-CBC encrypted plaintext (67 bytes + padding)

[Signature: 3306 bytes]
  - Dilithium3 signature of plaintext
  - Signed by: sdk_test_bip39
```

**Decryption:**
```bash
qgp --decrypt --file encrypted/single_recipient.enc --key sdk_test_random
```

---

### 2. multi_recipient.enc
**Encrypted for:** sdk_test_random, sdk_test_bip39
**Encrypted by:** sdk_test_bip39 (signed)
**File encrypted:** test_document.txt
**Encryption:** Kyber512 KEM + AES-256 CBC + RFC 3394 AES Key Wrap
**Recipients:** 2
**Size:** 5.0 KB (5,022 bytes)
**SHA256:** `83354e6eaed3662e84107b35e57d9df5e9a1671e40341c047bc2998afdbe7b09`

**File Structure:**
```
[Header: 20 bytes]
  - Magic: "PQSIGENC" (8 bytes)
  - Version: 0x04 (multi-recipient)
  - Encryption type: Kyber512
  - Recipient count: 2
  - Encrypted size: 80 bytes
  - Signature size: 3306 bytes

[Recipient Entry 1: 808 bytes]
  - Kyber ciphertext: 768 bytes (for sdk_test_random)
  - Wrapped DEK: 40 bytes (RFC 3394 AES Key Wrap)

[Recipient Entry 2: 808 bytes]
  - Kyber ciphertext: 768 bytes (for sdk_test_bip39)
  - Wrapped DEK: 40 bytes (RFC 3394 AES Key Wrap)

[Encrypted Data: 80 bytes]
  - AES-256-CBC encrypted plaintext with DEK
  - Shared among all recipients

[Signature: 3306 bytes]
  - Dilithium3 signature of plaintext
  - Signed by: sdk_test_bip39
```

**Decryption (either recipient):**
```bash
qgp --decrypt --file encrypted/multi_recipient.enc --key sdk_test_random
# OR
qgp --decrypt --file encrypted/multi_recipient.enc --key sdk_test_bip39
```

---

## Validation Tests

### Phase 1: Foundation Layer Validation
After replacing AES/random/utilities with OpenSSL:

**Test 1: Decrypt SDK-encrypted files**
```bash
# Decrypt files encrypted with SDK version
qgp --decrypt --file encrypted/single_recipient.enc --key sdk_test_random
qgp --decrypt --file encrypted/multi_recipient.enc --key sdk_test_bip39

# Verify plaintext matches original
sha256sum -c metadata/checksums.txt
```

**Expected Result:** ✅ Decryption succeeds, plaintext matches original

---

### Phase 2: Kyber512 Migration Validation
After replacing Kyber512 with upstream pq-crystals/kyber:

**Test 2: Cross-encryption compatibility**
```bash
# Encrypt with upstream Kyber, decrypt with SDK Kyber (if still available)
qgp --encrypt --file test_document.txt --recipient sdk_test_random --key sdk_test_bip39

# Encrypt with SDK Kyber, decrypt with upstream Kyber
qgp --decrypt --file encrypted/single_recipient.enc --key sdk_test_random
```

**Test 3: BIP39 deterministic keygen**
```bash
# Restore keys from mnemonic with upstream Kyber
qgp --restore --name upstream_test < keys/sdk_test_bip39_mnemonic.txt

# Compare key checksums
sha256sum ~/.qgp/upstream_test-encryption.pqkey
# Should match: 6470e09c4e0eb45666b998f41b8296cf789fed9d615f3eb792e652ce841c1210
```

**Expected Result:** ✅ Keys generated from same mnemonic are byte-identical

---

### Phase 3: Dilithium Migration Validation
After replacing Dilithium with upstream pq-crystals/dilithium:

**Test 4: Cross-signature compatibility**
```bash
# Verify SDK-generated signatures with upstream Dilithium
qgp --verify --file test_document.txt --signature signatures/sdk_test_random.asc
qgp --verify --file test_document.txt --signature signatures/sdk_test_bip39.asc
```

**Test 5: BIP39 deterministic signing**
```bash
# Restore keys from mnemonic with upstream Dilithium
qgp --restore --name upstream_test < keys/sdk_test_bip39_mnemonic.txt

# Compare key checksums
sha256sum ~/.qgp/upstream_test-signing.pqkey
# Should match: 7fc3b84ff60c21c264efb7afbed9dda3100d5ac799fb3884509d22432fb0ce3c
```

**Test 6: Sign with upstream, verify with SDK**
```bash
# Sign new file with upstream Dilithium
qgp --sign --file test_document.txt --key upstream_test

# Verify with SDK version (if still available)
# Should succeed
```

**Expected Result:** ✅ All cross-validation tests pass

---

### Phase 4: Complete Migration Validation
After removing all SDK dependencies:

**Test 7: Full round-trip**
```bash
# Generate new keys with upstream crypto
qgp --gen-key --name final_test --algo dilithium

# Sign file
qgp --sign --file test_document.txt --key final_test

# Encrypt for SDK-generated key
qgp --encrypt --file test_document.txt --recipient sdk_test_random --key final_test

# Decrypt with SDK-generated key
qgp --decrypt --file test_document.txt.enc --key sdk_test_random

# Verify signature from SDK-generated key
qgp --verify --file test_document.txt --signature signatures/sdk_test_random.asc
```

**Expected Result:** ✅ All operations succeed, full backward compatibility maintained

---

## Success Criteria

**100% PASS REQUIRED:**
- ✅ All SDK-generated signatures verify with upstream Dilithium
- ✅ All SDK-encrypted files decrypt with upstream Kyber + AES
- ✅ BIP39 mnemonic produces byte-identical keys with upstream crypto
- ✅ Multi-recipient encryption remains compatible
- ✅ ASCII armor format unchanged
- ✅ All file formats remain backward compatible
- ✅ No performance regressions (within 5%)

**Acceptance Criteria:**
- Zero user-visible changes
- Zero data loss
- Zero format incompatibilities

---

## Notes

### Binary Signature Format Deprecated
**Decision (2025-10-12):** Binary `.sig` format removed, ASCII armor `.asc` only going forward.

**Impact:** Test corpus only includes ASCII armored signatures.

### Falcon and SPHINCS+ Removed
**Decision (2025-10-12):** Focus on Dilithium + Kyber512 only for initial SDK independence.

**Impact:** Only Dilithium algorithm tested in this corpus.

### File Format Versions
- **v0.03:** Single-recipient encryption (authenticated)
- **v0.04:** Multi-recipient encryption (RFC 3394 AES Key Wrap)

Both versions must remain supported for backward compatibility.

---

## Regenerating Test Corpus

If test corpus needs to be regenerated (e.g., after SDK update):

```bash
cd /opt/pq_signum/test_corpus
rm -rf keys/ signatures/ encrypted/ metadata/

# Regenerate with current SDK version
/opt/pq_signum/qgp-c/build/qgp --gen-key --name sdk_test_random
/opt/pq_signum/qgp-c/build/qgp --gen-key --name sdk_test_bip39 --from-seed
# (save mnemonic to keys/sdk_test_bip39_mnemonic.txt)

# Generate signatures
/opt/pq_signum/qgp-c/build/qgp --sign --file test_document.txt --key sdk_test_random
/opt/pq_signum/qgp-c/build/qgp --sign --file test_document.txt --key sdk_test_bip39

# Generate encrypted files
/opt/pq_signum/qgp-c/build/qgp --encrypt --file test_document.txt --recipient sdk_test_random --key sdk_test_bip39
/opt/pq_signum/qgp-c/build/qgp --encrypt --file test_document.txt --recipient sdk_test_random --recipient sdk_test_bip39 --key sdk_test_bip39

# Update checksums
sha256sum test_document.txt signatures/*.asc encrypted/*.enc keys/*.pqkey keys/*.pub > metadata/checksums.txt
```

---

**Last Updated:** 2025-10-12
**Maintainer:** QGP Development Team
**Purpose:** SDK Independence Migration Validation
