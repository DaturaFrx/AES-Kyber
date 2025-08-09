### Overview

This tool provides a command-line interface for key generation, encryption, and decryption using the Kyber post-quantum key encapsulation mechanism combined with AES-256-GCM symmetric encryption.

---

### Features

* Generate Kyber public/private key pairs and save them in PEM format
* Encrypt arbitrary files with a Kyber public key
* Decrypt files with a Kyber private key
* Uses AES-256-GCM authenticated encryption with a random IV
* Ensures sensitive key and plaintext buffers are securely cleansed from memory after use

---

### Usage

```
kyber genkeys <pubkey_file> <privkey_file>
kyber encrypt <pubkey_file> <input_file> <output_file>
kyber decrypt <privkey_file> <input_file> <output_file>
```

---

### File Format

Encrypted files have the following structure:

* Magic bytes: 5 bytes to identify file type
* Kyber ciphertext: Fixed length (defined by PQClean Kyber constants)
* AES-GCM IV (nonce): 12 bytes
* AES-GCM ciphertext: Variable length (matches input file size)
* AES-GCM authentication tag: 16 bytes

---

### Security Notes

* Kyber provides post-quantum security for key encapsulation.
* AES-256-GCM provides authenticated encryption of file data.
* No password or passphrase protection on PEM key files, secure key storage is the user's responsibility (As per the AGE Scheme philosophy).
* Minimum plaintext size enforced at 8 bytes.
* Sensitive data buffers are cleansed after use to reduce risk of memory leakage.

---

### Limitations and Recommendations

* The Kyber shared secret is used directly as AES key without additional KDF processing (I'M WORKING ON IT!!!).
* Key files are stored in unencrypted PEM format; protect private keys carefully.
* Error messages may reveal operational details; avoid using in hostile environments without additional hardening.
* File magic bytes are static and visible; consider secure filesystem practices to protect encrypted files.
* Currently no support for large file streaming or chunked encryption.

---

### Build & Dependencies

* Requires PQClean Kyber implementation headers and libraries
* Requires OpenSSL development headers and libraries (for AES-GCM and base64)
* C++17 or later compiler recommended

---

# Future Versions (Planned Enhancements)

---

**1. Multi-Algorithm Symmetric Encryption Support**

* Add options to select symmetric cipher: AES-256-GCM, ChaCha20-Poly1305, or Serpent-GCM/EAX.
* Abstract cipher interface for easy extension and maintenance.
* Allow users to specify preferred cipher via CLI or config.

---

**2. Password-Based Encryption (PBE) Mode**

* Introduce symmetric encryption mode where a password/passphrase derives the encryption key.
* Implement Argon2id KDF for low-entropy passphrases to resist brute-force and side-channel attacks.
* Use HKDF or similar KDF for high-entropy keys or pre-shared secrets.
* Securely salt and nonce the encryption to avoid key reuse.

---

**3. Nonce Protection and Robust AE Modes**

* Explore use of AES-EAX mode or Serpent-EAX to offer combined confidentiality and nonce misuse resistance.
* Add nonce management policies to prevent reuse and reduce risks of catastrophic AE failures.
* Implement nonce derivation or ratcheting mechanisms for file chunking and streaming scenarios.

---

**4. File Format Versioning and Backward Compatibility**

* Extend encrypted file format with version metadata and cipher suite identifiers.
* Maintain backward compatibility with current Kyber + AES-GCM format.
* Facilitate future migrations and key format upgrades.

---

**5. Secure Key Storage Enhancements**

* Add encrypted PEM key storage with user-defined passphrase protection.
* Integrate hardware-backed secure elements (TPM, HSM) for private key isolation and usage.
* Support ephemeral keys with automatic expiration and rotation policies.

---

**6. Performance and Scalability**

* Support large file streaming and chunked encryption to handle gigabyte-scale files efficiently.
* Implement multi-threaded cryptographic operations where possible.
* Optimize memory usage and secure buffer handling in high-load scenarios.

---

**7. Enhanced Audit Logging and Error Handling**

* Standardize error codes with minimal information leakage.
* Add optional audit logs with configurable verbosity for forensic purposes.
* Harden against timing and side-channel leakage in all cryptographic primitives and I/O paths.
