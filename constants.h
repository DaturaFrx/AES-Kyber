// constants.h
#pragma once
#include <cstddef>
#include <cstdint>
#include <array>

// Include PQClean API first to get the constants
extern "C" {
#include "api.h"
}

// Kyber768 algorithm constants
#define CRYPTO_SECRETKEYBYTES PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_BYTES PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES

// Cryptographic parameters - also define without namespace for backward compatibility
namespace crypto {
    // Core symmetric crypto parameters
    constexpr size_t SALT_LEN = 32;                 // Salt for KDF operations
    constexpr size_t IV_LEN = 12;                   // AES-GCM nonce length (96 bits)
    constexpr size_t TAG_LEN = 16;                  // AES-GCM auth tag length (128 bits)
    constexpr size_t KEY_LEN = 32;                  // Symmetric key length (256 bits)
    
    // HKDF and MAC parameters
    constexpr size_t MAC_KEY_LEN = 32;              // HMAC key length
    constexpr size_t HKDF_OUTPUT_LEN = 96;          // HKDF derived key material length
    constexpr size_t MAC_LEN = 32;                  // HMAC-SHA256 output length
    
    // Entropy and randomness
    constexpr size_t SYSTEM_ENTROPY_BYTES = 128;    // System entropy collection size
    constexpr size_t MIXING_ROUNDS = 7;             // Entropy mixing iterations
    
    // File size constraints
    constexpr size_t MAX_FILE_SIZE = 1ULL << 30;    // 1 GiB (more readable than 1024*1024*1024)
    constexpr size_t MIN_FILE_SIZE = 8;            // Minimum plaintext (avoid edge cases)
    
    // File format magic bytes
    constexpr std::array<uint8_t, 5> MAGIC_BYTES = {0x4B, 0x59, 0x42, 0x52, 0x03}; // "KYBR" + version
    constexpr size_t MAGIC_LEN = MAGIC_BYTES.size();
    
    // Key size validation helpers (compile-time)
    static_assert(CRYPTO_SECRETKEYBYTES > 0, "Secret key size must be positive");
    static_assert(CRYPTO_PUBLICKEYBYTES > 0, "Public key size must be positive");
    static_assert(KEY_LEN == CRYPTO_BYTES, "Symmetric key length should match Kyber shared secret");
    
    // Overhead calculation for encrypted files
    constexpr size_t ENCRYPTION_OVERHEAD = CRYPTO_CIPHERTEXTBYTES + IV_LEN + TAG_LEN + MAGIC_LEN;
}

// Global constants for backward compatibility
constexpr size_t SALT_LEN = crypto::SALT_LEN;
constexpr size_t IV_LEN = crypto::IV_LEN;
constexpr size_t TAG_LEN = crypto::TAG_LEN;
constexpr size_t KEY_LEN = crypto::KEY_LEN;
constexpr size_t MAC_KEY_LEN = crypto::MAC_KEY_LEN;
constexpr size_t HKDF_OUTPUT_LEN = crypto::HKDF_OUTPUT_LEN;
constexpr size_t MAC_LEN = crypto::MAC_LEN;
constexpr size_t SYSTEM_ENTROPY_BYTES = crypto::SYSTEM_ENTROPY_BYTES;
constexpr size_t MIXING_ROUNDS = crypto::MIXING_ROUNDS;
constexpr size_t MAX_FILE_SIZE = crypto::MAX_FILE_SIZE;
constexpr size_t MIN_FILE_SIZE = crypto::MIN_FILE_SIZE;
constexpr auto MAGIC_BYTES = crypto::MAGIC_BYTES.data();
constexpr size_t MAGIC_LEN = crypto::MAGIC_LEN;