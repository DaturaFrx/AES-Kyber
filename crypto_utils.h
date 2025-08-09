// crypto_utils.h
#pragma once
#include <vector>
#include <string>
#include <cstdint>

struct KyberKeypair {
    std::vector<uint8_t> public_key;   // size CRYPTO_PUBLICKEYBYTES
    std::vector<uint8_t> secret_key;   // size CRYPTO_SECRETKEYBYTES
};

// PQClean Kyber function wrappers
bool crypto_generate_keypair(KyberKeypair &keypair);
bool crypto_encrypt_file(const std::vector<uint8_t> &public_key,
                         const std::string &in_file,
                         const std::string &out_file);
bool crypto_decrypt_file(const std::vector<uint8_t> &secret_key,
                         const std::string &in_file,
                         const std::string &out_file);
