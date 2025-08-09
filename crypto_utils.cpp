// crypto_utils.cpp
#include "crypto_utils.h"
#include "constants.h"

#include <fstream>
#include <iostream>
#include <vector>
#include <cstring> // for memset

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h> // for OPENSSL_cleanse

extern "C" {
    #include "api.h"  // Kyber PQClean API
}

static void secure_clean(std::vector<uint8_t> &buf) {
    if (!buf.empty()) {
        OPENSSL_cleanse(buf.data(), buf.size());
        buf.clear();
        buf.shrink_to_fit();
    }
}

static void secure_clean_raw(uint8_t *ptr, size_t len) {
    if (ptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

bool crypto_generate_keypair(KyberKeypair &keypair) {
    keypair.public_key.resize(CRYPTO_PUBLICKEYBYTES);
    keypair.secret_key.resize(CRYPTO_SECRETKEYBYTES);

    int ret = PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(keypair.public_key.data(), keypair.secret_key.data());
    if (ret != 0) {
        secure_clean(keypair.public_key);
        secure_clean(keypair.secret_key);
        return false;
    }
    return true;
}

bool crypto_encrypt_file(const std::vector<uint8_t> &public_key,
                         const std::string &in_file,
                         const std::string &out_file) {
    std::ifstream ifs(in_file, std::ios::binary | std::ios::ate);
    if (!ifs) {
        std::cerr << "Failed to open input file for encryption\n";
        return false;
    }

    auto file_size = ifs.tellg();
    if (file_size < MIN_FILE_SIZE || file_size > static_cast<std::streamsize>(MAX_FILE_SIZE)) {
        std::cerr << "Input file size is out of allowed range\n";
        return false;
    }

    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> plaintext(static_cast<size_t>(file_size));
    ifs.read(reinterpret_cast<char*>(plaintext.data()), file_size);
    ifs.close();

    std::vector<uint8_t> ciphertext(CRYPTO_CIPHERTEXTBYTES);
    std::vector<uint8_t> shared_secret(CRYPTO_BYTES);

    if (PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(ciphertext.data(), shared_secret.data(), public_key.data()) != 0) {
        secure_clean(shared_secret);
        std::cerr << "Kyber encapsulation failed\n";
        return false;
    }

    if (shared_secret.size() < KEY_LEN) {
        secure_clean(shared_secret);
        std::cerr << "Shared secret size too small\n";
        return false;
    }

    uint8_t iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) {
        secure_clean(shared_secret);
        std::cerr << "Failed to generate random IV\n";
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secure_clean(shared_secret);
        std::cerr << "Failed to create EVP context\n";
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, shared_secret.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_clean(shared_secret);
        std::cerr << "EVP_EncryptInit_ex failed\n";
        return false;
    }

    int out_len = 0;
    std::vector<uint8_t> encrypted(plaintext.size());

    if (EVP_EncryptUpdate(ctx, encrypted.data(), &out_len, plaintext.data(), (int)plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_clean(shared_secret);
        std::cerr << "EVP_EncryptUpdate failed\n";
        return false;
    }
    int ciphertext_len = out_len;

    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + out_len, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_clean(shared_secret);
        std::cerr << "EVP_EncryptFinal_ex failed\n";
        return false;
    }
    ciphertext_len += out_len;

    uint8_t tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_clean(shared_secret);
        std::cerr << "Failed to get GCM tag\n";
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    std::ofstream ofs(out_file, std::ios::binary);
    if (!ofs) {
        secure_clean(shared_secret);
        std::cerr << "Failed to open output file for encryption\n";
        return false;
    }

    ofs.write(reinterpret_cast<const char*>(MAGIC_BYTES), MAGIC_LEN);
    ofs.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    ofs.write(reinterpret_cast<const char*>(iv), IV_LEN);
    ofs.write(reinterpret_cast<const char*>(encrypted.data()), ciphertext_len);
    ofs.write(reinterpret_cast<const char*>(tag), TAG_LEN);
    ofs.close();

    // Purge sensitive data now
    secure_clean(shared_secret);
    secure_clean(plaintext);
    secure_clean(encrypted);

    return true;
}

bool crypto_decrypt_file(const std::vector<uint8_t> &secret_key,
                         const std::string &in_file,
                         const std::string &out_file) {
    std::ifstream ifs(in_file, std::ios::binary | std::ios::ate);
    if (!ifs) {
        std::cerr << "Failed to open input file for decryption\n";
        return false;
    }

    auto file_size = ifs.tellg();
    if (file_size < (MAGIC_LEN + CRYPTO_CIPHERTEXTBYTES + IV_LEN + TAG_LEN + MIN_FILE_SIZE)) {
        std::cerr << "Encrypted file too small or corrupted\n";
        return false;
    }

    ifs.seekg(0, std::ios::beg);

    std::vector<uint8_t> header(MAGIC_LEN);
    ifs.read(reinterpret_cast<char*>(header.data()), MAGIC_LEN);
    if (memcmp(header.data(), MAGIC_BYTES, MAGIC_LEN) != 0) {
        std::cerr << "Magic bytes do not match, invalid file format\n";
        return false;
    }

    std::vector<uint8_t> ciphertext(CRYPTO_CIPHERTEXTBYTES);
    ifs.read(reinterpret_cast<char*>(ciphertext.data()), CRYPTO_CIPHERTEXTBYTES);

    uint8_t iv[IV_LEN];
    ifs.read(reinterpret_cast<char*>(iv), IV_LEN);

    size_t aes_ciphertext_len = static_cast<size_t>(file_size) - MAGIC_LEN - CRYPTO_CIPHERTEXTBYTES - IV_LEN - TAG_LEN;
    if (aes_ciphertext_len < MIN_FILE_SIZE) {
        std::cerr << "AES ciphertext length too small\n";
        return false;
    }

    std::vector<uint8_t> encrypted(aes_ciphertext_len);
    ifs.read(reinterpret_cast<char*>(encrypted.data()), aes_ciphertext_len);

    uint8_t tag[TAG_LEN];
    ifs.read(reinterpret_cast<char*>(tag), TAG_LEN);

    ifs.close();

    std::vector<uint8_t> shared_secret(CRYPTO_BYTES);
    if (PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(shared_secret.data(), ciphertext.data(), secret_key.data()) != 0) {
        secure_clean(shared_secret);
        std::cerr << "Kyber decapsulation failed\n";
        return false;
    }

    if (shared_secret.size() < KEY_LEN) {
        secure_clean(shared_secret);
        std::cerr << "Shared secret size too small\n";
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secure_clean(shared_secret);
        std::cerr << "Failed to create EVP context\n";
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, shared_secret.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_clean(shared_secret);
        std::cerr << "EVP_DecryptInit_ex failed\n";
        return false;
    }

    int out_len = 0;
    std::vector<uint8_t> plaintext(encrypted.size());

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, encrypted.data(), (int)encrypted.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_clean(shared_secret);
        std::cerr << "EVP_DecryptUpdate failed\n";
        return false;
    }
    int plaintext_len = out_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_clean(shared_secret);
        std::cerr << "Failed to set GCM tag\n";
        return false;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &out_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) {
        secure_clean(shared_secret);
        secure_clean(plaintext);
        std::cerr << "Decryption failed: tag mismatch or corrupted data\n";
        return false;
    }
    plaintext_len += out_len;

    std::ofstream ofs(out_file, std::ios::binary);
    if (!ofs) {
        secure_clean(shared_secret);
        secure_clean(plaintext);
        std::cerr << "Failed to open output file for decryption\n";
        return false;
    }

    ofs.write(reinterpret_cast<const char*>(plaintext.data()), plaintext_len);
    ofs.close();

    // Purge sensitive buffers
    secure_clean(shared_secret);
    secure_clean(plaintext);
    secure_clean(encrypted);

    return true;
}
