// main.cpp
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>

#include "crypto_utils.h"
#include "key_io.h"
#include "pem_utils.h"
#include "constants.h"

void print_usage()
{
    std::cout << "Usage:\n";
    std::cout << "  kyber genkeys <pubkey_file> <privkey_file>\n";
    std::cout << "  kyber encrypt <pubkey_file> <input_file> <output_file>\n";
    std::cout << "  kyber decrypt <privkey_file> <input_file> <output_file>\n";
}

// Unified key loading function with size validation
bool load_key(const std::string &filepath, std::vector<uint8_t> &key, bool &is_private)
{
    // First try PEM format (most common)
    if (pem_read_key(filepath, key, is_private)) {
        // Validate key size based on type
        if (is_private && key.size() != CRYPTO_SECRETKEYBYTES) {
            std::cerr << "Warning: Private key size (" << key.size() 
                      << ") doesn't match expected size (" << CRYPTO_SECRETKEYBYTES << ")\n";
            // Don't fail immediately - some implementations may have different sizes
        }
        if (!is_private && key.size() != CRYPTO_PUBLICKEYBYTES) {
            std::cerr << "Warning: Public key size (" << key.size() 
                      << ") doesn't match expected size (" << CRYPTO_PUBLICKEYBYTES << ")\n";
        }
        return true;
    }
    
    // Try raw binary format as fallback
    std::ifstream ifs(filepath, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return false;
    }
    
    std::streamsize size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    if (size <= 0) {
        return false;
    }
    
    key.resize(static_cast<size_t>(size));
    if (!ifs.read(reinterpret_cast<char*>(key.data()), size)) {
        return false;
    }
    
    // Determine key type based on size
    if (key.size() == CRYPTO_SECRETKEYBYTES) {
        is_private = true;
    } else if (key.size() == CRYPTO_PUBLICKEYBYTES) {
        is_private = false;
    } else {
        std::cerr << "Warning: Key size (" << key.size() << ") doesn't match expected sizes. "
                  << "Expected: " << CRYPTO_PUBLICKEYBYTES << " (public) or " 
                  << CRYPTO_SECRETKEYBYTES << " (private)\n";
        // Default to public key assumption for unknown sizes
        is_private = false;
    }
    
    return true;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "genkeys") {
        if (argc != 4) {
            print_usage();
            return 1;
        }

        KyberKeypair keypair;
        if (!crypto_generate_keypair(keypair)) {
            std::cerr << "Key generation failed\n";
            return 1;
        }

        if (!save_key_pem(argv[2], keypair.public_key, false) ||
            !save_key_pem(argv[3], keypair.secret_key, true)) {
            std::cerr << "Failed to save keys\n";
            return 1;
        }

        std::cout << "Keys generated and saved successfully\n";
        return 0;
    }
    else if (cmd == "encrypt") {
        if (argc != 5) {
            print_usage();
            return 1;
        }

        std::vector<uint8_t> pub_key;
        bool is_private = false;
        
        if (!load_key(argv[2], pub_key, is_private)) {
            std::cerr << "Failed to load key from file: " << argv[2] << "\n";
            return 1;
        }
        
        if (is_private) {
            std::cerr << "Error: Provided key is private, but public key is required for encryption\n";
            return 1;
        }

        std::cout << "Loaded public key, size: " << pub_key.size() << " bytes\n";

        if (!crypto_encrypt_file(pub_key, argv[3], argv[4])) {
            std::cerr << "Encryption failed\n";
            return 1;
        }

        std::cout << "File encrypted successfully\n";
        return 0;
    }
    else if (cmd == "decrypt") {
        if (argc != 5) {
            print_usage();
            return 1;
        }

        std::vector<uint8_t> priv_key;
        bool is_private = false;
        
        if (!load_key(argv[2], priv_key, is_private)) {
            std::cerr << "Failed to load key from file: " << argv[2] << "\n";
            return 1;
        }
        
        if (!is_private) {
            std::cerr << "Error: Provided key is public, but private key is required for decryption\n";
            return 1;
        }

        std::cout << "Loaded private key, size: " << priv_key.size() << " bytes\n";

        if (!crypto_decrypt_file(priv_key, argv[3], argv[4])) {
            std::cerr << "Decryption failed\n";
            return 1;
        }

        std::cout << "File decrypted successfully\n";
        return 0;
    }
    else {
        print_usage();
        return 1;
    }
}