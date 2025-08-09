// pem_utils.cpp
#include "pem_utils.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cctype>
#include <algorithm>

static const char *PUB_HDR = "-----BEGIN KYBER PUBLIC KEY-----";
static const char *PUB_FTR = "-----END KYBER PUBLIC KEY-----";
static const char *PRIV_HDR = "-----BEGIN KYBER PRIVATE KEY-----";
static const char *PRIV_FTR = "-----END KYBER PRIVATE KEY-----";

// Standard PEM headers as fallback
static const char *STD_PUB_HDR = "-----BEGIN PUBLIC KEY-----";
static const char *STD_PUB_FTR = "-----END PUBLIC KEY-----";
static const char *STD_PRIV_HDR = "-----BEGIN PRIVATE KEY-----";
static const char *STD_PRIV_FTR = "-----END PRIVATE KEY-----";

static void cleanse_string(std::string &s) {
    OPENSSL_cleanse(s.data(), s.size());
    s.clear();
}

static bool is_base64_char(char c) {
    return (std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=');
}

static inline std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Base64 decode function
static bool base64_decode(const std::string &b64_data, std::vector<unsigned char> &out) {
    if (b64_data.empty()) {
        return false;
    }
    
    BIO *bio = BIO_new_mem_buf(b64_data.data(), static_cast<int>(b64_data.size()));
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    // Important: Set BIO_FLAGS_BASE64_NO_NL to handle concatenated base64 without newlines
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    out.resize(b64_data.size()); // Allocate enough space
    int decoded_len = BIO_read(bio, out.data(), static_cast<int>(out.size()));
    
    BIO_free_all(bio);
    
    if (decoded_len <= 0) {
        OPENSSL_cleanse(out.data(), out.size());
        out.clear();
        return false;
    }
    
    out.resize(static_cast<size_t>(decoded_len));
    return true;
}

// Unified PEM parsing function
static bool parse_pem_content(const std::string &content, std::vector<unsigned char> &out, bool &is_private) {
    std::istringstream iss(content);
    std::string line;
    bool header_found = false;
    bool private_found = false;
    std::string b64_data;
    
    while (std::getline(iss, line)) {
        line = trim(line);
        if (line.empty()) continue;
        
        // Check for headers
        if (line == PRIV_HDR || line == STD_PRIV_HDR) {
            header_found = true;
            private_found = true;
            continue;
        }
        else if (line == PUB_HDR || line == STD_PUB_HDR) {
            header_found = true;
            private_found = false;
            continue;
        }
        // Check for footers
        else if (line == PRIV_FTR || line == STD_PRIV_FTR || 
                 line == PUB_FTR || line == STD_PUB_FTR) {
            break;
        }
        
        // Collect base64 data
        if (header_found) {
            // Validate base64 characters
            for (char c : line) {
                if (!is_base64_char(c)) {
                    return false;
                }
            }
            b64_data += line;
        }
    }
    
    if (!header_found || b64_data.empty()) {
        return false;
    }
    
    is_private = private_found;
    return base64_decode(b64_data, out);
}

bool pem_write_key(const std::string &path, const unsigned char *data, size_t len, bool is_private)
{
    BIO *bmem = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bmem);

    if (BIO_write(b64, data, static_cast<int>(len)) <= 0) {
        BIO_free_all(b64);
        return false;
    }
    if (BIO_flush(b64) != 1) {
        BIO_free_all(b64);
        return false;
    }

    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);
    if (!bptr) {
        BIO_free_all(b64);
        return false;
    }

    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        BIO_free_all(b64);
        return false;
    }

    if (is_private) ofs << PRIV_HDR << "\n";
    else ofs << PUB_HDR << "\n";

    ofs.write(bptr->data, bptr->length);

    if (bptr->length == 0 || bptr->data[bptr->length - 1] != '\n') {
        ofs << "\n";
    }

    if (is_private) ofs << PRIV_FTR << "\n";
    else ofs << PUB_FTR << "\n";

    BIO_free_all(b64);
    return ofs.good();
}

bool pem_read_key(const std::string &path, std::vector<unsigned char> &out, bool &is_private)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    bool result = parse_pem_content(content, out, is_private);
    
    // Clean up sensitive content
    cleanse_string(content);
    
    return result;
}

bool pem_read_key_string(const std::string &pem_string, std::vector<unsigned char> &out, bool &is_private)
{
    return parse_pem_content(pem_string, out, is_private);
}