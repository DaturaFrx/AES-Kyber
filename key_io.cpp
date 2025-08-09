// key_io.cpp
#include "key_io.h"
#include "pem_utils.h"  // your existing PEM header

bool save_key_pem(const std::string &path, const std::vector<uint8_t> &key, bool is_private) {
    return pem_write_key(path, key.data(), key.size(), is_private);
}

bool load_key_pem(const std::string &path, std::vector<uint8_t> &key, bool &is_private) {
    return pem_read_key(path, key, is_private);
}