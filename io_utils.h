// io_utils.h
#pragma once
#include <string>
#include "crypto_utils.h"

bool is_valid_filename(const std::string &filename);
bool file_exists(const std::string &filename);
bool validate_file_size(const std::string &filename);
bool secure_read_file(const std::string &path, SecureVector<unsigned char> &data);
bool secure_write_file(const std::string &path, const unsigned char *data, size_t len);