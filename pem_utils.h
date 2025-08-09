// pem_utils.h
#pragma once
#include <string>
#include <vector>

bool pem_write_key(const std::string &path, const unsigned char *data, size_t len, bool is_private);
bool pem_read_key(const std::string &path, std::vector<unsigned char> &out, bool &is_private);
bool pem_read_key_string(const std::string &pem_string, std::vector<unsigned char> &out, bool &is_private);