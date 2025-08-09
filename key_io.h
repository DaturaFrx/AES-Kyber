// key_io.h
#pragma once
#include <cstdint>
#include <string>
#include <vector>

bool save_key_pem(const std::string &path, const std::vector<uint8_t> &key, bool is_private);
bool load_key_pem(const std::string &path, std::vector<uint8_t> &key, bool &is_private);