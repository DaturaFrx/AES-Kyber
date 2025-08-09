// io_utils.cpp
#include "io_utils.h"
#include <fstream>
#include <algorithm>
#include <iostream>

bool is_valid_filename(const std::string &filename)
{
    if (filename.empty() || filename.length() > 255) return false;
    const std::string dangerous_chars = "<>:\\"|?*";
    for (char c : dangerous_chars) if (filename.find(c) != std::string::npos) return false;
    const std::vector<std::string> reserved = {"CON","PRN","AUX","NUL","COM1","LPT1"};
    std::string upper = filename;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    for (auto &r : reserved) if (upper == r || upper.find(r + ".") == 0) return false;
    return true;
}

bool file_exists(const std::string &filename)
{
    std::ifstream f(filename);
    return f.good();
}

#include "constants.h"

bool validate_file_size(const std::string &filename)
{
    std::ifstream file(filename, std::ios::ate | std::ios::binary);
    if (!file.is_open()) return false;
    std::streamsize size = file.tellg();
    return size >= static_cast<std::streamsize>(MIN_FILE_SIZE) && size <= static_cast<std::streamsize>(MAX_FILE_SIZE);
}

bool secure_read_file(const std::string &path, SecureVector<unsigned char> &data)
{
    if (!is_valid_filename(path)) return false;
    if (!file_exists(path)) return false;
    if (!validate_file_size(path)) return false;
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) return false;
    std::streamsize size = ifs.tellg();
    if (size < 0) return false;
    ifs.seekg(0, std::ios::beg);
    data.resize(static_cast<size_t>(size));
    if (!ifs.read(reinterpret_cast<char *>(data.data()), size)) return false;
    return true;
}

bool secure_write_file(const std::string &path, const unsigned char *data, size_t len)
{
    if (!is_valid_filename(path)) return false;
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char *>(data), len);
    return ofs.good();
}