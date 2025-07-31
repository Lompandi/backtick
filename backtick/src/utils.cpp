
#include "utils.hpp"

#include <fstream>

#include "globals.hpp"

std::uint64_t ScanPattern(const std::vector<int>& pattern, std::uint64_t maxScanLength) {
    std::uint64_t baseAddr = (std::uint64_t)GetModuleHandleA("dbgeng.dll");
    for (std::uint64_t i = 0; i < maxScanLength; i++) {
        bool found = true;

        for (size_t j = 0; j < pattern.size(); j++) {
            if (pattern[j] != -1 && *(std::uint8_t*)(baseAddr + i + j) != pattern[j]) {
                found = false;
                break;
            }
        }

        if (found) return baseAddr + i;
    }

    return -1;
}

std::uint64_t ScanPattern(const std::string& pattern, std::uint64_t maxScanLength) {
    std::stringstream ss_pattern(pattern);
    std::string token;
    std::vector<int> processed_pattern;
    while (ss_pattern >> token) {
        if (token.starts_with("?")) {
            processed_pattern.push_back(-1);
        }
        else {
            processed_pattern.push_back(std::stoi(token, nullptr, 16));
        }
    }
    return ScanPattern(processed_pattern, maxScanLength);
}

void Hexdump(const void* data, size_t size) {
    const unsigned char* byteData = static_cast<const unsigned char*>(data);
    constexpr size_t bytesPerLine = 16;

    for (size_t i = 0; i < size; i += bytesPerLine) {
        std::print("{:08x}: ", i);

        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < size) {
                std::print("{:02x} ", byteData[i + j]);
            } else {
                std::print("   ");
            }
        }

        std::print(" ");

        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < size) {
                unsigned char c = byteData[i + j];
                std::print("{}", std::isprint(c) ? static_cast<char>(c) : '.');
            }
        }

        std::print("\n");
    }
}
