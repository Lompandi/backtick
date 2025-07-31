
#include <fstream>

#include "globals.hpp"
#include "utils.hpp"

void Hexdump(const void* data, size_t size) {
    const unsigned char* byteData = static_cast<const unsigned char*>(data);
    constexpr size_t bytesPerLine = 16;

    for (size_t i = 0; i < size; i += bytesPerLine) {
        std::print("{:08x}: ", i);

        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < size) {
                std::print("{:02x} ", byteData[i + j]);
            }
            else {
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