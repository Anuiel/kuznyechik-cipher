#include "cipher.hpp"

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>

uint8_t hexValue(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    if ('a' <= c && c <= 'f') return c - 'a' + 10;

    throw std::runtime_error("Invalid hex character");
}

bool readHexByte(std::istream& input, uint8_t& byte) {
    char high;
    char low;
    if (!(input >> high >> low)) return false;

    byte = static_cast<uint8_t>((hexValue(high) << 4) | hexValue(low));
    return true;
}

void writeHexByte(std::ostream& out, uint8_t byte) {
    out << std::hex
        << std::uppercase
        << std::setw(2)
        << std::setfill('0')
        << static_cast<int>(byte);
}

int main(int argc, char* argv[]) {
    const char* usage = "Usage: main (--encrypt | --decrypt) --input INPUT --output OUTPUT --key KEY\n";
    if (argc != 8) {
        std::cerr << usage;
        return 1;
    }

    std::string mode = argv[1];
    if (mode != "--encrypt" && mode != "--decrypt") {
        std::cerr << usage;
        return 1;
    }

    std::string input_path;
    std::string output_path;
    std::string key_path;
    for (int i = 2; i < argc; i += 2) {
        std::string option = argv[i];
        if (option == "--input") {
            input_path = argv[i + 1];
        } else if (option == "--output") {
            output_path = argv[i + 1];
        } else if (option == "--key") {
            key_path = argv[i + 1];
        } else {
            std::cerr << "Unknown option: " << option << '\n';
            return 1;
        }
    }
    if (input_path.empty() || output_path.empty() || key_path.empty()) {
        std::cerr << usage;
        return 1;
    }

    std::ifstream input(input_path);
    std::ofstream output(output_path);
    std::ifstream key_stream(key_path);
    if (!input || !output || !key_stream) {
        std::cerr << "Could not open file\n";
        return 1;
    }

    KeyBlock key{};
    for (auto& byte : key) {
        if (!readHexByte(key_stream, byte)) {
            std::cerr << "Key must contain 32 bytes\n";
            return 1;
        }
    }

    CipherFull cipher{key};
    Block block{};
    while (true) {
        std::size_t count = 0;
        while (count < BLOCK_SIZE && readHexByte(input, block[count])) {
            ++count;
        }
        if (count == 0) break;

        if (mode == "--decrypt") {
            cipher.decrypt(block);
        } else {
            cipher.encrypt(block);
        }
        for (auto byte : block) {
            writeHexByte(output, byte);
        }
    }
}
