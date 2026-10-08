#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include "cipher.hpp"

void encryptBlock(Block& block)
{
    EncryptBlockPermute permute_stage;
    permute_stage.encrypt(block);
}

uint8_t hexValue(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('A' <= c && c <= 'F') return c - 'A' + 10;

    throw std::runtime_error("Invalid hex character");
}

bool readHexByte(std::istream& input, uint8_t& byte) {
    char high;
    char low;
    if (!(input >> high))
        return false;
    if (!(input >> low))
        return false;
    byte = static_cast<uint8_t>(
        (hexValue(high) << 4) | hexValue(low)
    );
    return true;
}

void writeHexByte(std::ostream& out, uint8_t byte) {
    out << std::hex
        << std::uppercase
        << std::setw(2)
        << std::setfill('0')
        << static_cast<int>(byte);
}

int main()
{
    std::ifstream input("../data/input.txt", std::ios::binary);
    std::ofstream output("../data/output.txt", std::ios::binary);

    if (!input || !output) {
        std::cerr << "Could not open file\n";
        return 1;
    }

    std::array<std::uint8_t, BLOCK_SIZE> block{};

    while (true) {
        std::size_t count = 0;

        while (count < BLOCK_SIZE && readHexByte(input, block[count])) {
            ++count;
        }

        if (count == 0)
            break;

        encryptBlock(block);
        
        for (auto byte : block) {
            writeHexByte(output, byte);
        }
    }
}
