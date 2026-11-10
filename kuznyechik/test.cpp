#include "cipher.hpp"

#include <array>
#include <cassert>
#include <charconv>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>


template <size_t N>
std::array<uint8_t, N> bytesFromHex(std::string_view hex) {
    if (hex.size() != N * 2) {
        throw std::invalid_argument("Incorrect hex string length");
    }

    std::array<uint8_t, N> bytes{};
    for (size_t i = 0; i < N; ++i) {
        unsigned value = 0;
        const char* first = hex.data() + 2 * i;
        const auto result = std::from_chars(first, first + 2, value, 16);
        if (result.ec != std::errc{} || result.ptr != first + 2) {
            throw std::invalid_argument("Invalid hex character");
        }
        bytes[i] = static_cast<uint8_t>(value);
    }
    return bytes;
}

Block blockFromHex(std::string_view hex) {
    return bytesFromHex<BLOCK_SIZE>(hex);
}

KeyBlock keyFromHex(std::string_view hex) {
    return bytesFromHex<KEY_SIZE>(hex);
}

std::string blockToHex(const Block& block) {
    constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(block.size() * 2);
    for (uint8_t byte : block) {
        hex.push_back(digits[byte >> 4]);
        hex.push_back(digits[byte & 0x0f]);
    }
    return hex;
}

void expectBlockEqual(const Block& actual, const Block& expected, const char* test) {
    if (actual != expected) {
        throw std::runtime_error(
            std::string(test) + ": expected " + blockToHex(expected) + ", got " + blockToHex(actual)
        );
    }
}

void testHexHelpers() {
    const auto block = blockFromHex("0001aBcDeF1234567890ABCDEF00ff80");
    if (blockToHex(block) != "0001abcdef1234567890abcdef00ff80") {
        throw std::runtime_error("Block hex round trip failed");
    }
    const auto key = keyFromHex("000102030405060708090a0b0c0d0e0f"
                                "f0e0d0c0b0a090807060504030201000");
    if (key.front() != 0 || key[15] != 0x0f || key[16] != 0xf0 || key.back() != 0) {
        throw std::runtime_error("Key hex parsing failed");
    }
    
    std::array<std::string, 5> invalids_block = {
        "",
        "0",
        "0000000000000000000000000000000g",
        "+1000000000000000000000000000000",
        "000000000000000000000000000000000"
    };

    for (std::string_view invalid : invalids_block) {
        bool rejected = false;
        try {
            blockFromHex(invalid);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        if (!rejected) {
            throw std::runtime_error("Invalid block hex was accepted");
        }

        rejected = false;
        try {
            keyFromHex(invalid);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        if (!rejected) {
            throw std::runtime_error("Invalid key hex was accepted");
        }
    }
}

void testBlockFromNumber() {
    std::vector<uint8_t> numbers = {0, 1, 2, 3, 15, 31};
    std::vector<Block> outputs = {
        blockFromHex("00000000000000000000000000000000"),
        blockFromHex("00000000000000000000000000000001"),
        blockFromHex("00000000000000000000000000000002"),
        blockFromHex("00000000000000000000000000000003"),
        blockFromHex("0000000000000000000000000000000f"),
        blockFromHex("0000000000000000000000000000001f"),
    };
    assert(numbers.size() == outputs.size());
    for (size_t i = 0; i < outputs.size(); ++i) {
        expectBlockEqual(from_number(numbers[i]), outputs[i], __func__);
    }
}

// Most of the test results are from https://datatracker.ietf.org/doc/html/rfc7801

void testEncryptPermute() {
    CipherBlockPermute permute_block{};
    Block input = blockFromHex("ffeeddccbbaa99881122334455667700");
    std::vector<Block> outputs = {
                blockFromHex("b66cd8887d38e8d77765aeea0c9a7efc"),
                blockFromHex("559d8dd7bd06cbfe7e7b262523280d39"),
                blockFromHex("0c3322fed531e4630d80ef5c5a81c50b"),
                blockFromHex("23ae65633f842d29c5df529c13f5acda")
    };
    for (auto output : outputs) {
        permute_block.encrypt(input);
        expectBlockEqual(input, output, __func__);
    }
}

void testDecryptPermute() {
    CipherBlockPermute permute_block{};
    Block input = blockFromHex("23ae65633f842d29c5df529c13f5acda");
    std::vector<Block> outputs = {
                blockFromHex("0c3322fed531e4630d80ef5c5a81c50b"),
                blockFromHex("559d8dd7bd06cbfe7e7b262523280d39"),
                blockFromHex("b66cd8887d38e8d77765aeea0c9a7efc"),
                blockFromHex("ffeeddccbbaa99881122334455667700")
    };
    for (auto output : outputs) {
        permute_block.decrypt(input);
        expectBlockEqual(input, output, __func__);
    }
}

void testEncryptAdd() {
    CipherBlockAdd add_block{};
    Block input =  blockFromHex("00112233445566778899aabbccddeeff");
    Block key =    blockFromHex("0102030405060708090a0b0c0d0e0f00");
    Block output = blockFromHex("011321374153617f8193a1b7c1d3e1ff");
    add_block.encrypt(input, key);
    expectBlockEqual(input, output, __func__);
} 

void testDecryptAdd() {
    CipherBlockAdd add_block{};
    Block input =  blockFromHex("011321374153617f8193a1b7c1d3e1ff");
    Block key =    blockFromHex("0102030405060708090a0b0c0d0e0f00");
    Block output = blockFromHex("00112233445566778899aabbccddeeff");
    add_block.decrypt(input, key);
    expectBlockEqual(input, output, __func__);
}

void testEncryptLinearSingle() {
    CipherBlockLinear linear_block{};
    Block input = blockFromHex("00000000000000000000000000000100");
    std::vector<Block> outputs = {
                  blockFromHex("94000000000000000000000000000001"),
                  blockFromHex("a5940000000000000000000000000000"),
                  blockFromHex("64a59400000000000000000000000000"),
                  blockFromHex("0d64a594000000000000000000000000")
    };
    for (auto output : outputs) {
        linear_block.encryptSingle(input);
        expectBlockEqual(input, output, __func__);
    }
}

void testDecryptLinearSingle() {
    CipherBlockLinear linear_block{};
    Block input = blockFromHex("0d64a594000000000000000000000000");
    std::vector<Block> outputs = {
                  blockFromHex("64a59400000000000000000000000000"),
                  blockFromHex("a5940000000000000000000000000000"),
                  blockFromHex("94000000000000000000000000000001"),
                  blockFromHex("00000000000000000000000000000100")
    };
    for (auto output : outputs) {
        linear_block.decryptSingle(input);
        expectBlockEqual(input, output, __func__);
    }
}

void testEncryptLinear() {
    CipherBlockLinear linear_block{};
    Block input = blockFromHex("64a59400000000000000000000000000");
    std::vector<Block> outputs = {
                  blockFromHex("d456584dd0e3e84cc3166e4b7fa2890d"),
                  blockFromHex("79d26221b87b584cd42fbc4ffea5de9a"),
                  blockFromHex("0e93691a0cfc60408b7b68f66b513c13"),
                  blockFromHex("e6a8094fee0aa204fd97bcb0b44b8580")
    };
    for (auto output : outputs) {
        linear_block.encrypt(input);
        expectBlockEqual(input, output, __func__);
    }
}

void testDecryptLinear() {
    CipherBlockLinear linear_block{};
    Block input = blockFromHex("e6a8094fee0aa204fd97bcb0b44b8580");
    std::vector<Block> outputs = {
                  blockFromHex("0e93691a0cfc60408b7b68f66b513c13"),
                  blockFromHex("79d26221b87b584cd42fbc4ffea5de9a"),
                  blockFromHex("d456584dd0e3e84cc3166e4b7fa2890d"),
                  blockFromHex("64a59400000000000000000000000000")
    };
    for (auto output : outputs) {
        linear_block.decrypt(input);
        expectBlockEqual(input, output, __func__);
    }
}

void testKeyScheduleConsts() {
    CipherBlockLinear linear_block{};
    std::vector<Block> outputs = {
        blockFromHex("6ea276726c487ab85d27bd10dd849401"),
        blockFromHex("dc87ece4d890f4b3ba4eb92079cbeb02"),
        blockFromHex("b2259a96b4d88e0be7690430a44f7f03"),
        blockFromHex("7bcd1b0b73e32ba5b79cb140f2551504"),
        blockFromHex("156f6d791fab511deabb0c502fd18105"),
        blockFromHex("a74af7efab73df160dd208608b9efe06"),
        blockFromHex("c9e8819dc73ba5ae50f5b570561a6a07"),
        blockFromHex("f6593616e6055689adfba18027aa2a08")
    };
    for (size_t i = 0; i < outputs.size(); ++i) {
        Block input = from_number(i + 1);
        linear_block.encrypt(input);
        expectBlockEqual(input, outputs[i], __func__);
    }
}

void testKeyScheduleStep() {
    KeyScheduleStep block{};
    Block i_left =    blockFromHex("8899aabbccddeeff0011223344556677");
    Block i_right =   blockFromHex("fedcba98765432100123456789abcdef");
    Block key_const = blockFromHex("6ea276726c487ab85d27bd10dd849401");

    Block o_left =  blockFromHex("c3d5fa01ebe36f7a9374427ad7ca8949");
    Block o_right = blockFromHex("8899aabbccddeeff0011223344556677");

    block.encrypt(i_left, i_right, key_const);
    expectBlockEqual(i_left, o_left, __func__);
    expectBlockEqual(i_right, o_right, __func__);
}

void testKeySchedule() {
    const std::array<Block, 10> K{{
        blockFromHex("8899aabbccddeeff0011223344556677"),
        blockFromHex("fedcba98765432100123456789abcdef"),
        blockFromHex("db31485315694343228d6aef8cc78c44"),
        blockFromHex("3d4553d8e9cfec6815ebadc40a9ffd04"),
        blockFromHex("57646468c44a5e28d3e59246f429f1ac"),
        blockFromHex("bd079435165c6432b532e82834da581b"),
        blockFromHex("51e640757e8745de705727265a0098b1"),
        blockFromHex("5a7925017b9fdd3ed72a91a22286f984"),
        blockFromHex("bb44e25378c73123a5f32f73cdb6e517"),
        blockFromHex("72e9dd7416bcf45b755dbaa88e4a4043")
    }};
    auto round_keys = get_round_keys(K[0], K[1]);
    assert(round_keys.size() == K.size());
    for (size_t i = 0; i < K.size(); ++i) {
        expectBlockEqual(round_keys[i], K[i], __func__);
    }
}

void testEncryptPipeline() {
    const KeyBlock K = keyFromHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
    Block input =  blockFromHex("1122334455667700ffeeddccbbaa9988");
    Block output = blockFromHex("7f679d90bebc24305a468d42b9d4edcd");

    CipherFull cipher(K);
    cipher.encrypt(input);
    expectBlockEqual(input, output, __func__);
}

void testDecryptPipeline() {
    const KeyBlock K = keyFromHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
    Block input =  blockFromHex("7f679d90bebc24305a468d42b9d4edcd");
    Block output = blockFromHex("1122334455667700ffeeddccbbaa9988");

    CipherFull cipher(K);
    cipher.decrypt(input);
    expectBlockEqual(input, output, __func__);
}

int main() {
    testHexHelpers();
    testBlockFromNumber();

    testEncryptPermute();
    testDecryptPermute();

    testEncryptAdd();
    testDecryptAdd();

    testEncryptLinearSingle();
    testDecryptLinearSingle();
    testEncryptLinear();
    testDecryptLinear();

    testKeyScheduleConsts();
    testKeyScheduleStep();
    testKeySchedule();

    testEncryptPipeline();
    testDecryptPipeline();
}
