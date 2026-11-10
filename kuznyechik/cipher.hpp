#pragma once

#include <array>
#include <optional>
#include <vector>

// 128 bits
constexpr size_t BITS_PER_BLOCK = 128;
constexpr size_t BLOCK_SIZE = BITS_PER_BLOCK / 8;

constexpr size_t BITS_PER_KEY = 256;
constexpr size_t KEY_SIZE = BITS_PER_KEY / 8;

using Block = std::array<uint8_t, BLOCK_SIZE>;
using KeyBlock = std::array<uint8_t, KEY_SIZE>;


inline std::array<Block, 2> split_key_block(const KeyBlock& key) {
    static_assert(KEY_SIZE == 2 * BLOCK_SIZE, "A key must contain two blocks");
    std::array<Block, 2> blocks{};
    std::copy_n(key.begin(), BLOCK_SIZE, blocks[0].begin());
    std::copy_n(key.begin() + BLOCK_SIZE, BLOCK_SIZE, blocks[1].begin());
    return blocks;
}

inline Block single_bit_block(std::size_t i) {
    if (i >= BITS_PER_BLOCK) {
        throw std::out_of_range("Bit index is too large");
    }

    Block b{};
    b[BLOCK_SIZE - 1 - i / 8] = static_cast<uint8_t>(1u << (i % 8));
    return b;
}

inline Block from_number(uint8_t i) {
    Block b{};
    b.back() = i;
    return b;
}

class EncryptBlock {
public:
    virtual ~EncryptBlock() = default;
    virtual void encrypt(Block& block, const std::optional<Block>& key = std::nullopt) = 0;
};

class EncryptBlockPermute : public EncryptBlock {
public:
    void encrypt(Block& block, const std::optional<Block>& key = std::nullopt) override;

private:
    static constexpr std::array<uint8_t, 256> _permutation{
        252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77,
        233, 119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193,
        249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66, 139,   1, 142,  79,
          5, 132,   2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31,
        235,  52,  44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,  58, 206, 204,
        181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156, 183,  93, 135,
         21, 161, 150,  41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
         50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195, 189,  13,  87,
        223, 245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3,
        224,  15, 236, 222, 122, 148, 176, 188, 220, 232,  40,  80,  78,  51,  10,  74,
        167, 151,  96, 115,  30,   0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65,
        173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165, 125, 105, 213, 149,  59,
          7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107, 228, 136, 217, 231, 137,
        225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,  97,
         32, 113, 103, 164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82,
         89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,  75,  99, 182
    };
};


class EncryptBlockAdd : public EncryptBlock {
public:
    void encrypt(Block& block, const std::optional<Block>& key = std::nullopt) override;
};


class EncryptBlockLinear : public EncryptBlock {
public:
    std::optional<uint8_t> powerOf(uint8_t value) const;

    void encryptSingle(Block& block);
    void encrypt(Block& block, const std::optional<Block>& key = std::nullopt) override;

private:
    static constexpr size_t _LINEAR_ROUNDS = 16;
    static constexpr std::array<uint8_t, 256> _powers{
          1,   2,   4,   8,  16,  32,  64, 128, 195,  69, 138, 215, 109, 218, 119, 238,
         31,  62, 124, 248,  51, 102, 204,  91, 182, 175, 157, 249,  49,  98, 196,  75,
        150, 239,  29,  58, 116, 232,  19,  38,  76, 152, 243,  37,  74, 148, 235,  21,
         42,  84, 168, 147, 229,   9,  18,  36,  72, 144, 227,   5,  10,  20,  40,  80,
        160, 131, 197,  73, 146, 231,  13,  26,  52, 104, 208,  99, 198,  79, 158, 255,
         61, 122, 244,  43,  86, 172, 155, 245,  41,  82, 164, 139, 213, 105, 210, 103,
        206,  95, 190, 191, 189, 185, 177, 161, 129, 193,  65, 130, 199,  77, 154, 247,
         45,  90, 180, 171, 149, 233,  17,  34,  68, 136, 211, 101, 202,  87, 174, 159,
        253,  57, 114, 228,  11,  22,  44,  88, 176, 163, 133, 201,  81, 162, 135, 205,
         89, 178, 167, 141, 217, 113, 226,   7,  14,  28,  56, 112, 224,   3,   6,  12,
         24,  48,  96, 192,  67, 134, 207,  93, 186, 183, 173, 153, 241,  33,  66, 132,
        203,  85, 170, 151, 237,  25,  50, 100, 200,  83, 166, 143, 221, 121, 242,  39,
         78, 156, 251,  53, 106, 212, 107, 214, 111, 222, 127, 254,  63, 126, 252,  59,
        118, 236,  27,  54, 108, 216, 115, 230,  15,  30,  60, 120, 240,  35,  70, 140,
        219, 117, 234,  23,  46,  92, 184, 179, 165, 137, 209,  97, 194,  71, 142, 223,
        125, 250,  55, 110, 220, 123, 246,  47,  94, 188, 187, 181, 169, 145, 225,   1
    };

    static constexpr std::array<uint8_t, BLOCK_SIZE> _coefs{
        148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
    };

    inline static const std::array<uint8_t, 256> _reverse_powers = [] {
        std::array<uint8_t, 256> reverse{};
        reverse.fill(255);

        for (size_t power = 0; power < _powers.size() - 1; ++power) {
            reverse[_powers[power]] = static_cast<uint8_t>(power);
        }

        return reverse;
    }();
};


class KeyScheduleStep {
public:
    void encrypt(Block& block_a, Block& block_b, const Block& key);

private:
    EncryptBlockLinear _linear{};
    EncryptBlockPermute _permute{};
    EncryptBlockAdd _add{};
};

std::vector<Block> get_round_keys(const Block& key_left, const Block& key_right);

class EncryptFull {
public:
    EncryptFull(const KeyBlock& key);
    void encrypt(Block& block);
private:
    std::vector<Block> _round_keys;
    EncryptBlockLinear _linear{};
    EncryptBlockPermute _permute{};
    EncryptBlockAdd _add{};
};
