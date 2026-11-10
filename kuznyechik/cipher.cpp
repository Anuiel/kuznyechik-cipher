#include "cipher.hpp"

#include <cstddef>
#include <cstdint>
#include <algorithm>

void EncryptBlockPermute::encrypt(Block& block, const std::optional<Block>&) {
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        block[i] = _permutation[block[i]];
    }
}

void EncryptBlockAdd::encrypt(Block& block, const std::optional<Block>& key) {
    const Block& key_block = key.value();
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        block[i] ^= key_block[i];
    }
}

std::optional<std::uint8_t> EncryptBlockLinear::powerOf(uint8_t value) const {
    if (value == 0) {
        return std::nullopt;
    }
    return _reverse_powers[value];
}

void EncryptBlockLinear::encryptSingle(Block& block) {
    uint8_t result = 0;
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        auto opt_block_power = powerOf(block[i]);
        if (opt_block_power.has_value()) {
            uint8_t addend = _powers[(powerOf(_coefs[i]).value() + opt_block_power.value()) % 255];
            result ^= addend;
        } // else add 0 to result
    }

    for (size_t i = BLOCK_SIZE - 1; i > 0; --i) {
        block[i] = block[i - 1];
    }
    block[0] = result;
}


void EncryptBlockLinear::encrypt(Block& block, const std::optional<Block>&) {
    for (size_t _ = 0; _ < _LINEAR_ROUNDS; _++) {
        encryptSingle(block);
    }
}

void KeyScheduleStep::encrypt(Block& block_a, Block& block_b, const Block& key) {
    Block tmp = block_a;
    _add.encrypt(tmp, key);
    _permute.encrypt(tmp);
    _linear.encrypt(tmp);
    _add.encrypt(tmp, block_b);
    block_b = block_a;
    block_a = tmp;
}


std::vector<Block> get_round_keys(const Block& key_left, const Block& key_right) {
    KeyScheduleStep block{};
    EncryptBlockLinear linear{};

    std::vector<Block> c(32);
    for (size_t i = 0; i < 32; ++i) {
        c[i] = from_number(i + 1);
        linear.encrypt(c[i]);
    }
    std::vector<Block> keys(10);
    keys[0] = key_left;
    keys[1] = key_right;

    for (size_t i = 0; i < 4; ++i) {
        Block left = keys[2 * i], right = keys[2 * i + 1];
        for (size_t j = 0; j < 8; ++j) {
            block.encrypt(left, right, c[8 * i + j]);
        }
        keys[2 * (i + 1)] = left;
        keys[2 * (i + 1) + 1] = right;
    }
    return keys;
}

EncryptFull::EncryptFull(const KeyBlock& key) {
    auto [key_left, key_right] = split_key_block(key);
    _round_keys = get_round_keys(key_left, key_right);
}


void EncryptFull::encrypt(Block& block) {
    for (size_t i = 0; i + 1 < _round_keys.size(); ++i) {
        _add.encrypt(block, _round_keys[i]);
        _permute.encrypt(block);
        _linear.encrypt(block);
    }
    _add.encrypt(block, _round_keys.back());
}