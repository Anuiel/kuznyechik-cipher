#include "cipher.hpp"

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


EncryptBlockLinear::EncryptBlockLinear() {
    _reverse_powers.fill(255);
    for (size_t power = 0; power < _powers.size() - 1; ++power) {
        _reverse_powers[_powers[power]] = static_cast<std::uint8_t>(power);
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


// EncryptBlockFull::EncryptBlockFull() {
//     _add = EncryptBlockAdd{};
//     _linear = EncryptBlockLinear{};
//     _permute = EncryptBlockPermute{};
// }

void EncryptBlockFull::encrypt(Block& block, const std::optional<Block>& key) {
    _add.encrypt(block, key);
    _permute.encrypt(block);
    _linear.encrypt(block);
}

