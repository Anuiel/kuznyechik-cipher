#include "cipher.hpp"

#include <cstddef>
#include <cstdint>
#include <algorithm>

void CipherBlockPermute::encrypt(Block& block, const std::optional<Block>&) {
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        block[i] = _permutation[block[i]];
    }
}

void CipherBlockPermute::decrypt(Block& block, const std::optional<Block>&) {
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        block[i] = _permutation_inverse[block[i]];
    }
}

void CipherBlockAdd::encrypt(Block& block, const std::optional<Block>& key) {
    const Block& key_block = key.value();
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        block[i] ^= key_block[i];
    }
}

void CipherBlockAdd::decrypt(Block& block, const std::optional<Block>& key) {
    // Xor is involution x = f(f(x))
    CipherBlockAdd::encrypt(block, key);
}

std::optional<std::uint8_t> CipherBlockLinear::powerOf(uint8_t value) const {
    if (value == 0) {
        return std::nullopt;
    }
    return _reverse_powers[value];
}

void CipherBlockLinear::encryptSingle(Block& block) {
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

void CipherBlockLinear::decryptSingle(Block& block) {
    uint8_t result = 0;
    for (size_t i = 1; i < BLOCK_SIZE; ++i) {
        auto opt_block_power = powerOf(block[i]);
        if (opt_block_power.has_value()) {
            uint8_t addend = _powers[(powerOf(_coefs[i - 1]).value() + opt_block_power.value()) % 255];
            result ^= addend;
        } // else add 0 to result
    }
    result ^= block[0];
    static_assert(_coefs[BLOCK_SIZE - 1] == 1);

    for (size_t i = 0; i < BLOCK_SIZE - 1; ++i) {
        block[i] = block[i + 1];
    }
    block[BLOCK_SIZE - 1] = result;
}

void CipherBlockLinear::encrypt(Block& block, const std::optional<Block>&) {
    for (size_t _ = 0; _ < _LINEAR_ROUNDS; _++) {
        encryptSingle(block);
    }
}

void CipherBlockLinear::decrypt(Block& block, const std::optional<Block>&) {
    for (size_t _ = 0; _ < _LINEAR_ROUNDS; _++) {
        decryptSingle(block);
    }
}

LookupTable CipherBlockLinearFast::_makeTable(Direction direction) {
    CipherBlockLinear linear{};
    LookupTable table{};
    for (size_t b = 0; b < 256; ++b) {
        for (size_t pos = 0; pos < BLOCK_SIZE; ++pos) {
            Block dummy{};
            dummy[pos] = static_cast<uint8_t>(b);
            if (direction == Direction::Encrypt) {
                linear.encrypt(dummy);
            } else {
                linear.decrypt(dummy);
            }
            table[pos][b] = dummy;
        }
    }
    return table;
}

const LookupTable& CipherBlockLinearFast::_encryptTable() {
    static const LookupTable table = _makeTable(Direction::Encrypt);
    return table;
}

const LookupTable& CipherBlockLinearFast::_decryptTable() {
    static const LookupTable table = _makeTable(Direction::Decrypt);
    return table;
}

void _applyTable(Block& block, const LookupTable& table) {
    Block output{};
    for (size_t pos = 0; pos < BLOCK_SIZE; ++pos) {
        const Block& cache = table[pos][block[pos]];
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            output[i] ^= cache[i];
        }
    }
    block = output;
}

// __attribute__((noinline))
void CipherBlockLinearFast::encrypt(Block& block, const std::optional<Block>&) {
    _applyTable(block, _encrypt_lookup_table);
}

__attribute__((noinline))
void CipherBlockLinearFast::decrypt(Block& block, const std::optional<Block>&) {
    _applyTable(block, _decrypt_lookup_table);
}


LookupTable CipherBlockPermuteLinearFast::_makeTable() {
    CipherBlockLinear linear{};
    CipherBlockPermute permute{};
    LookupTable table{};
    for (size_t b = 0; b < 256; ++b) {
        for (size_t pos = 0; pos < BLOCK_SIZE; ++pos) {
            Block permute_dummy{};
            permute_dummy[pos] = static_cast<uint8_t>(b);
            permute.encrypt(permute_dummy);

            Block linear_dummy{};
            linear_dummy[pos] = permute_dummy[pos];
            linear.encrypt(linear_dummy);
            table[pos][b] = linear_dummy;
        }
    }
    return table;
}

const LookupTable& CipherBlockPermuteLinearFast::_encryptTable() {
    static const LookupTable table = _makeTable();
    return table;
}

void CipherBlockPermuteLinearFast::encrypt(Block& block, const std::optional<Block>&) {
    _applyTable(block, _encrypt_lookup_table);
}

void CipherBlockPermuteLinearFast::decrypt(Block& block, const std::optional<Block>&) {
    _linear.decrypt(block);
    _permute.decrypt(block);
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
    CipherBlockLinear linear{};

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

CipherFull::CipherFull(const KeyBlock& key) {
    auto [key_left, key_right] = split_key_block(key);
    _round_keys = get_round_keys(key_left, key_right);
}


void CipherFull::encrypt(Block& block) {
    for (size_t i = 0; i + 1 < _round_keys.size(); ++i) {
        _add.encrypt(block, _round_keys[i]);
        // _permute.encrypt(block);
        // _linear.encrypt(block);
        _permute_linear.encrypt(block);
    }
    _add.encrypt(block, _round_keys.back());
}

void CipherFull::decrypt(Block &block) {
    _add.decrypt(block, _round_keys.back());
    for (size_t i = _round_keys.size() - 1; i > 0; --i) {
        // _linear.decrypt(block);
        // _permute.decrypt(block);
        _permute_linear.decrypt(block);
        _add.decrypt(block, _round_keys[i - 1]);
    }
}
