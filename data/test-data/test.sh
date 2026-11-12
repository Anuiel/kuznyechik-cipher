#!/bin/sh
set -eu

cd "$(dirname "$0")"
make -s -C ../../kuznyechik main

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/kuznyechik-test.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT

xxd -r -p input.hex > "$test_dir/input.bin"
xxd -r -p expected.hex > "$test_dir/expected.bin"

../../kuznyechik/main --encrypt --input "$test_dir/input.bin" --output "$test_dir/encrypted.bin" --key key.hex
if ! cmp -s "$test_dir/expected.bin" "$test_dir/encrypted.bin"; then
    echo "Encryption test failed." >&2
    exit 1
fi
echo "Encryption test passed."

../../kuznyechik/main --decrypt --input "$test_dir/expected.bin" --output "$test_dir/decrypted.bin" --key key.hex
if ! cmp -s "$test_dir/input.bin" "$test_dir/decrypted.bin"; then
    echo "Decryption test failed." >&2
    exit 1
fi
echo "Decryption test passed."

python3 ../../generate_input.py --size 65552 --output "$test_dir/generated.bin"
if [ "$(wc -c < "$test_dir/generated.bin")" -ne 65552 ]; then
    echo "Generated file has the wrong size." >&2
    exit 1
fi
../../kuznyechik/main --encrypt --input "$test_dir/generated.bin" --output "$test_dir/encrypted.bin" --key key.hex
../../kuznyechik/main --decrypt --input "$test_dir/encrypted.bin" --output "$test_dir/decrypted.bin" --key key.hex
if ! cmp -s "$test_dir/generated.bin" "$test_dir/decrypted.bin"; then
    echo "Generated-file round trip failed." >&2
    exit 1
fi
echo "Generated-file round trip passed."
