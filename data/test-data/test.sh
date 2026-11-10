#!/bin/sh
set -eu

cd "$(dirname "$0")"
make -s -C ../../kuznyechik main

output=$(mktemp "${TMPDIR:-/tmp}/kuznyechik-test.XXXXXX")
trap 'rm -f "$output"' EXIT

../../kuznyechik/main --encrypt --input input.hex --output "$output" --key key.hex

if [ "$(cat "$output")" = "$(cat expected.hex)" ]; then
    echo "Encryption test passed."
else
    echo "Encryption test failed." >&2
    echo "Expected: $(cat expected.hex)" >&2
    echo "Actual:   $(cat "$output")" >&2
    exit 1
fi

../../kuznyechik/main --decrypt --input expected.hex --output "$output" --key key.hex

if [ "$(cat "$output")" = "$(cat input.hex)" ]; then
    echo "Decryption test passed."
else
    echo "Decryption test failed." >&2
    echo "Expected: $(cat input.hex)" >&2
    echo "Actual:   $(cat "$output")" >&2
    exit 1
fi
