#!/bin/sh
set -eu

cd "$(dirname "$0")"
make -s -C ../../kuznyechik main

output=$(mktemp "${TMPDIR:-/tmp}/kuznyechik-test.XXXXXX")
trap 'rm -f "$output"' EXIT

../../kuznyechik/main --input input.hex --output "$output" --key key.hex

if [ "$(cat "$output")" = "$(cat expected.hex)" ]; then
    echo "Integration test passed."
else
    echo "Integration test failed." >&2
    echo "Expected: $(cat expected.hex)" >&2
    echo "Actual:   $(cat "$output")" >&2
    exit 1
fi
