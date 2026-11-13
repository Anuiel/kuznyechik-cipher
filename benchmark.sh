#!/bin/sh
set -eu


dir='/tmp/kuznechik'

mkdir -p "$dir"

input_file="$dir/input.bin"
output_file="$dir/output.bin"
key_file="$dir/key.hex"

for file in "$input_file" "$output_file" "$key_file"; do
    touch "$file"
done


echo '8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef' > $key_file

cd kuznyechik

make -s -B main CXXFLAGS="-std=c++17 -O2 -march=native -DNDEBUG"

input_size=$(wc -c < "$input_file")

for i in 1 2 3; do
    echo "========== Run $i =========="

    python3 ../generate_input.py --output $input_file --seed $i --size '512Mb'

    start=$(date +%s.%N)

    ./main --encrypt \
        --input "$input_file" \
        --output "$output_file" \
        --key "$key_file"

    end=$(date +%s.%N)

    elapsed=$(awk -v s="$start" -v e="$end" 'BEGIN {print e-s}')
    speed=$(awk -v size="$input_size" -v t="$elapsed" \
        'BEGIN {printf "%.2f", size / 1000000 / t}')

    echo "Elapsed: ${elapsed} s"
    echo "Encryption speed: ${speed} MB/s"
done