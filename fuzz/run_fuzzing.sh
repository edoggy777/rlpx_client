#!/bin/bash
# Script to run various fuzzing campaigns

echo "Building fuzzing targets..."

# Build with AFL
export CC=afl-gcc
make clean && make fuzz

# Run RLP fuzzing
mkdir -p fuzz_output/rlp
echo -e "\x00hello" > fuzz_input/rlp_seed
afl-fuzz -i fuzz_input -o fuzz_output/rlp ./fuzz_harness

# Build with AddressSanitizer for better crash detection
export CC=clang
export CFLAGS="-fsanitize=address -g"
make clean && make fuzz

echo "Fuzzing setup complete. Run individual campaigns as needed."
