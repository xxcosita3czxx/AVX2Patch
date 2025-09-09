#!/bin/sh
# Run all test executables in the tests/ folder
set -e
cd "$(dirname "$0")/tests"

for src in *.c; do
    exe="${src%.c}"
    echo "Compiling $src..."
    gcc -msse4.2 -o "$exe" "$src"
    echo "Running $exe..."
    ./$exe
    echo
    rm -f "$exe"
done
