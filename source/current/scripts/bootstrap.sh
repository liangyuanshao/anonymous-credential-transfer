#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p vendor
if [ ! -d vendor/pbc-1.0.0 ]; then
  curl -fL https://crypto.stanford.edu/pbc/files/pbc-1.0.0.tar.gz -o vendor/pbc-1.0.0.tar.gz
  printf '%s  %s\n' 18275a367283077bafe35f443200499e3b19c4a3754953da2a1b2f0d6b5922dc vendor/pbc-1.0.0.tar.gz | sha256sum -c -
  tar -xzf vendor/pbc-1.0.0.tar.gz -C vendor
fi
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
