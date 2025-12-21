#!/usr/bin/env bash
set -euo pipefail

if [ $UID -ne 0 ]; then
  echo "[ERR] Please run this script as root (sudo)." >&2
  exit 1
fi

# Where to clone AFL++
AFL_DIR="${AFL_DIR:-$PWD/third_party/AFLplusplus}"
PREFIX="${PREFIX:-/usr/local}"

echo "[INFO] AFL_DIR = $AFL_DIR"
echo "[INFO] PREFIX  = $PREFIX"

# Ensure required tools exist
command -v git >/dev/null
command -v make >/dev/null

# Clone if missing
if [ ! -d "$AFL_DIR/.git" ]; then
  mkdir -p "$(dirname "$AFL_DIR")"
  git clone https://github.com/AFLplusplus/AFLplusplus.git "$AFL_DIR"
fi

pushd "$AFL_DIR" >/dev/null

# Keep it clean & reproducible
git fetch --all --tags
# If you want to pin a specific tag/commit, uncomment and set it:
# git checkout v4.30c

# Update submodules
git submodule update --init --recursive

# Ubuntu 22.04: prefer LLVM 14 to match your deps script
export LLVM_CONFIG="${LLVM_CONFIG:-llvm-config-14}"
export CC="${CC:-clang-14}"
export CXX="${CXX:-clang++-14}"

echo "[INFO] Using LLVM_CONFIG=$LLVM_CONFIG"
echo "[INFO] Using CC=$CC"
echo "[INFO] Using CXX=$CXX"

# Build
make clean >/dev/null 2>&1 || true
make distrib

# Install to /usr/local
# AFL++ Makefile honors PREFIX
make install PREFIX="$PREFIX"

popd >/dev/null

echo "[OK] AFL++ installed to $PREFIX"
echo "Check:"
command -v afl-fuzz && afl-fuzz -V || true
command -v afl-cc && afl-cc --version || true

