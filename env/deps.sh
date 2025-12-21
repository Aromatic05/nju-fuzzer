#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if [ $UID -ne 0 ]; then
  echo "[ERR] Please run this script as root (sudo)." >&2
  exit 1
fi

apt-get update -y

# 1) Java + Maven
apt-get install -y \
  openjdk-17-jdk \
  maven

# 2) AFL++ README dependencies (build AFL++ itself)
apt-get install -y \
  build-essential \
  python3-dev \
  automake \
  cmake \
  git \
  flex \
  bison \
  libglib2.0-dev \
  libpixman-1-dev \
  python3-setuptools \
  cargo \
  libtool \
  libpcap-dev \
  libgtk-3-dev

# 3) Pin LLVM/Clang to 14 for Ubuntu 22.04 stability
apt-get install -y \
  llvm-14 llvm-14-dev \
  clang-14 \
  lld-14

# Convenience: llvm-config-14 should exist; clang-14 available
echo "[OK] Installed LLVM/Clang 14 toolchain."

# 4) GCC plugin dev packages (best-effort)
GCC_MAJOR="$(gcc --version | head -n1 | sed 's/\..*//' | sed 's/.* //')"
apt-get install -y \
  "gcc-${GCC_MAJOR}-plugin-dev" \
  "libstdc++-${GCC_MAJOR}-dev" || true

# 5) Optional AFL++ modes dependencies (safe to keep)
apt-get install -y meson ninja-build    # QEMU mode
apt-get install -y cpio libcapstone-dev # Nyx mode
apt-get install -y wget curl            # Frida mode
apt-get install -y python3-pip          # Unicorn mode

echo "[OK] All dependencies installed."

echo "=== Versions ==="
java -version || true
mvn -version || true
clang-14 --version || true
llvm-config-14 --version || true
gcc --version | head -n1 || true

