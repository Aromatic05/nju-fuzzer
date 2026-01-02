#!/usr/bin/env bash
set -euo pipefail

# Fixed toolchain (no fallback)
export CC=/usr/local/bin/afl-cc
export CXX=/usr/local/bin/afl-c++

# Ensure output & prefixes exist
mkdir -p out
mkdir -p target/binutils target/libjpeg-turbo target/libpng target/libxml2 target/lua target/tcpdump target/mjs

JOBS=$(nproc)

# =========================================================
# binutils-2.28 (T01~T04)
# prefix: target/binutils
# outputs: out/c++filt out/readelf out/nm out/objdump
# =========================================================
cd third_party/binutils-2.28
make distclean || true
./configure --prefix="$(pwd)/../../target/binutils" --disable-shared
make -j"$JOBS"
make install
cd ../..

cp -f target/binutils/bin/c++filt out/c++filt
cp -f target/binutils/bin/readelf out/readelf
cp -f target/binutils/bin/nm  out/nm
cp -f target/binutils/bin/objdump out/objdump

# =========================================================
# libjpeg-turbo-3.0.4 (T05 djpeg)
# prefix: target/libjpeg-turbo
# outputs: out/djpeg
# =========================================================
rm -rf third_party/libjpeg-turbo-3.0.4/build-afl
mkdir -p third_party/libjpeg-turbo-3.0.4/build-afl
cd third_party/libjpeg-turbo-3.0.4/build-afl
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$(pwd)/../../../target/libjpeg-turbo" \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DENABLE_SHARED=OFF \
  -DENABLE_STATIC=ON \
  -DCMAKE_EXE_LINKER_FLAGS="-static"
make -j"$JOBS"
make install
cd ../../..

cp -f target/libjpeg-turbo/bin/djpeg out/djpeg

# =========================================================
# libpng-1.6.29 (T06 readpng)  [assignment-provided method]
# prefix: target/libpng (install is optional but kept)
# outputs: out/readpng
# =========================================================
cd third_party/libpng-1.6.29
make distclean || true
./configure --disable-shared --prefix="$(pwd)/../../target/libpng"
make clean || true
make -j"$JOBS"
$CC -o readpng ./contrib/libtests/readpng.c ./.libs/libpng16.a -lz -lm
make install || true
cd ../..

cp -f third_party/libpng-1.6.29/readpng out/readpng

# =========================================================
# libxml2-2.13.4 (T07 xmllint)
# prefix: target/libxml2
# outputs: out/xmllint
# =========================================================
cd third_party/libxml2-2.13.4
./autogen.sh --prefix="$(pwd)/../../target/libxml2" --disable-shared
make -j"$JOBS"
make install
cd ../..

cp -f target/libxml2/bin/xmllint out/xmllint

# =========================================================
# lua-5.4.7 (T08 lua)
# prefix: target/lua
# outputs: out/lua
# =========================================================
cd third_party/lua-5.4.7
make clean || true
make linux CC="$CC" -j"$JOBS"
make install INSTALL_TOP="$(pwd)/../../target/lua"
cd ../..

cp -f target/lua/bin/lua out/lua

# =========================================================
# mjs-2.20.0 (T09 mjs) [assignment-provided method]
# prefix: target/mjs (directory kept for consistency; no install needed)
# outputs: out/mjs
# =========================================================
cd third_party/mjs-2.20.0
rm -f mjs
$CC -DMJS_MAIN mjs.c -ldl -g -o mjs
cd ../..

cp -f third_party/mjs-2.20.0/mjs out/mjs

# =========================================================
# tcpdump-4.99.5 (T10 tcpdump)
# prefix: target/tcpdump
# outputs: out/tcpdump
# =========================================================
rm -rf third_party/tcpdump-tcpdump-4.99.5/build-afl
mkdir -p third_party/tcpdump-tcpdump-4.99.5/build-afl
cd third_party/tcpdump-tcpdump-4.99.5/build-afl
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$(pwd)/../../../target/tcpdump" \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX"
make -j"$JOBS"
make install
cd ../../..

cp -f target/tcpdump/bin/tcpdump out/tcpdump