#!/usr/bin/env bash

# 检查是否提供了参数
if [ -z "$1" ]; then
    echo "Usage: $0 <program_name>"
    exit 1
fi

PROG="$1"

CURVE_BUCKET_SEC=1

# 根据程序名映射到对应的种子文件夹ID
case "$PROG" in
    "c++filt") ID="01" ;;
    "readelf") ID="02" ;;
    "nm")      ID="03" ;;
    "objdump") ID="04" ;;
    "djpeg")   ID="05" ;;
    "readpng") ID="06" ;;
    "xmllint") ID="07" ;;
    "lua")     ID="08" ;;
    "mjs")     ID="09" ;;
    "tcpdump") ID="10" ;;
    *)
        echo "Error: Unknown program name '$PROG'"
        echo "Supported programs: cxxfilt(c++filt), readelf, nm-new(nm), objdump, djpeg, readpng, xmllint, lua, mjs, tcpdump"
        exit 1
        ;;
esac

RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
WORKDIR="./workdir/$PROG/$RUN_ID"
# 修改种子目录路径：使用映射出来的 ID
SEEDS_DIR="./env/seeds/$ID"

# 兼容不同构建产物命名：尽量让 AFL-CMD 保持为表格里的名字
# - cxxfilt 可能被构建为 c++filt
# - nm-new 可能被构建为 nm
if [ ! -x "./env/out/cxxfilt" ] && [ -x "./env/out/c++filt" ]; then
    ln -sf "c++filt" "./env/out/cxxfilt" 2>/dev/null || true
fi
if [ ! -x "./env/out/nm-new" ] && [ -x "./env/out/nm" ]; then
    ln -sf "nm" "./env/out/nm-new" 2>/dev/null || true
fi

# 根据目标生成命令行模板（对齐文档/表格里的 AFL-CMD 要求）
case "$PROG" in
    "c++filt")          CMD="./env/out/c++filt" ;;             # STDIN
    "readelf")          CMD="./env/out/readelf -a @@ @@" ;;    # FILE (two @@)
    "nm")               CMD="./env/out/nm @@" ;;               # FILE
    "objdump")          CMD="./env/out/objdump -d @@" ;;       # FILE
    "djpeg")            CMD="./env/out/djpeg @@" ;;            # FILE
    "readpng")          CMD="./env/out/readpng" ;;             # STDIN
    "xmllint")          CMD="./env/out/xmllint @@" ;;          # FILE
    "lua")              CMD="./env/out/lua @@" ;;              # FILE
    "mjs")              CMD="./env/out/mjs -f @@" ;;           # FILE
    "tcpdump")          CMD="./env/out/tcpdump -nr @@" ;;      # FILE
esac

echo "Target Program: $PROG"
echo "Seed Directory: $SEEDS_DIR"
echo "AFL-CMD: $CMD"

# 执行 Maven 命令
mvn -q -DskipTests exec:java \
    -Dnju.fuzzer.curveBucketSec=$CURVE_BUCKET_SEC \
  -Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain \
    -Dexec.args="--workdir $WORKDIR --seeds $SEEDS_DIR --duration 60 --timeout 2000 --tid $PROG --coverage shmex --cmd \"$CMD\""
