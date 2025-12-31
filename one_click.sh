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
        echo "Supported programs: c++filt, readelf, nm, objdump, djpeg, readpng, xmllint, lua, mjs, tcpdump"
        exit 1
        ;;
esac

RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
WORKDIR="./workdir/$PROG/$RUN_ID"
# 修改种子目录路径：使用映射出来的 ID
SEEDS_DIR="./env/seeds/$ID"
# 待测程序命令路径保持不变（通常还是用程序名）
CMD="./env/out/$PROG @@"

echo "Target Program: $PROG"
echo "Seed Directory: $SEEDS_DIR"

# 执行 Maven 命令
mvn -q -DskipTests exec:java \
    -Dnju.fuzzer.curveBucketSec=$CURVE_BUCKET_SEC \
  -Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain \
    -Dexec.args="--workdir $WORKDIR --seeds $SEEDS_DIR --duration 3600 --timeout 2000 --tid $PROG --coverage shmex --cmd \"$CMD\""
