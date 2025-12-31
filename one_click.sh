#!/usr/bin/env bash

# 检查是否提供了参数
if [ -z "$1" ]; then
    echo "Usage: $0 <program_name>"
    exit 1
fi

PROG="$1"

CURVE_BUCKET_SEC=1

# 控制每次执行是否落盘 stdout/stderr 到 workdir/tmp/exec-logs
# all: 每次 exec 都写 stdout_<id>.log / stderr_<id>.log（可能产生海量小文件）
# interesting: 只为 interesting（晋升入队）输入保存日志
EXEC_LOGS=interesting

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

# 将每次执行的临时输入文件放到 tmpfs（/dev/shm）中，避免写入硬盘
TMP_INPUTS_DIR="/dev/shm/nju-fuzzer/$PROG/$RUN_ID/inputs"
# 修改种子目录路径：使用映射出来的 ID
SEEDS_DIR="./env/seeds/$ID"
# 待测程序命令路径保持不变（通常还是用程序名）
CMD="./env/out/$PROG @@"

echo "Target Program: $PROG"
echo "Seed Directory: $SEEDS_DIR"

# 执行 Maven 命令
mvn -q -DskipTests exec:java \
    -Dnju.fuzzer.curveBucketSec=$CURVE_BUCKET_SEC \
        -Dnju.fuzzer.execLogs=$EXEC_LOGS \
        -Dnju.fuzzer.tmpInputsDir=$TMP_INPUTS_DIR \
  -Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain \
    -Dexec.args="--workdir $WORKDIR --seeds $SEEDS_DIR --duration 3600 --timeout 1000 --tid $PROG --coverage shmex --cmd \"$CMD\""
