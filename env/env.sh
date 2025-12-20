#!/usr/bin/env bash
set -euo pipefail

if [ $UID -ne 0 ]; then
  echo "[ERR] Please run this script as root (sudo)." >&2
  exit 1
fi

mkdir third_party
mkdir target
mkdir out
bash deps.sh
bash fetch_targets.sh
bash build_aflpp.sh
bash build_target.sh