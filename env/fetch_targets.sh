#!/usr/bin/env bash
set -euo pipefail

# Repo raw base (main branch)
REPO_RAW_BASE="${REPO_RAW_BASE:-https://github.com/QRXqrx/NJU-AT-fuzz-targets/raw/main}"

# Where to store archives and extracted sources
ARCHIVE_DIR="${ARCHIVE_DIR:-third_party}"
SRC_DIR="${SRC_DIR:-third_party}"

mkdir -p "$ARCHIVE_DIR" "$SRC_DIR"

# The tarballs listed in your assignment table (repo root)
TARBALLS=(
  "binutils-2.28.tar.gz"
  "libjpeg-turbo-3.0.4.tar.gz"
  "libpng-1.6.29.tar.gz"
  "libxml2-2.13.4.tar.gz"
  "lua-5.4.7.tar.gz"
  "mjs-2.20.0.tar.gz"
  "tcpdump-tcpdump-4.99.5.tar.gz"
)

download_one() {
  local name="$1"
  local url="${REPO_RAW_BASE}/${name}"
  local out="${ARCHIVE_DIR}/${name}"

  if [ -f "$out" ]; then
    echo "[SKIP] already downloaded: $out"
    return
  fi

  echo "[DL] $url"
  # -L follow redirects, --fail to fail on 404, --retry for robustness
  curl -L --fail --retry 5 --retry-delay 2 -o "$out" "$url"
  echo "[OK] saved: $out"
}

extract_one() {
  local name="$1"
  local archive="${ARCHIVE_DIR}/${name}"

  if [ ! -f "$archive" ]; then
    echo "[ERR] archive not found: $archive" >&2
    exit 1
  fi

  # Derive folder name: remove .tar.gz
  local base="${name%.tar.gz}"
  local outdir="${SRC_DIR}/${base}"

  # Heuristic: if outdir exists and non-empty, treat as extracted
  if [ -d "$outdir" ] && [ "$(ls -A "$outdir" | wc -l)" -gt 0 ]; then
    echo "[SKIP] already extracted: $outdir"
    return
  fi

  echo "[EXTRACT] $archive -> $outdir"
  mkdir -p "$outdir"

  # Many tarballs contain a top-level folder already; extract into SRC_DIR
  # then normalize by ensuring SRC_DIR/base exists.
  tar -xzf "$archive" -C "$SRC_DIR"

  # If the tarball extracted into a different folder name, attempt to fix:
  if [ ! -d "$outdir" ]; then
    # Find the newest directory under SRC_DIR that matches base prefix
    local candidate
    candidate="$(find "$SRC_DIR" -maxdepth 1 -type d -name "${base}*" -printf "%T@ %p\n" | sort -nr | head -n1 | awk '{print $2}')"
    if [ -n "${candidate:-}" ] && [ -d "$candidate" ]; then
      mv "$candidate" "$outdir"
    fi
  fi

  if [ ! -d "$outdir" ]; then
    echo "[ERR] extraction did not produce expected dir: $outdir" >&2
    exit 1
  fi

  echo "[OK] extracted: $outdir"
}

echo "== Downloading tarballs =="
for t in "${TARBALLS[@]}"; do
  download_one "$t"
done

echo "== Extracting tarballs =="
for t in "${TARBALLS[@]}"; do
  extract_one "$t"
done

echo "[DONE] archives in: $ARCHIVE_DIR"
echo "[DONE] sources  in: $SRC_DIR"

