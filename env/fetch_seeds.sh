#!/usr/bin/env bash
set -e

# run at env/
mkdir -p seeds/{01,02,03,04,05,06,07,08,09,10}

# T01 cxxfilt (LLM-Generate)
cat > seeds/01/000001 << 'EOF'
_Z1fv
EOF

# T02 readelf  (AFL++ elf testcases)
i=1
for f in third_party/AFLplusplus/testcases/others/elf/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/02/$(printf "%06d" "$i")"
  i=$((i+1))
done

# T03 nm-new   (same elf seeds)
i=1
for f in third_party/AFLplusplus/testcases/others/elf/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/03/$(printf "%06d" "$i")"
  i=$((i+1))
done

# T04 objdump  (same elf seeds)
i=1
for f in third_party/AFLplusplus/testcases/others/elf/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/04/$(printf "%06d" "$i")"
  i=$((i+1))
done

# T05 djpeg    (AFL++ jpeg + project testimages)
i=1
for f in third_party/AFLplusplus/testcases/images/jpeg/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/05/$(printf "%06d" "$i")"
  i=$((i+1))
done
for f in third_party/libjpeg-turbo-3.0.4/testimages/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/05/$(printf "%06d" "$i")"
  i=$((i+1))
done

# T06 readpng  (AFL++ png + project tests)
i=1
for f in third_party/AFLplusplus/testcases/images/png/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/06/$(printf "%06d" "$i")"
  i=$((i+1))
done
for f in third_party/libpng-1.6.29/tests/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/06/$(printf "%06d" "$i")"
  i=$((i+1))
done

# T07 xmllint  (AFL++ xml + project test)
i=1
for f in third_party/AFLplusplus/testcases/others/xml/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/07/$(printf "%06d" "$i")"
  i=$((i+1))
done
# libxml2 test/ has subdirs: copy only regular files from anywhere under test/
for f in $(find third_party/libxml2-2.13.4/test -type f); do
  cp "$f" "seeds/07/$(printf "%06d" "$i")"
  i=$((i+1))
done

# T08 lua (auto clone official lua tests, then copy testes/)
rm -rf third_party/lua
git clone --depth 1 https://github.com/lua/lua.git third_party/lua

i=1
for f in third_party/lua/testes/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/08/$(printf "%06d" "$i")"
  i=$((i+1))
done

# T09 mjs      (AFL++ mjs + project tests)
i=1
for f in third_party/AFLplusplus/testcases/others/js/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/09/$(printf "%06d" "$i")"
  i=$((i+1))
done
for f in third_party/mjs-2.20.0/tests/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/09/$(printf "%06d" "$i")"
  i=$((i+1))
done

# T10 tcpdump  (AFL++ pcap + project tests)
i=1
for f in third_party/AFLplusplus/testcases/others/pcap/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/10/$(printf "%06d" "$i")"
  i=$((i+1))
done
for f in third_party/tcpdump-tcpdump-4.99.5/tests/*; do
  [ -f "$f" ] || continue
  cp "$f" "seeds/10/$(printf "%06d" "$i")"
  i=$((i+1))
done

echo "done: seeds are in ./seeds/{01..10}"
