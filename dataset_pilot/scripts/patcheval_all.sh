#!/usr/bin/env bash
# PatchEval 검증판의 Python 항목마다: 이미지를 받고, 취약한 판(vul-run.sh)과 공식 수정판(fix-run.sh)을 돌린 뒤 이미지를 지운다.
# 판정: vul-run 이 실패(rc!=0)하고 fix-run 이 성공(rc==0)하면 양방향 재현.
# usage: bash patcheval_all.sh <list.tsv: cve<TAB>image> <out_dir>
set -u
LIST="$1"; OUT="$2"
mkdir -p "$OUT"
while IFS=$'\t' read -r CVE IMG; do
  [ -z "$CVE" ] && continue
  [ -f "$OUT/$CVE.done" ] && continue
  echo "[$(date +%H:%M:%S)] $CVE pull" >> "$OUT/progress.log"
  if ! docker pull -q "$IMG" > "$OUT/$CVE.pull.log" 2>&1; then
    echo -e "$CVE\tPULL_FAIL\t-\t-" >> "$OUT/summary.tsv"; touch "$OUT/$CVE.done"; continue
  fi
  SIZE=$(docker image inspect "$IMG" --format '{{.Size}}' 2>/dev/null)
  MSYS_NO_PATHCONV=1 docker run --rm --memory 4g --cpus 4 "$IMG" bash -lc 'cd /workspace && timeout 900 bash vul-run.sh' > "$OUT/$CVE.vul.log" 2>&1
  VRC=$?
  MSYS_NO_PATHCONV=1 docker run --rm --memory 4g --cpus 4 "$IMG" bash -lc 'cd /workspace && timeout 900 bash fix-run.sh' > "$OUT/$CVE.fix.log" 2>&1
  FRC=$?
  echo -e "$CVE\t$VRC\t$FRC\t$SIZE" >> "$OUT/summary.tsv"
  echo "[$(date +%H:%M:%S)] $CVE vul=$VRC fix=$FRC" >> "$OUT/progress.log"
  docker image rm -f "$IMG" > /dev/null 2>&1
  touch "$OUT/$CVE.done"
done < "$LIST"
echo "ALL_DONE" >> "$OUT/progress.log"
