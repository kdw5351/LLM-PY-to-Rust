#!/usr/bin/env bash
# 컨테이너 안에서만 실행. CWEval Python 과제마다 시험 파일을 돌려 마지막 요약 줄을 낸다.
# usage: bash /scripts/cweval_run.sh /src(읽기 전용 benchmark/core/py)
set -u
cp -r "$1" /tmp/w && cd /tmp/w
for t in cwe_*_test.py; do
  id=${t%_test.py}
  line=$(timeout 300 python -m pytest -q -p no:cacheprovider "$t" 2>&1 | tail -1)
  echo "$id | $line"
done
