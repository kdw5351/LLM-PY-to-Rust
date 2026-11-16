"""1단계 추가 표본(실험설계서_4단계 3절: 무작위 100항목 × 5개, temperature 0.8)의 항목 목록을 정한다. 결과를 보지 않고 시드로만.
확증용 735개(D 285 + H 450)에서 D/H 비율대로(반올림) 나눠 각 목록에서 시드 20261113 으로 뽑는다. 기존 분할 파일은 고치지 않는다.
usage: python -I make_extra100.py <split_dh dir> [n=100]   ->  <split_dh dir>/extra100.txt (이미 있으면 멈춘다)
"""
import hashlib
import os
import random
import sys

SEED = 20261113
d = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 100
out = os.path.join(d, "extra100.txt")
if os.path.exists(out):
    sys.exit(f"{out} exists (not overwritten)")
D = sorted(open(os.path.join(d, "discovery.txt")).read().split())
H = sorted(open(os.path.join(d, "holdout.txt")).read().split())
nd = round(n * len(D) / (len(D) + len(H)))
rng = random.Random(SEED)
pick = sorted(rng.sample(D, nd)) + sorted(rng.sample(H, n - nd))
with open(out, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(sorted(pick)) + "\n")
print(f"extra100: D {nd}, H {n - nd}, CWEval {sum(1 for i in pick if i.startswith('cwe_'))}, "
      f"sha256 {hashlib.sha256(open(out, 'rb').read()).hexdigest()}")
