"""개발용/확증용 분할(본실험_재설계안_2026-11-12.md 1절, 결정 3). 결과를 보지 않고 시드로만 정한다.
- 이미 손댄 항목(pilot20 + agent3)은 개발용.
- 나머지(SecCodePLT 재현 814 + CWEval 21 중 손대지 않은 것)에서 CWE 별 층화로 80개를 개발용으로 더 뽑는다
  (CWE 묶음 크기에 비례, 최대 나머지 방식). 그 밖은 확증용.
- 이번 시험 운행 10개: 새 개발용 80개 중 SecCodePLT 항목을 시드 순서로 늘어놓고, CWE 가 겹치지 않게 앞에서부터 10개.
usage: python -I make_split.py <dataset_pilot dir> <out dir>
"""
import hashlib
import json
import os
import random
import sys
from collections import defaultdict

SEED = 20261112
base, out = sys.argv[1:3]
exp = os.path.join(base, "export")
touched = set(open(os.path.join(exp, "pilot20_ids.txt")).read().split()) | set(open(os.path.join(exp, "agent3_ids.txt")).read().split())
scp = open(os.path.join(exp, "reproduced_ids.txt")).read().split()
cwe_ids = open(os.path.join(base, "export_cweval", "reproduced_ids.txt")).read().split()
cwe_of = {}
for i in scp:
    cwe_of[i] = "CWE-" + json.load(open(os.path.join(exp, "programs", i, "meta.json"), encoding="utf-8"))["cwe"]
for i in cwe_ids:
    cwe_of[i] = "CWE-" + str(int(i.split("_")[1]))
pool = sorted(i for i in cwe_of if i not in touched)
groups = defaultdict(list)
for i in pool:
    groups[cwe_of[i]].append(i)
rng = random.Random(SEED)
for g in sorted(groups):
    rng.shuffle(groups[g])
N = 80
quota = {g: N * len(v) / len(pool) for g, v in groups.items()}
alloc = {g: int(q) for g, q in quota.items()}
rest = N - sum(alloc.values())
for g in sorted(groups, key=lambda g: (-(quota[g] - alloc[g]), g))[:rest]:
    alloc[g] += 1
dev_new = sorted(i for g in groups for i in groups[g][:alloc[g]])
confirm = sorted(set(pool) - set(dev_new))
order = sorted(dev_new, key=lambda i: hashlib.sha256(f"{SEED}:{i}".encode()).hexdigest())
pilot, seen = [], set()
for i in order:
    if i in scp and cwe_of[i] not in seen:
        pilot.append(i)
        seen.add(cwe_of[i])
    if len(pilot) == 10:
        break
os.makedirs(out, exist_ok=True)
for name, ids in (("dev_touched", sorted(touched)), ("dev_new80", dev_new), ("confirmatory", confirm), ("pilot10", pilot)):
    txt = "\n".join(ids) + "\n"
    open(os.path.join(out, f"{name}.txt"), "w").write(txt)
    print(name, len(ids), hashlib.sha256(txt.encode()).hexdigest()[:16])
print("pilot10", [(i, cwe_of[i]) for i in pilot])
