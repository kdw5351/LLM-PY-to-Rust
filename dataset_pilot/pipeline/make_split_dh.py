"""확증용 735개를 원인 규명용(D)과 최종 검증용(H)으로 나눈다. 결과를 보지 않고 시드로만 정한다.
- 단위는 시드 묶음(export/seed_families.json 의 family_of; CWEval 항목은 각자 1개짜리 묶음). 한 묶음은 한쪽에만 들어간다.
- 약점 종류(CWE)별로 층을 나눠, 층마다 묶음을 시드 순서로 섞고 항목 수 기준으로 D 비율(기본 0.40)에 가장 가깝게 자른다.
- 묶음이 1개뿐인 층은 시드로 한쪽에 넣는다(D 확률 = 비율).
usage: python -I make_split_dh.py <dataset_pilot dir> <out dir> [ratio]
"""
import hashlib
import json
import os
import random
import sys
from collections import defaultdict

SEED = 20261113
base, out = sys.argv[1:3]
ratio = float(sys.argv[3]) if len(sys.argv) > 3 else 0.40
conf = open(os.path.join(base, "split_2026-11-12", "confirmatory.txt")).read().split()
fam_of = json.load(open(os.path.join(base, "export", "seed_families.json"), encoding="utf-8"))["family_of"]


def cwe(i):
    if i.startswith("cwe_"):
        return str(int(i.split("_")[1]))
    return str(json.load(open(os.path.join(base, "export", "programs", i, "meta.json"), encoding="utf-8"))["cwe"])


fam = {i: fam_of.get(i, "single_" + i) for i in conf}
strata = defaultdict(lambda: defaultdict(list))          # cwe -> family -> items
for i in conf:
    strata[cwe(i)][fam[i]].append(i)
rng = random.Random(SEED)
D, H = [], []
for c in sorted(strata, key=lambda x: int(x)):
    fams = sorted(strata[c])
    rng.shuffle(fams)
    total = sum(len(strata[c][f]) for f in fams)
    if len(fams) == 1:
        (D if rng.random() < ratio else H).extend(strata[c][fams[0]])
        continue
    target, acc, cut = ratio * total, 0, 0
    for k, f in enumerate(fams):                           # 누적 항목 수가 목표에 가장 가까운 지점에서 자른다
        nxt = acc + len(strata[c][f])
        if abs(nxt - target) <= abs(acc - target):
            acc, cut = nxt, k + 1
        else:
            break
    cut = min(max(cut, 1), len(fams) - 1)                  # 두 쪽 모두 묶음 1개 이상
    for f in fams[:cut]:
        D.extend(strata[c][f])
    for f in fams[cut:]:
        H.extend(strata[c][f])
os.makedirs(out, exist_ok=True)
for name, ids in (("discovery.txt", D), ("holdout.txt", H)):
    with open(os.path.join(out, name), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(sorted(ids)) + "\n")
assert not set(D) & set(H) and set(D) | set(H) == set(conf)
assert not {fam[i] for i in D} & {fam[i] for i in H}
h = lambda ids: hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()[:16]
info = {"seed": SEED, "ratio": ratio, "discovery": {"items": len(D), "families": len({fam[i] for i in D}), "sha": h(D)},
        "holdout": {"items": len(H), "families": len({fam[i] for i in H}), "sha": h(H)},
        "per_cwe": {c: {"D": sum(1 for i in D if cwe(i) == c), "H": sum(1 for i in H if cwe(i) == c)}
                    for c in sorted(strata, key=lambda x: int(x))}}
json.dump(info, open(os.path.join(out, "split_dh.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(json.dumps(info, ensure_ascii=False))
