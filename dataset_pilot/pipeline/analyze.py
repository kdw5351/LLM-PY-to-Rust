"""사전 등록 분석 (본실행_준비완료기준 G1). 강화 조건 비교와 옮기기 비교를 짝 McNemar·군집 부트스트랩으로 낸다.

분석 단위 = (원본 코드, 결함 종류). SecCodePLT·CWEval 은 항목마다 CWE 하나라 사실상 항목 단위다.
군집(부트스트랩·보정의 단위) = 시드 대리 묶음(export/seed_families.json). 조건 이름은 가리고 돌린 뒤 푼다(--blind).

통계(모두 numpy+표준 라이브러리로 직접 구현, scipy 없음):
  - 짝 McNemar: 불일치 짝 n10,n01. n<25 면 정확 이항(양측), 아니면 연속성 보정 카이제곱(df=1, erfc 로 정확 p).
  - 군집 McNemar p: 시드 묶음 단위 부트스트랩으로도 낸다(같은 묶음 항목의 상관을 흡수; Durkalski 2003 의 취지).
  - Holm 보정: 확증 묶음(H1·H4·H7-a') p 값에.
  - 비열등: 지표(또는 차이)의 단측 95% 부트스트랩 하한 vs 허용 폭 δ.
  - 동등성(TOST): 차이의 양측 90% 부트스트랩 구간이 (−δ, +δ) 안에 들면 "차이 없음".

usage:
  python analyze.py <out_dir> [--delta 0.05] [--B 10000] [--blind]
    자료 출처는 CONF 에 적는다(아래). 개발용으로 끝까지 도는지 확인할 때도 같은 스크립트를 쓴다.
"""
import argparse
import hashlib
import json
import math
import random
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
DS = HERE.parent
FAM = json.loads((DS / "export" / "seed_families.json").read_text(encoding="utf-8"))["family_of"]


def item_of(tkey):
    return tkey.split("__")[1]


def family(item):
    return FAM.get(item, "solo_" + item)


# ---- 자료 모으기: 조건 -> {item: {"left":0/1, "new":0/1, "broken":bool, "calls":n}} ----
def load_arm(path, cond):
    """단위 = (item, source). 한 항목이 취약판·수정판 두 행이라 분리해 담는다."""
    rows = [r for r in json.loads(Path(path).read_text(encoding="utf-8")) if r.get("cond", cond) == cond]
    out = {}
    for r in rows:
        key = (item_of(r["tkey"]), r["source"])
        broken = r["base_functional_ok"] and not r["hard_functional_ok"]
        rec = out.setdefault(key, {"left": 0, "new": 0, "broken": False, "calls": 0,
                                   "source": r["source"], "item": item_of(r["tkey"])})
        rec["broken"] = rec["broken"] or broken
        rec["calls"] += r.get("calls", 0)
        for p in r["pairs"]:
            if p == "left" and r["source"] == "vulnerable":
                rec["left"] = 1
            if p == "new" and r["source"] == "patched":
                rec["new"] = 1
    return out


# ---- McNemar ----
def _chi2_df1_sf(x):
    return math.erfc(math.sqrt(x / 2.0)) if x > 0 else 1.0


def _binom_two_sided(n10, n01):
    n = n10 + n01
    if n == 0:
        return 1.0
    k = min(n10, n01)
    c = sum(math.comb(n, i) for i in range(k + 1))
    return min(1.0, 2.0 * c * (0.5 ** n))


def mcnemar(a, b, items):
    """a,b: item->outcome(1=나쁨/뚫림). n10 = a 가 1, b 가 0(= b 가 고침). n01 반대."""
    n10 = sum(1 for it in items if a[it] == 1 and b[it] == 0)
    n01 = sum(1 for it in items if a[it] == 0 and b[it] == 1)
    nd = n10 + n01
    if nd == 0:
        return {"n10": 0, "n01": 0, "p": 1.0, "method": "none"}
    if nd < 25:
        return {"n10": n10, "n01": n01, "p": _binom_two_sided(n10, n01), "method": "exact"}
    stat = (abs(n10 - n01) - 1) ** 2 / nd
    return {"n10": n10, "n01": n01, "p": _chi2_df1_sf(stat), "method": "chi2cc"}


# ---- 군집 부트스트랩 ----
def cluster_boot(items, statfn, B=10000, seed=20261112):
    fams = {}
    for it in items:
        fams.setdefault(family(it[0] if isinstance(it, tuple) else it), []).append(it)
    keys = list(fams)
    rng = random.Random(seed)
    obs = statfn(items)
    vals = []
    for _ in range(B):
        samp = []
        for _ in range(len(keys)):
            samp += fams[keys[rng.randrange(len(keys))]]
        vals.append(statfn(samp))
    vals = np.array([v for v in vals if v is not None], float)
    return obs, vals


def ci(vals, lo=2.5, hi=97.5):
    return float(np.percentile(vals, lo)), float(np.percentile(vals, hi))


def holm(pairs):
    """pairs: [(name, p)] -> [(name, p, p_adj, reject@0.05)]."""
    s = sorted(pairs, key=lambda x: x[1])
    m = len(s)
    out = []
    running = 0.0
    for i, (name, p) in enumerate(s):
        adj = min(1.0, max(running, (m - i) * p))
        running = adj
        out.append((name, p, adj, adj < 0.05))
    return out


# ---- 지표 ----
def n_left(arm, items):
    return sum(arm[it]["left"] for it in items if arm[it]["source"] == "vulnerable")


def rr_left(arm, base, items):
    nb = n_left(base, items)
    return None if nb == 0 else 1 - n_left(arm, items) / nb


def removed_func_kept(arm, items):
    return sum(1 for it in items if arm[it]["source"] == "vulnerable" and not arm[it]["left"] and not arm[it]["broken"])


def compare(arm, base, label, delta, B):
    """강화 조건 arm 대 기준 base(보통 B1). 남은 위험 McNemar + RR^left 군집 CI."""
    items = sorted(set(arm) & set(base))
    vuln = [it for it in items if arm[it]["source"] == "vulnerable"]
    vuln.sort()
    a_left = {it: arm[it]["left"] for it in vuln}
    b_left = {it: base[it]["left"] for it in vuln}
    mc = mcnemar(b_left, a_left, vuln)            # base 가 1, arm 이 0 = arm 이 고침 -> n10
    obs, vals = cluster_boot(vuln, lambda s: rr_left(arm, base, s), B=B)
    lo, hi = (ci(vals) if len(vals) else (None, None))
    # 기능 비열등(H7-c): 기능 유지율의 단측 95% 하한이 (base 기능 유지율 − δ) 보다 크면 "나빠지지 않음".
    allk = sorted(set(arm) & set(base))
    fk = lambda arm2: (lambda s: (sum(1 for it in s if not arm2[it]["broken"]) / len(s)) if s else None)
    fo, fv = cluster_boot(allk, fk(arm), B=B)
    base_fk = (sum(1 for it in allk if not base[it]["broken"]) / len(allk)) if allk else None
    f_low = float(np.percentile(fv, 5)) if len(fv) else None
    noninf = (f_low is not None and base_fk is not None and f_low > base_fk - delta)
    return {"label": label, "n_items": len(vuln), "removed_func_kept": removed_func_kept(arm, vuln),
            "RR_left": obs, "RR_left_CI95": [lo, hi], "mcnemar": mc,
            "func_kept_rate": fo, "func_kept_low95": f_low, "func_noninferior": noninf,
            "calls": sum(arm[it]["calls"] for it in vuln)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--delta", type=float, default=0.05)
    ap.add_argument("--B", type=int, default=10000)
    ap.add_argument("--blind", action="store_true")
    ap.add_argument("--conf", default=None, help="자료 출처 JSON: {\"base\":[path,cond], \"arms\":{label:[path,cond]}}")
    a = ap.parse_args()
    conf = json.loads(Path(a.conf).read_text(encoding="utf-8")) if a.conf else DEV_CONF
    base = load_arm(*conf["base"])
    arms = {lab: load_arm(*pc) for lab, pc in conf["arms"].items()}

    labels = list(arms)
    keymap = {}
    if a.blind:
        shuf = labels[:]
        random.Random(a.B).shuffle(shuf)
        keymap = {f"arm{i}": real for i, real in enumerate(shuf)}
        arms = {bl: arms[real] for bl, real in keymap.items()}

    results = [compare(arms[lab], base, lab, a.delta, a.B) for lab in arms]
    primary = conf.get("primary")                 # 주 비교(확증)의 라벨들
    if primary:
        hol = holm([(r["label"], r["mcnemar"]["p"]) for r in results if r["label"] in primary])
        adj = {n: (p, pa, rej) for n, p, pa, rej in hol}
        for r in results:
            if r["label"] in adj:
                r["holm_p"], r["reject_0.05"] = adj[r["label"]][1], adj[r["label"]][2]

    out = {"delta": a.delta, "B": a.B, "base": conf["base"], "results": results}
    if keymap:
        Path(a.out + ".key.json").write_text(json.dumps(keymap, ensure_ascii=False, indent=1), encoding="utf-8")
        out["blinded"] = True
    Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=1))


# 개발용 기본 출처(파이프라인 확인용). 본 실행은 --conf 로 준다.
DEV_CONF = {
    "base": ["pilot_Bc_GFv2_2026-11-12/eval_rows.json", "B1"],
    "arms": {
        "B0": ["pilot_Bc_GFv2_2026-11-12/eval_rows.json", "B0"],
        "BUD": ["pilot_Bc_GFv2_2026-11-12/eval_rows.json", "BUD"],
        "B3": ["pilot_B3_GF_2026-11-12/eval_rows.json", "b3"],
        "B4": ["pilot_B4_GF_2026-11-12/eval_rows.json", "B4"],
    },
    "primary": ["B3", "B4"],
}

if __name__ == "__main__":
    sys.argv[0] = str(Path(sys.argv[0]).resolve())
    main()
