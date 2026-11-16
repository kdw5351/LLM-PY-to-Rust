"""새로 돌린 모의 결과 JSON 을 함께 보낸 _sims/ 의 JSON 과 비교한다(표준 라이브러리만).

usage: python pipeline/compare_sims.py FRESH_DIR [--ref REF_DIR] [--tol 0]
  FRESH_DIR: analyze_main_sims.py --out 으로 준 폴더.  REF_DIR 기본 = 이 스크립트 옆 ../_sims
  비교 파일: coverage.json, power.json, boundary.json, power_2ga1_sensitivity.json (FRESH_DIR 에 있는 것만)
  'seconds'(걸린 시간)는 빼고, 그 밖의 모든 칸(숫자·문자열·목록 길이·열쇠)을 비교한다.
  숫자는 |차이| <= tol 이면 같다고 본다(기본 0 = 완전히 같음). 하나라도 다르면 끝 코드 1.
"""
import argparse
import json
import math
import sys
from pathlib import Path

FILES = ("coverage.json", "power.json", "boundary.json", "power_2ga1_sensitivity.json")
IGNORE = {"seconds"}


def walk(a, b, path, st):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k in IGNORE:
                continue
            if k not in a or k not in b:
                st["other"].append(f"{path}/{k}: key only in {'fresh' if k in a else 'reference'}")
                continue
            walk(a[k], b[k], f"{path}/{k}", st)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            st["other"].append(f"{path}: list length {len(a)} vs {len(b)}")
            return
        for i, (x, y) in enumerate(zip(a, b)):
            walk(x, y, f"{path}[{i}]", st)
    elif isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool) and not isinstance(b, bool):
        st["numeric"] += 1
        if math.isnan(a) and math.isnan(b):
            return
        d = abs(a - b)
        st["max"] = max(st["max"], d)
        if d > st["tol"]:
            st["num_diff"].append(f"{path}: {a!r} vs {b!r}")
    else:
        st["other_n"] += 1
        if a != b:
            st["other"].append(f"{path}: {a!r} vs {b!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("fresh")
    ap.add_argument("--ref", default=str(Path(__file__).resolve().parent.parent / "_sims"))
    ap.add_argument("--tol", type=float, default=0.0)
    a = ap.parse_args()
    fresh, ref = Path(a.fresh), Path(a.ref)
    bad = done = 0
    for f in FILES:
        if not (fresh / f).exists():
            print(f"{f}: not in {fresh.name}/, skipped")
            continue
        A = json.loads((fresh / f).read_text(encoding="utf-8"))
        B = json.loads((ref / f).read_text(encoding="utf-8"))
        st = {"numeric": 0, "other_n": 0, "max": 0.0, "tol": a.tol, "num_diff": [], "other": []}
        walk(A, B, "", st)
        ok = not st["num_diff"] and not st["other"]
        done += 1
        bad += not ok
        print(f"{f}: {st['numeric']} numeric fields, {len(st['num_diff'])} differ (max |diff| {st['max']:.3g}); "
              f"{st['other_n']} other fields, {len(st['other'])} differ -> {'IDENTICAL' if ok else 'DIFFERENT'}")
        for line in (st["num_diff"] + st["other"])[:20]:
            print("   ", line)
    print(f"compared {done} files, {bad} different")
    sys.exit(1 if bad or not done else 0)


if __name__ == "__main__":
    main()
