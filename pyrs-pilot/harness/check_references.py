#!/usr/bin/env python3
"""참조 해답(reference/python, reference/rust)으로 하네스를 종단 검증한다.

각 과제의 참조 해답을 돌려 (1) 기능 테스트가 모두 통과하는지(테스트가 올바른지),
(2) 공격을 모두 방어하는지(안전한 기준 구현이 하네스에서 '막음'으로 나오는지),
(3) 도달 확인 입력이 모두 통과해 무효가 0인지 확인한다.
참조 해답은 사람이 쓴 코드이므로 local 모드 플래그 없이도 실행한다.

결과를 results/<run>/reference__<task>__Py__s0.json (rust는 __Rs__) 으로 저장해 aggregate.py가 바로 읽을 수 있게 한다.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness import runner  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="results/ref_check")
    ap.add_argument("--tasks", nargs="*", default=None)
    ap.add_argument("--langs", nargs="*", default=["python"], help="python rust")
    args = ap.parse_args(argv)
    cfg = runner.load_config()
    tasks = args.tasks or cfg["run"]["tasks"]
    run_dir = ROOT / args.run
    run_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for task in tasks:
        for lang in args.langs:
            sol = ROOT / "tasks" / task / "reference" / lang
            cond = "Py" if lang == "python" else "Rs"
            if not (sol / ("main.py" if lang == "python" else "Cargo.toml")).exists():
                rows.append((f"{task} {lang}", "no reference", "", "", ""))
                continue
            scratch = ROOT / "results" / "_scratch" / f"ref_{task}_{lang}"
            scratch.mkdir(parents=True, exist_ok=True)
            try:
                res = runner.run_task(task, sol, lang, cfg, scratch)
            except Exception as e:
                rows.append((f"{task} {lang}", f"ERROR: {e}", "", "", ""))
                continue
            summ = runner.summarize(res)
            res["_meta"] = {"model": "reference", "task": task, "cond": cond, "sample": 0, "lang": lang, "built": True}
            (run_dir / f"reference__{task}__{cond}__s0.json").write_text(
                json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
            bad = [x["id"] + ":" + ";".join(x["violations"])[:60] for x in res["functional"] + res["attacks"]
                   if x["status"] in ("fail", "exploited", "invalid")]
            rows.append((f"{task} {lang}", summ["verdict"],
                         f"{summ['functional_pass']}/{summ['functional_total']}",
                         f"{summ['attacks_defended']}/{summ['attacks_total']} (invalid {summ['attacks_invalid']})",
                         ", ".join(bad) or "-"))

    w = max(len(r[0]) for r in rows)
    print(f"{'task'.ljust(w)}  verdict            functional  attacks(defended/total)   problems")
    for t, v, f, a, c in rows:
        print(f"{t.ljust(w)}  {str(v).ljust(18)} {str(f).center(10)}  {str(a).ljust(24)}  {c}")
    print(f"\n결과 저장: {run_dir}")
    print("집계:  python -m harness.aggregate --run " + str(run_dir))


if __name__ == "__main__":
    main()
