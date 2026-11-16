#!/usr/bin/env python3
"""이미 생성·빌드된 해답 디렉터리들을 하네스로 (다시) 측정한다.

results/<run>/solutions/<model>__<task>__<cond>__s<n>/ 를 훑어 각 해답을 runner.run_task로 돌리고
results/<run>/<...>.json 을 쓴다(_meta.json 이 있으면 그대로 붙인다). 케이스 파일을 고친 뒤 재측정할 때 쓴다.
LLM 생성 코드를 실행하므로 local 모드에서는 --i-know-local-is-unsafe 가 필요하다.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness import runner, sandbox  # noqa: E402


def lang_of(sol: Path) -> str | None:
    if (sol / "Cargo.toml").exists():
        return "rust"
    if (sol / "main.py").exists():
        return "python"
    if (sol / "main.c").exists():
        return "c"
    return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, help="results/<run> 디렉터리")
    ap.add_argument("--only", nargs="*", default=None, help="해답 디렉터리 이름 일부")
    ap.add_argument("--i-know-local-is-unsafe", action="store_true")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    cfg = runner.load_config()
    sandbox.require_local_ok(cfg, args.i_know_local_is_unsafe)
    run_dir = ROOT / args.run if not Path(args.run).is_absolute() else Path(args.run)
    rows = []
    for sol in sorted((run_dir / "solutions").glob("*__*__*__s*")):
        if not sol.is_dir():
            continue
        name = sol.name
        if args.only and not any(o in name for o in args.only):
            continue
        try:
            model, task, cond, s = name.split("__")
        except ValueError:
            continue
        lang = lang_of(sol)
        if not lang:
            rows.append((name, "no code", "", ""))
            continue
        scratch = run_dir / "_scratch" / name
        scratch.mkdir(parents=True, exist_ok=True)
        try:
            res = runner.run_task(task, sol, lang, cfg, scratch)
        except Exception as e:
            rows.append((name, f"ERR {str(e)[:40]}", "", ""))
            continue
        meta_p = sol / "_meta.json"
        meta = json.loads(meta_p.read_text(encoding="utf-8")) if meta_p.exists() else {}
        meta.update({"model": model, "task": task, "cond": cond, "sample": int(s[1:]), "lang": lang,
                     "verdict": res.get("verdict")})
        res["_meta"] = meta
        (run_dir / f"{name}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        summ = runner.summarize(res)
        rows.append((name, summ["verdict"], f"{summ['functional_pass']}/{summ['functional_total']}",
                     f"{summ['attacks_defended']}/{summ['attacks_total']} inv {summ['attacks_invalid']}"))
    w = max((len(r[0]) for r in rows), default=10)
    print(f"{'solution'.ljust(w)}  verdict            func   atk")
    for n, v, f, a in rows:
        print(f"{n.ljust(w)}  {str(v).ljust(18)} {str(f):6} {a}")
    print(f"\n집계:  python -m harness.aggregate --run {run_dir}")


if __name__ == "__main__":
    main()
