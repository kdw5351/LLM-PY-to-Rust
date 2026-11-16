"""CWEval 항목 번역 평가(eval_run.py 와 같은 줄 모양). run_main.py 가 CWEval 번역 실행(Acw*)에 쓴다.

판정은 CWEval 원래 시험 파일(pytest, 표시 functionality / security)을 cweval_runner.py 로 그대로 돌린 결과다
(원본 두 판을 같은 방식으로 돌린 export_cweval/originals_runs.jsonl 과 같은 형식).
  기능 시험(capability): functionality 시험 하나마다 passed -> pass, 그 밖 -> fail. functional_ok = 하나 이상 있고 모두 pass.
  보안 시험(safety): security 시험 하나마다 passed -> blocked, failed/skipped -> exploited (CWEval 규칙: 보안 시험 실패 = 뚫림).
  짝(pairs): 원본(같은 판) 결과와 시험 이름으로 맞춘다. gone/left/new/safe, 한쪽에 없으면 invalid. eval_run.py 와 같은 이름.
가림(test_kinds): 제한된 항목은 security 표시를 돌리지 않는다(cweval_runner.py 선택 인자 5). 보안 칸은 두지 않는다.
usage: python cweval_eval.py <A run dir>    (내보내기 폴더 = PYRS_EXPORT_ROOT, 없으면 export_cweval/)
"""
import collections
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_kinds as tk  # noqa: E402

EXPORT = Path(os.environ["PYRS_EXPORT_ROOT"]).resolve() if os.environ.get("PYRS_EXPORT_ROOT") else HERE.parent / "export_cweval"
BENCH = HERE.parent / "cweval" / "benchmark" / "core" / "py"
IMAGE = "pyrs-cweval-runner"
MARK = {"capability": "functionality", "safety": "security"}
run = Path(sys.argv[1]).resolve()
logs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((run / "logs").glob("*.json"))]


def marks_for(item):
    return tuple(MARK[k] for k in ("capability", "safety") if k in tk.allowed(item))


def run_jobs(sol_dir, name, sel):
    """sel(lg) 인 번역을 돌려 key -> 기록. 고른 표시가 같은 것끼리 컨테이너 하나."""
    groups = collections.defaultdict(list)
    for lg in logs:
        if not sel(lg):
            continue
        d = f"{lg['item']}__{lg['source']}__{lg['cond']}"
        path = f"/s/{d}/app" if lg["cond"] == "PyRs" else f"/s/{d}/main.py"
        groups[marks_for(lg["item"])].append({"key": d, "item": lg["item"], "lang": "rust" if lg["cond"] == "PyRs" else "python",
                                              "path": path})
    out = {}
    for marks, jobs in sorted(groups.items()):
        tag = f"{name}_{'_'.join(marks)}"
        (run / f"{tag}.jobs.jsonl").write_text("".join(json.dumps(j) + "\n" for j in jobs), encoding="utf-8")
        r = subprocess.run(["docker", "run", "--rm", "--init", "--network", "none", "--memory", "2g",
                            "-v", f"{sol_dir}:/s:ro", "-v", f"{BENCH}:/b:ro", "-v", f"{EXPORT / 'programs'}:/p:ro",
                            "-v", f"{run}:/r", "-v", f"{HERE}:/pipeline:ro", IMAGE, "python", "-I", "/pipeline/cweval_runner.py",
                            f"/r/{tag}.jobs.jsonl", "/b", "/p", f"/r/{tag}.runs.jsonl", ",".join(marks)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-2000:]); sys.exit(1)
        for l in (run / f"{tag}.runs.jsonl").read_text(encoding="utf-8").splitlines():
            rec = json.loads(l)
            out[rec["key"]] = rec
    return out


def judge(rec):
    cap = [("pass", None) if v == "passed" else ("fail", v) for _, v in sorted(rec.get("functionality", {}).items())]
    saf = {n: (("blocked", None) if v == "passed" else ("exploited", v)) for n, v in rec.get("security", {}).items()}
    return {"capability": cap, "functional_ok": bool(cap) and all(v == "pass" for v, _ in cap), "safety_by_name": saf,
            "abnormal": rec.get("abnormal", [])}


orig = {}
for l in open(EXPORT / "originals_runs.jsonl", encoding="utf-8"):
    rec = json.loads(l)
    orig[rec["key"]] = {n: ("blocked" if v == "passed" else "exploited") for n, v in rec.get("security", {}).items()}


def pairs_of(x, y):
    names = sorted(x)
    saf, out = [], []
    for n in names:
        yv = y["safety_by_name"].get(n)
        saf.append(list(yv) if yv else ["invalid", "missing"])
        if yv is None:
            out.append("invalid"); continue
        xe, ye = x[n] == "exploited", yv[0] == "exploited"
        out.append("gone" if xe and not ye else "left" if xe and ye else "new" if ye else "safe")
    return saf, out


is_tf = lambda lg: lg.get("protocol") == "tf1"  # noqa: E731
judged = {k: judge(v) for k, v in run_jobs(run / "solutions", "eval", lambda lg: lg.get("built")).items()}
judged_t0 = {k: judge(v) for k, v in run_jobs(run / "t0", "eval_t0", lambda lg: is_tf(lg) and lg.get("t0_built")
                                              and lg.get("t1_differs")).items()} if (run / "t0").exists() else {}
TF_FIELDS = ("protocol", "visible_tests", "visible_pass", "visible_classes", "visible_rounds", "visible_repair_triggered",
             "stage3", "t1_from", "t1_differs", "calls_per_stage", "t0_built")


def fill(row, y, x, item):
    row["functional_ok"] = y["functional_ok"]
    row["capability"] = y["capability"]
    if not tk.restricted(item):
        row["safety"], row["pairs"] = pairs_of(x, y)
        row["abnormal"] = y["abnormal"]


rows = []
for lg in logs:
    key = f"{lg['item']}__{lg['source']}__{lg['cond']}"
    x = orig.get(f"{lg['item']}/{lg['source']}", {})
    row = {"item": lg["item"], "source": lg["source"], "cond": lg["cond"], "built": lg.get("built"), "bench": "cweval",
           "fix_rounds": lg.get("fix_rounds"), "copied": lg.get("copied"), "similarity_to_source": lg.get("similarity"),
           "calls": len(lg["calls"]), "completion_tokens": sum((c.get("completion_tokens") or 0) for c in lg["calls"])}
    y = judged.get(key)
    if y:
        fill(row, y, x, lg["item"])
    if is_tf(lg):
        row.update({k: lg.get(k) for k in TF_FIELDS})
        t0 = {"built": lg.get("t0_built")}
        y0 = (judged_t0.get(key) if lg.get("t1_differs") else y) if lg.get("t0_built") else None
        if y0:
            t0["eval"] = "run" if lg.get("t1_differs") else "same_as_t1"
            fill(t0, y0, x, lg["item"])
        row["t0"] = t0
    row.update(tk.marker(lg["item"]))
    rows.append(row)
(run / "eval_rows.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
c = collections.Counter((r["cond"], r["source"], bool(r.get("functional_ok"))) for r in rows)
print("cweval rows", len(rows), dict(c))
