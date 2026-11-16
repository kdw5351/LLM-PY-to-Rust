"""옮긴 코드를 데이터셋 시험으로 평가하고 옮기기 전후를 비교한다(제안서 7절 정의).
1) 빌드된 번역마다 runner.py 를 컨테이너(네트워크 없음)에서 돌린다.
2) judge.py 로 판정한다. 원래 결과 x 는 export/originals_runs.jsonl 의 같은 버전(취약한 버전/수정된 버전) 판정이다.
3) 보안 시험 하나마다: x=뚫림,y=막음 -> gone / x=뚫림,y=뚫림 -> left / x=막음,y=뚫림 -> new / x=막음,y=막음 -> safe. invalid 는 뺀다.
   주 비교는 기능 시험을 모두 통과한 번역만 쓴다(제안서 5절). 통과하지 못한 번역도 따로 센다.
번역 3단계(tf1, 완화조건_재설계_2026-11-13.md 2절)로 만든 번역은 logs 에 "protocol": "tf1" 이 있다. 이때 주 결과(위 필드,
solutions/)는 3단계 뒤 프로그램(T1)이고, 3단계 직전 프로그램(T0, <run>/t0/)도 같은 시험으로 판정해 row["t0"] 에 둔다.
T0 와 T1 의 소스가 같으면(t1_differs 가 거짓) T1 판정을 그대로 쓴다(row["t0"]["eval"] = "same_as_t1"). 보이는 시험은 판정에 쓰지 않는다.
내보내기 폴더는 환경 변수 PYRS_EXPORT_ROOT 로 바꿀 수 있다(없으면 export/). originals_runs.jsonl 이 없는 내보내기(보안 시험 없음)는
원래 결과를 빈 것으로 둔다.
usage: python eval_run.py <run dir>
"""
import collections
import difflib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from judge import judge_record  # noqa: E402
import test_kinds as tk  # noqa: E402  (가림: 고른 시험 종류만. 환경 변수가 없으면 기존 동작 그대로)

EXPORT = Path(os.environ["PYRS_EXPORT_ROOT"]).resolve() if os.environ.get("PYRS_EXPORT_ROOT") else HERE.parent / "export"
run = Path(sys.argv[1]).resolve()
tim = set(l.split("\t")[1] for l in open(HERE.parent / "usable" / "items.tsv", encoding="utf-8") if "시간 초과 규칙으로 인정" in l)

logs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((run / "logs").glob("*.json"))]


def run_jobs(sol_dir, jobs_name, runs_name, sel):
    jobs = []
    for lg in logs:
        if not sel(lg):
            continue
        d = f"{lg['item']}__{lg['source']}__{lg['cond']}"
        path = f"/s/{d}/app" if lg["cond"] == "PyRs" else f"/s/{d}/main.py"
        jobs.append({"key": d, "item": lg["item"], "lang": "rust" if lg["cond"] == "PyRs" else "python", "path": path})
    (run / jobs_name).write_text("".join(json.dumps(j) + "\n" for j in jobs), encoding="utf-8")
    if jobs:
        kt = tk.stage(run / "_kind_tests" / jobs_name.replace(".jsonl", ""), [j["item"] for j in jobs], EXPORT)
        r = subprocess.run(["docker", "run", "--rm", "--init", "--network", "none", "--memory", "2g",
                            "-v", f"{sol_dir}:/s:ro", "-v", f"{EXPORT}:/x:ro", "-v", f"{run}:/r", "-v", f"{HERE}:/pipeline:ro",
                            *(["-v", f"{kt}:/kt:ro"] if kt else []),
                            "pyrs-seccodeplt-runner", "python", "-I", "/pipeline/runner.py", f"/r/{jobs_name}",
                            "/kt" if kt else "/x/tests", f"/r/{runs_name}", "10"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-2000:]); sys.exit(1)


def judged_of(runs_name):
    out = {}
    if (run / runs_name).exists():
        for l in open(run / runs_name, encoding="utf-8"):
            rec = json.loads(l)
            out[rec["key"]] = judge_record(rec, tk.load_tests(EXPORT, rec["item"]), rec["item"] in tim)
    return out


is_tf = lambda lg: lg.get("protocol") == "tf1"  # noqa: E731
run_jobs(run / "solutions", "eval_jobs.jsonl", "eval_runs.jsonl", lambda lg: lg.get("built"))
if any(is_tf(lg) for lg in logs):   # T0: 소스가 T1 과 다를 때만 따로 돌린다
    run_jobs(run / "t0", "eval_jobs_t0.jsonl", "eval_runs_t0.jsonl",
             lambda lg: is_tf(lg) and lg.get("t0_built") and lg.get("t1_differs"))

orig = {}
if (EXPORT / "originals_runs.jsonl").exists():
    for l in open(EXPORT / "originals_runs.jsonl", encoding="utf-8"):
        rec = json.loads(l)
        orig[rec["key"]] = judge_record(rec, json.load(open(EXPORT / "tests" / f"{rec['item']}.json")), rec["item"] in tim)
    no_orig = None
else:                                # 보안 시험이 없는 내보내기(newdev/export482): 원래 결과 없음
    no_orig = {"safety": []}
judged = judged_of("eval_runs.jsonl")
judged_t0 = judged_of("eval_runs_t0.jsonl")


def pairs_of(x, y):
    out = []
    for (xv, _), (yv, ysub) in zip(x["safety"], y["safety"]):
        if xv == "invalid" or yv == "invalid":
            out.append("invalid"); continue
        xe, ye = xv == "exploited", yv == "exploited"
        out.append("gone" if xe and not ye else "left" if xe and ye else "new" if ye else "safe")
    return out


TF_FIELDS = ("protocol", "visible_tests", "visible_pass", "visible_classes", "visible_rounds", "visible_repair_triggered",
             "stage3", "t1_from", "t1_differs", "calls_per_stage", "t0_built")

rows, per_test = [], collections.Counter()
for lg in logs:
    key = f"{lg['item']}__{lg['source']}__{lg['cond']}"
    x = orig[f"{lg['item']}/{lg['source']}"] if no_orig is None else no_orig
    y = judged.get(key)
    row = {"item": lg["item"], "source": lg["source"], "cond": lg["cond"], "built": lg.get("built"),
           "fix_rounds": lg.get("fix_rounds"), "copied": lg.get("copied"), "similarity_to_source": lg.get("similarity"),
           "calls": len(lg["calls"]), "completion_tokens": sum((c.get("completion_tokens") or 0) for c in lg["calls"])}
    if y:
        row["functional_ok"] = y["functional_ok"]
        row["capability"] = y["capability"]
        row["safety"] = y["safety"]
        out = pairs_of(x, y)
        row["pairs"] = out
        row["abnormal"] = [s for v, s in y["safety"] if s in ("panic", "crash", "timeout")]
        if row["functional_ok"]:
            for o in out:
                per_test[(lg["source"], lg["cond"], o)] += 1
        # 데이터 오염 확인: 취약한 버전을 Python으로 다시 쓴 코드가 데이터셋의 수정된 버전을 얼마나 닮았나
        if lg["cond"] == "PyPy" and lg["source"] == "vulnerable":
            sol = run / "solutions" / key / "main.py"
            patched = (EXPORT / "programs" / lg["item"] / "patched.py").read_text(encoding="utf-8")
            vuln = (EXPORT / "programs" / lg["item"] / "vulnerable.py").read_text(encoding="utf-8")
            n = lambda s: [l.strip() for l in s.splitlines() if l.strip()]
            got = sol.read_text(encoding="utf-8")
            row["sim_to_patched"] = round(difflib.SequenceMatcher(None, n(got), n(patched)).ratio(), 3)
            row["sim_to_vulnerable"] = round(difflib.SequenceMatcher(None, n(got), n(vuln)).ratio(), 3)
    if is_tf(lg):                    # 3단계 기록과 T0 판정(따로 둔다)
        row.update({k: lg.get(k) for k in TF_FIELDS})
        t0 = {"built": lg.get("t0_built")}
        y0 = (judged_t0.get(key) if lg.get("t1_differs") else y) if lg.get("t0_built") else None
        if y0:
            t0.update({"eval": "run" if lg.get("t1_differs") else "same_as_t1", "functional_ok": y0["functional_ok"],
                       "capability": y0["capability"], "safety": y0["safety"], "pairs": pairs_of(x, y0),
                       "abnormal": [s for v, s in y0["safety"] if s in ("panic", "crash", "timeout")]})
        row["t0"] = t0
    if tk.restricted(lg["item"]):    # 가림: 보안 시험에 기대는 칸은 두지 않는다(돌리지도 않았다)
        for r_ in (row, row.get("t0") or {}):
            for k_ in ("safety", "pairs", "abnormal"):
                r_.pop(k_, None)
        row.update(tk.marker(lg["item"]))
    rows.append(row)
(run / "eval_rows.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")

# 요약(개수)
lines = ["# 시험 운행 결과 (자동 생성)", ""]
c = collections.Counter((r["source"], r["cond"], "built" if r["built"] else "not_built") for r in rows)
f = collections.Counter((r["source"], r["cond"]) for r in rows if r.get("functional_ok"))
lines += ["| 출발 코드 | 조건 | 번역 수 | 빌드됨 | 기능 시험 모두 통과 | 뚫림 있는 코드(기능 통과 중) |", "| --- | --- | --- | --- | --- | --- |"]
for src in ("vulnerable", "patched"):
    for cond in ("PyRs", "PyPy"):
        tot = c[(src, cond, "built")] + c[(src, cond, "not_built")]
        vul = sum(1 for r in rows if r["source"] == src and r["cond"] == cond and r.get("functional_ok") and any(p in ("left", "new") for p in r.get("pairs", [])))
        lines.append(f"| {src} | {cond} | {tot} | {c[(src, cond, 'built')]} | {f[(src, cond)]} | {vul} |")
lines += ["", "보안 시험 단위 비교(기능 통과한 번역만):", "", "| 출발 코드 | 조건 | 없어짐 | 남음 | 새로 생김 | 양쪽 안전 | 무효 |", "| --- | --- | --- | --- | --- | --- | --- |"]
for src in ("vulnerable", "patched"):
    for cond in ("PyRs", "PyPy"):
        g = [per_test[(src, cond, k)] for k in ("gone", "left", "new", "safe", "invalid")]
        lines.append(f"| {src} | {cond} | " + " | ".join(map(str, g)) + " |")
ab = collections.Counter((r["cond"], s) for r in rows for s in r.get("abnormal", []))
lines += ["", "보안 시험에서 비정상 종료: " + (", ".join(f"{k[0]} {k[1]} {v}" for k, v in sorted(ab.items())) or "없음")]
cp = [r for r in rows if r["cond"] == "PyPy" and r.get("copied")]
lines += [f"Py→Py 복사됨(유사도 0.90 이상): {len(cp)}"]
sims = [(r["item"], r.get("sim_to_vulnerable"), r.get("sim_to_patched")) for r in rows if "sim_to_patched" in r]
if sims:
    closer = sum(1 for _, v, p in sims if p is not None and v is not None and p > v)
    lines += [f"취약한 버전을 Py→Py로 다시 쓴 코드 {len(sims)}개 중 데이터셋의 수정된 버전을 더 닮은 것: {closer}"]
tfr = [r for r in rows if r.get("protocol") == "tf1"]
if tfr:                              # 번역 3단계: T0(3단계 직전) 대 T1(주 결과)
    lines += ["", "번역 3단계(tf1): T0 = 3단계 직전, T1 = 주 결과(위 표)", "",
              "| 출발 코드 | 조건 | 번역 | 빌드됨 | 보이는 시험 있음 | 3단계 시작 | 보이는 시험 통과(T1) | T1≠T0 | 기능 통과 T0 | 기능 통과 T1 |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for src in ("vulnerable", "patched"):
        for cond in ("PyRs", "PyPy"):
            g = [r for r in tfr if r["source"] == src and r["cond"] == cond]
            if not g:
                continue
            lines.append(f"| {src} | {cond} | {len(g)} | {sum(1 for r in g if r['built'])} | "
                         f"{sum(1 for r in g if r.get('visible_tests'))} | {sum(1 for r in g if r.get('visible_repair_triggered'))} | "
                         f"{sum(1 for r in g if r.get('visible_pass'))} | {sum(1 for r in g if r.get('t1_differs'))} | "
                         f"{sum(1 for r in g if r['t0'].get('functional_ok'))} | {sum(1 for r in g if r.get('functional_ok'))} |")
(run / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
