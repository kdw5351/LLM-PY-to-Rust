"""시험 운행(실험 A) 번역을 효과 판정으로 다시 센다(개발용 재채점).
효과 틀이 있는 항목만. 번역은 이미 만들어 둔 것을 그대로 쓴다(새로 만들지 않음).
usage: python -I effect_rescore.py <solutions_dir> <out.tsv> <item:cwe> [<item:cwe> ...]
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import judge  # noqa: E402

EXPORT = HERE.parent / "export"
EFF = EXPORT / "effect_tests"
IMAGE = "pyrs-seccodeplt-runner"


def main():
    sol = Path(sys.argv[1]).resolve()
    out_tsv = Path(sys.argv[2])
    items = [a.split(":")[0] for a in sys.argv[3:]]
    work = HERE.parent / "effect_work" / "rescore"
    work.mkdir(parents=True, exist_ok=True)
    jobs = []
    for it in items:
        for source in ("vulnerable", "patched"):
            for cond in ("PyRs", "PyPy"):
                d = f"{it}__{source}__{cond}"
                if not (sol / d).exists():
                    continue
                path = f"/s/{d}/app" if cond == "PyRs" else f"/s/{d}/main.py"
                jobs.append({"key": d, "item": it, "lang": "rust" if cond == "PyRs" else "python", "path": path})
    (work / "jobs.jsonl").write_text("".join(json.dumps(j) + "\n" for j in jobs), encoding="utf-8")
    r = subprocess.run(
        ["docker", "run", "--rm", "--init", "--network", "none", "--memory", "2g", "-e", "EFFECT_DIR=/e",
         "-v", f"{sol}:/s:ro", "-v", f"{EXPORT}:/x:ro", "-v", f"{EFF}:/e:ro", "-v", f"{HERE}:/pipeline:ro", "-v", f"{work}:/w",
         IMAGE, "python", "-I", "/pipeline/runner.py", "/w/jobs.jsonl", "/x/tests", "/w/out.jsonl", "10"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print("DOCKER FAIL", r.stdout[-1500:], r.stderr[-1500:]); sys.exit(1)
    lines = ["item\tsource\tcond\tfunctional_ok\tdataset\teffect\tcolumns"]
    print(f"{'item/source/cond':30} {'기능':5} {'데이터셋':12} {'효과':10} {'칸'}")
    for l in (work / "out.jsonl").read_text(encoding="utf-8").splitlines():
        if not l.strip():
            continue
        rec = json.loads(l)
        tests = json.load(open(EXPORT / "tests" / f"{rec['item']}.json", encoding="utf-8"))
        jr = judge.judge_record(rec, tests)
        it, source, cond = rec["key"].split("__")
        ds = ",".join(f"{v}:{s}" if s else v for v, s in jr["safety"])
        ef = ",".join(e[0] for e in jr.get("effect", []))
        cols = ",".join(jr.get("columns", []))
        lines.append(f"{it}\t{source}\t{cond}\t{jr['functional_ok']}\t{ds}\t{ef}\t{cols}")
        print(f"{rec['key']:30} {str(jr['functional_ok']):5} {ds:12} {ef:10} {cols}")
    out_tsv.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
