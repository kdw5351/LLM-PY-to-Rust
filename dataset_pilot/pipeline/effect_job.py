"""효과 시험 만들기와 승인(검증). 결과 맞추기를 막으려고 번역은 절대 보지 않는다.
원본 Python(export/programs_nc/<item>/{vulnerable,patched}.py)으로만 승인한다.

  make <item> <cwe>        -> effect_tests/<item>.effect.json 생성(보안 사례 수만큼)
  validate <item> <cwe>    -> 원본 취약/수정본에 3번씩 돌려 승인 규칙 확인
                              (취약: 3/3 표식 발생, 수정: 0/3)
  validate-all <cwe> <item...>
실행은 Docker(pyrs-seccodeplt-runner, 네트워크 없음) 안에서만 한다.
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import effect_templates as et  # noqa: E402

EXPORT = HERE.parent / "export"
NC = EXPORT / "programs_nc"
EFF = EXPORT / "effect_tests"
CWEVAL = HERE.parent / "export_cweval"
IMAGE = "pyrs-seccodeplt-runner"

# CWEval 항목(별도 export)은 cwe 번호 22·78 로 다룬다. 나머지는 SecCodePLT(export).
CWEVAL_CWES = {"22", "78"}


def _bench(cwe):
    return "cweval" if str(cwe) in CWEVAL_CWES else "seccodeplt"


def _roots(cwe):
    """(export 루트, 효과 시험 폴더) 반환. SecCodePLT 와 CWEval 을 가른다."""
    if _bench(cwe) == "cweval":
        return CWEVAL, CWEVAL / "effect_tests"
    return EXPORT, EXPORT / "effect_tests"


def n_safety(item):
    t = json.load(open(EXPORT / "tests" / f"{item}.json", encoding="utf-8"))
    return len(t["safety"])


def _str_arg_name(item):
    """보안 사례의 단일 문자열 인자 이름(94·95 처럼 인자가 하나인 종류)."""
    t = json.load(open(EXPORT / "tests" / f"{item}.json", encoding="utf-8"))
    a = t["safety"][0]["args"]
    names = [k for k, v in a.items() if isinstance(v, str)]
    return names[0] if len(names) == 1 else None


def make(item, cwe):
    build = et.BUILDERS[cwe]
    root, eff = _roots(cwe)
    eff.mkdir(parents=True, exist_ok=True)
    if _bench(cwe) == "cweval":
        meta = json.load(open(root / "programs" / item / "meta.json", encoding="utf-8"))
        cases = [c for c in [build(meta)] if c]
    elif cwe == "502":
        # 데이터셋 보안 사례의 인자를 그대로 쓰되 데이터 자리만 라이브러리별 카나리아로 바꾼다.
        t = json.load(open(root / "tests" / f"{item}.json", encoding="utf-8"))
        src = (root / "programs" / item / "vulnerable.py").read_text(encoding="utf-8")
        cases = []
        for case in t["safety"]:
            c = build(case["args"], src)
            if c:
                cases.append(c)
    else:  # 94·95: 단일 문자열 인자 틀
        kw = {}
        name = _str_arg_name(item)
        if name:
            kw["arg_name"] = name
        cases = [build(**kw) for _ in range(n_safety(item))]
    (eff / f"{item}.effect.json").write_text(
        json.dumps({"item": item, "cwe": cwe, "effect": cases}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"made {item}.effect.json  cases={len(cases)}  cwe={cwe}")


def _run_docker(jobs, workdir, root=EXPORT, eff=EFF):
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "jobs.jsonl").write_text("".join(json.dumps(j) + "\n" for j in jobs), encoding="utf-8")
    r = subprocess.run(
        ["docker", "run", "--rm", "--init", "--network", "none", "--memory", "2g",
         "-e", "EFFECT_DIR=/e",
         "-v", f"{root}:/x:ro", "-v", f"{eff}:/e:ro", "-v", f"{HERE}:/pipeline:ro", "-v", f"{workdir}:/w",
         IMAGE, "python", "-I", "/pipeline/runner.py", "/w/jobs.jsonl", "/x/tests", "/w/out.jsonl", "10"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print("DOCKER FAIL", r.stdout[-1500:], r.stderr[-1500:]); sys.exit(1)
    return [json.loads(l) for l in (workdir / "out.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def validate(item, cwe, reps=3):
    root, eff = _roots(cwe)
    if not (eff / f"{item}.effect.json").exists():
        make(item, cwe)
    cases = json.load(open(eff / f"{item}.effect.json", encoding="utf-8")).get("effect", [])
    if not cases:
        print(f"{item} cwe={cwe}: 건너뜀(맞는 카나리아 없음 -> 데이터셋 판정으로 한정)")
        return None
    jobs = []
    for source in ("vulnerable", "patched"):
        for i in range(reps):
            jobs.append({"key": f"{item}__{source}__r{i}", "item": item, "lang": "python",
                         "path": f"/x/programs_nc/{item}/{source}.py"})
    out = {r["key"]: r for r in _run_docker(jobs, HERE.parent / "effect_work" / item, root, eff)}
    ok = True
    for source, want in (("vulnerable", True), ("patched", False)):
        fired = []
        for i in range(reps):
            effs = out[f"{item}__{source}__r{i}"]["runs"].get("effect", [])
            fired.append(all(e.get("fired") for e in effs) and len(effs) > 0)
        good = all(f == want for f in fired)
        ok = ok and good
        print(f"  {item} {source}: fired per rep = {fired}  기대 {'발생' if want else '없음'}  -> {'OK' if good else 'FAIL'}")
    print(f"{item} cwe={cwe}: {'승인' if ok else '판정 불가'}")
    return ok


def items_of_cwe(cwe):
    import glob
    if _bench(cwe) == "cweval":
        pref = f"cwe_{int(cwe):03d}_"
        return sorted(Path(p).name for p in glob.glob(str(CWEVAL / "programs" / (pref + "*")))
                      if (Path(p) / "meta.json").exists())
    out = []
    for f in glob.glob(str(EXPORT / "programs" / "*" / "meta.json")):
        if str(json.load(open(f, encoding="utf-8"))["cwe"]) == cwe:
            out.append(Path(f).parent.name)
    return sorted(out)


def validate_class(cwe):
    """그 CWE 의 항목 전부에 효과 틀을 만들고 원본 Python 으로 승인한다. 보고서 tsv 를 쓴다.
    결과는 approved(승인)·skipped(맞는 카나리아 없음)·failed(승인 규칙 불통과)로 나눈다."""
    items = items_of_cwe(cwe)
    root, eff = _roots(cwe)
    rep = eff / f"_validate_{cwe}.tsv"
    eff.mkdir(parents=True, exist_ok=True)
    rows = ["item\tresult"]
    nok = nskip = 0
    for i, it in enumerate(items, 1):
        try:
            ok = validate(it, cwe)
        except Exception as e:
            ok = False
            print(f"  {it}: ERROR {e}")
        status = "approved" if ok else ("skipped" if ok is None else "failed")
        nok += (ok is True)
        nskip += (ok is None)
        rows.append(f"{it}\t{status}")
        print(f"[{i}/{len(items)}] {it} -> {status}  (누적 승인 {nok})")
    rep.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"CWE {cwe} 승인 수: {nok} / {len(items)}  (건너뜀 {nskip})  보고서 {rep}")


def main():
    cmd = sys.argv[1]
    if cmd == "make":
        make(sys.argv[2], sys.argv[3])
    elif cmd == "validate":
        validate(sys.argv[2], sys.argv[3])
    elif cmd == "validate-all":
        cwe = sys.argv[2]
        res = {it: validate(it, cwe) for it in sys.argv[3:]}
        print("승인 수:", sum(res.values()), "/", len(res), {k: ("승인" if v else "불가") for k, v in res.items()})
    elif cmd == "validate-class":
        validate_class(sys.argv[2])


if __name__ == "__main__":
    main()
