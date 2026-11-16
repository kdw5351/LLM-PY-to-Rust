#!/usr/bin/env python3
"""구조 지표와 코드 신호 σ_k (제안서 rev 723, 6절 구조 지표, 7절 점검 규칙).

σ 대응: unwrap/expect/panic/직접 인덱싱 → panic(248), 검사 없는 산술·as 변환 → intover(190),
unsafe → 따로(unsafe_blocks), Python 코드 실행형 읽기 함수 → deser(502)/inject.
값이 외부 입력에서 왔는지는 가리지 않는다(제안서: clippy 는 출처를 추적하지 못함).
Rust 의 코드 실행형 읽기 함수: std::process::Command, libloading/dlopen, pyo3 (+ Cargo.toml 새 의존성은 harden.accept).

Python 위험한 파일 읽기 지표(6절 목록, torch 2.6 이상 기준):
  pickle.load/loads, joblib.load, dill.load, marshal.load,
  weights_only=False 를 명시한 torch.load (torch.load 자체는 2.6부터 기본이 데이터 전용이므로 세지 않음),
  안전하지 않은 Loader 를 쓴 yaml.load (yaml.load(x, Loader=yaml.Loader|UnsafeLoader|FullLoader), yaml.unsafe_load, yaml.full_load),
  allow_pickle=True 를 준 numpy.load, eval/exec, shell=True/os.system/os.popen.
Rust 코드 신호: cargo clippy restriction lint(unwrap_used, expect_used, indexing_slicing, panic,
  arithmetic_side_effects, cast_* …)를 결함 종류 대응표(classes.CLIPPY_LINT_TO_CLASS)로 바꿔 센다.
  clippy 가 없으면 정규식 대체 집계로 떨어지고 sigma_source="regex_fallback" 으로 기록한다.

"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

from harness.classes import (CLIPPY_LINTS, CLIPPY_LINT_TO_CLASS, PY_SIGNAL_TO_CLASS,
                             RS_REGEX_TO_CLASS, SIGMA_CLASSES, all_classes)

ROOT = Path(__file__).resolve().parent.parent

PY_RISKY = {
    "pickle.load": re.compile(r"\bc?pickle\.loads?\s*\(|\bpickle\.Unpickler\s*\("),
    "joblib.load": re.compile(r"\bjoblib\.load\s*\("),
    "dill.load": re.compile(r"\bdill\.loads?\s*\("),
    "marshal.load": re.compile(r"\bmarshal\.loads?\s*\("),
    # torch.load(..., weights_only=False) 명시만 위험(2.6+ 기본은 True)
    "torch.load_weights_only_false": re.compile(r"\btorch\.load\s*\([^)]*weights_only\s*=\s*False", re.DOTALL),
    # yaml.load 에 안전하지 않은 Loader, 또는 unsafe_load/full_load
    "yaml.load_unsafe": re.compile(
        r"\byaml\.load\s*\([^)]*Loader\s*=\s*(yaml\.)?(Loader|UnsafeLoader|FullLoader|CLoader|CFullLoader|CUnsafeLoader)\b"
        r"|\byaml\.(unsafe_load|full_load)\s*\(", re.DOTALL),
    "numpy_allow_pickle": re.compile(r"\b(np|numpy)\.load\s*\([^)]*allow_pickle\s*=\s*True", re.DOTALL),
    "eval_exec": re.compile(r"(?<![\w.])(eval|exec)\s*\("),
    "shell": re.compile(r"(shell\s*=\s*True|\bos\.system\s*\(|\bos\.popen\s*\()"),
}
PY_SAFE = {
    "weights_only_true": re.compile(r"weights_only\s*=\s*True"),
    "yaml_safe": re.compile(r"\byaml\.safe_load\s*\(|SafeLoader"),
    "restricted_unpickler": re.compile(r"class\s+\w+\s*\(\s*(pickle\.)?Unpickler\s*\)|find_class"),
    "json_load": re.compile(r"\bjson\.loads?\s*\("),
}
# restricted unpickler(find_class 를 재정의)를 쓰면 pickle.load/Unpickler 호출은 데이터 전용으로 본다.
RS_PAT = {
    "unwrap": re.compile(r"\.unwrap\s*\("),
    "expect": re.compile(r"\.expect\s*\("),
    "panic": re.compile(r"\b(panic|unreachable|todo|unimplemented)!\s*\("),
    "index_direct": re.compile(r"\w\[[^\]\n]*\]"),
    "as_int_cast": re.compile(r"\bas\s+(u|i)(8|16|32|64|128|size)\b"),
    "unchecked_arith": re.compile(r"\b(len|size|count|offset|begin|end|n)\w*\s*[-+*]\s*\w"),
    "unsafe": re.compile(r"\bunsafe\b"),
}
# Rust 의 "파일 안 코드를 실행하는 읽기 함수"(제안서 7절, 사전 등록 목록). classes.RS_CODELOAD 와 같은 키.
RS_CODELOAD_PAT = {
    "process_command": re.compile(r"\b(std::)?process::Command\b|\bCommand::new\s*\("),
    "libloading": re.compile(r"\blibloading\b|\bdlopen\b|\bLibrary::new\s*\(|\bload_library\b"),
    "pyo3": re.compile(r"\bpyo3\b|\bPython::with_gil\b|\bPyModule::"),
}


def cargo_deps(sol: Path) -> list[str]:
    """Cargo.toml [dependencies] 의 크레이트 이름(정렬). 받아들이기 조건 (4) '새 의존성 추가' 판정용."""
    p = sol / "Cargo.toml"
    if not p.exists():
        return []
    toml = p.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"\[dependencies\](.*?)(\n\[|\Z)", toml, re.DOTALL)
    if not m:
        return []
    return sorted({l.split("=")[0].strip().strip('"') for l in m.group(1).splitlines()
                   if "=" in l and not l.strip().startswith("#")})


def split_lines(text: str) -> list[str]:
    """"\n"(과 "\r\n")에서만 줄을 나눈다(generate.split_lines 와 같음; 줄 번호·줄 수가 편집기·컴파일러와 맞게)."""
    return text.replace("\r\n", "\n").split("\n")


def loc_of(sol: Path, lang: str) -> int:
    """비어 있지 않은 소스 줄 수(1천 줄당 지표의 분모)."""
    pats = {"python": "*.py", "rust": "*.rs", "c": "*.c"}
    n = 0
    for p in sol.rglob(pats.get(lang, "*")):
        if any(part in ("target", "_venv", "__pycache__") for part in p.parts):
            continue
        n += sum(1 for l in split_lines(p.read_text(encoding="utf-8", errors="replace")) if l.strip())
    return n


def _lines_matching(text: str, pat: re.Pattern) -> list[int]:
    out = []
    for i, line in enumerate(split_lines(text), 1):
        if pat.search(line):
            out.append(i)
    return out


def scan_python(sol: Path) -> dict:
    files = [p for p in sol.rglob("*.py") if "_venv" not in p.parts]
    risky = Counter()
    locs = []
    safe = Counter()
    for p in files:
        txt = p.read_text(encoding="utf-8", errors="replace")
        for k, pat in PY_SAFE.items():
            safe[k] += len(pat.findall(txt))
        for k, pat in PY_RISKY.items():
            n = len(pat.findall(txt))
            if n:
                risky[k] += n
                for ln in _lines_matching(txt, pat):
                    locs.append({"file": str(p.relative_to(sol)), "line": ln, "signal": k,
                                 "class": PY_SIGNAL_TO_CLASS[k]})
    # restricted unpickler 를 정의했으면 pickle.load 는 데이터 전용으로 간주
    if risky["pickle.load"] and safe["restricted_unpickler"]:
        risky["pickle.load"] = 0
        locs = [l for l in locs if l["signal"] != "pickle.load"]
    code_exec = any(risky[k] for k in PY_RISKY)
    by_class = Counter(l["class"] for l in locs)
    return {"risky": dict(risky), "safe": dict(safe), "code_executing_loader": code_exec,
            "locations": locs, "by_class": {c: by_class.get(c, 0) for c in SIGMA_CLASSES}}


def clippy_available() -> bool:
    try:
        r = subprocess.run(["cargo", "clippy", "--version"], capture_output=True, text=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def scan_rust_clippy(sol: Path, cfg: dict) -> dict | None:
    """cargo clippy --message-format=json 으로 lint 별 위치를 모은다. 실패하면 None."""
    lint_args = []
    for l in CLIPPY_LINTS:
        lint_args += ["-W", l]
    env = dict(os.environ)
    env["CARGO_TERM_COLOR"] = "never"
    try:
        r = subprocess.run(["cargo", "clippy", "--release", "--message-format=json", "--", *lint_args],
                           cwd=sol, capture_output=True, text=True, env=env,
                           timeout=cfg["sandbox"]["build_timeout_s"])
    except Exception:
        return None
    locs = []
    counts = Counter()
    for line in r.stdout.splitlines():
        try:
            msg = json.loads(line)
        except Exception:
            continue
        if msg.get("reason") != "compiler-message":
            continue
        m = msg.get("message", {})
        code = (m.get("code") or {}).get("code")
        if code not in CLIPPY_LINT_TO_CLASS:
            continue
        spans = [s for s in m.get("spans", []) if s.get("is_primary")] or m.get("spans", [])
        for s in spans[:1]:
            if "target" in s.get("file_name", "") or ".cargo" in s.get("file_name", ""):
                continue
            locs.append({"file": s.get("file_name"), "line": s.get("line_start"), "signal": code,
                         "class": CLIPPY_LINT_TO_CLASS[code]})
            counts[code] += 1
    if r.returncode != 0 and not locs:
        return None
    by_class = Counter(l["class"] for l in locs)
    return {"lints": dict(counts), "locations": locs, "by_class": {c: by_class.get(c, 0) for c in SIGMA_CLASSES},
            "sigma_source": "clippy"}


def scan_rust_regex(sol: Path) -> dict:
    files = [p for p in sol.rglob("*.rs") if "target" not in p.parts]
    counts = Counter()
    locs = []
    for p in files:
        txt = p.read_text(encoding="utf-8", errors="replace")
        for k, pat in RS_PAT.items():
            n = len(pat.findall(txt))
            counts[k] += n
            if k in RS_REGEX_TO_CLASS and n:
                for ln in _lines_matching(txt, pat):
                    locs.append({"file": str(p.relative_to(sol)), "line": ln, "signal": k,
                                 "class": RS_REGEX_TO_CLASS[k]})
    by_class = Counter(l["class"] for l in locs)
    return {"patterns": dict(counts), "locations": locs, "by_class": {c: by_class.get(c, 0) for c in SIGMA_CLASSES},
            "sigma_source": "regex_fallback"}


def scan_rust(sol: Path, cfg: dict, prefer_clippy: bool = True) -> dict:
    regex = scan_rust_regex(sol)
    out = None
    if prefer_clippy and clippy_available():
        out = scan_rust_clippy(sol, cfg)
    if out is None:
        out = regex
    out["unsafe_blocks"] = regex["patterns"].get("unsafe", 0)
    out["regex_patterns"] = regex["patterns"]
    # 코드 실행형 읽기 함수(Rust): 패턴별 개수
    codeload = {}
    for p in sol.rglob("*.rs"):
        if "target" in p.parts:
            continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        for k, pat in RS_CODELOAD_PAT.items():
            codeload[k] = codeload.get(k, 0) + len(pat.findall(txt))
    out["codeload"] = codeload
    out["code_executing_loader"] = any(codeload.values())
    out["deps"] = cargo_deps(sol)
    return out


def sigma(sol: Path, lang: str, cfg: dict) -> dict:
    """코드 신호 σ_k: class 별 위험 지점 수 + 위치 목록 + 코드 실행형 로더 여부."""
    if lang == "python":
        s = scan_python(sol)
        return {"lang": "python", "by_class": s["by_class"], "locations": s["locations"],
                "code_executing_loader": s["code_executing_loader"], "risky": s["risky"],
                "sigma_source": "regex", "loc": loc_of(sol, "python")}
    if lang == "rust":
        s = scan_rust(sol, cfg, prefer_clippy=cfg.get("harden", {}).get("sigma_source", "clippy") == "clippy")
        return {"lang": "rust", "by_class": s["by_class"], "locations": s["locations"],
                "code_executing_loader": s["code_executing_loader"], "codeload": s["codeload"],
                "deps": s["deps"], "unsafe_blocks": s["unsafe_blocks"],
                "lints": s.get("lints", s.get("patterns")), "sigma_source": s["sigma_source"],
                "loc": loc_of(sol, "rust")}
    return {"lang": lang, "by_class": {c: 0 for c in SIGMA_CLASSES}, "locations": [],
            "code_executing_loader": False, "sigma_source": "none", "loc": loc_of(sol, lang)}


def main(argv=None):
    from harness import runner
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--task", default=None, help="특정 과제만")
    ap.add_argument("--no-clippy", action="store_true")
    args = ap.parse_args(argv)
    cfg = runner.load_config()
    if args.no_clippy:
        cfg.setdefault("harden", {})["sigma_source"] = "regex"
    run = ROOT / args.run if not Path(args.run).is_absolute() else Path(args.run)
    sols = sorted((run / "solutions").glob("*__*__*__s*"))
    rows = []
    py_cel = Counter(); py_n = Counter()
    rs_sum = {}
    for sol in sols:
        if not sol.is_dir():
            continue
        try:
            _, task, cond, s = sol.name.split("__")
        except ValueError:
            continue
        if args.task and task != args.task:
            continue
        lang = "rust" if (sol / "Cargo.toml").exists() else ("python" if (sol / "main.py").exists() else "c")
        sc = sigma(sol, lang, cfg)
        rec = {"task": task, "cond": cond, "sample": s, "lang": lang, "by_class": sc["by_class"],
               "sigma_source": sc["sigma_source"], "n_locations": len(sc["locations"]), "loc": sc.get("loc"),
               "per_kloc": {k: round(v * 1000 / sc["loc"], 2) for k, v in sc["by_class"].items() if sc.get("loc")}}
        if lang == "python":
            py_n[(task, cond)] += 1
            if sc["code_executing_loader"]:
                py_cel[(task, cond)] += 1
            rec["code_exec_loader"] = sc["code_executing_loader"]
            rec["py_risky"] = {k: v for k, v in sc["risky"].items() if v}
        elif lang == "rust":
            key = (task, cond)
            rs_sum.setdefault(key, Counter())
            for k, v in sc["by_class"].items():
                rs_sum[key][k] += v
            rec["unsafe_blocks"] = sc["unsafe_blocks"]
            rec["codeload"] = {k: v for k, v in sc.get("codeload", {}).items() if v}
            rec["lints"] = {k: v for k, v in (sc.get("lints") or {}).items() if v}
        rows.append(rec)
    (run / "structural.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    print("== Python: 코드 실행형 로더를 고른 비율 (조건별) ==")
    for key in sorted(py_n):
        t, c = key
        print(f"  {t[:3]} {c:9} {py_cel[key]}/{py_n[key]}")
    print("\n== Rust: 코드 신호 σ_k 합계 (조건별, class) ==")
    for key in sorted(rs_sum):
        t, c = key
        print(f"  {t[:3]} {c:9} " + ", ".join(f"{k}={v}" for k, v in rs_sum[key].items() if v))
    print(f"\n저장: {run/'structural.json'}")


if __name__ == "__main__":
    main()
