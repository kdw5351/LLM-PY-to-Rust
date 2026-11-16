#!/usr/bin/env python3
"""생성 드라이버 (제안서 5절 "생성 절차").

조건: Py, Rs, (C), PyPy(Py→Py), PyRs(Py→Rs), T-secure(보안 지시 옮기기),
      H-rules / H-checklist / H-both(=Py→Rs+강화) / H-all (7절, harness/harden.py 가 처리).
구 이름(A-Py, A-Rs, B-PyPy, B-PyRs, A-C)도 받는다.

- 프롬프트는 prompts/ 파일에서 읽고, 모델에 보낸 최종 문자열과 응답을 results/<run>/_prompts/ 에 그대로 남긴다.
- 보안 지시는 넣지 않는다(T-secure 제외). 명세는 과제마다 tasks/<T>/spec.md 하나이며 SHA-256 을 _meta.json 에 적는다.
- Py→Py, Py→Rs 는 대상 언어만 다른 같은 지시문(prompts/user_translate.md)을 쓰고 같은 명세를 받는다.
- Py→Py 복사 차단: 원본 main.py 와 줄 단위 유사도(공백·빈 줄 정규화, difflib ratio) ≥ copy_threshold 면
  최대 copy_max_regen 번 다시 만들고, 그래도 넘으면 copied=true.
- 실행되게 만들기: 빌드(컴파일/import) 오류 → 수정, 빌드되면 tests/example.json 의 예시 입력 실행 →
  비정상 종료·오류 메시지만 돌려주고 수정. 두 종류 합쳐 최대 max_fix_rounds 번.
- 모든 호출의 토큰 수를 _meta.json 과 usage.jsonl 에 적는다.

모델 출력 계약: 파일마다 `FILE: <상대경로>` 줄 + 펜스 코드 블록. 단일 코드 블록만 오면 언어별 기본 파일로 저장.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness import models, runner, sandbox  # noqa: E402

PROMPTS = ROOT / "prompts"

CONDITIONS = {
    "Py":       {"lang": "python", "kind": "gen"},
    "Rs":       {"lang": "rust",   "kind": "gen"},
    "C":        {"lang": "c",      "kind": "gen"},
    "PyPy":     {"lang": "python", "kind": "translate", "source": "Py"},
    "PyRs":     {"lang": "rust",   "kind": "translate", "source": "Py"},
    "T-secure": {"lang": "rust",   "kind": "translate_secure", "source": "Py"},
}
HARDEN_CONDITIONS = ["H-rules", "H-checklist", "H-both", "H-all"]
ALIASES = {"A-Py": "Py", "A-Rs": "Rs", "A-C": "C", "B-PyPy": "PyPy", "B-PyRs": "PyRs",
           "Py→Py": "PyPy", "Py->Py": "PyPy", "Py→Rs": "PyRs", "Py->Rs": "PyRs",
           "Py→Rs+강화": "H-both", "R-full": "H-both"}
LANG_NAME = {"python": "Python", "rust": "Rust", "c": "C"}

FILE_RE = re.compile(r"FILE:\s*(?P<path>[^\n`]+)\n+```[a-zA-Z0-9_+-]*\n(?P<body>.*?)```", re.DOTALL)
FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)


def norm_cond(c: str) -> str:
    return ALIASES.get(c, c)


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def prompt(name: str, **fields) -> str:
    """prompts/<name>.md 를 읽어 {placeholder} 를 채운다. str.format 은 코드의 중괄호 때문에 쓰지 않는다."""
    txt = read(PROMPTS / f"{name}.md")
    for k, v in fields.items():
        txt = txt.replace("{" + k + "}", str(v))
    return txt.rstrip("\n")


FILE_LINE_RE = re.compile(r"^\s*(?:[*#`_]+\s*)?FILE:\s*`?(?P<path>[^\s`*]+)`?")


def _extract_body(region: list[str]) -> str:
    """한 FILE 블록의 본문을 뽑는다. 펜스가 있으면 **펜스 안만** 쓰고 바깥 텍스트(설명문·뒤따르는
    새 펜스 블록)는 버린다. 여는 펜스가 ```lang 든 맨 ``` 든 똑같이 다룬다. 비어 있는 펜스는 건너뛰고
    내용이 있는 첫 펜스 블록을 쓴다. 펜스가 전혀 없으면 앞뒤 빈 줄만 떼고 그대로 쓴다."""
    n = len(region)
    k = 0
    saw_fence = False
    while k < n:
        if region[k].strip().startswith("```"):
            saw_fence = True
            start = k + 1
            e = start
            while e < n and not region[e].strip().startswith("```"):
                e += 1
            body = region[start:e]
            if any(l.strip() for l in body):
                return "\n".join(body) + "\n"
            k = e + 1  # 내용 없는 펜스(모델이 FILE 줄을 펜스로 감싼 경우 등) → 다음 펜스를 본다
        else:
            k += 1
    # 펜스는 있었으나 전부 비어 있으면 **빈 본문**이다(예: 의존성 없을 때 모델이 빈 ```…``` 로 낸
    # requirements.txt). 여기서 raw 폴백으로 내려가면 ``` 줄 자체가 파일 내용이 되어 pip 가 거부한다.
    if saw_fence:
        return ""
    body = list(region)
    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()
    return "\n".join(body) + "\n" if body else ""


def split_lines(text: str) -> list[str]:
    """"\n"(과 "\r\n")에서만 줄을 나눈다. str.splitlines() 는 U+2028·U+2029·\x0b·\x0c·\x1c~\x1e·\x85 에서도
    나누므로, 문자열 리터럴 안에 그 문자가 그대로 든 코드가 잘린다(2026-11-11 수정)."""
    return text.replace("\r\n", "\n").split("\n")


def parse_files(text: str, lang: str) -> dict[str, str]:
    """`FILE: <path>` 줄마다 그 줄부터 다음 FILE 줄(또는 끝)까지를 한 블록으로 보고, 블록 안의
    펜스 코드만 파일로 읽는다. 펜스 바깥 설명문이나 뒤에 붙은 새 펜스 블록은 버린다(그렇지 않으면
    curl 예시 같은 설명이 main.py 에 섞여 들어간다). 같은 경로가 여러 번 나오면 마지막 것을 쓴다.
    FILE 줄이 하나도 없으면 첫 펜스 블록(또는 전체)을 언어별 기본 파일로 저장한다."""
    lines = split_lines(text)
    n = len(lines)
    files: dict[str, str] = {}
    i = 0
    while i < n:
        m = FILE_LINE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        path = m.group("path")
        r = i + 1
        while r < n and not FILE_LINE_RE.match(lines[r]):
            r += 1
        body = _extract_body(lines[i + 1:r])
        if body.strip() or path not in files:
            files[path] = body
        i = r
    files = {p: b for p, b in files.items() if b.strip()}
    if files:
        return files
    m = FENCE_RE.search(text)
    body = m.group(1) if m else text
    return {{"python": "main.py", "c": "main.c"}.get(lang, "src/main.rs"): body}


def files_block(files: dict[str, str]) -> str:
    return "\n\n".join(f"FILE: {k}\n```\n{v}\n```" for k, v in files.items())


def write_solution(sol: Path, files: dict[str, str], keep: tuple[str, ...] = ("_venv", "target")):
    """소스 파일을 다시 쓴다. 빌드 캐시(target/, _venv/)는 남긴다."""
    sol.mkdir(parents=True, exist_ok=True)
    for p in list(sol.iterdir()):
        if p.name in keep or p.name.startswith("_"):
            continue
        shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink()
    for rel, body in files.items():
        p = sol / rel
        if ".." in Path(rel).parts or Path(rel).is_absolute():
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


# ------------------------------------------------------------------ similarity
def _norm_lines(src: str) -> list[str]:
    out = []
    for line in split_lines(src):
        s = " ".join(line.split())
        if s:
            out.append(s)
    return out


def line_similarity(a: str, b: str) -> float:
    """줄 단위 유사도: 공백 정규화·빈 줄 제거 후 difflib.SequenceMatcher ratio."""
    return round(difflib.SequenceMatcher(None, _norm_lines(a), _norm_lines(b), autojunk=False).ratio(), 4)


def main_source(files: dict[str, str], lang: str) -> str:
    if lang == "python":
        return files.get("main.py", "")
    if lang == "rust":
        return "\n".join(v for k, v in sorted(files.items()) if k.endswith(".rs"))
    return files.get("main.c", "")


def deps_of(files: dict[str, str], lang: str) -> list[str]:
    """처음 생성한 코드의 의존 라이브러리 목록(존재하지 않는 패키지 이름 집계용)."""
    if lang == "python":
        return [l.strip() for l in files.get("requirements.txt", "").splitlines() if l.strip() and not l.startswith("#")]
    if lang == "rust":
        toml = files.get("Cargo.toml", "")
        m = re.search(r"\[dependencies\](.*?)(\n\[|\Z)", toml, re.DOTALL)
        if not m:
            return []
        return [l.split("=")[0].strip() for l in m.group(1).splitlines() if "=" in l]
    return []


# ---------------------------------------------------------------- prompt build
def source_qualified(run_dir: Path, src_name: str) -> bool:
    """원본 해답이 자격(빌드 + T^acc 전부 통과)을 갖췄는가. 결과 JSON 의 qualified 로 판단."""
    p = run_dir / f"{src_name}.json"
    if not p.exists():
        return False
    return bool(json.loads(p.read_text(encoding="utf-8")).get("qualified", False))


def build_prompts(cond: str, task_dir: Path, lang: str, source_files: dict | None,
                  checklist: str | None = None) -> tuple[str, str, dict]:
    spec_path = (task_dir / "spec.md").resolve()
    conv_path = ROOT / "tasks" / "CONVENTIONS.md"
    spec, conv = read(spec_path), read(conv_path)
    contract = prompt("contract")
    info = {"spec_file": str(spec_path.relative_to(ROOT)).replace("\\", "/"), "spec_sha256": sha256_file(spec_path),
            "conventions_sha256": sha256_file(conv_path)}
    kind = CONDITIONS[cond]["kind"]
    if kind == "gen":
        info["prompt_files"] = ["system_generate.md", "user_generate.md", "contract.md"]
        return (prompt("system_generate", lang=LANG_NAME[lang]),
                prompt("user_generate", spec=spec, conventions=conv, contract=contract), info)
    src = files_block(source_files or {})
    if kind == "translate":
        info["prompt_files"] = ["system_translate.md", "user_translate.md", "contract.md"]
        return (prompt("system_translate", lang=LANG_NAME[lang]),
                prompt("user_translate", lang=LANG_NAME[lang], source_files=src, spec=spec,
                       conventions=conv, contract=contract), info)
    if kind == "translate_secure":
        # 보안 지시 옮기기: 공통 규칙 전체 + 같은 명세에서 뽑은 검사 목록 𝒞_t 를 옮길 때 프롬프트에 넣는다.
        from harness.harden import rules_text
        info["prompt_files"] = ["system_translate.md", "user_translate_secure.md", "rules.md", "pi_ext.md", "contract.md"]
        return (prompt("system_translate", lang=LANG_NAME[lang]),
                prompt("user_translate_secure", lang=LANG_NAME[lang], source_files=src, spec=spec,
                       conventions=conv, contract=contract, rules=rules_text(None),
                       checklist=checklist or "(checklist unavailable)"), info)
    raise ValueError(cond)


# ----------------------------------------------------------------- generation
class Gen:
    """한 run 의 생성 상태(사용량 로그, 프롬프트 저장 위치)."""

    def __init__(self, cfg: dict, run_dir: Path):
        self.cfg = cfg
        self.run_dir = run_dir
        self.usage = models.UsageLog(run_dir)
        (run_dir / "_prompts").mkdir(parents=True, exist_ok=True)

    def call(self, model_cfg: dict, system: str, user: str, seed: int | None, tag: str, ctx: dict,
             temperature: float | None = None) -> tuple[str, dict]:
        """temperature 를 주지 않으면 [run] temperature(생성·옮기기). 강화·검사 목록 추출은 harden.py 가 따로 넘긴다."""
        temp = self.cfg["run"]["temperature"] if temperature is None else temperature
        comp = models.call_model(model_cfg, system, user, temp, seed=seed)
        row = self.usage.record(comp, model=model_cfg["name"], purpose=tag, temperature=temp, **ctx)
        p = self.run_dir / "_prompts" / f"{ctx.get('name', 'x')}__{tag}.md"
        p.write_text(f"# SYSTEM\n\n{system}\n\n# USER\n\n{user}\n\n# RESPONSE\n\n{comp.text}\n", encoding="utf-8")
        return comp.text, row


def fix_loop(gen: Gen, model_cfg: dict, system: str, files: dict, sol: Path, lang: str, task: str,
             seed: int | None, name: str, ctx: dict, max_rounds: int, scratch: Path,
             example_step: bool = True) -> tuple[bool, str, list[dict], dict | None, dict]:
    """빌드 → (예시 입력) → 수정 을 최대 max_rounds 번. (built, build_log, history, example_result, timing).
    timing 은 빌드·예시실행·수정호출의 벽시계와 수정 호출 토큰을 나눠 담는다(제안서 계측)."""
    cfg = gen.cfg
    history: list[dict] = []
    contract = prompt("contract")
    rounds = 0
    build_s = example_s = fix_calls_s = 0.0
    tok0 = dict(gen.usage.totals)
    _t = time.time(); ok, log = sandbox.build(sol, lang, cfg); build_s += time.time() - _t
    ex = None
    while True:
        if ok and example_step:
            _t = time.time(); ex = runner.run_example(task, sol, lang, cfg, scratch); example_s += time.time() - _t
        problem = None
        if not ok:
            problem = ("build", prompt("fix_build", kind="compile" if lang != "python" else "import",
                                       error=log[-4000:], files=files_block(files), contract=contract))
        elif ex and ex["abnormal"]:
            problem = ("example", prompt("fix_example", exit_code=ex["exit_code"],
                                         command=ex.get("command") or "(not recorded)",
                                         stderr=ex["stderr"][-3000:], stdout=ex.get("stdout", "")[-1500:],
                                         files=files_block(files), contract=contract))
        if problem is None or rounds >= max_rounds:
            break
        rounds += 1
        kind, user = problem
        _t = time.time()
        text, _ = gen.call(model_cfg, system, user, seed, f"fix{rounds}_{kind}", ctx)
        fix_calls_s += time.time() - _t
        files = parse_files(text, lang)
        write_solution(sol, files)
        _t = time.time(); ok, log = sandbox.build(sol, lang, cfg); build_s += time.time() - _t
        history.append({"round": rounds, "kind": kind, "built": ok})
        ex = None
    tok1 = gen.usage.totals
    timing = {"fix_calls_s": round(fix_calls_s, 1), "build_s": round(build_s, 1), "example_s": round(example_s, 1),
              "fix_tokens": {"prompt": tok1["prompt_tokens"] - tok0["prompt_tokens"],
                             "completion": tok1["completion_tokens"] - tok0["completion_tokens"],
                             "calls": tok1["calls"] - tok0["calls"]}}
    return ok, log, history, ex, timing


def generate_one(gen: Gen, model_cfg: dict, cond: str, task: str, sample: int, src_cache: dict,
                 measure: bool = True) -> dict:
    cfg, run_dir = gen.cfg, gen.run_dir
    task_dir = ROOT / "tasks" / task
    lang = CONDITIONS[cond]["lang"]
    name = f"{model_cfg['name']}__{task}__{cond}__s{sample}"
    sol = run_dir / "solutions" / name
    ctx = {"name": name, "task": task, "cond": cond, "sample": sample}
    source_cond = CONDITIONS[cond].get("source")
    source_files = None
    if source_cond:
        src_name = f"{model_cfg['name']}__{task}__{source_cond}__s{sample}"
        source_files = src_cache.get((model_cfg["name"], task, sample, source_cond)) or load_solution_files(
            run_dir / "solutions" / src_name)
        if not source_files:
            return {"skipped": f"no built {source_cond} source to translate"}
        if not source_qualified(run_dir, src_name):
            # 제안서 5절 3: 옮기기 조건에는 빌드되고 T^acc 를 모두 통과한 Py 코드만 쓴다. 그 밖에는 AI 호출 없음.
            return {"skipped": f"{source_cond} source not qualified (T^acc not all passed); no model call"}
    checklist = None
    if CONDITIONS[cond]["kind"] == "translate_secure":
        from harness.harden import checklist_for
        checklist, _ = checklist_for(gen, model_cfg, task)
    system, user, info = build_prompts(cond, task_dir, lang, source_files, checklist)
    seed_base = cfg["run"]["seed_base"]
    seed = seed_base + sample
    t0 = time.time()
    tokens0 = dict(gen.usage.totals)

    # 1) 생성 (+ Py→Py 복사 차단)
    gen_t0 = time.time()
    gen_tok0 = dict(gen.usage.totals)
    attempt = 0
    sim = None
    copied = False
    threshold = cfg["run"]["copy_threshold"]
    max_regen = cfg["run"]["copy_max_regen"]
    while True:
        text, row = gen.call(model_cfg, system, user, seed + 100 * attempt, f"gen_a{attempt}", ctx)
        seed_supported = row.get("seed_supported")
        files = parse_files(text, lang)
        if source_files is not None:
            sim = line_similarity(main_source(source_files, "python"), main_source(files, lang))
        if cond == "PyPy" and sim is not None and sim >= threshold and attempt < max_regen:
            attempt += 1
            continue
        copied = bool(cond == "PyPy" and sim is not None and sim >= threshold)
        break
    gen_tok1 = gen.usage.totals
    gen_phase = {"wall_s": round(time.time() - gen_t0, 1),
                 "prompt_tokens": gen_tok1["prompt_tokens"] - gen_tok0["prompt_tokens"],
                 "completion_tokens": gen_tok1["completion_tokens"] - gen_tok0["completion_tokens"],
                 "calls": gen_tok1["calls"] - gen_tok0["calls"]}
    first_files = dict(files)
    write_solution(sol, files)

    # 2) 실행되게 만들기
    scratch = run_dir / "_scratch" / name
    scratch.mkdir(parents=True, exist_ok=True)
    ok, log, history, ex, fix_timing = fix_loop(gen, model_cfg, system, files, sol, lang, task, seed, name, ctx,
                                                cfg["run"]["max_fix_rounds"], scratch, cfg["run"].get("example_step", True))
    if ok and source_cond is None:
        src_cache[(model_cfg["name"], task, sample, cond)] = load_solution_files(sol)
    tokens1 = gen.usage.totals
    meta = {"cond": cond, "task": task, "sample": sample, "lang": lang, "model": model_cfg["name"],
            "model_id": model_cfg["model"], "temperature": cfg["run"]["temperature"],
            "seed": seed, "seed_supported": seed_supported,
            "built": ok, "fix_rounds": len(history), "fix_history": history,
            "example": ex if ex else ({"abnormal": False} if ok else None),
            "similarity_to_source": sim, "copy_regen": attempt, "copied": copied,
            "copy_threshold": threshold if cond == "PyPy" else None,
            "n_files": len(files), "deps_first_gen": deps_of(first_files, lang),
            "tokens": {"prompt": tokens1["prompt_tokens"] - tokens0["prompt_tokens"],
                       "completion": tokens1["completion_tokens"] - tokens0["completion_tokens"],
                       "calls": tokens1["calls"] - tokens0["calls"]},
            "wall_s": round(time.time() - t0, 1),
            "phases": {"generate": gen_phase, "fix": fix_timing},  # test 단계는 측정 후 채운다
            **info,
            "lockfiles": {"Cargo.lock": (sol / "Cargo.lock").exists(), "pip_freeze.txt": (sol / "pip_freeze.txt").exists()}}
    (sol / "_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    if not measure:
        return meta
    # 3) 측정
    if ok:
        try:
            res = runner.run_task(task, sol, lang, cfg, scratch, build_log=log, skip_build=True)
        except Exception as e:
            meta["harness_error"] = str(e)
            res = {"task": task, "lang": lang, "verdict": "harness_error", "error": str(e),
                   "functional": [], "attacks": []}
    else:
        res = {"task": task, "lang": lang, "verdict": "build_failed", "build_log_tail": log[-1500:],
               "functional": [], "attacks": []}
    # 측정 단계(기능 시험·공격 실행)의 벽시계를 phases.test 에 적는다. 빌드는 이미 fix 단계에서 쟀다.
    meta["phases"]["test"] = res.get("timing", {"build_s": 0.0, "functional_s": 0.0, "attacks_s": 0.0})
    meta["verdict"] = res.get("verdict")
    meta["qualified"] = res.get("qualified", False)
    res["_meta"] = meta
    (run_dir / f"{name}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    (sol / "_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


def load_solution_files(sol: Path) -> dict[str, str] | None:
    """해답 디렉터리의 소스 파일을 dict 로 읽는다(빌드 캐시 제외). _meta.json 이 built=false 면 None."""
    if not sol.exists():
        return None
    meta = sol / "_meta.json"
    if meta.exists() and not json.loads(meta.read_text(encoding="utf-8")).get("built", True):
        return None
    files = {}
    for p in sol.rglob("*"):
        if not p.is_file():
            continue
        parts = p.relative_to(sol).parts
        if parts[0] in ("target", "_venv") or parts[0].startswith("_") or p.name in ("Cargo.lock", "pip_freeze.txt"):
            continue
        if p.suffix in (".py", ".rs", ".toml", ".txt", ".c", ".h"):
            files[p.relative_to(sol).as_posix()] = p.read_text(encoding="utf-8", errors="replace")
    return files or None


def order_conditions(conds: list[str]) -> list[str]:
    """Py 먼저, 그다음 생성·옮기기, 강화 조건은 마지막."""
    rank = {"Py": 0, "Rs": 1, "C": 1, "PyPy": 2, "PyRs": 2, "T-secure": 3}
    return sorted(conds, key=lambda c: (rank.get(c, 9), c))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default=None, help="results/<run> 디렉터리 (기본: 타임스탬프)")
    ap.add_argument("--tasks", nargs="*", default=None)
    ap.add_argument("--conditions", nargs="*", default=None)
    ap.add_argument("--samples", type=int, default=None, help="config n_samples 덮어쓰기")
    ap.add_argument("--sample-ids", type=int, nargs="*", default=None,
                    help="이 샘플 번호만 생성 (예: --sample-ids 1 2). 기존 run 에 샘플을 더하거나 한 조건만 다시 만들 때")
    ap.add_argument("--models", nargs="*", default=None, help="config [[models]] name 중 일부만")
    ap.add_argument("--dry-run", action="store_true", help="모델 연결만 확인")
    ap.add_argument("--i-know-local-is-unsafe", action="store_true",
                    help="sandbox.mode=local 에서 LLM 생성 코드를 격리 없이 실행하는 데 동의")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    cfg = runner.load_config()
    enabled = [m for m in cfg["models"] if m.get("enabled")]
    if args.models:
        enabled = [m for m in enabled if m["name"] in args.models]
    if not enabled:
        print("사용 설정된 모델이 없습니다. config.toml에서 enabled=true로 바꾸세요.")
        return 1
    print("모델 연결 확인:")
    live = []
    for m in enabled:
        ok, msg = models.reachable(m)
        print(f"  {m['name']:20} {'OK' if ok else '실패'}  {msg}")
        if ok:
            live.append(m)
    if args.dry_run:
        return 0
    if not live:
        print("연결되는 모델이 없습니다. (Ollama 실행 또는 API 키 확인)")
        return 1
    sandbox.require_local_ok(cfg, args.i_know_local_is_unsafe)
    if args.samples:
        cfg["run"]["n_samples"] = args.samples
    run_dir = ROOT / (args.run or f"results/run_{time.strftime('%Y%m%d_%H%M%S')}")
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "config_snapshot.toml").write_bytes((ROOT / "config.toml").read_bytes())
    tasks = args.tasks or cfg["run"]["tasks"]
    conds = [norm_cond(c) for c in (args.conditions or cfg["run"]["conditions"])]
    unknown = [c for c in conds if c not in CONDITIONS and c not in HARDEN_CONDITIONS]
    if unknown:
        print(f"모르는 조건: {unknown}. 가능: {list(CONDITIONS)} + {HARDEN_CONDITIONS}")
        return 1
    gen_conds = order_conditions([c for c in conds if c in CONDITIONS])
    h_conds = [c for c in conds if c in HARDEN_CONDITIONS]
    n = cfg["run"]["n_samples"]
    sample_ids = args.sample_ids if args.sample_ids is not None else list(range(n))
    gen = Gen(cfg, run_dir)
    src_cache: dict = {}
    for m in live:
        for task in tasks:
            for s in sample_ids:
                for cond in gen_conds:
                    meta = generate_one(gen, m, cond, task, s, src_cache)
                    print(f"  {m['name']} {task} {cond} s{s}: " + _short(meta))
                if h_conds:
                    from harness import harden
                    for hc in h_conds:
                        meta = harden.harden_one(gen, m, hc, task, s)
                        print(f"  {m['name']} {task} {hc} s{s}: " + _short(meta))
    print(f"\n완료. 토큰 합계: {gen.usage.totals}")
    print(f"분해표:  python -m harness.aggregate --run {run_dir}")
    return 0


def _short(meta: dict) -> str:
    if "skipped" in meta:
        return "skipped: " + meta["skipped"]
    keys = ("built", "verdict", "qualified", "fix_rounds", "similarity_to_source", "copied", "tokens", "flagged", "accepted", "iterations", "passthrough")
    return ", ".join(f"{k}={meta[k]}" for k in keys if k in meta and meta[k] is not None)


if __name__ == "__main__":
    sys.exit(main())
