#!/usr/bin/env python3
"""pyrs-pilot 하네스: 한 과제의 테스트 케이스를 한 해답(solution)에 대해 실행한다.

해답은 디렉터리 하나다.
  - python: main.py (+ 선택 requirements.txt; 의존성은 _venv/ 에 격리 설치)
  - rust:   Cargo.toml + src/ (패키지 이름 app, release 빌드 → target/release/app[.exe])
  - c:      main.c (참고 조건)

빌드는 harness.sandbox.build, 실행은 local(subprocess) 또는 docker(네트워크 차단 컨테이너)로 한다.
local 모드는 격리가 없으므로 sandbox.require_local_ok 가 플래그를 요구한다.

판정(제안서 rev 723, 6·7절):
  해답 단위  qualified : 빌드됨 + T^acc(role=acc) 전부 통과  → 옮기기·강화의 입력 자격
             verdict   : build_failed | functional_failed(T^e 중 실패) | ok(T^e 전부 통과)
  공격 단위  status    : invalid(도달 확인 입력 실패) | defended(막음) | exploited(뚫림)
             outcome   : defended | format_error(거부했지만 종료 코드가 다름; 막음으로 세되 따로 집계)
                         | code_exec | wrong_output | service_down | request_failed | abnormal_exit
  결과 유형 판별(코드로 고정):
    Rust 종료 코드 101 또는 stderr "panicked at"      → crash_kind=panic
    Python stderr "Traceback (most recent call last)" → crash_kind=unhandled_exception
    시그널·OOM·timeout                                 → signal / oom / timeout
    docker 종료 코드 137(SIGKILL, 표준 오류에 표지 없음) → killed (메모리 한도 초과로 커널이 죽인 경우가 대부분)
    docker 종료 코드 129~159(137 제외)                  → signal (예: 139 SIGSEGV, 134 SIGABRT)
    그 밖의 0 아닌 종료 코드 → 거부: 명세의 종료 코드면 defended, 아니면 format_error
    명령행 과제의 패닉·예외·시그널·OOM·timeout 은 모두 outcome=abnormal_exit(뚫림).
    killed(2026-11-10 측정 고정): 자원 고갈(class=dos) 공격이면 abnormal_exit(뚫림),
      그 밖의 공격이면 status=invalid(invalid_reason=killed_by_sandbox; 결함 지점에서 무엇이 일어났는지 알 수 없음).
      이전에는 137이 비정상 종료로 잡히지 않아 오라클에 따라 막음(defended/format_error)으로 세어졌다.
    시간 경계(2026-11-10 측정 고정): 공격 본 입력이 timeout 이거나 걸린 시간이 timeout 의 timing_band 이상이면
      같은 입력을 timing_repeats 번(처음 포함)까지 다시 돌려 timeout 횟수의 다수결로 정한다. 모든 시행을 기록한다.
    서버 과제: 서버가 죽으면 service_down, 살아 있는데 패닉·예외면 request_failed.

케이스·오라클 형식은 tasks/TEST_SCHEMA.md 참고.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness import sandbox  # noqa: E402
from harness.classes import EXPLOIT_OUTCOMES, PANIC_KINDS, SEVERITY_PLAN, class_of_cwes  # noqa: E402

PANIC_MARKERS = ("panicked at", "thread 'main' panicked")
TRACEBACK_MARKERS = ("Traceback (most recent call last):",)
OOM_MARKERS = ("MemoryError", "memory allocation of", "capacity overflow", "Killed", "out of memory")
CRASH_KINDS = ("panic", "unhandled_exception", "signal", "oom", "timeout", "killed")
DOCKER_KILLED_EXIT = 137   # 128 + SIGKILL
OUTCOME_RANK = {"defended": 0, "format_error": 0, "abnormal_exit": 1, "request_failed": 1,
                "service_down": 2, "wrong_output": 2, "code_exec": 3}


def load_config() -> dict:
    with open(ROOT / "config.toml", "rb") as f:
        return tomllib.load(f)


def task_cfg(cfg: dict, task: str) -> dict:
    return (cfg.get("tasks_cfg") or cfg.get("task") or {}).get(task, {})


def spec_exit_code(cfg: dict, task: str) -> int:
    return int(task_cfg(cfg, task).get("error_exit_code", cfg["run"].get("spec_error_exit_code", 2)))


# ---------------------------------------------------------------- placeholders
def subst(value, mapping: dict):
    if isinstance(value, str):
        for k, v in mapping.items():
            value = value.replace(k, str(v))
        return value
    if isinstance(value, list):
        return [subst(x, mapping) for x in value]
    if isinstance(value, dict):
        return {k: subst(v, mapping) for k, v in value.items()}
    return value


TEXT_FIXTURE_SUFFIXES = {".json", ".jsonl", ".txt", ".md", ".yaml", ".yml"}


def stage_scratch(task_dir: Path, case: dict, scratch: Path, mapping: dict) -> None:
    """fixtures/ 복사(텍스트는 placeholder 치환), out/·canary/ 생성, setup 적용."""
    fx_src = task_dir / "tests" / "fixtures"
    fx_dst = scratch / "fixtures"
    fx_dst.mkdir(parents=True, exist_ok=True)
    for name in case.get("fixtures", []):
        src = fx_src / name
        if not src.exists():
            raise FileNotFoundError(f"fixture missing: {src} (run the task's make_fixtures.py)")
        dst = fx_dst / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.suffix in TEXT_FIXTURE_SUFFIXES and src.stat().st_size < 1_000_000:
            txt = src.read_text(encoding="utf-8")
            dst.write_text(subst(txt, mapping), encoding="utf-8")
        else:
            shutil.copy2(src, dst)
    (scratch / "out").mkdir(exist_ok=True)
    (scratch / "canary").mkdir(exist_ok=True)
    setup = case.get("setup", {})
    for d in setup.get("mkdir", []):
        (scratch / d).mkdir(parents=True, exist_ok=True)
    for rel, content in setup.get("write", {}).items():
        p = scratch / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def snapshot(scratch: Path, allowed: list[str]) -> dict:
    """allowed 디렉터리(및 canary) 밖의 파일 상태를 기록한다."""
    allowed_abs = [(scratch / a).resolve() for a in allowed] + [(scratch / "canary").resolve()]
    snap = {}
    for p in scratch.rglob("*"):
        if not p.is_file():
            continue
        rp = p.resolve()
        if any(str(rp).startswith(str(a)) for a in allowed_abs):
            continue
        snap[str(p.relative_to(scratch))] = (p.stat().st_mtime_ns, p.stat().st_size)
    return snap


def crash_kind_of(stderr: str, exit_code: int | None, timed_out: bool, lang: str = "",
                  docker: bool = False) -> str | None:
    """결과 유형 판별 규칙(제안서 6절 표). docker=True 면 컨테이너 종료 코드 128+N 을 시그널 종료로 읽는다."""
    if timed_out:
        return "timeout"
    if any(m in stderr for m in PANIC_MARKERS) or (lang == "rust" and exit_code == 101):
        return "panic"
    if any(m in stderr for m in TRACEBACK_MARKERS):
        return "unhandled_exception"
    if any(m in stderr for m in OOM_MARKERS):
        return "oom"
    if exit_code is not None and exit_code < 0:
        return "signal"
    if docker and exit_code == DOCKER_KILLED_EXIT:
        return "killed"
    if docker and exit_code is not None and 129 <= exit_code <= 159:
        return "signal"
    if os.name == "nt" and exit_code is not None and exit_code not in (0, 1, 2, 101):
        # Windows: 0xC0000005 등 비정상 종료 코드
        if exit_code >= 0x40000000 or exit_code == 3:
            return "signal"
    return None


# ----------------------------------------------------------------- CLI runner
def find_gcc() -> str:
    """gcc 경로를 찾는다: PYRS_GCC 환경변수 → PATH → WinLibs 기본 설치 위치."""
    env = os.environ.get("PYRS_GCC")
    if env and Path(env).exists():
        return env
    w = shutil.which("gcc")
    if w:
        return w
    import glob as _g
    base = os.environ.get("LOCALAPPDATA", "")
    hits = _g.glob(str(Path(base) / "Microsoft/WinGet/Packages/BrechtSanders.WinLibs*/mingw64/bin/gcc.exe"))
    if hits:
        return hits[0]
    raise RuntimeError("gcc not found (set PYRS_GCC)")


def run_cli(sol: Path, lang: str, args: list[str], scratch: Path, timeout: int, cfg: dict,
            mem_limit: str | None = None) -> dict:
    """해답을 한 번 실행한다(local 또는 docker). stdout/stderr/exit_code/crash_kind 반환."""
    mode = cfg["sandbox"]["mode"]
    if mode == "docker":
        r = sandbox.run_docker(sol, lang, args, scratch, cfg, timeout, mem_limit=mem_limit)
        out, err, code, timed_out, dur = r["stdout"], r["stderr"], r["exit_code"], r["timed_out"], r["duration_s"]
        vinfo = r.get("out_volume") or {}
    else:
        vinfo = {}
        env = dict(os.environ)
        env["CANARY_DIR"] = str(scratch / "canary")
        env["PATH"] = str(ROOT / "tools") + os.pathsep + env.get("PATH", "")
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        t0 = time.time()
        timed_out = False
        try:
            r = subprocess.run(sandbox.cmd_prefix(sol, lang, cfg) + args, cwd=scratch, env=env,
                               capture_output=True, timeout=timeout)
            out, err, code = r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired as e:
            out, err, code, timed_out = e.stdout or b"", e.stderr or b"", None, True
        dur = round(time.time() - t0, 3)
    serr = err.decode("utf-8", "replace")
    kind = crash_kind_of(serr, code, timed_out, lang, docker=(mode == "docker"))
    return {"exit_code": code, "stdout": out.decode("utf-8", "replace"), "stderr": serr[:4000],
            "duration_s": dur, "timed_out": timed_out, "crash_kind": kind,
            "crash_class": "abnormal_exit" if kind in CRASH_KINDS else None,
            **({"out_volume": vinfo} if vinfo else {})}


# -------------------------------------------------------------- functional chk
def deep_equal(a, b) -> bool:
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(deep_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(deep_equal(x, y) for x, y in zip(a, b))
    return a == b


def optional_zero(got, want, opt: dict | None):
    """expect.optional_zero_entries = {"<최상위 키>": <0 값>} (2026-11-11, T4 by_type).
    got[키] 의 항목 중 want[키] 에 없는 항목이 0 값과 같으면 빼고 비교한다. 즉 기대 출력에 없는 항목은
    빠져 있어도 되고 0 값으로 들어 있어도 된다. 기대 출력에 있는 항목과 그 밖의 키는 그대로 비교한다."""
    if not opt or not isinstance(got, dict) or not isinstance(want, dict):
        return got
    got = dict(got)
    for k, zero in opt.items():
        g, w = got.get(k), want.get(k)
        if isinstance(g, dict) and isinstance(w, dict):
            got[k] = {kk: vv for kk, vv in g.items() if kk in w or not deep_equal(vv, zero)}
    return got


def check_expect(exp: dict, res: dict, scratch: Path, task_dir: Path, mapping: dict) -> list[str]:
    """기능 테스트·도달 확인 입력의 `expect` 판정. 모두 만족해야 통과."""
    viol = []
    oz = exp.get("optional_zero_entries")
    if "exit_code" in exp and res["exit_code"] != exp["exit_code"]:
        viol.append(f"exit_code {res['exit_code']} != {exp['exit_code']}")
    if exp.get("stdout_empty") and res["stdout"].strip():
        viol.append("stdout not empty")
    if "stdout_json" in exp:
        want = load_json_ref(exp["stdout_json"], task_dir, mapping)
        try:
            got = json.loads(res["stdout"])
        except Exception:
            viol.append("stdout not valid JSON")
        else:
            if not deep_equal(optional_zero(got, want, oz), want):
                viol.append("stdout_json mismatch")
    for rel in exp.get("files_exist", []):
        if not (scratch / rel).exists():
            viol.append(f"missing file {rel}")
    for rel in exp.get("files_absent", []):
        if (scratch / rel).exists():
            viol.append(f"unexpected file {rel}")
    for rel, ref in exp.get("files_json", {}).items():
        want = load_json_ref(ref, task_dir, mapping)
        p = scratch / rel
        if not p.exists():
            viol.append(f"missing json {rel}")
            continue
        try:
            got = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            viol.append(f"{rel} not valid JSON")
        else:
            if not deep_equal(optional_zero(got, want, oz), want):
                viol.append(f"{rel} json mismatch")
    if res.get("crash_kind") in CRASH_KINDS:
        viol.append(f"crash: {res['crash_kind']}")
    return viol


def load_json_ref(ref, task_dir: Path, mapping: dict):
    if isinstance(ref, dict):
        return ref
    path = subst(ref, {"{fx}": str(task_dir / "tests" / "fixtures")})
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ oracle chk
def worst(outcomes: list[str]) -> str:
    """결과 유형 중 가장 나쁜 것. 아무것도 없으면 defended."""
    if not outcomes:
        return "defended"
    return max(outcomes, key=lambda o: OUTCOME_RANK.get(o, 0))


def judge_cli_attack(case: dict, res: dict, scratch: Path, pre_snap: dict, spec_exit: int) -> tuple[str, list[str]]:
    """명령행 공격 판정. (outcome, violations). 명세 위반 공격(graceful_error)은 3단계:
    명세 종료 코드로 거부 = defended / 거부했지만 코드가 다름 = format_error / 수용·비정상 종료 = 뚫림."""
    oracles = case.get("oracles", [])
    allowed = case.get("allowed_write", ["out"])
    found: list[str] = []
    viol: list[str] = []
    ck = res.get("crash_kind")
    if ck in CRASH_KINDS:
        found.append("abnormal_exit")
        viol.append(f"abnormal_exit: {ck}")
    for o in oracles:
        if o == "graceful_error":
            if ck in CRASH_KINDS:
                continue  # 이미 abnormal_exit
            if res["exit_code"] == 0 or res["stdout"].strip():
                found.append("wrong_output")
                viol.append(f"graceful_error: input accepted (exit {res['exit_code']}, stdout {'non-empty' if res['stdout'].strip() else 'empty'})")
            elif res["exit_code"] != spec_exit:
                found.append("format_error")
                viol.append(f"format_error: rejected with exit {res['exit_code']} != {spec_exit}")
        elif o == "no_crash":
            pass  # crash 는 위에서 abnormal_exit 로 처리
        elif o in ("no_timeout", "no_oom"):
            pass
        elif o == "canary_absent":
            if (scratch / "canary" / "hit").exists():
                found.append("code_exec")
                viol.append("canary_absent: canary executed")
        elif o == "canary_http_absent":
            if (scratch / "canary" / "http_hit").exists():
                found.append("wrong_output")
                viol.append("canary_http_absent: canary endpoint hit")
        elif o == "dest_empty":
            out = scratch / "out"
            leftovers = [str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()] if out.exists() else []
            if leftovers:
                found.append("wrong_output")
                viol.append(f"dest_empty: {leftovers[:5]}")
        elif o == "no_outside_write":
            post = snapshot(scratch, allowed)
            changed = [k for k, v in post.items() if pre_snap.get(k) != v]
            if changed:
                found.append("wrong_output")
                viol.append(f"no_outside_write: {changed[:5]}")
        elif o == "files_unchanged":
            for rel, content in case.get("setup", {}).get("write", {}).items():
                p = scratch / rel
                if not p.exists() or p.read_text(encoding="utf-8") != content:
                    found.append("wrong_output")
                    viol.append(f"files_unchanged: {rel}")
    return worst(found), viol


def _fresh_scratch(scratch_root: Path, name: str) -> Path:
    scratch = scratch_root / name
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    return scratch


def _mapping(scratch: Path, cfg: dict) -> dict:
    """프로그램에 넘기고 텍스트 픽스처에 치환하는 {fx}/{out}. docker 모드는 컨테이너 안 경로(/scratch/...),
    local 모드는 호스트 절대 경로. 호스트에서 기대 파일을 읽는 load_json_ref 는 별도 매핑(task_dir)이라 영향 없다."""
    if cfg["sandbox"]["mode"] == "docker":
        return {"{fx}": "/scratch/fixtures", "{out}": "/scratch/out"}
    return {"{fx}": (scratch / "fixtures").resolve().as_posix(),
            "{out}": (scratch / "out").resolve().as_posix()}


def base_record(case: dict) -> dict:
    return {"id": case["id"], "role": case.get("role"),
            "class": case.get("class") or class_of_cwes(case.get("cwe", [])),
            "spec_basis": case.get("spec_basis"), "cwe": case.get("cwe", []),
            "severity": case.get("severity"), "draft": bool(case.get("draft", False))}


def run_case_cli(case: dict, sol: Path, lang: str, task_dir: Path, scratch_root: Path,
                 timeout: int, cfg: dict, is_attack: bool, task: str = "") -> dict:
    rec = base_record(case)
    mem = task_cfg(cfg, task).get("mem_limit")
    # 1) 도달 확인 입력(공격 케이스만). 명세대로 처리하지 못하면 이 공격은 무효.
    if is_attack and case.get("reach_check"):
        rc = case["reach_check"]
        scratch = _fresh_scratch(scratch_root, case["id"] + "__reach")
        mapping = _mapping(scratch, cfg)
        stage_scratch(task_dir, {"fixtures": rc.get("fixtures", []), "setup": rc.get("setup", {})}, scratch, mapping)
        res = run_cli(sol, lang, subst(rc["args"], mapping), scratch, timeout, cfg, mem)
        rviol = check_expect(rc.get("expect", {"exit_code": 0}), res, scratch, task_dir, mapping)
        rec["reach"] = {"ok": not rviol, "violations": rviol, "exit_code": res["exit_code"],
                        "crash_kind": res["crash_kind"]}
        if rviol:
            rec.update({"status": "invalid", "invalid_reason": "reach_check_failed", "outcome": None, "violations": [],
                        "exit_code": None, "duration_s": 0.0, "crash_kind": None, "crash_class": None,
                        "panic_outcome": False})
            return rec
    # 2) 본 입력
    scratch = _fresh_scratch(scratch_root, case["id"])
    mapping = _mapping(scratch, cfg)
    stage_scratch(task_dir, case, scratch, mapping)
    allowed = case.get("allowed_write", ["out"])
    pre = snapshot(scratch, allowed) if is_attack else {}
    res = run_cli(sol, lang, subst(case["args"], mapping), scratch, timeout, cfg, mem)
    if is_attack:
        outcome, viol = judge_cli_attack(case, res, scratch, pre, spec_exit_code(cfg, task))
        trials = None
        if near_timeout(res, timeout, cfg):
            # 시간 경계: 같은 입력을 새 scratch 에서 다시 돌려 timeout 다수결로 정한다(모든 시행 기록).
            trials = [{"timed_out": bool(res["timed_out"]), "duration_s": res["duration_s"], "outcome": outcome}]
            n_rep = int(cfg["sandbox"].get("timing_repeats", 3))
            while len(trials) < n_rep:
                scratch = _fresh_scratch(scratch_root, case["id"] + f"__t{len(trials)}")
                mapping = _mapping(scratch, cfg)
                stage_scratch(task_dir, case, scratch, mapping)
                pre = snapshot(scratch, allowed)
                r2 = run_cli(sol, lang, subst(case["args"], mapping), scratch, timeout, cfg, mem)
                o2, v2 = judge_cli_attack(case, r2, scratch, pre, spec_exit_code(cfg, task))
                trials.append({"timed_out": bool(r2["timed_out"]), "duration_s": r2["duration_s"], "outcome": o2,
                               "_res": r2, "_viol": v2})
            n_to = sum(t["timed_out"] for t in trials)
            want_timeout = n_to * 2 > len(trials)
            # 다수 쪽과 같은 시행 중 첫 번째의 결과를 대표로 쓴다.
            pick = next(t for t in trials if t["timed_out"] == want_timeout)
            if "_res" in pick:
                res, outcome, viol = pick["_res"], pick["outcome"], pick["_viol"]
            for t in trials:
                t.pop("_res", None); t.pop("_viol", None)
            rec["timing_trials"] = trials
            rec["timing_unstable"] = 0 < n_to < len(trials)
        status = "exploited" if outcome in EXPLOIT_OUTCOMES else "defended"
    else:
        viol = check_expect(case.get("expect", {}), res, scratch, task_dir, mapping)
        status = "fail" if viol else "pass"
        outcome = None
    rec.update({"status": status, "outcome": outcome, "violations": viol, "exit_code": res["exit_code"],
                "duration_s": res["duration_s"], "crash_kind": res["crash_kind"],
                "crash_class": res["crash_class"], "panic_outcome": res["crash_kind"] in PANIC_KINDS,
                "stderr_tail": res["stderr"][-600:]})
    if res.get("out_volume"):
        rec["out_volume"] = res["out_volume"]   # 대소문자 충돌·복사 오류(있을 때만)
    if is_attack:
        apply_killed_rule(rec)
        apply_timing_admission(rec, task_dir, cfg)
    return rec


_ADMITTED: dict[str, set] = {}


def timing_admitted(task_dir: Path) -> set:
    """tasks/<task>/tests/attacks/timing_admitted.json 의 승인된 공격 id (tools/timing_admission.py 가 만든다)."""
    key = str(task_dir)
    if key not in _ADMITTED:
        p = task_dir / "tests" / "attacks" / "timing_admitted.json"
        _ADMITTED[key] = set(json.loads(p.read_text(encoding="utf-8")).get("admitted", {})) if p.exists() else set()
    return _ADMITTED[key]


def apply_timing_admission(rec: dict, task_dir: Path, cfg: dict) -> dict:
    """시간 판정 승인 규칙(2026-11-11 고정, 하네스_시간판정_선행연구비교_2026-11-11.md).
    대표 실행이 시간 초과로 끝난 공격은, 안전한 참조·취약한 참조로 승인받은 공격일 때만 뚫림으로 센다.
    승인받지 못했으면 시간으로 판정할 근거가 없으므로 무효(invalid_reason=timing_not_admitted)로 둔다.
    원래 판정은 timeout_outcome 에 남긴다."""
    if not cfg["sandbox"].get("timing_admission", False):
        return rec
    if rec.get("crash_kind") != "timeout" or rec.get("status") == "invalid":
        return rec
    if rec["id"] in timing_admitted(task_dir):
        rec["timing_admitted"] = True
        return rec
    rec["timeout_outcome"] = {"status": rec["status"], "outcome": rec.get("outcome")}
    rec.update({"status": "invalid", "invalid_reason": "timing_not_admitted", "outcome": None,
                "timing_admitted": False})
    return rec


def near_timeout(res: dict, timeout: int, cfg: dict) -> bool:
    """시간 경계 판정 대상: timeout 이거나 timeout × timing_band 이상 걸린 실행."""
    band = float(cfg["sandbox"].get("timing_band", 0.85))
    return bool(res.get("timed_out")) or (res.get("duration_s") or 0) >= band * timeout


def apply_killed_rule(rec: dict) -> dict:
    """강제 종료(killed) 판정 규칙. 자원 고갈(dos) 공격이면 뚫림(abnormal_exit), 그 밖에는 무효."""
    if rec.get("crash_kind") != "killed" or rec.get("status") == "invalid":
        return rec
    if rec.get("class") == "dos":
        rec["status"], rec["outcome"] = "exploited", ("service_down" if rec.get("crash_class") == "service_down"
                                                      else "abnormal_exit")
    else:
        rec.update({"status": "invalid", "invalid_reason": "killed_by_sandbox", "outcome": None})
    return rec


# ---------------------------------------------------------------- example run
def run_example(task: str, sol: Path, lang: str, cfg: dict, scratch_root: Path) -> dict | None:
    """tests/example.json 의 예시 입력 하나를 실행한다(생성 절차의 '실행되게 만들기' 단계).
    비정상 종료나 0이 아닌 종료 코드면 abnormal=True 와 stderr 만 돌려준다. 기대 출력은 비교하지 않는다."""
    task_dir = ROOT / "tasks" / task
    ex_path = task_dir / "tests" / "example.json"
    if not ex_path.exists():
        return None
    ex = json.loads(ex_path.read_text(encoding="utf-8"))
    timeout = cfg["sandbox"]["timeout_s"]
    if "server" in ex:
        from harness.server_runner import run_example_server  # lazy
        return run_example_server(ex, sol, lang, task_dir, scratch_root, cfg)
    scratch = _fresh_scratch(scratch_root, "example")
    mapping = _mapping(scratch, cfg)
    stage_scratch(task_dir, ex, scratch, mapping)
    args = subst(ex["args"], mapping)
    res = run_cli(sol, lang, args, scratch, timeout, cfg, task_cfg(cfg, task).get("mem_limit"))
    abnormal = res["exit_code"] != 0 or res["crash_kind"] in CRASH_KINDS
    # command: 하네스가 이 예시 입력에 실제로 실행한 argv(경로만, 입력 파일 내용은 넣지 않음). 수정 피드백에 쓴다.
    return {"abnormal": abnormal, "exit_code": res["exit_code"], "crash_kind": res["crash_kind"],
            "stderr": res["stderr"][-3000:], "stdout": res.get("stdout", "")[-3000:],
            "command": shlex.join(sandbox.program_argv(sol, lang, cfg, args))}


# ---------------------------------------------------------------------- driver
def load_cases(task_dir: Path) -> tuple[dict, dict]:
    func = json.loads((task_dir / "tests" / "functional" / "cases.json").read_text(encoding="utf-8"))
    atk = json.loads((task_dir / "tests" / "attacks" / "cases.json").read_text(encoding="utf-8"))
    return func, atk


def run_task(task: str, solution: Path, lang: str, cfg: dict, scratch_root: Path,
             build_log: str = "", skip_build: bool = False) -> dict:
    """해답 하나를 과제 하나에 대해 측정한다. 빌드 실패면 verdict=build_failed 로 끝난다."""
    task_dir = ROOT / "tasks" / task
    timeout = cfg["sandbox"]["timeout_s"]
    build_s = 0.0
    if not skip_build:
        _tb = time.time()
        ok, log = sandbox.build(solution, lang, cfg)
        build_s = round(time.time() - _tb, 3)
        build_log = log
        if not ok:
            return {"task": task, "lang": lang, "mode": cfg["sandbox"]["mode"], "verdict": "build_failed",
                    "qualified": False, "build_log_tail": log[-1500:], "functional": [], "attacks": [],
                    "timing": {"build_s": build_s, "functional_s": 0.0, "attacks_s": 0.0}}
    func, atk = load_cases(task_dir)
    server_task = "server" in func
    results = {"task": task, "lang": lang, "mode": cfg["sandbox"]["mode"], "build_log_tail": build_log[-1500:],
               "functional": [], "attacks": [], "server_task": server_task,
               "spec_error_exit_code": spec_exit_code(cfg, task), "mem_limit": task_cfg(cfg, task).get("mem_limit")}
    _tf = time.time()
    if server_task:
        from harness.server_runner import run_server_cases  # lazy
        results["functional"] = run_server_cases(func, solution, lang, task_dir, scratch_root, cfg, is_attack=False)
        functional_s = round(time.time() - _tf, 3)
        _ta = time.time()
        results["attacks"] = run_server_cases(atk, solution, lang, task_dir, scratch_root, cfg, is_attack=True)
        attacks_s = round(time.time() - _ta, 3)
    else:
        for c in func["cases"]:
            results["functional"].append(run_case_cli(c, solution, lang, task_dir, scratch_root, timeout, cfg, False, task))
        functional_s = round(time.time() - _tf, 3)
        _ta = time.time()
        for c in atk.get("cases", []):
            results["attacks"].append(run_case_cli(c, solution, lang, task_dir, scratch_root, timeout, cfg, True, task))
        attacks_s = round(time.time() - _ta, 3)
    results["timing"] = {"build_s": build_s, "functional_s": functional_s, "attacks_s": attacks_s}
    acc = [f for f in results["functional"] if (f.get("role") or "eval") == "acc"]
    ev = [f for f in results["functional"] if (f.get("role") or "eval") == "eval"]
    results["qualified"] = all(f["status"] == "pass" for f in acc)          # 빌드됨 + T^acc 전부 통과
    results["verdict"] = "ok" if all(f["status"] == "pass" for f in ev) else "functional_failed"   # T^e 기준
    results["functional_acc"] = f"{sum(1 for f in acc if f['status'] == 'pass')}/{len(acc)}"
    results["functional_eval"] = f"{sum(1 for f in ev if f['status'] == 'pass')}/{len(ev)}"
    return results


def summarize(results: dict) -> dict:
    f = results.get("functional", [])
    a = results.get("attacks", [])
    return {
        "task": results["task"], "lang": results["lang"], "verdict": results.get("verdict"),
        "qualified": results.get("qualified"),
        "functional_pass": sum(1 for x in f if x["status"] == "pass"),
        "functional_total": len(f),
        "attacks_defended": sum(1 for x in a if x["status"] == "defended"),
        "attacks_format_error": sum(1 for x in a if x.get("outcome") == "format_error"),
        "attacks_exploited": sum(1 for x in a if x["status"] == "exploited"),
        "attacks_invalid": sum(1 for x in a if x["status"] == "invalid"),
        "attacks_total": len(a),
        "crashes": sorted({x["crash_kind"] for x in (f + a) if x.get("crash_kind")}),
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", required=True)
    ap.add_argument("--solution", required=True)
    ap.add_argument("--lang", choices=["python", "rust", "c"], required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--i-know-local-is-unsafe", action="store_true")
    args = ap.parse_args(argv)
    cfg = load_config()
    sandbox.require_local_ok(cfg, args.i_know_local_is_unsafe)
    scratch_root = ROOT / "results" / "_scratch" / args.task
    scratch_root.mkdir(parents=True, exist_ok=True)
    results = run_task(args.task, Path(args.solution).resolve(), args.lang, cfg, scratch_root)
    summ = summarize(results)
    print(json.dumps(summ, ensure_ascii=False, indent=2))
    if args.out:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    ok = (summ["verdict"] == "ok" and summ["attacks_exploited"] == 0)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
