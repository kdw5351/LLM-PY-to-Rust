#!/usr/bin/env python3
"""점검·강화(triage and targeted security hardening, 제안서 7절).

조건(기준은 PyRs = 단순 옮기기):
  H-rules      점검 있음, 강화에 공통 규칙만
  H-checklist  점검 있음, 강화에 검사 목록만
  H-both       점검 있음, 둘 다  (= 제안서의 Py→Rs+강화)
  H-all        점검 없음(모든 종류 표시), 둘 다
  T-secure     보안 지시 옮기기 — generate.py 의 옮기기 조건(prompts/user_translate_secure.md)

점검 F(p) = F_s ∪ G^d
  F_s : 코드 신호 σ_k(p) ≥ τ_k 인 결함 종류 (σ 는 structural.sigma: clippy restriction lint → class)
  G^d : role=triage 공격 중 뚫린(exploited) 공격의 결함 종류 (invalid 는 제외)
  F 가 비면 그대로 통과(passthrough): PyRs 코드를 그 조건의 결과로 쓴다.

강화 1회 = 수정 요청(π_rep) 1번 + 컴파일 수정 최대 compile_fix_rounds 번 + 받아들이기 판정.
받아들이기: (1) 빌드, (2) T^acc 중 전에 통과하던 것 모두 통과, (3) 어떤 종류의 σ도 늘지 않고 F_s 종류는 줄었음,
            (4) 코드 실행형 로더가 들어오지 않음(Rust: Command::new / unsafe 수 비증가).
받아들이지 못하면 실패 이유의 종류만 알리고 최대 K번. 끝내 없으면 원래 코드를 두고 harden_failed.
다시 요청(2026-11-10 구현 바로잡기): 매 회차 요청에 처음 요청의 내용(표시된 종류, 위험 위치, 규칙, 검사 목록, 계약)을
  그대로 다시 넣고, 직전 수정본을 "Current files"로 주며, 실패 이유의 종류 한 줄만 덧붙인다(prompts/pi_rep_retry.md).
  위험 위치는 직전 수정본이 빌드됐으면 그 코드에서 다시 잰 위치, 빌드되지 않았으면 처음 위치를 쓰고 그 사실을 적는다.
온도(2026-11-10): 검사 목록 추출 [harden] temperature_extract(0), 강화 수정·컴파일 수정 temperature_repair(0.2).
고치는 AI는 기능 테스트·공격 입력·공격 결과를 보지 못한다.

검사 목록 𝒞_t 는 π_ext 로 과제·모델마다 한 번 뽑아 results/<run>/checklists/ 에 두고 명세 해시를 적는다.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness import runner, sandbox, structural  # noqa: E402
from harness.classes import ALWAYS_RULES, PANIC_CLASS, SIGMA_CLASSES, all_classes, rules_for  # noqa: E402

RULE_RE = re.compile(r"^RULE (\d+):\s*(.*)$", re.MULTILINE)
COND_USES = {"H-rules": ("rules",), "H-checklist": ("checklist",), "H-both": ("rules", "checklist"),
             "H-all": ("rules", "checklist")}


def rules_text(classes: set[str] | None) -> str:
    """prompts/rules.md 에서 표시된 종류에 해당하는 규칙만(None 이면 전부) 골라 돌려준다. 규칙 6 은 항상 포함."""
    txt = (ROOT / "prompts" / "rules.md").read_text(encoding="utf-8")
    rules = {int(m.group(1)): m.group(2).strip() for m in RULE_RE.finditer(txt)}
    nums = sorted(rules) if classes is None else rules_for(classes)
    return "\n".join(f"RULE {n}: {rules[n]}" for n in nums if n in rules)


def checklist_for(gen, model_cfg: dict, task: str) -> tuple[str, dict]:
    """𝒞_t: 명세만 읽고 뽑은 검사 목록. run 안에서 과제·모델마다 한 번만 뽑고 그대로 둔다."""
    from harness.generate import prompt, read, sha256_file
    d = gen.run_dir / "checklists"
    d.mkdir(exist_ok=True)
    p = d / f"{model_cfg['name']}__{task}.md"
    spec_path = ROOT / "tasks" / task / "spec.md"
    info = {"checklist_file": str(p.relative_to(ROOT)).replace("\\", "/"), "spec_sha256": sha256_file(spec_path)}
    if p.exists():
        return p.read_text(encoding="utf-8").split("\n---\n", 1)[-1], info
    user = prompt("pi_ext", spec=read(spec_path))
    text, _ = gen.call(model_cfg, "You extract checklists from specifications.", user, gen.cfg["run"]["seed_base"],
                       "pi_ext", {"name": f"{model_cfg['name']}__{task}__checklist", "task": task},
                       temperature=float(gen.cfg["harden"].get("temperature_extract", 0.0)))
    items = [l for l in text.replace("\r\n", "\n").split("\n") if l.strip().startswith("CHECK")]   # 2026-11-11: \n 에서만 나눔
    body = "\n".join(items) if items else text.strip()
    p.write_text(f"spec_sha256: {info['spec_sha256']}\nmodel: {model_cfg['model']}\n---\n{body}\n", encoding="utf-8")
    return body, info


def triage(base_result: dict, sigma0: dict, cfg: dict) -> dict:
    """F(p) = F_s ∪ G^d. G^d_k: 점검용 공격 중 class k 가 뚫림. G^d_248: 점검용 공격 중 하나라도
    패닉(Rust)/미처리 예외(Python)로 끝남(어느 class 의 공격이든)."""
    tau = cfg["harden"].get("tau", {})
    default_tau = cfg["harden"].get("tau_default", 1)
    f_s = {k for k, v in sigma0["by_class"].items() if v >= tau.get(k, default_tau)}
    triage_atks = [a for a in base_result.get("attacks", []) if a.get("role") == "triage"]
    g_d = {a["class"] for a in triage_atks if a.get("status") == "exploited" and a.get("class")}
    if any(a.get("panic_outcome") for a in triage_atks):
        g_d.add(PANIC_CLASS)
    return {"F_s": sorted(f_s), "G_d": sorted(g_d), "F": sorted(f_s | g_d),
            "tau": {k: tau.get(k, default_tau) for k in SIGMA_CLASSES}, "sigma0": sigma0["by_class"],
            "sigma_source": sigma0.get("sigma_source")}


def _run_acc(task: str, sol: Path, lang: str, cfg: dict, scratch: Path, ids: set[str]) -> dict[str, str]:
    """T^acc(role=acc) 기능 테스트 중 ids 만 돌려 id -> status."""
    task_dir = ROOT / "tasks" / task
    func, _ = runner.load_cases(task_dir)
    cases = [c for c in func["cases"] if c["id"] in ids]
    if "server" in func:
        from harness.server_runner import run_server_cases
        res = run_server_cases({"server": func["server"], "cases": cases}, sol, lang, task_dir, scratch, cfg, False)
    else:
        res = [runner.run_case_cli(c, sol, lang, task_dir, scratch, cfg["sandbox"]["timeout_s"], cfg, False) for c in cases]
    return {r["id"]: r["status"] for r in res}


def accept(sol: Path, lang: str, cfg: dict, task: str, scratch: Path, sigma0: dict, f_s: set[str],
           acc_pass0: set[str], built: bool) -> tuple[bool, str, dict]:
    """받아들이기 판정. (accepted, reason_category, details)"""
    if not built:
        return False, "build", {}
    acc = _run_acc(task, sol, lang, cfg, scratch, acc_pass0)
    broken = sorted(i for i in acc_pass0 if acc.get(i) != "pass")
    sigma1 = structural.sigma(sol, lang, cfg)
    details = {"acc_tests": acc, "sigma1": sigma1["by_class"], "_sigma1_locations": sigma1.get("locations", [])}
    if broken:
        return False, "functional_regression", {**details, "broken": broken}
    inc = [k for k in SIGMA_CLASSES if sigma1["by_class"].get(k, 0) > sigma0["by_class"].get(k, 0)]
    if sigma1.get("unsafe_blocks", 0) > sigma0.get("unsafe_blocks", 0):
        inc.append("unsafe")
    if inc:
        return False, "risk_points_increased", {**details, "increased": inc}
    not_reduced = [k for k in f_s if sigma0["by_class"].get(k, 0) > 0 and sigma1["by_class"].get(k, 0) >= sigma0["by_class"].get(k, 0)]
    if not_reduced:
        return False, "risk_points_not_reduced", {**details, "not_reduced": not_reduced}
    if lang == "python" and sigma1.get("code_executing_loader") and not sigma0.get("code_executing_loader"):
        return False, "loader_changed", details
    if lang == "rust":
        # 사전 등록 목록: process::Command, libloading/dlopen, pyo3 가 새로 들어오거나 Cargo.toml 에 새 의존성 추가
        c0, c1 = sigma0.get("codeload", {}), sigma1.get("codeload", {})
        new_load = [k for k, v in c1.items() if v > c0.get(k, 0)]
        new_deps = sorted(set(sigma1.get("deps", [])) - set(sigma0.get("deps", [])))
        if new_load or new_deps:
            return False, "loader_changed", {**details, "new_codeload": new_load, "new_deps": new_deps}
    return True, "accepted", details


def _copy_solution(src: Path, dst: Path):
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("target", "_venv"))


def harden_one(gen, model_cfg: dict, hcond: str, task: str, sample: int, base_cond: str = "PyRs") -> dict:
    from harness.generate import (files_block, load_solution_files, parse_files, prompt, write_solution)
    cfg, run_dir = gen.cfg, gen.run_dir
    hc = cfg["harden"]
    base_name = f"{model_cfg['name']}__{task}__{base_cond}__s{sample}"
    name = f"{model_cfg['name']}__{task}__{hcond}__s{sample}"
    base_sol = run_dir / "solutions" / base_name
    base_json = run_dir / f"{base_name}.json"
    if not base_json.exists() or not base_sol.exists():
        return {"skipped": f"no {base_cond} result for {base_name}"}
    base = json.loads(base_json.read_text(encoding="utf-8"))
    files = load_solution_files(base_sol)
    if base.get("verdict") == "build_failed" or not files:
        return {"skipped": f"{base_cond} not built"}
    if not base.get("qualified", False):
        # 제안서 5절 3: 강화에는 빌드되고 T^acc 를 모두 통과한 Py→Rs 코드만 넣고, 그 밖에는 AI 호출 없음
        return {"skipped": f"{base_cond} not qualified (T^acc not all passed); no model call"}
    lang = base["lang"]
    sol = run_dir / "solutions" / name
    scratch = run_dir / "_scratch" / name
    scratch.mkdir(parents=True, exist_ok=True)
    ctx = {"name": name, "task": task, "cond": hcond, "sample": sample}
    t0 = time.time()
    tok0 = dict(gen.usage.totals)
    sigma0 = structural.sigma(base_sol, lang, cfg)
    uses = COND_USES[hcond]
    if hcond == "H-all":
        # 점검 없이 전체 강화: 위험 지점이 하나 이상인 종류(σ_k > 0)를 모두 표시. F_s 도 그 종류.
        fs_all = sorted(k for k, v in sigma0["by_class"].items() if v > 0)
        tri = {"F_s": fs_all, "G_d": [], "F": fs_all, "sigma0": sigma0["by_class"], "no_triage": True,
               "sigma_source": sigma0.get("sigma_source")}
    else:
        tri = triage(base, sigma0, cfg)
        if hcond == "H-checklist":
            tri["F_s_accept"] = []   # 검사 목록만: 위험 지점이 늘지 않는 것만 요구
    meta = {"cond": hcond, "base_cond": base_cond, "task": task, "sample": sample, "lang": lang,
            "model": model_cfg["name"], "triage": tri, "flagged": tri["F"], "uses": list(uses),
            "K": hc["K"], "compile_fix_rounds": hc["compile_fix_rounds"], "feedback": hc.get("feedback", "category")}
    # F 가 비면 그대로 통과
    if not tri["F"]:
        _copy_solution(base_sol, sol)
        res = dict(base)
        meta.update({"passthrough": True, "accepted": None, "iterations": 0, "tokens": {"prompt": 0, "completion": 0, "calls": 0},
                     "cost_tokens": 0, "wall_s": round(time.time() - t0, 1), "verdict": base.get("verdict"),
                     "qualified": base.get("qualified")})
        res["_meta"] = meta
        (sol / "_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        (run_dir / f"{name}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        return meta

    f_s = set(tri.get("F_s_accept", tri["F_s"]))
    acc_pass0 = {f["id"] for f in base.get("functional", []) if f.get("role") == "acc" and f["status"] == "pass"}
    flagged = set(tri["F"])
    # 규칙 6 외에 해당하는 규칙이 없고 검사 목록도 쓰지 않는 조건이면 코드를 고치지 않고 그대로 둔다.
    applicable = [n for n in rules_for(flagged) if n not in ALWAYS_RULES]
    if "checklist" not in uses and not applicable:
        _copy_solution(base_sol, sol)
        res = dict(base)
        meta.update({"passthrough": True, "passthrough_reason": "no applicable rule besides rule 6 and no checklist",
                     "accepted": None, "iterations": 0, "tokens": {"prompt": 0, "completion": 0, "calls": 0},
                     "cost_tokens": 0, "wall_s": round(time.time() - t0, 1), "verdict": base.get("verdict"),
                     "qualified": base.get("qualified")})
        res["_meta"] = meta
        (sol / "_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        (run_dir / f"{name}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        return meta
    def _loc_txt(locations):
        ls = [l for l in locations if l["class"] in flagged]
        return "\n".join(f"{l['file']}:{l['line']} — {l['signal']} ({l['class']})" for l in ls) or "(none from code signal)"
    loc_txt = _loc_txt(sigma0["locations"])
    # 규칙 6 은 항상 넣는다(모든 강화 조건). 나머지는 표시된 종류에 해당하는 것만.
    rules = "# Security rules to apply\n\n" + (rules_text(flagged) if "rules" in uses else rules_text(set()))
    checklist = ""
    chk_info = {}
    if "checklist" in uses:
        body, chk_info = checklist_for(gen, model_cfg, task)
        checklist = "# Input conditions from the specification (check each; on violation end as the specification says)\n\n" + body
    contract = prompt("contract")
    system = prompt("system_translate", lang={"python": "Python", "rust": "Rust"}.get(lang, lang))
    def _request(cur, locations_txt):
        return prompt("pi_rep", files=files_block(cur), flagged=", ".join(sorted(flagged)), locations=locations_txt,
                      rules=rules, checklist=checklist, contract=contract)
    user = _request(files, loc_txt)
    t_rep = float(hc.get("temperature_repair", 0.2))
    seed = cfg["run"]["seed_base"] + sample
    iterations = []
    accepted = False
    cur_files = files
    for k in range(1, hc["K"] + 1):
        k_t0 = time.time()
        k_tok0 = dict(gen.usage.totals)
        text, _ = gen.call(model_cfg, system, user, seed + 10 * k, f"rep{k}", ctx, temperature=t_rep)
        new_files = parse_files(text, lang)
        write_solution(sol, new_files)
        _tb = time.time(); ok, log = sandbox.build(sol, lang, cfg); build_s = time.time() - _tb
        cfix = 0
        while not ok and cfix < hc["compile_fix_rounds"]:
            cfix += 1
            fix_user = prompt("fix_build", kind="compile" if lang != "python" else "import", error=log[-4000:],
                              files=files_block(new_files), contract=contract)
            text, _ = gen.call(model_cfg, system, fix_user, seed + 10 * k, f"rep{k}_fix{cfix}", ctx, temperature=t_rep)
            new_files = parse_files(text, lang)
            write_solution(sol, new_files)
            _tb = time.time(); ok, log = sandbox.build(sol, lang, cfg); build_s += time.time() - _tb
        _ta = time.time()
        accepted, reason, details = accept(sol, lang, cfg, task, scratch / f"acc{k}", sigma0, f_s, acc_pass0, ok)
        accept_s = time.time() - _ta
        k_tok1 = gen.usage.totals
        _norm = lambda fs: {k: v.rstrip() for k, v in (fs or {}).items()}   # noqa: E731  끝 공백 차이는 무시
        same_as_input = bool(new_files) and _norm(new_files) == _norm(cur_files)
        iterations.append({"k": k, "built": ok, "compile_fixes": cfix, "accepted": accepted, "reason": reason,
                           "same_as_input": same_as_input,
                           "wall_s": round(time.time() - k_t0, 1), "build_s": round(build_s, 1),
                           "accept_s": round(accept_s, 1),
                           "tokens": {"prompt": k_tok1["prompt_tokens"] - k_tok0["prompt_tokens"],
                                      "completion": k_tok1["completion_tokens"] - k_tok0["completion_tokens"],
                                      "calls": k_tok1["calls"] - k_tok0["calls"]},
                           **{kk: vv for kk, vv in details.items() if kk != "acc_tests" and not kk.startswith("_")}})
        if accepted:
            break
        # 실패 이유의 종류만 알린다. 다음 반복은 최신 수정본에서 이어 간다(config harden.retry_from).
        from_latest = hc.get("retry_from", "latest") == "latest" and bool(new_files)
        base_files = new_files if from_latest else cur_files
        if from_latest and ok and details.get("_sigma1_locations") is not None:
            retry_locs = _loc_txt(details["_sigma1_locations"])          # 직전 수정본에서 다시 잰 위치
        elif from_latest:
            retry_locs = ("(the previous revision did not build, so these locations are from the code before it)\n"
                          + loc_txt)
        else:
            retry_locs = loc_txt
        cur_files = base_files
        # 처음 요청의 내용을 그대로 다시 넣고, 실패 이유의 종류만 덧붙인다(제안서 7절, 제안서대조 1.2 #1).
        user = prompt("pi_rep_retry", reason=reason, request=_request(base_files, retry_locs))
    tok1 = gen.usage.totals
    toks = {"prompt": tok1["prompt_tokens"] - tok0["prompt_tokens"],
            "completion": tok1["completion_tokens"] - tok0["completion_tokens"],
            "calls": tok1["calls"] - tok0["calls"]}
    meta.update({"accepted": accepted, "iterations": len(iterations), "iteration_log": iterations,
                 "tokens": toks, "cost_tokens": toks["prompt"] + toks["completion"],   # Cost = 입력+출력 토큰
                 "wall_s": round(time.time() - t0, 1), **chk_info})
    if not accepted:
        # 원래 코드를 그대로 두고 강화 실패로 기록
        _copy_solution(base_sol, sol)
        res = dict(base)
        meta.update({"harden_failed": True, "verdict": base.get("verdict"), "qualified": base.get("qualified")})
    else:
        res = runner.run_task(task, sol, lang, cfg, scratch, build_log="", skip_build=True)
        meta["verdict"] = res.get("verdict")
        meta["qualified"] = res.get("qualified")
        meta["sigma1"] = iterations[-1].get("sigma1")
    res["_meta"] = meta
    (sol / "_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    (run_dir / f"{name}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


def main(argv=None):
    """이미 생성된 PyRs 결과가 있는 run 에 강화 조건을 더한다."""
    from harness import models
    from harness.generate import Gen
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--conditions", nargs="*", default=["H-both"])
    ap.add_argument("--tasks", nargs="*", default=None)
    ap.add_argument("--i-know-local-is-unsafe", action="store_true")
    args = ap.parse_args(argv)
    cfg = runner.load_config()
    sandbox.require_local_ok(cfg, args.i_know_local_is_unsafe)
    run_dir = ROOT / args.run if not Path(args.run).is_absolute() else Path(args.run)
    gen = Gen(cfg, run_dir)
    by_name = {m["name"]: m for m in cfg["models"]}
    for js in sorted(run_dir.glob("*__*__PyRs__s*.json")):
        model, task, _, s = js.stem.split("__")
        if args.tasks and task not in args.tasks:
            continue
        if model not in by_name:
            print(f"  {js.stem}: model {model} not in config, skipped")
            continue
        ok, msg = models.reachable(by_name[model])
        if not ok:
            print(f"  {model}: unreachable ({msg})")
            return 1
        for hc in args.conditions:
            meta = harden_one(gen, by_name[model], hc, task, int(s[1:]))
            print(f"  {model} {task} {hc} {s}: {meta.get('skipped') or {k: meta.get(k) for k in ('flagged', 'accepted', 'iterations', 'verdict', 'tokens')}}")
    print(f"토큰 합계: {gen.usage.totals}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
