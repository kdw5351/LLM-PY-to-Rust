#!/usr/bin/env python3
"""결과 집계 (제안서 rev 723: 6절 지표, 7절 옮기기 전후 비교·강화 평가, 8절 차이 분해).

입력: results/<run>/<model>__<task>__<cond>__s<n>.json (runner.run_task 출력 + _meta)
조건 이름은 Py, Rs, PyPy, PyRs, T-secure, H-rules, H-checklist, H-both, H-all (구 이름 A-Py 등도 읽는다).

고정 규칙(플래그 아님):
- 모든 주 지표는 조건과 관계없이 평가용(role=eval) 공격만 쓴다. triage 는 점검 신호에만.
- "통과" = T^e 전부 통과(verdict ok). "자격" = 빌드 + T^acc 전부 통과(qualified).
- 무효(invalid)는 안전으로 세지 않는다. CVR 분모 = 통과 + 그 종류의 평가용 공격이 하나 이상 도달한 코드.
  동시 통과율 분모 = 공격이 하나라도 도달한 통과 코드(모두 무효면 "판정 불가"로 빼고 수를 보고).
- 명세 위반 공격의 format_error 는 막음으로 세되 따로 집계한다.
- 248(패닉·미처리 예외)은 결과 유형 행: 자기 class 에서 뚫림으로 센 뒤 248 행에 따로 센다(합치지 않음).
- 복사됨 Py→Py: 주 분석에 포함(main), 뺀 결과를 민감도 분석(sensitivity)으로 둘 다 낸다.
- 강화 후 무효가 된 공격(기준에서 도달): Break 에서만 y_c=1, RR·Keep·S·짝 비교에서는 무효로 제외.
- S(c) = Σ w(a)·o_c / Σ w(a) (심각도 w 는 cases.json severity; 없으면 1). Cost = 입력+출력 토큰.
  CPR(c) = Cost / ((N_left_B + N_new_B) − (N_left_c + N_new_c)); 분모 ≤ 0 이면 해당 없음.
- 짝 비교의 (코드, 결함 종류) 단위는 양쪽 조건 모두 그 종류 공격이 하나 이상 도달했을 때만.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
ALIASES = {"A-Py": "Py", "A-Rs": "Rs", "A-C": "C", "B-PyPy": "PyPy", "B-PyRs": "PyRs", "R-full": "H-both"}
BASE_CONDS = ["Py", "Rs", "PyPy", "PyRs"]
HARDEN_CONDS = ["H-rules", "H-checklist", "H-both", "H-all", "T-secure"]
PANIC_ROW = "panic(248)"


def load_cfg() -> dict:
    p = ROOT / "config.toml"
    if not p.exists():
        return {}
    with open(p, "rb") as f:
        return tomllib.load(f)


def load_run(run_dir: Path) -> list[dict]:
    rows = []
    for f in sorted(run_dir.glob("*__*__*__s*.json")):
        try:
            model, task, cond, s = f.stem.split("__")
        except ValueError:
            continue
        data = json.loads(f.read_text(encoding="utf-8"))
        meta = data.get("_meta", {})
        cond = ALIASES.get(cond, cond)
        verdict = data.get("verdict") or ("build_failed" if not meta.get("built", True) else "ok")
        rows.append({"model": model, "task": task, "cond": cond, "sample": s, "data": data, "meta": meta,
                     "verdict": verdict, "qualified": bool(data.get("qualified", meta.get("qualified", False))),
                     "copied": bool(meta.get("copied"))})
    return rows


def attack_class(a: dict) -> str | None:
    if a.get("class"):
        return a["class"]
    from harness.classes import class_of_cwes
    return class_of_cwes(a.get("cwe", []))


def sev(a: dict) -> float:
    s = a.get("severity")
    return float(s) if isinstance(s, (int, float)) else 1.0


def eval_attacks(row: dict, invalid_policy: str = "exclude") -> list[dict]:
    """평가용(role=eval) 공격만. invalid 는 정책에 따라 제외 또는 뚫림으로."""
    out = []
    for a in row["data"].get("attacks", []):
        if (a.get("role") or "eval") != "eval":
            continue
        st = a["status"]
        if st == "invalid":
            if invalid_policy == "exploited":
                st = "exploited"
            else:
                out.append({**a, "status": "invalid", "class": attack_class(a)})
                continue
        out.append({**a, "status": st, "class": attack_class(a)})
    return out


def reached(a: dict) -> bool:
    return a["status"] in ("defended", "exploited")


def _mean(xs):
    xs = [x for x in xs if isinstance(x, (int, float))]
    return round(sum(xs) / len(xs), 3) if xs else None


# ------------------------------------------------------------- per condition
def cond_stats(rows: list[dict], invalid_policy: str) -> dict:
    classes = sorted({attack_class(a) for r in rows for a in r["data"].get("attacks", []) if attack_class(a)})
    n = len(rows)
    ok = [r for r in rows if r["verdict"] == "ok"]
    atk_all = [a for r in rows for a in r["data"].get("attacks", []) if (a.get("role") or "eval") == "eval"]
    invalid_n = sum(1 for a in atk_all if a["status"] == "invalid")
    cvr = {}
    for c in classes:
        vuln = tot = excluded = 0
        a_exp = a_reach = a_fmt = 0
        for r in ok:
            atks = [a for a in eval_attacks(r, invalid_policy) if a["class"] == c]
            if not atks:
                continue
            rch = [a for a in atks if reached(a)]
            if not rch:
                excluded += 1          # 그 종류의 공격이 모두 무효 → 분모에서 빼고 수를 보고
                continue
            tot += 1
            if any(a["status"] == "exploited" for a in rch):
                vuln += 1
            a_reach += len(rch)
            a_exp += sum(1 for a in rch if a["status"] == "exploited")
            a_fmt += sum(1 for a in rch if a.get("outcome") == "format_error")
        cvr[c] = {"vuln_codes": vuln, "codes": tot, "excluded_all_invalid": excluded,
                  "cvr": round(vuln / tot, 3) if tot else None,
                  "attacks_exploited": a_exp, "attacks_reached": a_reach, "attacks_format_error": a_fmt,
                  "attack_rate": round(a_exp / a_reach, 3) if a_reach else None}
    # 248 행: 결과 유형 집계(패닉·미처리 예외로 끝난 평가용 공격 / 그런 코드 수). 다른 행과 합치지 않는다.
    panic_codes = sum(1 for r in ok if any(a.get("panic_outcome") for a in eval_attacks(r, invalid_policy)))
    panic_atks = sum(1 for r in ok for a in eval_attacks(r, invalid_policy) if a.get("panic_outcome"))
    # 명세 위반 입력 / 일반 보안 기대 분리 (도달한 평가용 공격 기준)
    basis = {}
    for b in ("spec_violation", "general"):
        e = t = f = 0
        for r in ok:
            for a in eval_attacks(r, invalid_policy):
                if (a.get("spec_basis") or "general") == b and reached(a):
                    t += 1
                    e += 1 if a["status"] == "exploited" else 0
                    f += 1 if a.get("outcome") == "format_error" else 0
        basis[b] = {"exploited": e, "reached": t, "format_error": f, "rate": round(e / t, 3) if t else None}
    # 결과 유형 분포
    outcomes = defaultdict(int)
    for r in ok:
        for a in eval_attacks(r, invalid_policy):
            if reached(a):
                outcomes[a.get("outcome") or "?"] += 1
    # 기능·보안 동시 통과율: 공격이 하나라도 도달한 통과 코드만 분모, 모두 무효는 판정 불가
    judgeable = [r for r in ok if any(reached(a) for a in eval_attacks(r, invalid_policy))]
    unjudgeable = len(ok) - len(judgeable)
    sec_pass = sum(1 for r in judgeable if not any(a["status"] == "exploited" for a in eval_attacks(r, invalid_policy)))
    # 심각도 점수 S: Σ w·o / Σ w (도달한 평가용 공격)
    w_sum = w_exp = 0.0
    for r in ok:
        for a in eval_attacks(r, invalid_policy):
            if reached(a):
                w_sum += sev(a)
                w_exp += sev(a) if a["status"] == "exploited" else 0
    # 2026-11-11 시간 판정 규칙: 시간 초과로만 뚫린 평가용 공격(승인된 공격) 수. BaxBench 방식(시간 초과 = 뚫리지 않음)으로
    # 다시 셀 때 빼면 되는 수. 승인받지 못해 무효가 된 시간 초과 수도 따로 낸다.
    timeout_exp = sum(1 for r in ok for a in eval_attacks(r, invalid_policy)
                      if a["status"] == "exploited" and a.get("crash_kind") == "timeout")
    timeout_exp_codes = sum(1 for r in ok if any(a["status"] == "exploited" and a.get("crash_kind") == "timeout"
                                                  for a in eval_attacks(r, invalid_policy)))
    timing_not_admitted = sum(1 for a in atk_all if a.get("invalid_reason") == "timing_not_admitted")
    crashes = defaultdict(int)
    for r in rows:
        for x in r["data"].get("functional", []) + r["data"].get("attacks", []):
            if x.get("crash_class"):
                crashes[x["crash_class"]] += 1
    locs = [r["meta"].get("loc") for r in rows]
    return {"n": n, "build_failed": sum(1 for r in rows if r["verdict"] == "build_failed"),
            "functional_failed": sum(1 for r in rows if r["verdict"] == "functional_failed"),
            "ok": len(ok), "qualified": sum(1 for r in rows if r["qualified"]),
            "copied": sum(1 for r in rows if r["copied"]),
            "attacks_invalid": invalid_n, "attacks_total": len(atk_all),
            "attacks_exploited_by_timeout": timeout_exp, "codes_with_timeout_exploit": timeout_exp_codes,
            "attacks_timing_not_admitted": timing_not_admitted,
            "func_sec_pass": sec_pass, "judgeable": len(judgeable), "unjudgeable_all_invalid": unjudgeable,
            "func_sec_pass_rate": round(sec_pass / len(judgeable), 3) if judgeable else None,
            "func_sec_pass_rate_all": round(sec_pass / n, 3) if n else None,
            "severity_S": round(w_exp / w_sum, 3) if w_sum else None,
            "fix_rounds_mean": _mean([r["meta"].get("fix_rounds") for r in rows]),
            "similarity_mean": _mean([r["meta"].get("similarity_to_source") for r in rows]),
            "copy_regen_mean": _mean([r["meta"].get("copy_regen") for r in rows]),
            "tokens_mean": _mean([(r["meta"].get("tokens") or {}).get("completion") for r in rows]),
            "loc_mean": _mean(locs),
            "cvr": cvr, "panic_row": {"codes": panic_codes, "attacks": panic_atks, "of_codes": len(ok)},
            "spec_basis": basis, "outcomes": dict(outcomes), "crash_classes": dict(crashes)}


# ---------------------------------------------------------------- paired cmp
def _index(rows):
    idx = defaultdict(dict)
    for r in rows:
        idx[(r["model"], r["task"], r["sample"])][r["cond"]] = r
    return idx


def paired(rows: list[dict], cond_x: str, cond_y: str, invalid_policy: str) -> dict:
    """같은 (model, task, sample, 평가용 공격 id) 짝의 gone/left/new/safe (심각도 가중 합도). 양쪽 다 통과(ok)인 짝만.
    (코드, 결함 종류) 단위는 양쪽 모두 그 종류 공격이 하나 이상 도달했을 때만 센다."""
    counts = defaultdict(lambda: {"gone": 0, "left": 0, "new": 0, "safe": 0, "skipped_invalid": 0,
                                  "w_gone": 0.0, "w_new": 0.0, "w_x1": 0.0, "w_x0": 0.0})
    code_cls = defaultdict(lambda: {"n10": 0, "n01": 0, "n11": 0, "n00": 0, "excluded": 0})
    pairs = 0
    fkeep_num = fkeep_den = 0
    for key, by in _index(rows).items():
        x, y = by.get(cond_x), by.get(cond_y)
        if not x or not y:
            continue
        pairs += 1
        if x["verdict"] != "ok" or y["verdict"] != "ok":
            continue
        ax = {a["id"]: a for a in eval_attacks(x, invalid_policy)}
        ay = {a["id"]: a for a in eval_attacks(y, invalid_policy)}
        per_cls_x, per_cls_y = defaultdict(list), defaultdict(list)
        for aid, a in ax.items():
            b = ay.get(aid)
            if not b:
                continue
            c = a["class"] or "?"
            if not reached(a) or not reached(b):
                counts[c]["skipped_invalid"] += 1
                continue
            xs, ys = a["status"] == "exploited", b["status"] == "exploited"
            w = sev(a)
            k = "gone" if xs and not ys else "left" if xs and ys else "new" if (not xs and ys) else "safe"
            counts[c][k] += 1
            if xs:
                counts[c]["w_x1"] += w
                counts[c]["w_gone"] += w if not ys else 0
            else:
                counts[c]["w_x0"] += w
                counts[c]["w_new"] += w if ys else 0
            per_cls_x[c].append(xs)
            per_cls_y[c].append(ys)
        for c in set(per_cls_x) | set(per_cls_y):
            if not per_cls_x.get(c) or not per_cls_y.get(c):
                code_cls[c]["excluded"] += 1
                continue
            vx, vy = any(per_cls_x[c]), any(per_cls_y[c])
            code_cls[c]["n10" if vx and not vy else "n01" if (not vx and vy) else "n11" if vx else "n00"] += 1
        fx = {f["id"]: f for f in x["data"].get("functional", []) if (f.get("role") or "eval") == "eval"}
        fy = {f["id"]: f for f in y["data"].get("functional", [])}
        for fid, f in fx.items():
            if f["status"] == "pass" and fid in fy:
                fkeep_den += 1
                fkeep_num += 1 if fy[fid]["status"] == "pass" else 0
    tot = {"gone": 0, "left": 0, "new": 0, "safe": 0, "skipped_invalid": 0}
    rates = {}
    for c, v in counts.items():
        for k in tot:
            tot[k] += v[k]
        rates[c] = {"r_gone_w": round(v["w_gone"] / v["w_x1"], 3) if v["w_x1"] else None,
                    "r_new_w": round(v["w_new"] / v["w_x0"], 3) if v["w_x0"] else None}
    return {"x": cond_x, "y": cond_y, "pairs": pairs,
            "by_class": {c: {k: v[k] for k in tot} for c, v in counts.items()}, "weighted_rates": rates,
            "code_class_pairs": dict(code_cls), "total": tot,
            "fkeep": round(fkeep_num / fkeep_den, 3) if fkeep_den else None, "fkeep_n": fkeep_den}


def hardening_metrics(rows: list[dict], base: str, cond: str, invalid_policy: str) -> dict:
    """RR_left, RR_new, Keep, Break, S, Cost, CPR (기준 PyRs 대비, 평가용 공격만).
    left/new 의 구분은 같은 샘플의 Py 결과(원본)로 한다. 원본이 없거나 무효면 그 공격은 구분에서 뺀다.
    강화 후 무효가 된 공격(기준에서는 도달)은 Break 에서만 y_c=1 로 세고 나머지 지표에서는 뺀다."""
    n_left_b = n_left_c = n_new_b = n_new_c = 0
    keep_num = keep_den = brk_num = brk_den = 0
    invalid_after = 0
    w_sum = w_exp = 0.0
    iters, costs, flagged, accepted, passthrough, failed, n = [], [], 0, 0, 0, 0, 0
    accepted_still_vuln = 0
    for key, by in _index(rows).items():
        b, c, py = by.get(base), by.get(cond), by.get("Py")
        if not b or not c:
            continue
        n += 1
        m = c["meta"]
        if m.get("passthrough"):
            passthrough += 1
        elif cond == "T-secure":
            pass
        else:
            flagged += 1
            accepted += 1 if m.get("accepted") else 0
            failed += 1 if m.get("harden_failed") else 0
            iters.append(m.get("iterations"))
            costs.append(m.get("cost_tokens", ((m.get("tokens") or {}).get("prompt", 0) + (m.get("tokens") or {}).get("completion", 0))))
        if b["verdict"] != "ok" or c["verdict"] != "ok":
            continue
        ab = {a["id"]: a for a in eval_attacks(b, invalid_policy)}
        ac = {a["id"]: a for a in eval_attacks(c, invalid_policy)}
        ap = {a["id"]: a for a in eval_attacks(py, invalid_policy)} if py and py["verdict"] == "ok" else {}
        vuln_after = False
        for aid, a in ab.items():
            bb = ac.get(aid)
            if not bb or not reached(a):
                continue
            xb = a["status"] == "exploited"
            if not reached(bb):
                invalid_after += 1
                if not xb:                       # 기준이 막던 공격이 강화 후 무효 → Break 에서만 뚫림으로
                    brk_den += 1; brk_num += 1
                continue
            xc = bb["status"] == "exploited"
            vuln_after |= xc
            w = sev(a)
            w_sum += w; w_exp += w if xc else 0
            xp = (ap[aid]["status"] == "exploited") if aid in ap and reached(ap[aid]) else None
            if xb:
                if xp is False:
                    n_new_b += 1; n_new_c += 1 if xc else 0
                elif xp is True:
                    n_left_b += 1; n_left_c += 1 if xc else 0
            else:
                brk_den += 1; brk_num += 1 if xc else 0
                if xp is True:                  # 옮기면서 없어진 위험 → 강화 후에도 막히는가(Keep)
                    keep_den += 1; keep_num += 0 if xc else 1
        if m.get("accepted") and vuln_after:
            accepted_still_vuln += 1
    reduction = (n_left_b + n_new_b) - (n_left_c + n_new_c)
    cost_total = sum(x for x in costs if isinstance(x, (int, float)))
    return {"base": base, "cond": cond, "n_pairs": n, "flagged": flagged, "passthrough": passthrough,
            "accepted": accepted, "harden_failed": failed, "accepted_still_vulnerable": accepted_still_vuln,
            "RR_left": round(1 - n_left_c / n_left_b, 3) if n_left_b else None, "n_left_base": n_left_b,
            "RR_new": round(1 - n_new_c / n_new_b, 3) if n_new_b else None, "n_new_base": n_new_b,
            "Keep": round(keep_num / keep_den, 3) if keep_den else None, "keep_n": keep_den,
            "Break": round(brk_num / brk_den, 3) if brk_den else None, "break_n": brk_den,
            "invalid_after_hardening": invalid_after,
            "S": round(w_exp / w_sum, 3) if w_sum else None,
            "Cost_tokens_total": cost_total, "Cost_tokens_mean": _mean(costs), "iterations_mean": _mean(iters),
            "CPR": round(cost_total / reduction, 1) if reduction > 0 else None, "CPR_reduction": reduction}


def code_signal_prec_rec(rows: list[dict], cond: str = "PyRs") -> dict:
    """Prec_k, Rec_k: 코드 신호 G^s(_meta.triage.F_s) 대 공격 신호 G^d(_meta.triage.G_d). 강화 조건의 triage 기록에서."""
    stats = defaultdict(lambda: {"gs": 0, "gd": 0, "both": 0})
    for r in rows:
        tri = (r["meta"] or {}).get("triage")
        if not tri or tri.get("no_triage"):
            continue
        fs, gd = set(tri.get("F_s", [])), set(tri.get("G_d", []))
        for k in fs | gd:
            stats[k]["gs"] += 1 if k in fs else 0
            stats[k]["gd"] += 1 if k in gd else 0
            stats[k]["both"] += 1 if (k in fs and k in gd) else 0
    return {k: {"prec": round(v["both"] / v["gs"], 3) if v["gs"] else None,
                "rec": round(v["both"] / v["gd"], 3) if v["gd"] else None, **v} for k, v in stats.items()}


# ------------------------------------------------------------------ aggregate
def _tables(rows: list[dict], invalid_policy: str) -> dict:
    by_cond = defaultdict(list)
    for r in rows:
        by_cond[r["cond"]].append(r)
    per_cond = {c: cond_stats(rs, invalid_policy) for c, rs in by_cond.items()}
    classes = sorted({c for st in per_cond.values() for c in st["cvr"]})

    def rate(cond, cls):
        return per_cond.get(cond, {}).get("cvr", {}).get(cls, {}).get("cvr")

    decomp = []
    for cls in classes:
        py, rs, pp, pr = (rate(c, cls) for c in BASE_CONDS)
        total = round(py - rs, 3) if py is not None and rs is not None else None
        lang = round(pp - pr, 3) if pp is not None and pr is not None else None
        eco = round(total - lang, 3) if total is not None and lang is not None else None
        decomp.append({"class": cls, "Py": py, "Rs": rs, "total_diff": total, "PyPy": pp, "PyRs": pr,
                       "language_effect": lang, "ecosystem_effect": eco})
    pairs = {}
    if "Py" in by_cond and "PyRs" in by_cond:
        pairs["PyRs_vs_Py"] = paired(rows, "Py", "PyRs", invalid_policy)
    if "Py" in by_cond and "PyPy" in by_cond:
        pairs["PyPy_vs_Py"] = paired(rows, "Py", "PyPy", invalid_policy)
    hard = {}
    for hc in HARDEN_CONDS:
        if hc in by_cond and "PyRs" in by_cond:
            pairs[f"{hc}_vs_PyRs"] = paired(rows, "PyRs", hc, invalid_policy)
            hard[hc] = hardening_metrics(rows, "PyRs", hc, invalid_policy)
    return {"per_condition": per_cond, "decomposition": decomp, "paired": pairs, "hardening": hard,
            "code_signal": code_signal_prec_rec(rows)}


def aggregate(run_dir: Path, cfg: dict) -> dict:
    an = cfg.get("analysis", {})
    invalid_policy = an.get("invalid_policy", "exclude")
    include_copied = an.get("include_copied", True)
    rows = load_run(run_dir)
    tasks = sorted({r["task"] for r in rows})
    conds = sorted({r["cond"] for r in rows})
    with_copied = _tables(rows, invalid_policy)
    without_copied = _tables([r for r in rows if not r["copied"]], invalid_policy)
    main, sens = (with_copied, without_copied) if include_copied else (without_copied, with_copied)
    return {"run_dir": str(run_dir), "tasks": tasks, "conditions_present": conds,
            "flags": {"include_copied": include_copied, "invalid_policy": invalid_policy,
                      "main_table": "copied included" if include_copied else "copied excluded",
                      "sensitivity_table": "copied excluded" if include_copied else "copied included"},
            "n_copied": sum(1 for r in rows if r["copied"]),
            "main": main, "sensitivity": sens}


def fmt(v):
    if v is None:
        return "–"
    return f"{v:.3f}" if isinstance(v, float) else str(v)


def _md_tables(t: dict, L: list[str], title: str):
    L.append(f"## {title}\n")
    L.append("### 조건별 상태 분포 (빌드 실패·기능 실패·무효·복사됨을 함께 보고)\n")
    L.append("| 조건 | 코드 수 | 자격(빌드+T^acc) | 통과(T^e) | 빌드 실패 | 기능 실패 | 복사됨 | 무효 공격/평가용 | 동시 통과 (판정 가능 중) | 판정 불가 | S | 수정 횟수 | 유사도 | 재생성 | 줄 수 |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for c, st in sorted(t["per_condition"].items()):
        L.append(f"| {c} | {st['n']} | {st['qualified']} | {st['ok']} | {st['build_failed']} | {st['functional_failed']} | {st['copied']} | "
                 f"{st['attacks_invalid']}/{st['attacks_total']} | {st['func_sec_pass']}/{st['judgeable']} ({fmt(st['func_sec_pass_rate'])}) | "
                 f"{st['unjudgeable_all_invalid']} | {fmt(st['severity_S'])} | {fmt(st['fix_rounds_mean'])} | {fmt(st['similarity_mean'])} | {fmt(st['copy_regen_mean'])} | {fmt(st['loc_mean'])} |")
    L.append("\n### 결함 종류(class)별 CVR 과 분해 (통과 코드 중 그 종류의 평가용 공격이 하나 이상 도달한 코드가 분모)\n")
    L.append("| class | Py | Rs | 총 차이 | PyPy | PyRs | 언어 효과 | 생태계 효과 |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for d in t["decomposition"]:
        L.append(f"| {d['class']} | {fmt(d['Py'])} | {fmt(d['Rs'])} | {fmt(d['total_diff'])} | {fmt(d['PyPy'])} | {fmt(d['PyRs'])} | "
                 f"{fmt(d['language_effect'])} | {fmt(d['ecosystem_effect'])} |")
    pr = {c: st["panic_row"] for c, st in t["per_condition"].items()}
    L.append("| " + PANIC_ROW + " (결과 유형 행, 합치지 않음) | " + " | ".join(
        f"{pr[c]['codes']}/{pr[c]['of_codes']} 코드, {pr[c]['attacks']} 공격" if c in pr else "–" for c in BASE_CONDS) + " | | | |")
    L.append("\n### 공격 단위 (도달한 평가용 공격 중 뚫린 비율) — 명세 위반 입력 / 일반 보안 기대 / 결과 유형\n")
    L.append("| 조건 | 명세 위반 입력 (형식 오류) | 일반 보안 기대 | class별 뚫림/도달 (형식 오류) | 결과 유형 |")
    L.append("| --- | --- | --- | --- | --- |")
    for c, st in sorted(t["per_condition"].items()):
        b = st["spec_basis"]
        cls = ", ".join(f"{k} {v['attacks_exploited']}/{v['attacks_reached']} ({v['attacks_format_error']})" for k, v in st["cvr"].items())
        oc = ", ".join(f"{k}×{v}" for k, v in sorted(st["outcomes"].items())) or "–"
        L.append(f"| {c} | {b['spec_violation']['exploited']}/{b['spec_violation']['reached']} ({fmt(b['spec_violation']['rate'])}; 형식 오류 {b['spec_violation']['format_error']}) | "
                 f"{b['general']['exploited']}/{b['general']['reached']} ({fmt(b['general']['rate'])}) | {cls} | {oc} |")
    if t["paired"]:
        L.append("\n### 짝 비교 (같은 과제·샘플·평가용 공격; 양쪽 다 통과이고 양쪽 다 도달한 짝만)\n")
        L.append("| 비교 | 짝 수 | 없어진 | 남은 | 새로 생긴 | 양쪽 안전 | 무효 제외 | (코드,종류) n10/n01/n11/n00 (제외) | FKeep |")
        L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for k, p in t["paired"].items():
            tt = p["total"]
            cc = p["code_class_pairs"]
            agg = {k2: sum(v[k2] for v in cc.values()) for k2 in ("n10", "n01", "n11", "n00", "excluded")}
            L.append(f"| {p['y']} vs {p['x']} | {p['pairs']} | {tt['gone']} | {tt['left']} | {tt['new']} | {tt['safe']} | {tt['skipped_invalid']} | "
                     f"{agg['n10']}/{agg['n01']}/{agg['n11']}/{agg['n00']} ({agg['excluded']}) | {fmt(p['fkeep'])} (n={p['fkeep_n']}) |")
    if t["hardening"]:
        L.append("\n### 강화 조건 평가 (기준 PyRs; 평가용 공격·기능 테스트만)\n")
        L.append("| 조건 | 짝 | 표시됨 | 통과(미수정) | 받아들임 | 강화 실패 | 받아들였지만 뚫림 | RR_left (n) | RR_new (n) | Keep (n) | Break (n) | 강화 후 무효 | S | Cost 토큰 평균 | CPR | 반복 평균 |")
        L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for hc, h in t["hardening"].items():
            cpr = fmt(h["CPR"]) if h["CPR"] is not None else f"해당 없음(감소 {h['CPR_reduction']})"
            L.append(f"| {hc} | {h['n_pairs']} | {h['flagged']} | {h['passthrough']} | {h['accepted']} | {h['harden_failed']} | {h['accepted_still_vulnerable']} | "
                     f"{fmt(h['RR_left'])} ({h['n_left_base']}) | {fmt(h['RR_new'])} ({h['n_new_base']}) | {fmt(h['Keep'])} ({h['keep_n']}) | "
                     f"{fmt(h['Break'])} ({h['break_n']}) | {h['invalid_after_hardening']} | {fmt(h['S'])} | {fmt(h['Cost_tokens_mean'])} | {cpr} | {fmt(h['iterations_mean'])} |")
    if t["code_signal"]:
        L.append("\n### 코드 신호 정밀도·재현율 (Prec_k, Rec_k; 점검 기록이 있는 조건에서)\n")
        L.append("| class | G^s=1 | G^d=1 | 둘 다 | Prec | Rec |")
        L.append("| --- | --- | --- | --- | --- | --- |")
        for k, v in sorted(t["code_signal"].items()):
            L.append(f"| {k} | {v['gs']} | {v['gd']} | {v['both']} | {fmt(v['prec'])} | {fmt(v['rec'])} |")


def to_markdown(s: dict) -> str:
    L = [f"# 결과: `{s['run_dir']}`\n",
         f"- 과제: {', '.join(s['tasks'])}", f"- 조건: {', '.join(s['conditions_present'])}",
         f"- 플래그: {s['flags']}", f"- 복사됨 코드 수: {s['n_copied']}\n",
         "모든 주 지표는 평가용(eval) 공격만 쓴다. 무효는 분모에서 뺀다. 형식 오류(거부했지만 종료 코드가 다름)는 막음으로 세되 괄호에 따로 적는다. "
         "248 행은 결과 유형 집계이며 class 행과 합치지 않는다.\n"]
    _md_tables(s["main"], L, f"주 분석 ({s['flags']['main_table']})")
    L.append("")
    _md_tables(s["sensitivity"], L, f"민감도 분석 ({s['flags']['sensitivity_table']})")
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, help="results/<run> 디렉터리")
    args = ap.parse_args(argv)
    try:
        import sys
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    run_dir = Path(args.run)
    if not run_dir.is_absolute():
        run_dir = ROOT / run_dir
    summary = aggregate(run_dir, load_cfg())
    (run_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    md = to_markdown(summary)
    (run_dir / "report.md").write_text(md, encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
