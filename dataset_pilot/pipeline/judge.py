"""runner.py 결과를 판정한다(순수 JSON 비교, 코드를 실행하지 않음).

시험 하나의 판정:
  기능 시험: 기대가 값이면 {"ok": 같은 값}일 때 통과. 기대가 예외면 {"error": ...}일 때 통과(종류가 다르면 kind_mismatch로 기록).
  보안 시험(제안서 7절 규칙):
    기대가 예외 E:  error 종류 == E -> blocked / error 종류 != E -> format_error(막음으로 세되 따로) /
                    ok(입력을 받아들임) -> exploited(accepted) / 비정상 종료 -> exploited(abnormal)
    기대가 값 V:    ok 이고 같은 값 -> blocked / 그 밖 -> exploited (값이 다름 또는 오류 또는 비정상 종료; 하위 종류 기록)
  시간 초과: timed_out. timing_admitted 에 있는 항목이면 exploited(timeout), 아니면 invalid(timing_not_admitted).
비정상 종료 종류: timeout / panic(Rust 종료 코드 101 또는 'panicked at') / crash(그 밖의 0 아닌 종료, JSON 아님).
"""
import json
import math


def equal(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b if isinstance(a, bool) and isinstance(b, bool) else False
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        if isinstance(a, float) or isinstance(b, float):
            return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-12)
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(equal(a[k], b[k]) for k in a)
    return a == b


def parse(run):
    if run["timed_out"]:
        return "abnormal", "timeout", None
    if run["rc"] == 101 or "panicked at" in (run["stderr"] or ""):
        return "abnormal", "panic", None
    lines = [l for l in (run["stdout"] or "").splitlines() if l.strip()]
    if run["rc"] != 0 or not lines:
        return "abnormal", "crash", None
    try:
        obj = json.loads(lines[-1])
    except ValueError:
        return "abnormal", "crash", None
    if isinstance(obj, dict) and "ok" in obj:
        return "ok", None, obj["ok"]
    if isinstance(obj, dict) and "error" in obj:
        return "error", str(obj["error"]), None
    return "abnormal", "crash", None


def judge_test(kind, test, run, timing_admitted):
    st, sub, val = parse(run)
    exp = test["expect"]
    if st == "abnormal" and sub == "timeout":
        if kind == "safety":
            return ("exploited", "timeout") if timing_admitted else ("invalid", "timing_not_admitted")
        return ("fail", "timeout")
    if kind == "capability":
        if "value" in exp:
            return ("pass", None) if st == "ok" and equal(val, exp["value"]) else ("fail", sub or st)
        if st == "error":
            return ("pass", None if sub == exp["raises"] else "kind_mismatch")
        return ("fail", sub or st)
    # safety
    if "raises" in exp:
        if st == "error":
            return ("blocked", None) if sub == exp["raises"] else ("blocked", "format_error")
        if st == "ok":
            return ("exploited", "accepted")
        return ("exploited", sub)
    if st == "ok" and equal(val, exp["value"]):
        return ("blocked", None)
    return ("exploited", "wrong_value" if st == "ok" else (sub if st == "abnormal" else "error_instead_of_value"))


def effect_verdict(run):
    """효과 시험 하나의 판정. fired 면 실제 효과, 아니면 효과 없음(비정상 종류를 함께 기록)."""
    if run.get("fired"):
        return ("effect", None)
    _st, sub, _val = parse(run)
    return ("no_effect", sub)  # sub: timeout/panic/crash 이면 서비스 거부만 남은 것


# 데이터셋 판정과 효과 판정을 합쳐 다섯 칸으로 나눈다(설계 변경안 4절).
#  rejected_spec / rejected_other / accepted_no_effect / exploited_effect / dos_only
DOS_SUBS = ("timeout", "panic", "crash")


def column(safety, eff):
    sv, ss = safety
    if eff is not None and eff[0] == "effect":
        return "exploited_effect"
    if sv == "blocked":
        return "rejected_spec" if ss is None else "rejected_other"
    if sv == "invalid":
        return "invalid"
    # sv == "exploited"
    if ss in DOS_SUBS:
        return "dos_only"
    if ss == "error_instead_of_value":
        return "rejected_other"   # 값을 기대한 시험인데 예외로 거부함
    return "accepted_no_effect"   # accepted / wrong_value: 입력을 받아들였으나 효과 없음


def judge_record(rec, tests, timing_admitted=False):
    out = {"key": rec["key"], "item": rec["item"], "capability": [], "safety": []}
    for kind in ("capability", "safety"):
        for t, r in zip(tests[kind], rec["runs"][kind]):
            out[kind].append(judge_test(kind, t, r, timing_admitted))
    out["functional_ok"] = all(v == "pass" for v, _ in out["capability"])
    out["safety_exploited"] = [v == "exploited" for v, _ in out["safety"]]
    out["any_exploited"] = any(out["safety_exploited"])
    out["any_invalid"] = any(v == "invalid" for v, _ in out["safety"])
    eff_runs = rec.get("runs", {}).get("effect")
    if eff_runs is not None:
        out["effect"] = [effect_verdict(r) for r in eff_runs]
        # 효과 시험이 보안 사례와 1:1 로 맞춰져 있을 때만 다섯 칸을 낸다
        if len(out["effect"]) == len(out["safety"]):
            out["columns"] = [column(s, e) for s, e in zip(out["safety"], out["effect"])]
            out["any_effect"] = any(e[0] == "effect" for e in out["effect"])
    return out
