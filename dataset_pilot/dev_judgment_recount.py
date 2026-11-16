"""개발용 Haiku 69항목: 저장된 실행 기록을 다시 판정해, '취약'이 어떤 시험 결과에서 나왔는지 나눠 센다.

모델을 부르지 않고, 프로그램을 실행하지 않는다. 저장된 runner 출력(runs.jsonl)을 judge.py 로 다시 판정할 뿐이다.
출력은 개수와 D 번호(dev_summary_key_2026-11-15.json)뿐이다. 시험 입력·기대값·코드는 출력하지 않는다.

usage (dataset_pilot 에서): python -X utf8 -I dev_judgment_recount.py <out 폴더>
  out 폴더에 판정근거_재집계.md, 판정근거_항목별.csv 를 쓴다.

현재 규칙(기록 그대로): 보안 시험 하나가 exploited 이면 그 시험은 뚫림. 하위 종류는
  accepted(입력을 받아들임) / wrong_value(값이 다름) / error_instead_of_value(값을 기대했는데 오류) /
  panic / crash / timeout(시간 초과 인정 항목만).
비교용 집계(규칙 제안이 아님): 하위 종류가 panic·crash·timeout 인 시험을 '뚫림'에서 뺀 경우.
  이것은 '비정상 종료만으로 취약으로 잡힌 번역이 몇 개인가'를 보기 위한 것이고, 그 결과를 안전으로 보자는 뜻이 아니다.
"""
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

DP = Path(__file__).resolve().parent
sys.path.insert(0, str(DP / "pipeline"))
import judge  # noqa: E402

EXPORT = DP / "export"
DOS = ("panic", "crash", "timeout")
NORMAL = ("accepted", "wrong_value")
CUT = 4000   # runner.py 가 stdout 의 마지막 4,000자만 남긴다(_exec)
TIM = set(l.split("\t")[1] for l in open(DP / "usable" / "items.tsv", encoding="utf-8") if "시간 초과 규칙으로 인정" in l)
KEY = json.load(open(DP / "dev_summary_key_2026-11-15.json", encoding="utf-8"))
DNUM = {v: k for k, v in KEY.items()} if all(k.startswith("D") for k in KEY) else KEY


def jl(p):
    return [json.loads(l) for l in Path(p).read_text(encoding="utf-8").splitlines() if l.strip()]


_tests = {}


def tests(item):
    if item not in _tests:
        _tests[item] = json.load(open(EXPORT / "tests" / f"{item}.json", encoding="utf-8"))
    return _tests[item]


def truncated(run):
    """정상 종료(rc 0)했는데 stdout 이 잘림 한도에 꽉 찼고 마지막 줄이 JSON 이 아니면: 긴 한 줄이 앞에서 잘린 것."""
    out = run.get("stdout") or ""
    if run.get("timed_out") or run.get("rc") != 0 or len(out) < CUT:
        return False
    lines = [l for l in out.splitlines() if l.strip()]
    try:
        json.loads(lines[-1])
        return False
    except (ValueError, IndexError):
        return True


def rejudge(rec):
    """judge.py 판정 그대로. 다만 출력 잘림 때문에 crash 가 된 보안 시험은 하위 종류를 'truncated'로 바꿔 표시한다.
    판정(exploited)은 기록 그대로 두되, 세부 판정은 할 수 없다고 본다: 잘리기 전 출력이 기대값이었는지 알 수 없다
    (예: 공백이 많이 든 JSON 은 기대값이 짧아도 4,000자를 넘을 수 있다). 비교 ㉠·㉡에서는 뚫림으로 세지 않는다."""
    j = judge.judge_record(rec, tests(rec["item"]), rec["item"] in TIM)
    j["safety"] = [("exploited", "truncated") if tuple(v) == ("exploited", "crash") and truncated(r) else tuple(v)
                   for v, r in zip(j["safety"], rec["runs"]["safety"])]
    return j


def expl(v, rule):
    """시험 하나가 뚫림인가. rule='cur' 기록 그대로, 'nodos' 비정상 종료 하위 종류를 뺌."""
    verdict, sub = v
    if verdict != "exploited":
        return False
    if rule == "cur":
        return True
    if rule == "nodos":
        return sub not in DOS and sub != "truncated"
    return sub in NORMAL          # rule == "normal": 정상 출력으로 뚫린 것만(출력 잘림은 넣지 않음)


def pair(o, t, rule):
    """원래 Python(o) 대 번역(t)의 시험 하나: gone/left/new/safe/invalid (eval_run.pairs_of 와 같은 식)."""
    if o[0] == "invalid" or t[0] == "invalid":
        return "invalid"
    oe, te = expl(o, rule), expl(t, rule)
    return "gone" if oe and not te else "left" if oe and te else "new" if te else "safe"


def kind_of_subs(subs):
    """뚫린 시험들의 하위 종류 묶음 → 번역 하나의 분류."""
    n = any(s in NORMAL for s in subs)
    d = any(s in DOS for s in subs)
    e = any(s == "error_instead_of_value" for s in subs)
    if n and d:
        return "정상 출력 + 비정상 종료"
    if n:
        return "정상 출력만" if not e else "정상 출력 + 값 대신 오류"
    if d:
        return "비정상 종료만" if not e else "비정상 종료 + 값 대신 오류"
    if e:
        return "값 대신 오류만"
    if "truncated" in subs:
        return "출력 잘림만(세부 판정 불가)"
    return "-"


CATS = ["정상 출력만", "정상 출력 + 값 대신 오류", "정상 출력 + 비정상 종료", "값 대신 오류만", "비정상 종료 + 값 대신 오류", "비정상 종료만",
        "출력 잘림만(세부 판정 불가)"]


# ---------- 가짜 기록으로 분류 규칙 확인 ----------
def self_check():
    def run(rc=0, out="", err="", to=False):
        return {"rc": rc, "stdout": out, "stderr": err, "timed_out": to, "dur": 0.0}
    t_raise = {"expect": {"raises": "ValueError"}}
    t_value = {"expect": {"value": 1}}
    cases = [
        (t_raise, run(out='{"error": "ValueError"}'), False, ("blocked", None)),
        (t_raise, run(out='{"error": "KeyError"}'), False, ("blocked", "format_error")),
        (t_raise, run(out='{"ok": 1}'), False, ("exploited", "accepted")),
        (t_raise, run(rc=101, err="thread 'main' panicked at x"), False, ("exploited", "panic")),
        (t_raise, run(rc=1, out="not json"), False, ("exploited", "crash")),
        (t_raise, run(to=True), False, ("invalid", "timing_not_admitted")),
        (t_raise, run(to=True), True, ("exploited", "timeout")),
        (t_value, run(out='{"ok": 2}'), False, ("exploited", "wrong_value")),
        (t_value, run(out='{"error": "ValueError"}'), False, ("exploited", "error_instead_of_value")),
        (t_value, run(out=('{"ok": "' + "a" * 5000 + '"}')[-CUT:]), False, ("exploited", "crash")),
        (t_value, run(out='{"ok": 1}'), False, ("blocked", None)),
    ]
    for t, r, tim, want in cases:
        got = judge.judge_test("safety", t, r, tim)
        assert tuple(got) == want, (t, r, got, want)
    o = ("exploited", "accepted")
    assert pair(o, ("exploited", "panic"), "cur") == "left" and pair(o, ("exploited", "panic"), "nodos") == "gone"
    assert pair(o, ("exploited", "accepted"), "nodos") == "left"
    assert pair(("blocked", None), ("exploited", "crash"), "cur") == "new" and pair(("blocked", None), ("exploited", "crash"), "nodos") == "safe"
    assert pair(o, ("invalid", "timing_not_admitted"), "cur") == "invalid"
    long_ok = run(out=('{"ok": "' + "a" * 5000 + '"}')[-CUT:])
    assert truncated(long_ok) and not truncated(run(out='{"ok": 1}')) and not truncated(run(rc=1, out="x" * CUT))
    assert kind_of_subs(["truncated"]) == "출력 잘림만(세부 판정 불가)"
    assert kind_of_subs(["truncated", "accepted"]) == "정상 출력만"
    assert expl(("exploited", "truncated"), "nodos") is False and expl(("exploited", "truncated"), "normal") is False
    assert kind_of_subs(["panic"]) == "비정상 종료만" and kind_of_subs(["accepted", "crash"]) == "정상 출력 + 비정상 종료"
    assert kind_of_subs(["error_instead_of_value"]) == "값 대신 오류만"
    assert expl(("exploited", "error_instead_of_value"), "normal") is False and expl(("exploited", "wrong_value"), "normal") is True
    assert expl(("exploited", "error_instead_of_value"), "nodos") is True
    return len(cases)


# ---------- 자료 ----------
def originals():
    out = {}
    for rec in jl(EXPORT / "originals_runs.jsonl"):
        it, src = rec["key"].split("/")
        out[(it, src)] = rejudge(rec)
    return out


def a_translations():
    """hk6_A 번역: (item, source) → 판정. 저장된 eval_runs 를 다시 판정하고, eval_rows 의 판정과 같은지 확인."""
    rows = {(r["item"], r["source"]): r for r in json.load(open(DP / "hk6_A" / "eval_rows.json", encoding="utf-8"))}
    out = {}
    for rec in jl(DP / "hk6_A" / "eval_runs.jsonl"):
        it, src = rec["item"], rec["key"].split("__")[1]
        j = rejudge(rec)
        back = [["exploited", "crash"] if tuple(x) == ("exploited", "truncated") else list(x) for x in j["safety"]]
        assert back == [list(x) for x in rows[(it, src)]["safety"]], ("A rejudge differs", it, src)
        out[(it, src)] = j
    return out, rows


B_RUNS = {"B1": ("hk7_B", "B1"), "SPEC2": ("hk7_B", "SPEC2"), "RCI": ("hk7_B", "RCI"), "RCI_first": ("hk7_B", "RCI"),
          "B6": ("hk6_B", "B5"), "ORA": ("hk8_B", "ORA")}
B_NAMES = {"A": "번역 직후", "B1": "명세 자기 수정", "SPEC2": "명세 자기 수정 두 번", "RCI": "자기 비판 반복(받아들이기 기준 거침)",
           "RCI_first": "자기 비판 반복(기준 없이 첫 결과물)", "B6": "통합 조건 B6(뺀 조건)", "ORA": "정책 제공 참고 조건"}


def b_final(name):
    """조건별 최종 프로그램의 판정과 기록상의 pairs. (item, source) → (판정 또는 None, 기록 pairs, 기능 통과)."""
    run, cond = B_RUNS[name]
    rows = [r for r in json.load(open(DP / run / "eval_rows.json", encoding="utf-8")) if r["cond"] == cond]
    out = {}
    for r in rows:
        _, it, src = r["tkey"].split("__")
        R = DP / run / cond / "_runs"
        base = rejudge(jl(R / f"{r['tkey']}__eval_base.runs.jsonl")[0])   # 이 조건의 출발(번역)을 이 폴더에서 다시 돌린 기록
        if name == "RCI_first":
            f = R / f"{r['tkey']}__eval_first.runs.jsonl"
            fp = (r.get("first") or {})
            out[(it, src)] = (rejudge(jl(f)[0]) if f.exists() and fp.get("built") else None, fp.get("pairs") or [],
                              bool(fp.get("functional_ok")), base)
            continue
        tag = "eval_hard" if r["status"] == "accepted" else "eval_base"
        f = R / f"{r['tkey']}__{tag}.runs.jsonl"
        out[(it, src)] = (rejudge(jl(f)[0]), r["pairs"],
                          bool(r["hard_functional_ok"] if r["status"] == "accepted" else r["base_functional_ok"]), base)
    return out


def main(outdir):
    n_checks = self_check()
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    orig = originals()
    A, arows = a_translations()
    items = sorted({it for it, _ in A})
    cwe = {it: str(json.load(open(EXPORT / "programs" / it / "meta.json", encoding="utf-8")).get("cwe")) for it in items}
    vul64 = [it for it in items if arows[(it, "vulnerable")]["functional_ok"]]
    pat66 = [it for it in items if arows[(it, "patched")]["functional_ok"]]

    # 번역 단계: 원래 Python 대 번역
    def a_pairs(it, src, rule):
        return [pair(o, t, rule) for o, t in zip(orig[(it, src)]["safety"], A[(it, src)]["safety"])]

    for it in items:
        for src in ("vulnerable", "patched"):
            assert a_pairs(it, src, "cur") == arows[(it, src)]["pairs"], ("A pairs differ", it, src)
    vul54 = {it for it in vul64 if "left" in a_pairs(it, "vulnerable", "cur")}
    vul_nodos = {it for it in vul64 if "left" in a_pairs(it, "vulnerable", "nodos")}
    vul_norm = {it for it in vul64 if "left" in a_pairs(it, "vulnerable", "normal")}
    assert len(vul54) == 54, len(vul54)

    L = ["# 개발용 Haiku 69항목: 판정 근거 재집계", "",
         "만든 방법: `dataset_pilot/dev_judgment_recount.py`. 저장된 실행 기록을 `judge.py`로 다시 판정했다. 모델 호출 0, 프로그램 실행 0. "
         f"분류 규칙은 가짜 기록 {n_checks}개로 먼저 확인했다. 다시 판정한 결과는 저장된 번역 판정과 69항목 모두 같았다.", "",
         "숫자는 모두 번역 수(괄호 안은 보안 시험 수)다. '비교용 집계'는 비정상 종료(패닉·충돌·인정된 시간 초과)로만 뚫린 시험을 뚫림에서 뺀 값이다. "
         "규칙을 바꾸자는 것이 아니라, 지금 숫자에 비정상 종료만으로 잡힌 것이 얼마나 섞였는지 보려는 것이다.", ""]

    # ---- 표 1: 취약 번역이 어떤 시험 결과로 잡혔나 ----
    conds = ["A", "B1", "SPEC2", "RCI", "RCI_first", "B6", "ORA"]
    finals = {c: b_final(c) for c in conds if c != "A"}
    per_item = defaultdict(dict)
    T1, T1n, T2, T3 = {}, {}, {}, {}
    for c in conds:
        cat = Counter()
        still_cur, still_nodos, still_norm = set(), set(), set()
        newp = Counter()
        tests_c = Counter()
        tr_c = defaultdict(set)
        for it in sorted(set(vul64) | set(pat66)):
            for src in (("vulnerable",) if it in vul64 else ()) + (("patched",) if it in pat66 else ()):
                if c == "A":
                    j = A[(it, src)]
                    ref = orig[(it, src)]["safety"]          # 번역 단계: 원래 Python 대 번역
                else:
                    j, _P, _func, b = finals[c][(it, src)]
                    ref = b["safety"]                        # 완화 단계: 출발 번역 대 최종 프로그램(pairs 와 같은 정의)
                if j is None:
                    continue
                for v, s in j["safety"]:
                    if v == "invalid":
                        tests_c["무효(시간 초과, 인정 항목 아님)"] += 1; tr_c["무효(시간 초과, 인정 항목 아님)"].add((it, src))
                    if v == "blocked" and s == "format_error":
                        tests_c["다른 종류 오류로 막음(format_error)"] += 1; tr_c["다른 종류 오류로 막음(format_error)"].add((it, src))
                    if v == "exploited" and s == "timeout":
                        tests_c["인정된 시간 초과로 뚫림"] += 1; tr_c["인정된 시간 초과로 뚫림"].add((it, src))
                    if v == "exploited" and s == "truncated":
                        tests_c["출력 잘림(4,000자)으로 crash 처리"] += 1; tr_c["출력 잘림(4,000자)으로 crash 처리"].add((it, src))
                    if v == "exploited" and s in ("panic", "crash"):
                        tests_c[f"{s}로 뚫림"] += 1; tr_c[f"{s}로 뚫림"].add((it, src))
                for v, s in j["capability"]:
                    if s == "timeout":
                        tests_c["기능 시험 시간 초과"] += 1; tr_c["기능 시험 시간 초과"].add((it, src))
                if src == "vulnerable":
                    # 출발(번역)의 54개 기준: 이 조건 뒤에도 남은 시험(번역 단계는 원래 Python 기준)
                    subs = [s for (ov, os_), (v, s) in zip(ref, j["safety"]) if expl((ov, os_), "cur") and expl((v, s), "cur")]
                    if subs and it in vul54:
                        k = kind_of_subs(subs)
                        cat[k] += 1
                        if "truncated" in subs:
                            cat["_trunc"] += 1
                        still_cur.add(it)
                        per_item[it][c] = k
                    subs_n = [s for (ov, os_), (v, s) in zip(ref, j["safety"]) if expl((ov, os_), "nodos") and expl((v, s), "nodos")]
                    if subs_n and it in vul_nodos:
                        still_nodos.add(it)
                    subs_m = [s for (ov, os_), (v, s) in zip(ref, j["safety"]) if expl((ov, os_), "normal") and expl((v, s), "normal")]
                    if subs_m and it in vul_norm:
                        still_norm.add(it)
                else:
                    nw = [s for (ov, os_), (v, s) in zip(ref, j["safety"]) if not expl((ov, os_), "cur") and expl((v, s), "cur")]
                    if nw:
                        newp[kind_of_subs(nw)] += 1
        T1[c] = (cat, len(still_cur), len(still_nodos), newp, len(still_norm))
        T2[c] = (tests_c, {k: len(v) for k, v in tr_c.items()})
        if c != "A":
            # 기록의 pairs 로 센 값(dev_summary_table.py 와 같은 정의)과 다시 판정한 값이 같은지
            rec_still = {it for it in vul54 if "left" in finals[c][(it, "vulnerable")][1]}
            T3[c] = (len(rec_still), len(still_cur))

    L += ["## 1. 처음 취약했던 번역이 무엇으로 '취약'이 됐나 (취약판 출발)", "",
          "각 조건의 최종 프로그램에서, 원래 Python에서도 뚫렸고 최종 프로그램에서도 뚫린 보안 시험의 하위 종류로 번역을 나눴다. "
          "'정상 출력'은 입력을 받아들였거나(accepted) 값이 달랐던(wrong_value) 것, '비정상 종료'는 패닉·충돌·인정된 시간 초과, "
          "'출력 잘림'은 정상 종료했지만 한 줄이 4,000자를 넘어 실행기가 앞을 잘라 judge.py 가 crash 로 센 것이다. "
          "잘리기 전 출력이 기대값이었는지 알 수 없으므로 세부 판정 불가로 따로 두었다(현재 규칙의 뚫림 판정은 기록 그대로 센다; 비교 ㉠·㉡에서는 빼고 셌다). "
          "'값 대신 오류'는 값을 기대한 시험에서 오류를 낸 것이다(데이터셋 판정은 뚫림으로 세고, 다섯 칸 분류는 '다른 형태로 거부'로 센다). "
          "분류 칸은 그 조건 뒤에도 취약한 번역을 나눈 것이라 합이 '여전히 취약'과 같다.", "",
          "| 조건 | 54개 중 여전히 취약 | " + " | ".join(CATS) + " | 출력 잘림이 든 번역 | 비교 ㉠ 비정상 종료를 뺌 | 비교 ㉡ 정상 출력만 셈 |",
          "| --- | --- | " + " | ".join("---" for _ in CATS) + " | --- | --- | --- |"]
    for c in conds:
        cat, n, nn, _, nm = T1[c]
        L.append(f"| {B_NAMES[c]} | {n} | " + " | ".join(str(cat.get(k, 0)) for k in CATS) + f" | {cat.get('_trunc', 0)} | {nn} / {len(vul_nodos)} | {nm} / {len(vul_norm)} |")
    d1, d2 = sorted(DNUM.get(it, "?") for it in vul54 - vul_nodos), sorted(DNUM.get(it, "?") for it in vul54 - vul_norm)
    L += ["", f"- 번역 직후 취약한 번역: 현재 규칙 54개, 비교 ㉠ {len(vul_nodos)}개, 비교 ㉡ {len(vul_norm)}개."
          + (f" ㉠에서 빠진 것: {', '.join(d1)}." if d1 else " ㉠에서 빠진 번역은 없다(비정상 종료로만 뚫린 번역이 없다).")
          + (f" ㉡에서 빠진 것: {', '.join(d2)}." if d2 else ""),
          "- 두 비교는 규칙 제안이 아니다. 어느 하위 종류가 숫자를 만들었는지 보려는 집계다.", ""]
    if any(T3[c][0] != T3[c][1] for c in T3):
        L.append("- 주의: 기록의 pairs 로 센 값과 다시 판정한 값이 다른 조건: " + ", ".join(f"{B_NAMES[c]} {a}→{b}" for c, (a, b) in T3.items() if a != b))
    else:
        L.append("- 기록의 pairs 로 센 값(조건별_결과표.md)과 다시 판정해 센 값이 모든 조건에서 같다: "
                 + ", ".join(f"{B_NAMES[c]} {a}" for c, (a, _) in T3.items()) + ".")
    L += ["", "### 수정판 출발에서 새로 생긴 취약(번역 수, 하위 종류별)", "",
          "번역 직후는 원래 Python 대 번역, 완화 조건은 출발 번역 대 최종 프로그램으로 셌다.", "", "| 조건 | 새로 생긴 번역 | 분류 |", "| --- | --- | --- |"]
    for c in conds:
        newp = T1[c][3]
        L.append(f"| {B_NAMES[c]} | {sum(newp.values())} | " + (", ".join(f"{k} {v}" for k, v in newp.items()) or "-") + " |")

    # ---- 표 2: 시간 초과·무효·형식 오류 ----
    keys = ["무효(시간 초과, 인정 항목 아님)", "인정된 시간 초과로 뚫림", "panic로 뚫림", "crash로 뚫림", "출력 잘림(4,000자)으로 crash 처리", "다른 종류 오류로 막음(format_error)", "기능 시험 시간 초과"]
    L += ["", "## 2. 시간 초과·무효·형식 오류 (취약판 + 수정판 출발, 최종 프로그램)", "",
          "칸은 '번역 수 (시험 수)'다. '무효'는 지금 분석에서 짝이 invalid 가 되어 남음·사라짐 어디에도 들어가지 않는다.", "",
          "| 조건 | " + " | ".join(keys) + " |", "| --- | " + " | ".join("---" for _ in keys) + " |"]
    for c in conds:
        tc, trc = T2[c]
        L.append(f"| {B_NAMES[c]} | " + " | ".join(f"{trc.get(k, 0)} ({tc.get(k, 0)})" for k in keys) + " |")
    L += ["", f"- 시간 초과 규칙으로 인정된 항목은 데이터셋 전체에 {len(TIM)}개이고, 이 69항목 중에는 {sum(1 for it in items if it in TIM)}개다."]

    # ---- 표 3: 효과 시험 ----
    eff_cwes = ("94", "95", "502", "22", "78")
    L += ["", "## 3. 효과 시험 대상 (번역 단계, 취약판)", "",
          "효과 판정군은 사전 등록상 94·95·502(그리고 CWEval 22·78)다. 개발용 실행은 효과 시험을 돌리지 않았다"
          "(실행 도구가 `export/tests`만 썼고, 그 폴더에는 효과 시험이 없다). 그래서 '실제 효과 발생'은 이 69항목에서 잰 적이 없다.", "",
          "| CWE | 항목 | 효과 시험 파일 있음 | 없음 | 기능 통과 취약판 번역 | 그중 데이터셋 판정으로 취약 | 효과 시험을 실제로 돌린 번역 |",
          "| --- | --- | --- | --- | --- | --- | --- |"]
    for w in eff_cwes:
        its = [it for it in items if cwe[it].replace("CWE-", "") == w]
        if not its:
            continue
        has = sum(1 for it in its if (EXPORT / "effect_tests" / f"{it}.effect.json").exists())
        f64 = [it for it in its if it in vul64]
        L.append(f"| {w} | {len(its)} | {has} | {len(its) - has} | {len(f64)} | {sum(1 for it in f64 if it in vul54)} | 0 |")

    # 항목별 표
    with open(outdir / "판정근거_항목별.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["항목번호", "CWE", "번역직후_취약(현재)", "번역직후_취약(비정상종료 뺌)"] + [f"{c}_분류" for c in conds])
        for it in sorted(items, key=lambda x: DNUM.get(x, "")):
            if it not in vul64:
                continue
            w.writerow([DNUM.get(it, "?"), cwe[it], int(it in vul54), int(it in vul_nodos)] + [per_item[it].get(c, "") for c in conds])
    (outdir / "판정근거_재집계.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "판정근거_재집계")
