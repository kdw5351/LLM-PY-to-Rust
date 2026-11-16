"""analyze_main.py 의 단위 확인과 보정(모의) 확인. 모델 호출 없음, 확증용 자료 없음(묶음 크기 분포만 읽음).
unit 의 dev_decision_checks 는 개발용 자료(pilot_A_v2·pilot_Bc_GFv2)와 가짜 답 점검(_dry_main/run6)을 읽기만 하고
결과는 임시 폴더에 쓴다(결정 13: 이전 판정 재현과 새 기본값 판정, 라벨만 비교).

usage: python analyze_main_checks.py unit
       python analyze_main_checks.py sim [--n 1000] [--perm 2000] [--boot 1000] [--seed 20261113] [--out sim.json]
출력은 개수·통계만.
"""
import argparse
import itertools
import math
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analyze_main as AM  # noqa: E402


# ---------------------------------------------------------------- 단위 확인
def unit():
    res = []

    def check(name, got, want):
        ok = got == want if not isinstance(want, float) else abs(got - want) < 1e-9
        res.append((name, ok))
        print(("PASS" if ok else "FAIL"), name, "" if ok else f"got={got} want={want}")
    check.skipped = []      # (이름, 이유): 자료가 없어 돌리지 못한 확인. 실패로 세지 않는다

    # Holm — 손으로 계산한 값
    H = AM.holm([("a", 0.01), ("b", 0.04), ("c", 0.03), ("d", 0.005)])
    for k, w in {"d": 0.02, "a": 0.03, "c": 0.06, "b": 0.06}.items():
        check(f"holm4 {k}", round(H[k]["p_holm"], 12), w)
    check("holm4 rejects", sorted(k for k, v in H.items() if v["reject"]), ["a", "d"])
    seven = [("H1", 0.001), ("H4", 0.01), ("2-ga-1", 0.02), ("2-ga-2", 0.03), ("2-na", 0.04), ("4-ga", 0.2), ("4-na", 0.5)]
    H = AM.holm(seven)
    for k, w in {"H1": 0.007, "H4": 0.06, "2-ga-1": 0.10, "2-ga-2": 0.12, "2-na": 0.12, "4-ga": 0.4, "4-na": 0.5}.items():
        check(f"holm7 {k}", round(H[k]["p_holm"], 12), w)
    check("holm7 rejects", sorted(k for k, v in H.items() if v["reject"]), ["H1"])
    H = AM.holm(seven[:5])        # 4단계가 없을 때 5개
    for k, w in {"H1": 0.005, "H4": 0.04, "2-ga-1": 0.06, "2-ga-2": 0.06, "2-na": 0.06}.items():
        check(f"holm5 {k}", round(H[k]["p_holm"], 12), w)
    check("holm5 rejects", sorted(k for k, v in H.items() if v["reject"]), ["H1", "H4"])
    H = AM.holm([("x", 0.03), ("y", 0.03)])
    check("holm ties", (H["x"]["p_holm"], H["y"]["p_holm"]), (0.06, 0.06))

    # 동등성·비열등
    d = 0.05
    check("equiv inside", AM.equivalent([-0.03, 0.04], d), True)
    check("equiv lower out", AM.equivalent([-0.06, 0.01], d), False)
    check("equiv upper out", AM.equivalent([-0.01, 0.051], d), False)
    check("equiv at bound", AM.equivalent([-0.05, 0.0], d), False)
    check("equiv none", AM.equivalent(None, d), False)
    check("noninf ok", AM.noninferior([-0.04, 0.10], d), True)
    check("noninf fail", AM.noninferior([-0.051, 0.10], d), False)

    # 4단계 결론(결정 11-2, 일곱 줄; 이전 4절 다섯 줄 표의 확인 11개를 대체)
    s4_checks(check)
    ci_checks(check)
    col3_checks(check)
    misc_r3_checks(check)

    # McNemar 정확
    check("mcnemar 0/5", AM.mcnemar_exact(0, 5), 0.0625)
    check("mcnemar 0/0", AM.mcnemar_exact(0, 0), 1.0)
    check("mcnemar 3/3", AM.mcnemar_exact(3, 3), 1.0)

    # 치환 검정: 작은 경우를 완전 열거와 비교
    dfam = [3, 2, 1, 1, -1, 2, 0, 4]
    units = []
    for f, dv in enumerate(dfam):
        for _ in range(abs(dv)):
            units.append((f"f{f}", 1, 0) if dv > 0 else (f"f{f}", 0, 1))
        units.append((f"f{f}", 1, 1))
    nz = [x for x in dfam if x]
    T = sum(dfam)
    exact = np.mean([abs(sum(s * x for s, x in zip(sg, nz))) >= abs(T) for sg in itertools.product((-1, 1), repeat=len(nz))])
    mc = AM.perm_test(units, 1, "unit", 20000, True)["p"]
    check("perm vs exact |diff|<0.01", abs(mc - exact) < 0.01, True)
    print(f"  perm exact {exact:.4f}  monte-carlo {mc:.4f}")
    check("perm all-zero p", AM.perm_test([("f", 1, 1), ("g", 0, 0)], 1, "z", 100, True)["p"], 1.0)
    b = AM.boot_ci([("f", 1, 1), ("g", 0, 0)], 1, "z", 200, True)
    check("boot all-zero", (b["count_ci95"], b["prop_ci90"]), ([0.0, 0.0], [0.0, 0.0]))
    # 묶음 치환은 묶음 안에서 같이 뒤집는다: 한 묶음에 모든 차이 -> p = 1
    check("perm single family", AM.perm_test([("f", 1, 0)] * 6, 1, "one", 2000, True)["p"], 1.0)
    check("perm naive same data small p", AM.perm_test([("f", 1, 0)] * 6, 1, "one", 2000, False)["p"] < 0.05, True)

    # 모델 방향 갈림 표시
    U = [("m1", "it1", 1, 0)] * 5 + [("m2", "it2", 0, 1)] * 2
    pc = AM.paired_compare(U, "dir", 1, 500, 200, 0.05)
    check("direction flag", (pc["diff"], pc["direction_disagrees"]), (3, ["m2"]))

    # 단일 취약 판정식(결정 4절)
    e_fire, e_none = ["effect", None], ["no_effect", None]
    v_eff_noexec = {"pairs": ["left"], "safety": [["exploited", "accepted"]], "effect": [e_none], "columns": ["accepted_no_effect"]}
    v_eff_exec = {"pairs": ["left"], "safety": [["exploited", "accepted"]], "effect": [e_fire], "columns": ["exploited_effect"]}
    v_eff_missing = {"pairs": ["left"], "safety": [["exploited", "accepted"]], "effect": None, "columns": None}
    v_logic = {"pairs": ["left"], "safety": [["exploited", "accepted"]], "effect": None, "columns": None}
    check("rule effect ③ not vulnerable", AM.s1_vuln(v_eff_noexec, 502, "primary"), (0, "effect"))
    check("rule effect ④ vulnerable", AM.s1_vuln(v_eff_exec, 502, "primary"), (1, "effect"))
    check("rule effect missing -> dataset", AM.s1_vuln(v_eff_missing, 502, "primary"), (1, "dataset"))
    check("rule sensitivity dataset", AM.s1_vuln(v_eff_noexec, 502, "dataset"), (1, "dataset"))
    check("rule logic dataset", AM.s1_vuln(v_logic, 863, "primary"), (1, "dataset"))
    p_dos = {"pairs": ["new"], "safety": [["exploited", "panic"]], "effect": [e_none], "columns": ["dos_only"]}
    p_ok = {"pairs": ["safe"], "safety": [["blocked", None]], "effect": [e_none], "columns": ["rejected_spec"]}
    check("H4 newly via ⑤ (effect class)", AM.s1_newly(p_dos, 94, "primary"), 1)
    check("H4 not newly", AM.s1_newly(p_ok, 94, "primary"), 0)
    x = {"cond": "B1", "cwe": 94, "pairs": ["new"], "effect": [e_none], "base_effect": [e_none], "columns": ["dos_only"]}
    check("stage2 new ⑤", AM.new_after(x)[0], 1)
    x2 = dict(x, columns=["accepted_no_effect"])
    check("stage2 new ③ not counted", AM.new_after(x2)[0], 0)
    check("stage2 new ③ sensitivity dataset", AM.new_after(x2, "dataset")[0], 1)
    y = {"cond": "B1", "cwe": 95, "pairs": ["left"], "effect": [e_none], "base_effect": [e_fire]}
    check("stage2 still vulnerable effect ③ -> 0", AM.vuln_after(y)[0], 0)
    yn = dict(y, cond=AM.NONE, pairs=["removed"])
    check("stage2 NONE uses base effect", AM.vuln_after(yn)[0], 1)
    check("visible null", AM.visible_fail(None), None)
    check("visible passed", AM.visible_fail({"n": 4, "failed": 0, "class": "passed"}), 0)
    check("visible failed", AM.visible_fail({"n": 4, "failed": 1, "class": "failed"}), 1)
    check("visible compile", AM.visible_fail({"n": 4, "failed": 0, "class": "compile"}), 1)

    # Cohen kappa (hand-made): 10 targets, A/B agree on 7; marginals A: x6 y4, B: x5 y5
    la = ["x"] * 6 + ["y"] * 4
    lb = ["x"] * 4 + ["y", "y"] + ["y"] * 3 + ["x"]
    ag, kp = AM.cohen_kappa(la, lb)
    # po = 0.7, pe = 0.6*0.5 + 0.4*0.5 = 0.5, kappa = 0.4
    check("kappa agree", ag, 7)
    check("kappa value", round(kp, 12), 0.4)
    check("kappa perfect", AM.cohen_kappa(["a", "b"], ["a", "b"])[1], 1.0)
    check("kappa one label both", AM.cohen_kappa(["a", "a"], ["a", "a"])[1], 1.0)
    ag, kp = AM.cohen_kappa(["S1"] + ["S2"] * 4 + ["S3"] * 6, ["S1"] + ["S2"] * 4 + ["S3"] * 6)
    check("kappa pilot-like S", (ag, kp), (11, 1.0))

    # 40개 규칙
    check("rule 39 refused", AM.rule_11_7(39)[0], False)
    check("rule 39 sentence", AM.rule_11_7(39)[1], AM.RULE_11_7_SENTENCE)
    check("rule 40 allowed", AM.rule_11_7(40), (True, "within_rule"))
    check("rule None refused", AM.rule_11_7(None)[0], False)
    check("rule override labelled", AM.rule_11_7(5, True), (True, "OUTSIDE_PRE_REGISTERED_RULE"))

    rq_checks(check)
    bca_rule_checks(check)
    dev_decision_checks(check)

    n_ok = sum(ok for _, ok in res)
    k = len(check.skipped)
    for reason in sorted({r for _, r in check.skipped}):
        print(f"SKIPPED {sum(r == reason for _, r in check.skipped)} checks: {reason}")
    print(f"\nunit checks: {n_ok}/{len(res)} passed, {k} skipped" + (" (data not in bundle)" if k else ""))
    return n_ok == len(res)


def s4_checks(check):
    """결정 11-2: 신규 위험 세 갈래(경계 포함), 2%p 보조, 일곱 줄 판정 순서, 겹침 문장."""
    K = AM.classify_new_risk
    d = 0.05
    check("3way upper just below +5 -> noninferior", K([-0.01, 0.0499999], d), "noninferior")
    check("3way upper == +5 -> undecided", K([-0.01, 0.05], d), "undecided")
    check("3way upper just above +5 -> undecided", K([0.0, 0.0500001], d), "undecided")
    check("3way lower == +5 -> undecided", K([0.05, 0.09], d), "undecided")
    check("3way lower just above +5 -> worse", K([0.0500001, 0.09], d), "worse_beyond_margin")
    check("3way negative interval -> noninferior", K([-0.08, -0.06], d), "noninferior")
    check("3way None -> not_available", K(None, d), "not_available")
    check("2pt secondary: same ci, 5pt noninf / 2pt undecided", (K([0.0, 0.03], 0.05), K([0.0, 0.03], 0.02)),
          ("noninferior", "undecided"))
    check("2pt secondary: worse at 2pt only", (K([0.021, 0.04], 0.05), K([0.021, 0.04], 0.02)),
          ("noninferior", "worse_beyond_margin"))
    check("2pt boundary upper == +2 -> undecided", K([0.0, 0.02], 0.02), "undecided")

    C = AM.choose_s4_conclusion
    EQ, WIDE = [-0.03, -0.01], [-0.12, -0.02]       # d_잔여: ±5%p 안 / 밖
    NI, UND, WORSE = [-0.01, 0.02], [0.0, 0.07], [0.06, 0.10]     # d_신규
    # (ga_rej, ga_diff, nb_rej, nb_diff, res_ci90, new_ci90)
    check("s4 row1 worse beyond margin", C(True, -10, True, -6, WIDE, WORSE)[0], 1)
    check("s4 row1 even when residual equivalent", C(False, -1, False, 0, EQ, WORSE)[0], 1)
    check("s4 row1 sentence + residual numbers", C(False, -1, False, 0, EQ, WORSE)[1].startswith(AM.S4_SENT[1] + " (잔여:"), True)
    check("s4 row1 before row2", C(True, 9, False, 0, WIDE, WORSE)[0], 1)
    check("s4 row2 significantly more left", C(True, 9, False, 0, WIDE, NI)[0], 2)
    check("s4 row2 even if new risk undecided", C(True, 9, True, -3, WIDE, UND)[0], 2)
    check("s4 row3", C(True, -10, True, -6, WIDE, NI)[:2], (3, AM.S4_SENT[3]))
    check("s4 row3 significant AND within ±5 -> overlap appended",
          C(True, -10, True, -6, EQ, NI)[:2], (3, AM.S4_SENT[3] + " " + AM.S4_OVERLAP))
    check("s4 row4 nb not significant", C(True, -10, False, -2, WIDE, NI)[:2], (4, AM.S4_SENT[4]))
    check("s4 row4 + overlap", C(True, -10, False, -2, EQ, NI)[2]["overlap_appended"], True)
    check("s4 row5 new risk undecided", C(True, -10, True, -6, WIDE, UND)[:2], (5, AM.S4_SENT[5]))
    check("s4 row5 + overlap", C(True, -10, False, 0, EQ, UND)[1].endswith(AM.S4_OVERLAP), True)
    check("s4 row6 equivalent + noninferior", C(False, -1, False, 0, EQ, NI)[:2], (6, AM.S4_SENT[6]))
    check("s4 row6 no overlap sentence", C(False, -1, False, 0, EQ, NI)[2]["overlap_appended"], False)
    check("s4 row7 not significant, not equivalent", C(False, -3, False, 0, WIDE, NI)[0], 7)
    check("s4 row7 equivalent but new risk undecided", C(False, -1, False, 0, EQ, UND)[0], 7)
    check("s4 row7 names undecided part", "신규 위험" in C(False, -1, False, 0, EQ, UND)[1], True)
    check("s4 row7 nb significant opposite", C(True, -10, True, 4, WIDE, NI)[0], 7)
    check("s4 row7 no new-risk data", C(True, -10, True, -6, WIDE, None)[0], 7)
    check("s4 improve needs Holm reject (not rej, diff<0, equiv) -> row6", C(False, -10, True, -6, EQ, NI)[0], 6)
    check("s4 row7 sentence starts", C(False, -3, False, 0, WIDE, NI)[1].startswith(AM.S4_SENT[7]), True)
    check("s4 residual equivalence boundary excluded", C(False, 0, False, 0, [-0.05, 0.0], NI)[0], 7)


def ci_checks(check):
    """구간 계산법(결정 11-5): t 분위수, 묶음 강건 SE 손 계산, 네 방법의 기본 성질."""
    check("t_ppf df=1 0.975", round(AM.t_ppf(0.975, 1), 4), 12.7062)
    check("t_ppf df=10 0.95", round(AM.t_ppf(0.95, 10), 4), 1.8125)
    check("t_ppf df=316 0.95", round(AM.t_ppf(0.95, 316), 3), 1.650)
    check("t_cdf symmetric", round(AM.t_cdf(0.0, 7), 12), 0.5)
    # 묶음 3개: d = [1, 0, -1], n = [2, 2, 2] -> θ = 0, e = d, SE = sqrt(3/2 * 2)/6 = sqrt(3)/6
    d, n = np.array([1.0, 0.0, -1.0]), np.array([2.0, 2.0, 2.0])
    check("ratio_se hand", round(AM.ratio_se(d, n), 12), round(math.sqrt(3) / 6, 12))
    ci = AM.prop_intervals(d, n, None, "cluster_t")[0.90]
    q = AM.t_ppf(0.95, 2)
    check("cluster_t hand", [round(x, 10) for x in ci], [round(-q * math.sqrt(3) / 6, 10), round(q * math.sqrt(3) / 6, 10)])
    units = [(f"f{i}", 1, 0) for i in range(30)] + [(f"f{i}", 0, 0) for i in range(30)] + \
            [(f"g{i}", 0, 1) for i in range(10)] + [(f"g{i}", 0, 0) for i in range(10)]
    est = (30 - 10) / 80
    outs = {}
    for m in AM.CI_METHODS:
        b = AM.boot_ci(units, 3, "cimeth", 2000, True, method=m)
        outs[m] = b
        check(f"ci {m} contains estimate", b["prop_ci90"][0] <= est <= b["prop_ci90"][1], True)
        check(f"ci {m} 95 wider than 90", b["prop_ci95"][0] <= b["prop_ci90"][0] and b["prop_ci95"][1] >= b["prop_ci90"][1], True)
        check(f"ci {m} recorded", b["ci_method"], m)
    check("ci percentile field = default", outs["percentile"]["prop_ci90"], outs["bca"]["prop_ci90_percentile"])
    z = AM.boot_ci([("f", 1, 1), ("g", 0, 0)], 1, "z", 200, True, method="boot_t")
    check("boot_t all-zero -> point", z["prop_ci90"], [0.0, 0.0])
    z = AM.boot_ci([("f", 1, 1), ("g", 0, 0)], 1, "z", 200, True, method="bca")
    check("bca all-zero -> point", z["prop_ci90"], [0.0, 0.0])


def col3_checks(check):
    """결정 11-4: ③칸 사례 목록, 분류 파일 세 수, 민감도(남음으로 다시 셈)."""
    import tempfile
    import types
    e0 = ["no_effect", "exit0"]
    mkA = lambda it, src, cond, cols, func=True: {  # noqa: E731
        "item": it, "source": src, "cond": cond, "functional_ok": func, "pairs": ["left"] * len(cols),
        "safety": [["exploited", "accepted"]] * len(cols), "effect": [e0 if c != "exploited_effect" else ["effect", "x"]
                                                                       for c in cols], "columns": cols}
    # 항목 이름 cwe_094_* / cwe_502_* -> cwe_of 가 이름에서 CWE 를 읽는다(CWEval 꼴)
    A0 = {("m1", "cwe_094_0", "vulnerable", "PyRs"): mkA("cwe_094_0", "vulnerable", "PyRs", ["accepted_no_effect", "rejected_spec"]),
          ("m1", "cwe_094_0", "vulnerable", "PyPy"): mkA("cwe_094_0", "vulnerable", "PyPy", ["exploited_effect", "rejected_spec"]),
          ("m1", "cwe_502_0", "vulnerable", "PyRs"): mkA("cwe_502_0", "vulnerable", "PyRs", ["accepted_no_effect", "accepted_no_effect"]),
          ("m1", "cwe_502_0", "vulnerable", "PyPy"): mkA("cwe_502_0", "vulnerable", "PyPy", ["accepted_no_effect"]),
          ("m1", "cwe_078_0", "vulnerable", "PyRs"): mkA("cwe_078_0", "vulnerable", "PyRs", ["accepted_no_effect"], func=False),
          ("m1", "cwe_078_0", "vulnerable", "PyPy"): mkA("cwe_078_0", "vulnerable", "PyPy", ["accepted_no_effect"]),
          ("m1", "cwe_863_0", "vulnerable", "PyRs"): mkA("cwe_863_0", "vulnerable", "PyRs", ["accepted_no_effect"])}
    cases = AM.col3_cases(A0, {})
    check("col3 cases: effect classes only, every ③ test", len(cases), 6)
    check("col3 case fields", sorted(k for k in cases[0] if k != "key") == sorted(c for c in AM.COL3_COLS
                                                                                  if c not in ("label", "q1_reached", "q2_risky_feature")), True)
    U0 = AM.h1_units(A0)
    check("h1_units main (func-pass, code-exec)", sorted((u[1], u[2], u[3]) for u in U0),
          [("cwe_094_0", 1, 0), ("cwe_502_0", 1, 1)])
    with tempfile.TemporaryDirectory() as td:
        tsv = Path(td) / "col3.tsv"
        a = types.SimpleNamespace(col3_tsv=str(tsv), col3_labels=None, seed=1, perm=200, boot=200, delta=0.05)
        r, still = AM.col3_block(A0, {}, None, None, a)
        check("col3 export rows", len(tsv.read_text(encoding="utf-8").splitlines()), 7)
        check("col3 no labels -> not available", (isinstance(r["labels"], str), still), (True, None))
        # 분류: 내보낸 목록에 채운다 — 094 PyRs = 공격 표현만 실패, 502 PyRs #0 = 위험 기능 제거, #1 = 구분 불가,
        #       502 PyPy = 위험 기능 제거, 078 PyRs = (빈칸), 078 PyPy = 잘못된 라벨
        lab = {"A|PyRs|m1|cwe_094_0|vulnerable|0": ("공격 표현만 실패", "갔다", "있다"),
               "A|PyRs|m1|cwe_502_0|vulnerable|0": ("위험 기능 제거", "갔다", "없다"),
               "A|PyRs|m1|cwe_502_0|vulnerable|1": ("구분 불가", "알 수 없다", "알 수 없다"),
               "A|PyPy|m1|cwe_502_0|vulnerable|0": ("위험 기능 제거", "갔다", "없다"),
               "A|PyPy|m1|cwe_078_0|vulnerable|0": ("removed?", "", ""),
               "A|PyRs|m1|nope|vulnerable|0": ("구분 불가", "", "")}
        L = tsv.read_text(encoding="utf-8").splitlines()
        hdr = L[0].split("\t")
        out = [L[0]]
        for l in L[1:]:
            f = l.split("\t")
            v = lab.get(f[0])
            if v:
                f[hdr.index("label")], f[hdr.index("q1_reached")], f[hdr.index("q2_risky_feature")] = v
            out.append("\t".join(f))
        out.append("A|PyRs|m1|nope|vulnerable|0\t" + "\t" * 11 + "구분 불가\t\t")
        lp = Path(td) / "labels.tsv"
        lp.write_text("\n".join(out) + "\n", encoding="utf-8")
        a = types.SimpleNamespace(col3_tsv=None, col3_labels=str(lp), seed=1, perm=200, boot=200, delta=0.05)
        r, still = AM.col3_block(A0, {}, None, None, a)
        cnt = r["labels"]["counts"]
        check("col3 three counts", (cnt["위험 기능 제거"], cnt["공격 표현만 실패"], cnt["구분 불가"]), (2, 1, 1))
        check("col3 unlabelled / invalid / unknown ids", (cnt["unlabelled"], cnt["invalid_label"],
                                                         r["labels"]["labels_for_unknown_case_ids"]), (1, 1, 1))
        check("col3 q1 tally", r["labels"]["q1_reached"].get("갔다"), 3)
        check("col3 sensitivity translations", (r["sensitivity"]["translations_reclassified"],
                                                r["sensitivity"]["translations_reclassified_unlabelled_as_still"]), (2, 4))
        check("col3 sensitivity H1 disappeared", (r["sensitivity"]["H1"]["main_disappeared"],
                                                  r["sensitivity"]["H1"]["sensitivity_disappeared"]),
              ({"PyRs": 2, "PyPy": 1, "n": 2}, {"PyRs": 0, "PyPy": 1, "n": 2}))
        a = types.SimpleNamespace(col3_tsv=str(lp), col3_labels=str(lp), seed=1, perm=200, boot=200, delta=0.05)
        r, _ = AM.col3_block(A0, {}, None, None, a)
        check("col3 never overwrites labels file", r["tsv"].startswith("NOT WRITTEN"), True)
    # 2단계: '없음'은 A 의 Py→Rs 열쇠, 조건은 B 열쇠
    x = {"model": "m1", "item": "cwe_094_0", "source": "vulnerable", "cond": "B1", "cwe": 94, "pairs": ["left"],
         "effect": [e0], "base_effect": [e0], "columns": ["accepted_no_effect"], "status": "accepted", "hard_func": True}
    Brec = {("m1", "cwe_094_0", "vulnerable", "B1"): x,
            ("m1", "cwe_094_0", "vulnerable", AM.NONE): dict(x, cond=AM.NONE, pairs=["left"])}
    check("col3 B case listed (NONE skipped)", [c["case_id"] for c in AM.col3_cases({}, Brec)], ["B|B1|m1|cwe_094_0|vulnerable|0"])
    U = AM.s2_units_sens(Brec, "B1", AM.NONE, None, {("A", "PyRs", "m1", "cwe_094_0", "vulnerable")})
    check("col3 stage2 sensitivity NONE uses A key", [(u[2], u[3]) for u in U], [(0, 1)])
    U = AM.s2_units_sens(Brec, "B1", AM.NONE, None, {("B", "B1", "m1", "cwe_094_0", "vulnerable")})
    check("col3 stage2 sensitivity B key", [(u[2], u[3]) for u in U], [(1, 0)])


def misc_r3_checks(check):
    """결정 11-3 최초 Py→Py 판 칸, 11-6 모델 집합과 표현."""
    r_no = {"cond": "PyPy", "regen": 0}
    r_rg = {"cond": "PyPy", "regen": 2, "functional_ok": True, "pairs": ["left"]}
    A = {("m", "i1", "vulnerable", "PyPy"): dict(r_no), ("m", "i2", "vulnerable", "PyPy"): dict(r_rg)}
    check("first pypy: key absent -> not available", AM.first_pypy_status(A)["available"], False)
    A[("m", "i1", "vulnerable", "PyPy")][AM.FIRST_PYPY_KEY] = None
    A[("m", "i2", "vulnerable", "PyPy")][AM.FIRST_PYPY_KEY] = None
    check("first pypy: regenerated row without dict -> not available", AM.first_pypy_status(A)["available"], False)
    A[("m", "i2", "vulnerable", "PyPy")][AM.FIRST_PYPY_KEY] = {"built": True, "functional_ok": False, "pairs": ["gone"]}
    check("first pypy: available", AM.first_pypy_status(A)["available"], True)
    check("first pypy view uses first result", AM.first_pypy_view(A[("m", "i2", "vulnerable", "PyPy")])[("func")], False)
    check("first pypy view null -> main row", AM.first_pypy_view(dict(r_rg, **{AM.FIRST_PYPY_KEY: None}))["pairs"], ["left"])
    check("expected key name", AM.FIRST_PYPY_KEY, "first_before_regen")
    B = {}
    for m in ("m1", "m2", "m3"):
        for it in ("a", "b"):
            B[(m, it, "vulnerable", AM.NONE)] = {}
            for c in ("NEW", "B1", "REP"):
                if not (m == "m2" and c == "NEW") and not (m == "m3" and c == "REP" and it == "b"):
                    B[(m, it, "vulnerable", c)] = {}
    used, cov = AM.s4_model_set(B, ["NEW", "B1", "REP"], None)
    check("model set: only models with every stage-4 condition on every target", used, ["m1"])
    check("model set coverage partial", cov["m3"]["REP"], {"targets": 2, "with_row": 1})
    check("model set without repeat cond", AM.s4_model_set(B, ["NEW", "B1", None], None)[0], ["m1", "m3"])
    check("pooled wording 4", AM.pooled_phrase(4), "선정한 네 모델을 합친 결과")
    check("pooled wording 3", AM.pooled_phrase(3), "선정한 세 모델을 합친 결과")


def rq_checks(check):
    """RQ3·RQ4·RQ5 남김 표: 손으로 만든 작은 줄."""
    import tempfile
    ind = lambda p, i, u, nd: {"panic_sites": p, "int_sites": i, "unsafe_blocks": u, "deps": ["x"] * nd, "n_deps": nd,  # noqa: E731
                               "code_loading": 0, "code_exec_deps": [], "source": "clippy"}
    r1 = {"item": "zzA", "source": "vulnerable", "cond": "PyRs", "built": True, "fix_rounds": 0, "visible_rounds": 1,
          "stage3": "passed", "functional_ok": True, "pairs": ["gone", "safe", "left"],
          "safety": [["blocked", None], ["blocked", None], ["exploited", "panic"]],
          "capability": [["pass", None], ["fail", "panic"]], "rust_indicators": ind(3, 0, 1, 1)}
    r2 = {"item": "zzB", "source": "vulnerable", "cond": "PyRs", "built": False, "fix_rounds": 5,
          "build_failure": "unresolved_crate", "unresolved_crates": ["foo"]}
    r3 = {"item": "zzA", "source": "patched", "cond": "PyRs", "built": True, "fix_rounds": 2, "visible_rounds": 0,
          "stage3": "not_triggered", "functional_ok": True, "pairs": ["safe", "safe"],
          "safety": [["blocked", None], ["blocked", None]], "capability": [["pass", None]], "rust_indicators": ind(0, 2, 0, 0)}
    r4 = {"item": "zzA", "source": "vulnerable", "cond": "PyPy", "built": True, "fix_rounds": 1, "visible_rounds": 0,
          "stage3": "not_triggered", "functional_ok": True, "pairs": ["left", "left", "left"],
          "safety": [["exploited", "accepted"]] * 3, "capability": [["pass", None]]}
    A0 = {("m1", r["item"], r["source"], r["cond"]): r for r in (r1, r2, r3, r4)}
    with tempfile.TemporaryDirectory() as td:
        b4 = Path(td) / "B4"
        (b4 / "state").mkdir(parents=True)
        s0 = {"by_class": {"panic": 2, "intover": 0}, "unsafe_blocks": 0, "deps": [], "codeload": {}}
        (b4 / "state" / "main__zzA__vulnerable.json").write_text(json.dumps({"sigma0": s0}), encoding="utf-8")
        mk = lambda cond, status, pairs: dict(AM.b_rec({"tkey": "main__zzA__vulnerable", "source": "vulnerable", "cond": cond,  # noqa: E731
                                                        "status": status, "pairs": pairs, "calls": 1, "_bdir": Path(td) / "B",
                                                        "_b4": b4}, "m1", None), _state={}, _lines=(None, None))
        Brec = {("m1", "zzA", "vulnerable", "B1"): mk("B1", "accepted", ["new", "safe", "left"]),
                ("m1", "zzA", "vulnerable", "B0"): mk("B0", "harden_failed", ["safe", "safe", "left"])}
        Brec[("m1", "zzA", "vulnerable", AM.NONE)] = dict(Brec[("m1", "zzA", "vulnerable", "B0")], cond=AM.NONE,
                                                          pairs=["safe", "safe", "removed"])
        R = AM.rq_tables(A0, Brec, True, 1, 2000)
        s2 = AM.stage2(Brec, ["B1", "B0", AM.NONE], True, 1, None)
    T = R["rq3"]["translations_PyRs"]
    v = T["m1|vulnerable"]
    check("rq3 vuln counts", (v["translations"], v["built"], v["never_built"], v["build_failure"], v["unresolved_crate"],
                              v["unresolved_crate_names"]), (2, 1, 1, {"unresolved_crate": 1}, 1, {"foo": 1}))
    check("rq3 func abnormal", (v["func_translations_abnormal"], v["func_tests_abnormal"]), (1, {"panic": 1}))
    i = v["indicators_T1"]
    check("rq3 indicators vuln", (i["with_indicators"], i["any_panic_sites"], i["total_panic_sites"], i["any_unsafe_blocks"],
                                  i["any_int_sites"]), (1, 1, 3, 1, 0))
    i = T["pooled|all"]["indicators_T1"]
    check("rq3 indicators pooled all", (i["with_indicators"], i["any_panic_sites"], i["any_int_sites"], i["total_int_sites"],
                                        i["any_deps"]), (2, 1, 1, 2, 1))
    check("rq3 security abnormal", (v["security"]["judged"], v["security"]["abnormal_tests"]), (1, {"panic": 1}))
    st = R["rq3"]["stage2_targets_sigma0"]["m1|vulnerable"]
    check("rq3 stage2 sigma0", (st["targets"], st["with_sigma0"], st["any_panic_sites"], st["total_panic_sites"]), (1, 1, 1, 2))
    af = R["rq3"]["after_stage2"]
    check("rq3 after accepted n/a", (af["m1|B1|all"]["accepted"], af["m1|B1|all"]["returned_to_start_indicators"],
                                     isinstance(af["m1|B1|all"]["accepted_indicators"], str)), (1, None, True))
    check("rq3 after returned = sigma0", (af["m1|B0|all"]["returned_to_start"],
                                          af["m1|B0|all"]["returned_to_start_indicators"]["any_panic_sites"]), (1, 1))
    w = R["rq4"]["rounds"]
    x = w["m1|PyRs|all"]
    check("rq4 PyRs rounds", (x["translations"], x["built"], x["never_built"], x["build_fix_rounds_built"], x["build_fix_ge1_built"],
                              x["visible_tests_run"], x["visible_fix_rounds"], x["visible_fix_ge1"]),
          (3, 2, 1, {"0": 1, "2": 1}, 1, 2, {"1": 1, "0": 1}, 1))
    check("rq4 PyPy rounds", (w["m1|PyPy|vulnerable"]["build_fix_ge1_built"], w["m1|PyPy|vulnerable"]["build_fix_rounds_built"]),
          (1, {"1": 1}))
    cr = R["rq4"]["cross_rounds_x_vulnerable"]
    check("rq4 cross vuln total", cr["m1|PyRs|vulnerable|total"], {"1": {"translations": 1, "vulnerable": 1}})
    check("rq4 cross patched build", cr["m1|PyRs|patched|build_fix"], {"2+": {"translations": 1, "vulnerable": 0}})
    check("rq4 cross pypy", cr["pooled|PyPy|vulnerable|build_fix"], {"1": {"translations": 1, "vulnerable": 1}})
    check("rq4 perm one group empty", R["rq4"]["perm_ge1_vs_0"]["PyRs|vulnerable|total"]["p"], None)
    k = R["rq5_kept"]["table"]["m1|B1"]
    check("rq5 kept B1", (k["vulnerable_targets"], k["start_safe_tests"], k["reintroduced_tests"], k["targets_with_reintroduced"],
                          k["gone_in_translation_tests"], k["gone_reintroduced_tests"], k["gone_kept_tests"],
                          k["safe_in_both_tests"], k["safe_in_both_reintroduced_tests"], k["still_vulnerable"]),
          (1, 2, 1, 1, 1, 1, 0, 1, 0, 1))
    k0 = R["rq5_kept"]["table"]["m1|B0"]
    check("rq5 kept B0", (k0["reintroduced_tests"], k0["gone_kept_tests"], k0["safe_in_both_tests"]), (0, 1, 1))
    check("rq5 no NONE row", "m1|NONE" in R["rq5_kept"]["table"], False)
    check("rq5 = stage2 new_tests_vulnerable_src", k["reintroduced_tests"], s2["security"]["m1|B1|all"]["new_tests_vulnerable_src"])
    Rb = AM.rq_tables(A0, Brec, False, 1, 100)
    check("rq blinded refuses security parts", (Rb["rq5_kept"], Rb["rq4"]["cross_rounds_x_vulnerable"],
                                                Rb["rq3"]["translations_PyRs"]["m1|vulnerable"]["security"]),
          ("REFUSED (blinded rows)",) * 3)
    check("rq blinded keeps counts", Rb["rq3"]["translations_PyRs"]["m1|vulnerable"]["never_built"], 1)
    # 묶음 안 치환: 두 묶음 [(1,1),(0,0)] -> 관측 S1=2, 치환 S1 ~ Bin(2, 1/2), |차| ≥ 1 확률 0.5. 고정 묶음(전부 1)은 그대로 더한다
    U = [("f1", 1, 1), ("f1", 0, 0), ("f2", 1, 1), ("f2", 0, 0), ("f3", 1, 1), ("f3", 1, 0)]
    p = AM.strat_perm(U, 1, "u", 20000)
    check("strat perm p ~ 0.5", abs(p["p"] - 0.5) < 0.02, True)
    check("strat perm counts", (p["n_ge1"], p["n_0"], p["vuln_ge1"], p["vuln_0"], p["n_informative_families"]), (4, 2, 3, 0, 2))
    p1 = AM.strat_perm([("f1", 1, 1), ("f1", 0, 1), ("f2", 1, 0), ("f2", 0, 0)], 1, "u2", 2000)
    check("strat perm no informative family -> p 1", (p1["p"], p1["n_informative_families"]), (1.0, 0))


def bca_rule_checks(check):
    """결정 13-2·13-3: 기본값(BCa, 명목 95%), 예외 처리 가·나·다·라(합성 묶음 배열), prop_intervals 반환 모양(모의 스크립트가 쓴다)."""
    check("default ci method bca", AM.CI_METHOD, "bca")
    check("default decision level 0.95", AM.DECISION_LEVEL, 0.95)
    check("ci label wording", AM.ci_label("bca", 0.95), "BCa의 명목 95% 구간")
    check("family-count auto-pass removed (결정 15-1)", hasattr(AM, "all_zero_min_families"), False)
    D = AM.interval_decision
    conc = lambda F: [(f"f{i}", 1, 1) for i in range(F)] + [(f"f{i}", 0, 0) for i in range(F)]  # noqa: E731
    # 가(결정 15-1): 묶음별 차이의 합이 모두 0 -> 묶음 수와 상관없이 늘 판정 보류
    b60, b59 = AM.boot_ci(conc(60), 1, "az60", 200, True), AM.boot_ci(conc(59), 1, "az59", 200, True)
    b200 = AM.boot_ci(conc(200), 1, "az200", 200, True)
    check("boot_ci reports discordant clusters/units, sign counts, degenerate (all concordant)",
          (b60["n_discordant_clusters"], b60["n_discordant_units"], b60["n_units_pos"], b60["n_units_neg"], b60["n_units"],
           b60["degenerate"]), (0, 0, 0, 0, 120, True))
    for F, bb in ((59, b59), (60, b60), (200, b200)):
        de, dn, d2 = D(bb, 0.05), D(bb, 0.05, "new_risk"), D(bb, 0.02, "new_risk")
        check(f"가 all concordant {F} families -> undecided (equivalence, 5pt, 2pt)",
              (de["verdict"], de["within"], de["exception"], de["all_zero_case"], de["interval_used"], dn["class"], d2["class"]),
              ("undecided", False, "all_zero", "all_concordant", False, "undecided", "undecided"))
    canc = []      # 묶음마다 한 쌍은 A 쪽만, 한 쌍은 B 쪽만 나쁨 -> 묶음 합 0, 엇갈린 쌍 있음
    for i in range(80):
        canc += [(f"f{i}", 1, 0), (f"f{i}", 0, 1), (f"f{i}", 0, 0)]
    canc += [("f0", 1, 0), ("f0", 0, 1)]
    bc_ = AM.boot_ci(canc, 1, "canc", 200, True)
    d = D(bc_, 0.05, "new_risk")
    check("가 cancellation detected and labelled with pair counts",
          (d["class"], d["all_zero_case"], d["n_pairs_a_worse"], d["n_pairs_a_better"], d["n_discordant_units"], d["n_units"],
           d["n_clusters"], d["both_arms_zero"]), ("undecided", "family_sums_zero", 81, 81, 162, 242, 80, False))
    check("가 cancellation report tag names pair counts", "A 쪽만 나쁨 81쌍, B 쪽만 나쁨 81쌍" in AM._dec_tag(d), True)
    check("가 rules off (legacy) -> interval decides", D(b59, 0.05, level=0.90, exceptions=False)["within"], True)
    # 라: 재표본 추정값이 모두 같은데 차이 ≠ 0
    deg = [(f"f{i}", 1, 0) for i in range(10)] + [(f"f{i}", 0, 0) for i in range(10)]      # 모든 묶음 비율 0.5
    bd = AM.boot_ci(deg, 1, "deg", 200, True)
    check("라 boot degenerate nonzero", (bd["degenerate"], bd["n_discordant_clusters"], bd["estimate"]), (True, 10, 0.5))
    d = D(bd, 0.05)
    check("라 equivalence -> undecided", (d["verdict"], d["exception"]), ("undecided_insufficient_data", "degenerate_nonzero"))
    b1 = AM.boot_ci([("f", 1, 0)] * 3 + [("f", 0, 0)] * 50, 1, "onefam", 200, True)
    d = D(b1, 0.05, "new_risk")
    check("라 single family new risk -> undecided", (d["class"], d["exception"], d["n_clusters"]), ("undecided", "degenerate_nonzero", 1))
    # 나: 엇갈린 묶음 1~4개
    few = [(f"f{i}", 1, 0) for i in range(3)] + [(f"f{i}", 0, 0) for i in range(100)]
    bf = AM.boot_ci(few, 1, "few", 1000, True)
    d = D(bf, 0.05)
    both = AM.equivalent(bf["prop_ci95"], 0.05) and AM.equivalent(bf["prop_ci95_percentile"], 0.05)
    check("나 real arrays: count recorded, within = BCa and percentile both within",
          (d["n_discordant_clusters"], d.get("few_discordant_rule"), d["within"]), (3, True, both))
    fake = {"ci_method": "bca", "n_clusters": 100, "n_discordant_clusters": 3, "degenerate": False, "estimate": 0.01,
            "prop_ci95": [-0.01, 0.04], "prop_ci95_percentile": [-0.01, 0.06], "prop_ci90": [-0.01, 0.03],
            "prop_ci90_percentile": [-0.01, 0.04], "bca_guard": None}
    d = D(fake, 0.05)
    check("나 methods disagree -> not within", (d["within"], d["verdict"], d["exception"]),
          (False, "not_within", "few_discordant_methods_disagree"))
    d = D(fake, 0.05, "new_risk")
    check("나 methods disagree, new risk -> undecided", (d["class"], d["exception"]), ("undecided", "few_discordant_methods_disagree"))
    check("나 methods agree -> within, no exception",
          (D(dict(fake, prop_ci95_percentile=[-0.01, 0.045]), 0.05)["within"],
           D(dict(fake, prop_ci95_percentile=[-0.01, 0.045]), 0.05)["exception"]), (True, None))
    check("나 not applied at 5 discordant families", D(dict(fake, n_discordant_clusters=5), 0.05)["within"], True)
    check("나 at decision level 0.90 uses 90% intervals", D(fake, 0.05, level=0.90)["within"], True)
    # 다: BCa 보정식 분모 ≤ 0 -> 재표본 끝값; 잭나이프 값이 모두 같음 -> 가속 0
    # |가속| ≤ 1/6 이므로 분모 ≤ 0 은 |z0 + z| ≥ 6 일 때만 생긴다(재표본 수가 아주 많고 모든 θ* 가 한쪽일 때). 재표본 합을 직접 만든다:
    # 묶음 50개 중 하나만 d = 0(가속 ≈ −1/6), θ̂ = 0.98, θ* 는 모두 0.99~1.0(z0 = Φ⁻¹(1/(2B)), B = 200,000).
    dd, nn = np.array([1.0] * 49 + [0.0]), np.ones(50)
    Bn = 200000
    M = {"Wd": np.linspace(99.0, 100.0, Bn), "Wn": np.full(Bn, 100.0)}
    ci = AM.prop_intervals(dd, nn, M, "bca", (0.90, 0.95))
    note = dict(AM.LAST_INTERVAL_NOTE)
    ps = M["Wd"] / M["Wn"]
    check("다 denominator <= 0 -> lower = bootstrap min, noted",
          ([0.95, "lower"] in note["endpoint_fallback"], ci[0.95][0] == float(ps.min())), (True, True))
    orig = AM.prop_intervals

    def fake_pi(d, n, M, method, levels=(0.90, 0.95)):
        out = orig(d, n, M, method, levels)
        if method == "bca":
            AM.LAST_INTERVAL_NOTE = dict(AM.LAST_INTERVAL_NOTE, endpoint_fallback=[[0.95, "upper"]])
        return out
    AM.prop_intervals = fake_pi
    try:
        bg = AM.boot_ci([(f"f{i}", 0, 0) for i in range(99)] + [("f99", 1, 0)], 1, "guard", 500, True)
    finally:
        AM.prop_intervals = orig
    check("다 boot_ci carries bca_guard into result and decision",
          (bg["bca_guard"]["endpoint_fallback"], D(bg, 0.05)["bca_guard"]["endpoint_fallback"]), ([[0.95, "upper"]], [[0.95, "upper"]]))
    Mc = {"Wd": np.array([1.0, 2.0, 3.0, 1.0]), "Wn": np.array([2.0, 2.0, 4.0, 4.0])}
    ci = AM.prop_intervals(np.array([1.0, 1.0, 1.0]), np.array([2.0, 2.0, 2.0]), Mc, "bca", (0.90, 0.95))
    check("다 constant jackknife -> acceleration 0, noted",
          (AM.LAST_INTERVAL_NOTE["acc_zero_constant_jackknife"], all(math.isfinite(x) for v in ci.values() for x in v)), (True, True))
    check("bca_guard only for bca", AM.boot_ci([(f"f{i}", 0, 0) for i in range(99)] + [("f99", 1, 0)], 1, "guard", 500, True,
                                                 method="percentile")["bca_guard"], None)
    # 결합 판정에 예외 반영
    C = AM.choose_s4_conclusion
    EQ, WIDE = [-0.03, -0.01], [-0.12, -0.02]
    bz = AM.boot_ci([(f"f{i}", 0, 0) for i in range(70)] * 2, 1, "zero", 200, True)     # 두 조건 모두 새로 생김 0건
    dz = D(bz, 0.05, "new_risk")
    zs = "신규 위험은 두 조건 모두 0건이었다(번역 140개, 묶음 70개). 구간으로 판정할 수 없어 보류했다."
    check("가 both arms zero recorded", (dz["both_arms_zero"], dz["n_bad_a"], dz["n_bad_b"], AM.all_zero_sentence(dz)), (True, 0, 0, zs))
    r = C(True, -10, True, -6, EQ, dz["ci"], 0.05, new_dec=dz)
    check("s4 new risk all zero + 4-가 significant improvement -> row 5 + appended sentence",
          (r[0], r[1].startswith(AM.S4_SENT[5]), r[1].endswith(" " + zs)), (5, True, True))
    r = C(False, -1, False, 0, EQ, dz["ci"], 0.05, new_dec=dz)
    check("s4 new risk all zero + 4-가 not significant -> row 7 + appended sentence",
          (r[0], r[1].startswith(AM.S4_SENT[7]), r[1].endswith(" " + zs)), (7, True, True))
    check("s4 new risk all zero: rows 3/4/6 never chosen (would-be 3, 4, 6 -> 5, 5, 7)",
          tuple(C(*x, dz["ci"], 0.05, new_dec=dz)[0] for x in ((True, -10, True, -6, WIDE), (True, -10, False, -2, WIDE),
                                                                   (False, -1, False, 0, EQ))), (5, 5, 7))
    check("s4 new risk all concordant (both arms nonzero), 60 families -> row 7, not 6",
          C(False, -1, False, 0, EQ, [0.0, 0.0], 0.05, new_dec=D(b60, 0.05, "new_risk"))[0], 7)
    r = C(True, -10, True, -6, WIDE, [0.0, 0.0], 0.05, new_dec=D(bc_, 0.05, "new_risk"))
    check("s4 new risk cancellation -> row 5, cancellation wording with pair counts",
          (r[0], "상쇄" in r[1] and "새 기법에서만 새로 생긴 번역 81개" in r[1] and "기존 최선에서만 새로 생긴 번역 81개" in r[1]), (5, True))
    check("s4 residual all_zero -> not equivalent -> row 7",
          C(False, 0, False, 0, [0.0, 0.0], [-0.01, 0.02], 0.05, res_dec=D(b200, 0.05))[0], 7)
    check("s4 row1 prints decision interval label", ("BCa의 명목 95% 구간" in C(False, -1, False, 0, [-0.03, -0.01], [0.06, 0.1])[1]), True)
    # prop_intervals 반환 모양(analyze_main_sims.py 가 이 모양에 기댄다)
    units = [(f"f{i}", 1, 0) for i in range(30)] + [(f"f{i}", 0, 0) for i in range(30)] + \
            [(f"g{i}", 0, 1) for i in range(10)] + [(f"g{i}", 0, 0) for i in range(10)]
    d_, n_ = AM._clusters(units, True)
    W = np.random.default_rng(7).multinomial(len(d_), np.full(len(d_), 1.0 / len(d_)), size=500)
    Mo = AM.boot_moments(W, d_, n_)
    shape = lambda o, lv: sorted(o) == sorted(lv) and all(  # noqa: E731
        isinstance(v, list) and len(v) == 2 and all(isinstance(x, float) for x in v) for v in o.values())
    for m in AM.CI_METHODS:
        check(f"prop_intervals shape {m}", (shape(AM.prop_intervals(d_, n_, Mo, m, (0.90, 0.95)), (0.90, 0.95)),
                                            shape(AM.prop_intervals(d_, n_, Mo, m), (0.90, 0.95)),
                                            shape(AM.prop_intervals(d_, n_, Mo, m, (0.8, 0.99)), (0.8, 0.99))), (True, True, True))
    check("CI_METHODS order unchanged", AM.CI_METHODS, ("percentile", "bca", "boot_t", "cluster_t"))


# 개발용 자료에서의 판정(라벨만). 이전(결정 13 이전, 스크립트 828bdbd705571c7f) 결과와 새 기본값 결과.
# 값 = (가족 묶음, 독립 가정판, CWE 묶음)의 equivalent_5pt 를 T/F 로; 4단계는 (5%p, 2%p, 독립 가정판 5%p) 분류와 (d_잔여 동등성, 줄).
DEV_SETS = {
    "dev_pilot": (["--arun", "dev={DS}/pilot_A_v2_2026-11-12", "--brun", "dev={DS}/pilot_Bc_GFv2_2026-11-12",
                   "--s4-new", "B1", "--s4-base", "B0", "--s4-repeat", "BUD"], ["pilot_A_v2_2026-11-12", "pilot_Bc_GFv2_2026-11-12"]),
    "dry_run6": (["--run", "{DS}/_dry_main/run6", "--s4-new", "SPEC2", "--s4-base", "B1", "--s4-repeat", "BESTREP"],
                 ["_dry_main/run6"]),
}
DEV_EXPECT_LEGACY = {
    "dev_pilot": {"1:H2": "TTT", "2:2-ga-1": "FFF", "2:2-ga-2": "FFF", "2:2-na": "FFF", "4:ga": "FFF", "4:nb": "FFF",
                  "4:new_risk": "TTT", "4:class": ("noninferior", "noninferior", "noninferior"), "4:resid_row": (False, 7)},
    "dry_run6": {"1:H1": "FFF", "1:H1_dataset_only": "FFF", "1:H4": "TTT", "1:H4_dataset_only": "TTT", "1:H4_abnormal_only": "TTT",
                 "1:H4_any_new_dataset_test": "TTT", "1:H1_no_regen": "FFF", "1:H4_no_regen": "TTT", "1:H1_first_pypy": "FFF",
                 "1:H4_first_pypy": "TTT", "1:H2": "FFF", "2:2-ga-1": "TTT", "2:2-ga-2": "TTT", "2:2-na": "TTT", "2:2-da": "TTT",
                 "2:sec_B1_vs_RCI": "TTT", "4:ga": "TTT", "4:nb": "TTT", "4:new_risk": "TTT",
                 "4:class": ("noninferior", "noninferior", "noninferior"), "4:resid_row": (True, 6)},
}
DEV_EXPECT_NEW = {   # 바뀐 것은 모두 결정 13-2 가(엇갈린 묶음 0개, 묶음 < 60)
    "dev_pilot": dict(DEV_EXPECT_LEGACY["dev_pilot"], **{"1:H2": "FFF", "4:new_risk": "FFF",
                                                        "4:class": ("undecided", "undecided", "undecided")}),
    "dry_run6": dict({k: "FFF" for k in DEV_EXPECT_LEGACY["dry_run6"] if k[0] in "124" and k[1] == ":" and k not in ("4:class", "4:resid_row")},
                     **{"4:class": ("undecided", "undecided", "undecided"), "4:resid_row": (False, 7)}),
}


DEV_CHECK_NAMES = ("legacy percentile/0.90 reproduces pre-13 decisions ({nm})", "legacy run records method/level, rules off ({nm})",
                   "default bca/0.95 decisions ({nm})", "default run records bca/0.95 at top and per decision ({nm})")  # 아래 네 check


def _dec_sig(r):
    out = {}

    def pc(pre, c):
        if isinstance(c, dict) and c.get("n") and "family" in c:
            out[pre] = "".join("T" if c[k]["equivalent_5pt"] else "F" for k in ("family", "naive", "cwe_cluster_sensitivity"))
    for h, c in ((r.get("stage1") or {}).get("hypotheses") or {}).items():
        pc("1:" + h, c)
    for h, c in ((r.get("stage2") or {}).get("confirmatory") or {}).items():
        pc("2:" + h, c)
    s4 = r.get("stage4")
    if isinstance(s4, dict):
        for h in ("ga", "nb", "new_risk"):
            pc("4:" + h, s4[h])
        ni = s4["new_risk"]
        out["4:class"] = (ni["class_5pt"], ni["class_2pt_secondary"], ni["naive_class_5pt"])
        out["4:resid_row"] = (s4["residual"]["equivalent_5pt"], s4["conclusion"]["row"])
    return out


def dev_decision_checks(check):
    """--ci-method percentile --decision-level 0.90 이 결정 13 이전 판정을 그대로 내는지, 새 기본값의 판정(개발용·가짜 답 자료, 읽기만)."""
    import tempfile
    common = ["--seed", "20261114", "--perm", "2000", "--boot", "2000", "--override-11-7"]
    saved = (AM.CI_METHOD, AM.DECISION_LEVEL, AM.EXCEPTION_RULES)
    try:
        with tempfile.TemporaryDirectory() as td:
            for nm, (args, need) in DEV_SETS.items():
                if not all((AM.DS / p).exists() for p in need) or not AM.SEED_FAMILIES.exists():
                    why = "needs result folders that are not in the bundle"
                    for t in DEV_CHECK_NAMES:
                        check.skipped.append((t.format(nm=nm), why))
                    print(f"SKIPPED {len(DEV_CHECK_NAMES)} checks ({nm}): {why}")
                    continue
                args = [x.replace("{DS}", str(AM.DS)) for x in args]
                o = lambda tag: ["--out-json", str(Path(td) / f"{nm}_{tag}.json"), "--out-md", str(Path(td) / f"{nm}_{tag}.md")]  # noqa: E731
                r = AM.main(args + common + ["--ci-method", "percentile", "--decision-level", "0.90"] + o("legacy"))
                check(f"legacy percentile/0.90 reproduces pre-13 decisions ({nm})", _dec_sig(r), DEV_EXPECT_LEGACY[nm])
                check(f"legacy run records method/level, rules off ({nm})",
                      (r["ci_method"], r["decision_level"], r["exception_rules_13_2"].startswith("off")), ("percentile", 0.9, True))
                r = AM.main(args + common + o("new"))
                check(f"default bca/0.95 decisions ({nm})", _dec_sig(r), DEV_EXPECT_NEW[nm])
                d5 = r["stage4"]["new_risk"]["decision_5pt"]
                check(f"default run records bca/0.95 at top and per decision ({nm})",
                      (r["ci_method"], r["decision_level"], r["exception_rules_13_2"], d5["ci_method"], d5["decision_level"],
                       r["stage4"]["conclusion"]["decision_level"]), ("bca", 0.95, "applied", "bca", 0.95, 0.95))
    finally:
        AM.CI_METHOD, AM.DECISION_LEVEL, AM.EXCEPTION_RULES = saved


# ---------------------------------------------------------------- 보정 모의
def family_sizes():
    conf = AM.read_list(AM.DS / "split_2026-11-12" / "confirmatory.txt")
    fams = {}
    for it in conf:
        fams.setdefault(AM.family(it), 0)
        fams[AM.family(it)] += 1
    return sorted(fams.values(), reverse=True)


def simulate_dataset(rng, sizes, n_models, delta, tau_f, tau_i, rho):
    """번역 = (항목, 모델). 나쁨(고친 뒤에도 취약) 확률: 묶음·항목·모델 효과 + 묶음·항목 단위의 조건 상호작용(대칭) + delta(B 쪽).
    두 조건의 결과는 같은 균등 난수를 rho 확률로 공유(짝 상관)."""
    F = len(sizes)
    fam_idx = np.repeat(np.arange(F), sizes)
    n_items = len(fam_idx)
    u_f = rng.normal(0, 1.0, F)
    v_i = rng.normal(0, 0.7, n_items)
    m_k = rng.normal(0, 0.5, n_models)
    w_f = rng.normal(0, tau_f, F)
    w_i = rng.normal(0, tau_i, n_items)
    eta = -1.0 + u_f[fam_idx][:, None] + v_i[:, None] + m_k[None, :]
    w = (w_f[fam_idx] + w_i)[:, None]
    pa = 1 / (1 + np.exp(-(eta + w / 2)))
    pb = 1 / (1 + np.exp(-(eta - w / 2 + delta)))
    U = rng.random(eta.shape)
    share = rng.random(eta.shape) < rho
    U2 = np.where(share, U, rng.random(eta.shape))
    ya = (U < pa).astype(int)
    yb = (U2 < pb).astype(int)
    fam = np.repeat(fam_idx[:, None], n_models, axis=1)
    units = [(f"f{f}", a, b) for f, a, b in zip(fam.ravel(), ya.ravel(), yb.ravel())]
    return units, ya.mean() - yb.mean()


def sim(a):
    sizes = family_sizes()
    rng = np.random.default_rng(a.seed)
    out = {"n_datasets": a.n, "perm_per_dataset": a.perm, "boot_per_dataset": a.boot, "seed": a.seed,
           "n_families": len(sizes), "n_items": int(sum(sizes)), "max_family": max(sizes), "n_models": 4,
           "kish_m": float(sum(s * s for s in sizes) / sum(sizes)),
           "params": {"tau_family": a.tau_f, "tau_item": a.tau_i, "rho_shared_uniform": a.rho, "alt_delta_logit": a.delta}}
    for label, delta in (("null", 0.0), ("alt", a.delta)):
        rej_f = rej_n = rej_mc = boot_excl_f = boot_excl_n = 0
        diffs = []
        for k in range(a.n):
            units, dpp = simulate_dataset(rng, sizes, 4, delta, a.tau_f, a.tau_i, a.rho)
            diffs.append(dpp)
            key = f"{label}{k}"
            pf = AM.perm_test(units, a.seed, key, a.perm, True)["p"]
            pn = AM.perm_test(units, a.seed, key, a.perm, False)["p"]
            n10 = sum(1 for _, x, y in units if x == 1 and y == 0)
            n01 = sum(1 for _, x, y in units if x == 0 and y == 1)
            pm = AM.mcnemar_exact(n10, n01)
            rej_f += pf < 0.05
            rej_n += pn < 0.05
            rej_mc += pm < 0.05
            if a.boot:
                bf = AM.boot_ci(units, a.seed, key, a.boot, True)["count_ci95"]
                bn = AM.boot_ci(units, a.seed, key, a.boot, False)["count_ci95"]
                boot_excl_f += not (bf[0] <= 0 <= bf[1])
                boot_excl_n += not (bn[0] <= 0 <= bn[1])
        out[label] = {"reject_family_perm": rej_f / a.n, "reject_naive_perm": rej_n / a.n,
                      "reject_naive_mcnemar_exact": rej_mc / a.n,
                      "family_boot95_excludes_0": boot_excl_f / a.n if a.boot else None,
                      "naive_boot95_excludes_0": boot_excl_n / a.n if a.boot else None,
                      "mean_true_diff_pp_A_minus_B": float(np.mean(diffs) * 100)}
        print(label, json.dumps(out[label]))
    if a.out:
        Path(a.out).write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k not in ("null", "alt")}))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["unit", "sim"])
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--perm", type=int, default=2000)
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=20261113)
    ap.add_argument("--delta", type=float, default=-0.35)
    ap.add_argument("--tau-f", type=float, default=1.0)
    ap.add_argument("--tau-i", type=float, default=0.5)
    ap.add_argument("--rho", type=float, default=0.7)
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.mode == "unit":
        sys.exit(0 if unit() else 1)
    sim(a)
