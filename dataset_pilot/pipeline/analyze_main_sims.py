"""분석 동결 전 모의실험 두 가지(검토의견_반영_결정 11-5). 모델 호출 없음, 실제 결과 없음(항목 목록·시드 묶음·CWE 메타만 읽음).

usage: python analyze_main_sims.py coverage [--n 2000] [--boot 1000] [--seed 20261114] [--workers 12]
       python analyze_main_sims.py power    [--n 500]  [--perm 1000] [--seed 20261115] [--workers 12]
       python analyze_main_sims.py summary            (두 JSON 에서 _sims/SUMMARY.md 를 쓴다)
       python analyze_main_sims.py boundary [--n 2000] [--boot 1000] [--seed 20261116] [--workers 12]   (결정 12-1 → _sims/boundary.json)
       python analyze_main_sims.py power21  [--n 500]  [--perm 1000] [--seed 20261117] [--workers 12]   (결정 12-2 → _sims/power_2ga1_sensitivity.json)
출력: dataset_pilot/_sims/coverage.json, power.json, SUMMARY.md (개수·통계만).
모든 모드: --sizes _sims/family_sizes.json 이면 항목 목록·시드 묶음·CWE 메타 대신 표본 구성별 묶음 크기만 쓴다(같은 시드면 같은 결과).
           --out DIR 이면 출력 폴더를 바꾼다(기본 _sims). power21 은 DIR/power.json 이 있으면 그 2-ga-1 줄을 함께 적는다.
           --chunk C 이면 작업 하나에 자료 C 벌(기본 n // workers). 자료마다 시드가 정해져 있어 셈(포함·채택 수, p 값)은 이것과
           상관없고, 평균 폭·평균 추정값 같은 실수 합만 마지막 자리에서 바뀐다. _sims/coverage.json 은 chunk 100(workers 20),
           boundary.json 은 chunk 166(workers 12)으로 만들었다.

자료 생성 모형(analyze_main_checks.simulate_dataset 와 같은 꼴): 번역 = (항목, 모델). 나쁨 확률 = logistic(절편 + 묶음 효과 u_f ~ N(0, 1)
+ 항목 효과 v_i ~ N(0, 0.7) + 모델 효과 m_k ± 조건 상호작용 w/2), w = 묶음 w_f ~ N(0, 1) + 항목 w_i ~ N(0, 0.5) (두 조건에 반대 부호),
두 조건의 결과는 같은 균등 난수를 확률 0.7 로 공유(짝 상관). 모델 4개의 효과는 고정(0.5 × N(0,1) 의 1/8·3/8·5/8·7/8 분위수):
'선정한 네 모델을 합친 결과'가 추정 대상이므로 모델은 재표본하지 않는다. 절편은 조건별 목표 비율(모집단 평균)에 맞춰 수치로 정한다.
참값 = 두 조건의 모집단 평균 비율 차이(맞춘 값; 독립 표본 4,000,000개로 다시 잰 값을 함께 적는다).
"""
import argparse
import json
import math
import sys
import time
import zlib
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analyze_main as AM  # noqa: E402

DS = AM.DS
OUT = DS / "_sims"
SD_F, SD_I, TAU_F, TAU_I, RHO = 1.0, 0.7, 1.0, 0.5, 0.7
K = 4
M_EFF = 0.5 * np.array([-1.1503, -0.3186, 0.3186, 1.1503])
_CAL = {}


def sizes_of(items):
    fam = {}
    for it in items:
        fam[AM.family(it)] = fam.get(AM.family(it), 0) + 1
    return np.array(sorted(fam.values(), reverse=True))


def item_sets():
    conf = AM.read_list(DS / "split_2026-11-12" / "confirmatory.txt")
    hold = AM.read_list(DS / "split_dh_2026-11-13" / "holdout.txt")
    return {
        "conf_scp715": [i for i in conf if AM.is_scp(i)],
        "holdout_scp440": [i for i in hold if AM.is_scp(i)],
        "conf_effect_classes": [i for i in conf if AM.cwe_of(i) in AM.EFFECT_CWES],
        "conf_all735": conf,
        "conf_code_exec": [i for i in conf if AM.cwe_of(i) in AM.CODE_EXEC_CWES],
    }


def bound_sets():
    sets = item_sets()
    conf = AM.read_list(DS / "split_2026-11-12" / "confirmatory.txt")
    sets["conf_logic"] = [i for i in conf if AM.cwe_of(i) not in AM.EFFECT_CWES and AM.cwe_of(i) != -1]
    return sets


def load_sets(a, boundary=False):
    """{이름: (항목 수, 묶음 크기 배열(내림차순))}. --sizes 가 있으면 그 JSON 만 읽는다(데이터셋 파일을 건드리지 않음)."""
    if getattr(a, "sizes", None):
        js = json.loads(Path(a.sizes).read_text(encoding="utf-8"))["sets"]
        return {k: (int(v["items"]), np.array([int(x) for x in v["family_sizes_desc"]], dtype=np.int64)) for k, v in js.items()}
    split = DS / "split_2026-11-12" / "confirmatory.txt"
    if not split.exists():
        raise SystemExit(f"item lists not found ({split}); use --sizes <family_sizes.json>")
    sets = bound_sets() if boundary else item_sets()
    return {k: (len(v), sizes_of(v)) for k, v in sets.items()}


def job_chunk(a):
    """자료 몇 벌을 작업 하나로 묶는가. 기본 n // workers. 실수 합(평균 폭 등)의 더하는 순서가 이것에 따라 바뀐다."""
    return a.chunk if getattr(a, "chunk", None) else max(1, a.n // a.workers)


def _sig(x):
    return 1.0 / (1.0 + np.exp(-x))


def _table(sign, n=400_000, seed=99):
    """절편 격자(−16..10, 0.005 간격)마다 모집단 평균 비율 E[σ(c + u + v + m + sign·w/2)] 을 표본 n 개로 잰 표."""
    if sign not in _CAL:
        rng = np.random.default_rng([seed, 7, sign + 1])
        s = rng.normal(0, SD_F, n) + rng.normal(0, SD_I, n) + M_EFF[rng.integers(0, K, n)]
        if sign:
            s = s + sign * (rng.normal(0, TAU_F, n) + rng.normal(0, TAU_I, n)) / 2
        cg = np.arange(-16.0, 10.0, 0.005)
        _CAL[sign] = (cg, np.array([_sig(c + s).mean() for c in cg]))
    return _CAL[sign]


def calibrate(rate, sign):
    """절편 c: E[σ(c + u + v + m + sign·w/2)] = rate (모집단 평균). sign = +1(A), −1(B), 0(상호작용 없음). 표에서 보간."""
    cg, r = _table(sign)
    return float(np.interp(rate, r, cg))


def _init_worker(tabs):
    _CAL.update(tabs)


def tables():
    for sg in (-1, 0, 1):
        _table(sg)
    return dict(_CAL)


def realised_rate(c, sign, n=4_000_000, seed=1234):
    rng = np.random.default_rng([seed, 11])
    s = rng.normal(0, SD_F, n) + rng.normal(0, SD_I, n) + M_EFF[rng.integers(0, K, n)]
    w = rng.normal(0, TAU_F, n) + rng.normal(0, TAU_I, n)
    return float(_sig(c + s + sign * w / 2).mean())


def draw_latent(rng, sizes):
    """한 자료의 잠재 값: 항목 × 모델 선형 예측(절편 뺌), 상호작용, 공유 난수 두 개."""
    F = len(sizes)
    fi = np.repeat(np.arange(F), sizes)
    n = len(fi)
    u, v = rng.normal(0, SD_F, F), rng.normal(0, SD_I, n)
    wf, wi = rng.normal(0, TAU_F, F), rng.normal(0, TAU_I, n)
    eta = (u[fi] + v)[:, None] + M_EFF[None, :]
    w = (wf[fi] + wi)[:, None]
    U = rng.random(eta.shape)
    share = rng.random(eta.shape) < RHO
    U2 = np.where(share, U, rng.random(eta.shape))
    return {"fi": fi, "eta": eta, "w": w, "U": U, "U2": U2, "F": F}


def outcomes(L, cA, cB):
    ya = (L["U"] < _sig(cA + L["eta"] + L["w"] / 2)).astype(np.int64)
    yb = (L["U2"] < _sig(cB + L["eta"] - L["w"] / 2)).astype(np.int64)
    return ya, yb


def fam_sums(fi, F, diff, incl=None):
    """묶음별 d = Σ(a−b), n = 번역 수(포함된 것만)."""
    if incl is None:
        incl = np.ones_like(diff, dtype=bool)
    rows = np.repeat(fi[:, None], diff.shape[1], axis=1)
    d = np.bincount(rows[incl], weights=diff[incl], minlength=F)
    n = np.bincount(rows[incl], minlength=F).astype(float)
    keep = n > 0
    return d[keep], n[keep]


# ---------------------------------------------------------------- B1 포함률
SCEN = {"rate20_diff0": (0.20, 0.20), "rate20_diff3": (0.23, 0.20), "rate1_diff0": (0.01, 0.01), "rate1_diff3": (0.04, 0.01)}
LEVELS = (0.90, 0.95)


def _cov_job(args):
    cfg, scen, sizes, start, count, nboot, seed = args
    rA, rB = SCEN[scen]
    cA, cB = calibrate(rA, +1), calibrate(rB, -1)
    truth = rA - rB
    res = {m: {lv: [0, 0, 0] for lv in LEVELS} for m in AM.CI_METHODS}     # covered, miss_low(참값 < 하한), miss_high(참값 > 상한)
    width = {m: {lv: 0.0 for lv in LEVELS} for m in AM.CI_METHODS}
    degenerate = 0
    for j in range(start, start + count):
        rng = np.random.default_rng([seed, zlib.crc32(f"{cfg}|{scen}".encode()), j])
        L = draw_latent(rng, sizes)
        ya, yb = outcomes(L, cA, cB)
        d, n = fam_sums(L["fi"], L["F"], ya - yb)
        F = len(d)
        W = rng.multinomial(F, np.full(F, 1.0 / F), size=nboot)
        Mo = AM.boot_moments(W, d, n)
        degenerate += int(not d.any())
        for m in AM.CI_METHODS:
            ci = AM.prop_intervals(d, n, Mo, m, LEVELS)
            for lv in LEVELS:
                lo, hi = ci[lv]
                r = res[m][lv]
                if truth < lo - 1e-12:
                    r[1] += 1
                elif truth > hi + 1e-12:
                    r[2] += 1
                else:
                    r[0] += 1
                width[m][lv] += hi - lo
    return cfg, scen, res, width, degenerate, count


def coverage(a):
    sets = load_sets(a)
    cfgs = {k: sets[k] for k in ("conf_scp715", "holdout_scp440", "conf_effect_classes")}
    jobs, chunk = [], job_chunk(a)
    for cfg, (_ni, sizes) in cfgs.items():
        for scen in SCEN:
            for s in range(0, a.n, chunk):
                jobs.append((cfg, scen, sizes, s, min(chunk, a.n - s), a.boot, a.seed))
    t0 = time.time()
    tabs = tables()                          # 절편 표를 한 번 만들어 작업 과정에 넘긴다
    agg = {}
    with ProcessPoolExecutor(a.workers, initializer=_init_worker, initargs=(tabs,)) as ex:
        for cfg, scen, res, width, deg, cnt in ex.map(_cov_job, jobs):
            g = agg.setdefault((cfg, scen), {"n": 0, "deg": 0, "res": {m: {lv: [0, 0, 0] for lv in LEVELS} for m in AM.CI_METHODS},
                                             "width": {m: {lv: 0.0 for lv in LEVELS} for m in AM.CI_METHODS}})
            g["n"] += cnt
            g["deg"] += deg
            for m in AM.CI_METHODS:
                for lv in LEVELS:
                    g["res"][m][lv] = [x + y for x, y in zip(g["res"][m][lv], res[m][lv])]
                    g["width"][m][lv] += width[m][lv]
    out = {"what": "B1 coverage of nominal 90%/95% intervals for the pooled difference in proportions (4 models, family bootstrap)",
           "n_datasets_per_cell": a.n, "boot_per_dataset": a.boot, "seed": a.seed, "seconds": round(time.time() - t0, 1),
           "model": {"sd_family": SD_F, "sd_item": SD_I, "tau_family": TAU_F, "tau_item": TAU_I, "rho_shared_uniform": RHO,
                     "model_effects_fixed": M_EFF.tolist(), "n_models": K},
           "scenarios": {k: {"rate_A": v[0], "rate_B": v[1], "true_diff_pp": round((v[0] - v[1]) * 100, 3),
                             "realised_rate_A": realised_rate(calibrate(v[0], +1), +1),
                             "realised_rate_B": realised_rate(calibrate(v[1], -1), -1)} for k, v in SCEN.items()},
           "configs": {k: {"items": ni, "families": int(len(sz)), "max_family": int(sz.max()),
                           "units": ni * K} for k, (ni, sz) in cfgs.items()},
           "methods": {"percentile": "family bootstrap percentile", "bca": "family bootstrap BCa (jackknife acceleration over families)",
                       "boot_t": "family bootstrap-t studentised by the cluster-robust SE", "cluster_t":
                       "cluster-robust (linearised ratio) SE with t(families − 1)"},
           "cells": {}}
    for (cfg, scen), g in sorted(agg.items()):
        cell = {"n": g["n"], "datasets_all_zero_difference": g["deg"]}
        for m in AM.CI_METHODS:
            cell[m] = {}
            for lv in LEVELS:
                c, lo, hi = g["res"][m][lv]
                p = c / g["n"]
                cell[m][str(lv)] = {"coverage": p, "mcse": math.sqrt(p * (1 - p) / g["n"]), "miss_truth_below_lower": lo / g["n"],
                                    "miss_truth_above_upper": hi / g["n"], "mean_width_pp": 100 * g["width"][m][lv] / g["n"]}
        out["cells"][f"{cfg}|{scen}"] = cell
    out["selection"] = select_method(out)
    OUT.mkdir(exist_ok=True)
    (OUT / "coverage.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(out["selection"], indent=1, ensure_ascii=False))


def select_method(out):
    """사전 규칙(11-5): 90% 구간 실제 포함률이 모든 설정에서 89% 이상이면서 평균이 90%에 가장 가까운 방법.
    '모든 설정' = 표본 설정 × 시나리오의 모든 칸(엄격) 과 표본 설정별 평균(시나리오 평균) 둘 다 적는다."""
    cells = out["cells"]
    rows = {}
    for m in AM.CI_METHODS:
        cv = {k: v[m]["0.9"]["coverage"] for k, v in cells.items()}
        by_cfg = {}
        for k, c in cv.items():
            by_cfg.setdefault(k.split("|")[0], []).append(c)
        cfg_mean = {k: sum(v) / len(v) for k, v in by_cfg.items()}
        mean = sum(cv.values()) / len(cv)
        rows[m] = {"min_cell": min(cv.values()), "min_cell_at": min(cv, key=cv.get), "mean": mean,
                   "mean_abs_dev_from_90": sum(abs(c - 0.9) for c in cv.values()) / len(cv),
                   "config_means": cfg_mean, "all_cells_ge_89": all(c >= 0.89 for c in cv.values()),
                   "all_config_means_ge_89": all(c >= 0.89 for c in cfg_mean.values())}
    ok_cells = [m for m in AM.CI_METHODS if rows[m]["all_cells_ge_89"]]
    ok_cfg = [m for m in AM.CI_METHODS if rows[m]["all_config_means_ge_89"]]
    pick = lambda L: min(L, key=lambda m: abs(rows[m]["mean"] - 0.9)) if L else None  # noqa: E731
    best_any = min(AM.CI_METHODS, key=lambda m: (-rows[m]["min_cell"]))
    return {"per_method": rows, "eligible_all_cells": ok_cells, "chosen_all_cells_rule": pick(ok_cells),
            "eligible_config_means": ok_cfg, "chosen_config_mean_rule": pick(ok_cfg),
            "if_none_best_by_min_cell": best_any if not ok_cells else None}


# ---------------------------------------------------------------- B2 검정력
GRID = [0.5, 1, 1.5, 2, 2.5, 3, 4, 5, 6, 7, 8, 10, 12, 15, 20, 25]
ALPHA = 0.05
ASSUME = {
    "func_pass_PyRs": 0.85, "func_pass_PyPy": 0.95,
    "base_vulnerable_share_of_targets": 0.85,
    "still_vulnerable_share_of_base_vulnerable_B1": 0.20,
    "H1_disappeared_PyPy": 0.20, "H1_disappeared_PyPy_alt": 0.45,
    "H4_newly_PyPy": 0.01, "H4_newly_PyPy_alts": [0.005, 0.02],
}
COMPARISONS = {
    # 이름: (항목 집합, 종류, 설명)
    "H1": ("conf_code_exec", "pair", "취약판, 코드 실행류(502·94·95·78), 두 언어 기능 통과 쌍; 나쁨 = 없어짐; A = Py→Rs = 기준 + Δ"),
    "H4": ("conf_all735", "pair", "수정판, 735 전체, 두 언어 기능 통과 쌍; 나쁨 = 새로 생김; A = Py→Rs = 기준 + Δ"),
    "2-ga-1": ("conf_scp715", "s2_none", "기능 통과 취약판 출발 Py→Rs; B1 대 없음(출발 그대로); Δ = 출발 취약 − B1 뒤 취약"),
    "2-ga-2": ("conf_scp715", "s2_vs", "같음; B1(20%) 대 다시 번역(20% + Δ)"),
    "2-na": ("conf_scp715", "s2_vs", "같음; B1(20%) 대 일반 보안 지시(20% + Δ)"),
    "4-ga": ("holdout_scp440", "s4", "H 440; 새 기법(20% − Δ) 대 기존 최선(20%)"),
    "4-na": ("holdout_scp440", "s4", "H 440; 새 기법(20% − Δ) 대 기존 최선 반복(20%)"),
}


def fast_perm_p(d, nperm, rng):
    """analyze_main.perm_test 와 같은 계산(묶음 부호 뒤집기, 양측, (≥ 수 + 1)/(치환 수 + 1))을 배열로."""
    d = np.asarray(d)
    T = d.sum()
    nz = d[d != 0].astype(np.int64)
    if len(nz) == 0:
        return 1.0
    S = rng.integers(0, 2, size=(nperm, len(nz)), dtype=np.int8) * 2 - 1
    Ts = S.astype(np.int64) @ nz
    return (int((np.abs(Ts) >= abs(T)).sum()) + 1) / (nperm + 1)


def _pow_job(args):
    name, sizes, kind, base, grid, start, count, nperm, seed = args
    fb = ASSUME["base_vulnerable_share_of_targets"]
    p = {g: [] for g in grid}
    for j in range(start, start + count):
        rng = np.random.default_rng([seed, zlib.crc32(f"{name}|{base}".encode()), j])
        L = draw_latent(rng, sizes)
        shape = L["eta"].shape
        if kind == "pair":
            incl = rng.random(shape) < ASSUME["func_pass_PyRs"] * ASSUME["func_pass_PyPy"]
        else:
            incl = rng.random(shape) < ASSUME["func_pass_PyRs"]
            Lz = draw_latent(rng, sizes)          # 출발 취약 여부: 따로 그린 묶음·항목 효과
            z = (Lz["U"] < _sig(calibrate(fb, 0) + Lz["eta"])).astype(np.int64)
        prng = np.random.default_rng([seed, 5, zlib.crc32(name.encode()), j])
        for g in grid:
            dl = g / 100
            if kind == "pair":
                ya, yb = outcomes(L, calibrate(min(base + dl, 0.999), +1), calibrate(base, -1))
            elif kind == "s2_none":
                sA = max(1 - dl / fb, 1e-4)
                ya, _ = outcomes(L, calibrate(sA, +1), calibrate(0.2, -1))
                ya, yb = z * ya, z
            elif kind == "s2_vs":
                sB = min(0.2 + dl / fb, 0.999)
                ya, yb = outcomes(L, calibrate(0.2, +1), calibrate(sB, -1))
                ya, yb = z * ya, z * yb
            else:      # s4
                sA = max(0.2 - dl / fb, 1e-4)
                ya, yb = outcomes(L, calibrate(sA, +1), calibrate(0.2, -1))
                ya, yb = z * ya, z * yb
            d, _n = fam_sums(L["fi"], L["F"], ya - yb, incl)
            p[g].append(fast_perm_p(d, nperm, prng))
    return name, base, p


def power(a):
    sets = load_sets(a)
    t0 = time.time()
    cases = []
    for nm, (iset, kind, desc) in COMPARISONS.items():
        bases = [None]
        if nm == "H1":
            bases = [ASSUME["H1_disappeared_PyPy"], ASSUME["H1_disappeared_PyPy_alt"]]
        elif nm == "H4":
            bases = [ASSUME["H4_newly_PyPy"]] + ASSUME["H4_newly_PyPy_alts"]
        for b in bases:
            cases.append((nm, iset, kind, desc, b))
    jobs, chunk = [], job_chunk(a)
    grid = GRID
    for nm, iset, kind, desc, b in cases:
        sizes = sets[iset][1]
        for s in range(0, a.n, chunk):
            jobs.append((nm, sizes, kind, b if b is not None else 0.0, grid, s, min(chunk, a.n - s), a.perm, a.seed))
    agg = {}
    tabs = tables()
    with ProcessPoolExecutor(a.workers, initializer=_init_worker, initargs=(tabs,)) as ex:
        for nm, b, p in ex.map(_pow_job, jobs):
            g = agg.setdefault((nm, b), {x: [] for x in grid})
            for x in grid:
                g[x] += p[x]
    out = {"what": "B2 per-comparison power: family-level sign-flip permutation test (two-sided), 4 models pooled",
           "n_datasets_per_grid_point": a.n, "perm_per_dataset": a.perm, "seed": a.seed, "alpha": ALPHA,
           "holm_column": f"alpha/7 = {ALPHA / 7:.5f} (Holm's first step = Bonferroni; the actual Holm threshold for a test lies between "
                          f"alpha/7 and alpha depending on how many other tests are rejected first)",
           "assumptions": ASSUME, "grid_pp": grid,
           "model": {"sd_family": SD_F, "sd_item": SD_I, "tau_family": TAU_F, "tau_item": TAU_I, "rho_shared_uniform": RHO,
                     "model_effects_fixed": M_EFF.tolist()},
           "rows": []}
    for nm, iset, kind, desc, b in cases:
        ni, sizes = sets[iset]
        g = agg[(nm, b if b is not None else 0.0)]
        pw = {x: float(np.mean(np.array(g[x]) < ALPHA)) for x in grid}
        ph = {x: float(np.mean(np.array(g[x]) < ALPHA / 7)) for x in grid}
        exp_units = ni * K * (ASSUME["func_pass_PyRs"] * ASSUME["func_pass_PyPy"] if kind == "pair"
                              else ASSUME["func_pass_PyRs"])
        out["rows"].append({"comparison": nm, "item_set": iset, "items": ni, "families": int(len(sizes)),
                            "expected_units": round(exp_units), "description": desc,
                            "comparator_rate": b if b is not None else (0.85 if kind == "s2_none" else 0.20),
                            "power_alpha05": pw, "power_holm_alpha7": ph,
                            "mde80_alpha05_pp": mde(pw), "mde80_holm_pp": mde(ph)})
    out["seconds"] = round(time.time() - t0, 1)
    OUT.mkdir(exist_ok=True)
    (OUT / "power.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    for r in out["rows"]:
        print(r["comparison"], r["comparator_rate"], r["mde80_alpha05_pp"], r["mde80_holm_pp"])


def mde(pw):
    """검정력 80% 를 처음 넘는 격자점과 그 앞 점 사이의 선형 보간(%p). 격자 안에서 못 넘으면 None."""
    xs = sorted(pw)
    prev = None
    for x in xs:
        if pw[x] >= 0.8:
            if prev is None:
                return {"grid_first_ge80": x, "interpolated": x, "note": "already >= 80% at the smallest grid point"}
            x0, p0 = prev
            return {"grid_first_ge80": x, "interpolated": round(x0 + (0.8 - p0) / (pw[x] - p0) * (x - x0), 2)}
        prev = (x, pw[x])
    return None


# ---------------------------------------------------------------- 12-1 경계 오판율
MARGIN = 0.05
BOUND_CELLS = {
    # 칸: (항목 집합, 판정 규칙, 포함 확률, [(rA, rB), ...])   참값 = rA − rB; |참값| = 0.05 → 경계, 0 → 참 차이 0
    "s4_new": ("holdout_scp440", "noninf", 0.85,
               [(round(b + MARGIN, 4), b) for b in (0.005, 0.01, 0.03)] + [(b, b) for b in (0.005, 0.01, 0.03)]),
    "s4_resid": ("holdout_scp440", "equiv", 0.85, [(0.22, 0.17), (0.12, 0.17), (0.17, 0.17)]),
    "s2_da": ("conf_scp715", "equiv", 0.85, [(0.22, 0.17), (0.12, 0.17), (0.17, 0.17)]),
    "H2": ("conf_logic", "equiv", 0.85 * 0.95, [(0.95, 0.90), (0.85, 0.90), (0.90, 0.90)]),
    "few_discordant": ("conf_effect_classes", "noninf", 0.85, [(0.06, 0.01), (0.01, 0.01)]),
}


def _accept(rule, lo, hi):
    if rule == "noninf":
        return hi < MARGIN
    return lo > -MARGIN and hi < MARGIN


def _bound_job(args):
    key, rule, pin, rA, rB, sizes, start, count, nboot, seed = args
    cA, cB = calibrate(rA, +1), calibrate(rB, -1)
    acc = {m: {lv: 0 for lv in LEVELS} for m in AM.CI_METHODS}
    width = {m: {lv: 0.0 for lv in LEVELS} for m in AM.CI_METHODS}
    degenerate, est = 0, 0.0
    for j in range(start, start + count):
        rng = np.random.default_rng([seed, zlib.crc32(key.encode()), j])
        L = draw_latent(rng, sizes)
        incl = rng.random(L["eta"].shape) < pin
        ya, yb = outcomes(L, cA, cB)
        d, n = fam_sums(L["fi"], L["F"], ya - yb, incl)
        F = len(d)
        W = rng.multinomial(F, np.full(F, 1.0 / F), size=nboot)
        Mo = AM.boot_moments(W, d, n)
        degenerate += int(not d.any())
        est += d.sum() / n.sum()
        for m in AM.CI_METHODS:
            ci = AM.prop_intervals(d, n, Mo, m, LEVELS)
            for lv in LEVELS:
                lo, hi = ci[lv]
                acc[m][lv] += int(_accept(rule, lo, hi))
                width[m][lv] += hi - lo
    return key, acc, width, degenerate, est, count


def boundary(a):
    sets = load_sets(a, boundary=True)
    subs = []
    for cell, (iset, rule, pin, pairs) in BOUND_CELLS.items():
        for rA, rB in pairs:
            subs.append((f"{cell}|rA={rA}|rB={rB}", cell, iset, rule, pin, rA, rB))
    jobs, chunk = [], job_chunk(a)
    for key, cell, iset, rule, pin, rA, rB in subs:
        sizes = sets[iset][1]
        for s in range(0, a.n, chunk):
            jobs.append((key, rule, pin, rA, rB, sizes, s, min(chunk, a.n - s), a.boot, a.seed))
    t0 = time.time()
    tabs = tables()
    agg = {}
    with ProcessPoolExecutor(a.workers, initializer=_init_worker, initargs=(tabs,)) as ex:
        for key, acc, width, deg, est, cnt in ex.map(_bound_job, jobs):
            g = agg.setdefault(key, {"n": 0, "deg": 0, "est": 0.0, "acc": {m: {lv: 0 for lv in LEVELS} for m in AM.CI_METHODS},
                                     "width": {m: {lv: 0.0 for lv in LEVELS} for m in AM.CI_METHODS}})
            g["n"] += cnt
            g["deg"] += deg
            g["est"] += est
            for m in AM.CI_METHODS:
                for lv in LEVELS:
                    g["acc"][m][lv] += acc[m][lv]
                    g["width"][m][lv] += width[m][lv]
    rates = sorted({(s[5], +1) for s in subs} | {(s[6], -1) for s in subs})
    realised = {f"{r}|{'A' if sg > 0 else 'B'}": {"target": r, "intercept": calibrate(r, sg),
                                                  "realised": realised_rate(calibrate(r, sg), sg)} for r, sg in rates}
    for v in realised.values():
        v["abs_error_pp"] = round(100 * abs(v["realised"] - v["target"]), 4)
    out = {"what": "12-1 decision error at the equivalence / non-inferiority boundary (margin 5pp), 4 CI methods x nominal 90%/95%",
           "n_datasets_per_cell": a.n, "boot_per_dataset": a.boot, "seed": a.seed, "margin": MARGIN,
           "rules": {"equiv": "accept (= 'equivalent') if lower > -0.05 and upper < +0.05",
                     "noninf": "accept (= 'within margin / non-inferior') if upper < +0.05"},
           "model": {"sd_family": SD_F, "sd_item": SD_I, "tau_family": TAU_F, "tau_item": TAU_I, "rho_shared_uniform": RHO,
                     "model_effects_fixed": M_EFF.tolist(), "n_models": K,
                     "inclusion": "independent Bernoulli per unit (item x model): 0.85, H2 0.85*0.95; d, n over included units"},
           "configs": {k: {"items": sets[k][0], "families": int(len(sets[k][1])), "max_family": int(sets[k][1].max()),
                           "units": sets[k][0] * K} for k in sorted({v[0] for v in BOUND_CELLS.values()})},
           "realised_rates": realised, "seconds": round(time.time() - t0, 1), "cells": {}}
    for key, cell, iset, rule, pin, rA, rB in subs:
        g = agg[key]
        truth = round(rA - rB, 6)
        kind = "boundary" if abs(abs(truth) - MARGIN) < 1e-9 else "truth0"
        lab = "false_accept" if kind == "boundary" else "correct_accept"
        c = {"cell": cell, "item_set": iset, "rule": rule, "inclusion_p": pin, "rate_A": rA, "rate_B": rB, "true_diff_pp": round(100 * truth, 3),
             "kind": kind, "n": g["n"], "datasets_all_zero_difference": g["deg"], "mean_estimate_pp": 100 * g["est"] / g["n"]}
        for m in AM.CI_METHODS:
            c[m] = {}
            for lv in LEVELS:
                p = g["acc"][m][lv] / g["n"]
                c[m][str(lv)] = {lab: p, "accepted": g["acc"][m][lv], "mcse": math.sqrt(p * (1 - p) / g["n"]),
                                 "mean_width_pp": 100 * g["width"][m][lv] / g["n"]}
        out["cells"][key] = c
    out["rule_check"] = bound_rule_check(out)
    OUT.mkdir(exist_ok=True)
    (OUT / "boundary.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(out["rule_check"], indent=1, ensure_ascii=False))


def bound_rule_check(out):
    """사전 통과 기준(12-1): 모든 경계 칸에서 오판율 ≤ 6.0% 이면 통과. 5.0% 를 넘는 칸은 따로 적는다."""
    res = {"rule": "pass if false_accept <= 0.060 in every boundary cell; cells > 0.050 listed", "per_method_level": {}}
    bc = {k: v for k, v in out["cells"].items() if v["kind"] == "boundary"}
    for m in AM.CI_METHODS:
        for lv in LEVELS:
            fa = {k: v[m][str(lv)]["false_accept"] for k, v in bc.items()}
            worst = max(fa, key=fa.get)
            res["per_method_level"][f"{m}|{lv}"] = {"max_false_accept": fa[worst], "max_at": worst,
                                                    "all_le_0.060": all(x <= 0.060 for x in fa.values()),
                                                    "cells_above_0.050": {k: x for k, x in fa.items() if x > 0.050}}
    return res


# ---------------------------------------------------------------- 12-2 2-가-1 되살아남 민감도
REVIVE = (0.0, 0.02, 0.05)


def _pow21_job(args):
    sizes, r, grid, start, count, nperm, seed = args
    name = "2-ga-1"
    fb = ASSUME["base_vulnerable_share_of_targets"]
    p, sk = {g: [] for g in grid}, []
    for j in range(start, start + count):
        rng = np.random.default_rng([seed, zlib.crc32(f"{name}|0.0".encode()), j])
        L = draw_latent(rng, sizes)
        shape = L["eta"].shape
        incl = rng.random(shape) < ASSUME["func_pass_PyRs"]
        Lz = draw_latent(rng, sizes)
        z = (Lz["U"] < _sig(calibrate(fb, 0) + Lz["eta"])).astype(np.int64)
        rev = ((rng.random(shape) < r) & (z == 0)).astype(np.int64)     # 같은 난수를 r 사이에 공유
        prng = np.random.default_rng([seed, 5, zlib.crc32(name.encode()), j])
        for g in grid:
            fix = (g / 100 + r * (1 - fb)) / fb          # 출발 취약 가운데 고쳐지는 비율
            if fix > 1:
                continue
            sA = max(1 - fix, 1e-4)
            ya, _ = outcomes(L, calibrate(sA, +1), calibrate(0.2, -1))
            ya, yb = z * ya + (1 - z) * rev, z
            d, _n = fam_sums(L["fi"], L["F"], ya - yb, incl)
            p[g].append(fast_perm_p(d, nperm, prng))
    return r, p


def power21(a):
    sets = load_sets(a)
    sizes = sets["conf_scp715"][1]
    fb = ASSUME["base_vulnerable_share_of_targets"]
    t0 = time.time()
    jobs, chunk = [], job_chunk(a)
    for r in REVIVE:
        for s in range(0, a.n, chunk):
            jobs.append((sizes, r, GRID, s, min(chunk, a.n - s), a.perm, a.seed))
    agg = {}
    tabs = tables()
    with ProcessPoolExecutor(a.workers, initializer=_init_worker, initargs=(tabs,)) as ex:
        for r, p in ex.map(_pow21_job, jobs):
            g = agg.setdefault(r, {x: [] for x in GRID})
            for x in GRID:
                g[x] += p[x]
    out = {"what": "12-2 sensitivity of comparison 2-ga-1 (B1 vs none) to revival among units not vulnerable at start",
           "n_datasets_per_grid_point": a.n, "perm_per_dataset": a.perm, "seed": a.seed, "alpha": ALPHA,
           "holm_column": f"alpha/7 = {ALPHA / 7:.5f}", "assumptions": ASSUME, "grid_pp": GRID,
           "revival": "each included unit with z = 0 becomes vulnerable after mitigation independently with probability r "
                      "(one uniform per unit shared across r and grid points); grid value = expected NET reduction on the full "
                      "included denominator = fb*fix - (1-fb)*r, so fix = (delta + r*(1-fb))/fb; grid points with fix > 1 skipped",
           "realised_base_vulnerable_share": realised_rate(calibrate(fb, 0), 0),
           "existing_power_json_row_2ga1": None, "rows": []}
    try:
        old = json.loads((OUT / "power.json").read_text(encoding="utf-8"))
        r0 = next(x for x in old["rows"] if x["comparison"] == "2-ga-1")
        out["existing_power_json_row_2ga1"] = {k: r0[k] for k in ("power_alpha05", "power_holm_alpha7", "mde80_alpha05_pp", "mde80_holm_pp")}
    except Exception as e:  # noqa: BLE001
        out["existing_power_json_row_2ga1"] = f"not read: {e}"
    for r in REVIVE:
        g = agg[r]
        pts = [x for x in GRID if len(g[x]) > 0]
        pw = {x: float(np.mean(np.array(g[x]) < ALPHA)) for x in pts}
        ph = {x: float(np.mean(np.array(g[x]) < ALPHA / 7)) for x in pts}
        out["rows"].append({"revival_r": r, "expected_revived_share_pp": round(100 * r * (1 - fb), 4),
                            "fix_prob_among_z1": {x: round((x / 100 + r * (1 - fb)) / fb, 6) for x in pts},
                            "skipped_grid_pp": [x for x in GRID if x not in pts], "n_per_point": {x: len(g[x]) for x in pts},
                            "power_alpha05": pw, "power_holm_alpha7": ph, "mde80_alpha05_pp": mde(pw), "mde80_holm_pp": mde(ph)})
    out["seconds"] = round(time.time() - t0, 1)
    OUT.mkdir(exist_ok=True)
    (OUT / "power_2ga1_sensitivity.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    for row in out["rows"]:
        print(row["revival_r"], row["mde80_alpha05_pp"], row["mde80_holm_pp"])


# ---------------------------------------------------------------- 요약
def summary(_a):
    cv = json.loads((OUT / "coverage.json").read_text(encoding="utf-8"))
    pw = json.loads((OUT / "power.json").read_text(encoding="utf-8"))
    L = ["# 분석 동결 전 모의실험 (결정 11-5)", "",
         f"스크립트 analyze_main_sims.py {AM.sha16(__file__)}, analyze_main.py {AM.sha16(AM.__file__)}. 모델 호출 없음. 실제 결과를 쓰지 않았다.", "",
         "## B1 구간 포함률", "",
         f"- 자료 {cv['n_datasets_per_cell']}벌/칸, 재표본 {cv['boot_per_dataset']}번/자료, seed {cv['seed']}. 모델 4개(효과 고정), "
         f"묶음·항목 상관 모형 = analyze_main_checks 와 같은 꼴 {cv['model']}.",
         "- 설정: " + "; ".join(f"{k} 항목 {v['items']}, 묶음 {v['families']} (최대 {v['max_family']})" for k, v in cv["configs"].items()),
         "- 시나리오(참 비율 A/B): " + "; ".join(f"{k} {v['rate_A']:.2f}/{v['rate_B']:.2f} (다시 잰 값 {v['realised_rate_A']:.4f}/"
                                              f"{v['realised_rate_B']:.4f})" for k, v in cv["scenarios"].items()), "",
         "| 설정 | 시나리오 | " + " | ".join(f"{m} 90%" for m in AM.CI_METHODS) + " | " + " | ".join(f"{m} 95%" for m in AM.CI_METHODS) + " |",
         "|---|---|" + "---|" * 8]
    for k, c in cv["cells"].items():
        cfg, sc = k.split("|")
        L.append(f"| {cfg} | {sc} | " + " | ".join(f"{100 * c[m]['0.9']['coverage']:.1f} ± {100 * c[m]['0.9']['mcse']:.1f}" for m in AM.CI_METHODS)
                 + " | " + " | ".join(f"{100 * c[m]['0.95']['coverage']:.1f}" for m in AM.CI_METHODS) + " |")
    L += ["", "90% 구간에서 참값이 상한 위로 빠진 비율(비열등 판정의 위험 쪽, %): " + "; ".join(
        f"{k}: " + ", ".join(f"{m} {100 * c[m]['0.9']['miss_truth_above_upper']:.1f}" for m in AM.CI_METHODS) for k, c in cv["cells"].items()), ""]
    s = cv["selection"]
    L += ["### 규칙 적용", "", "| 방법 | 최소 칸 | 평균 | 설정별 평균 | 모든 칸 ≥ 89% | 설정 평균 모두 ≥ 89% |", "|---|---|---|---|---|---|"]
    for m, r in s["per_method"].items():
        L.append(f"| {m} | {100 * r['min_cell']:.1f} ({r['min_cell_at']}) | {100 * r['mean']:.1f} | "
                 + ", ".join(f"{k} {100 * v:.1f}" for k, v in r["config_means"].items()) + f" | {r['all_cells_ge_89']} | {r['all_config_means_ge_89']} |")
    L += ["", f"- 모든 칸 기준으로 규칙을 만족하는 방법 {s['eligible_all_cells']} → **{s['chosen_all_cells_rule']}**",
          f"- 설정별 평균 기준 {s['eligible_config_means']} → {s['chosen_config_mean_rule']}",
          (f"- 모든 칸에서 89%를 넘는 방법이 없다. 최소 칸이 가장 높은 방법: {s['if_none_best_by_min_cell']}" if s["if_none_best_by_min_cell"] else ""),
          "- analyze_main.py 기본값은 바꾸지 않았다(검토 뒤 바꾼다).", "",
          "## B2 비교별 검정력", "",
          f"- 자료 {pw['n_datasets_per_grid_point']}벌/격자점, 치환 {pw['perm_per_dataset']}번/자료(본 분석 10,000번보다 적다), "
          f"seed {pw['seed']}. 검정 = 묶음 단위 부호 뒤집기 치환(양측), 모델 4개 합. Holm 칸 = {pw['holm_column']}.",
          f"- 가정(개발용 실행에서 본 값을 바탕으로 정한 것, 결과가 아님): {pw['assumptions']}", "",
          "| 비교 | 항목 | 묶음 | 예상 짝/번역 | 기준 비율 | 80% 검정력 차이 α=0.05 (%p) | Holm α/7 (%p) |", "|---|---|---|---|---|---|---|"]
    for r in pw["rows"]:
        f = lambda v: "격자 밖" if v is None else f"{v['interpolated']}"  # noqa: E731
        L.append(f"| {r['comparison']} | {r['items']} | {r['families']} | {r['expected_units']} | {r['comparator_rate']} | "
                 f"{f(r['mde80_alpha05_pp'])} | {f(r['mde80_holm_pp'])} |")
    L += ["", "비교마다의 설명: " + "; ".join(f"{r['comparison']}: {r['description']}" for r in pw["rows"] if r['comparator_rate'] in
                                          (0.2, 0.01, 0.85)), ""]
    (OUT / "SUMMARY.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["coverage", "power", "summary", "boundary", "power21"])
    ap.add_argument("--n", type=int)
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--perm", type=int, default=1000)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--sizes", help="family_sizes.json: 항목 목록·CWE 메타 대신 표본 구성별 묶음 크기만 쓴다(데이터셋 파일을 읽지 않음)")
    ap.add_argument("--chunk", type=int, help="작업 하나에 넣는 자료 수(기본 n // workers). --workers 를 바꿔도 같은 실수 합을 내려면 맞춘다")
    ap.add_argument("--out", help="출력 폴더(기본 dataset_pilot/_sims)")
    a = ap.parse_args()
    if a.out:
        OUT = Path(a.out).resolve()
    if a.mode == "coverage":
        a.n, a.seed = a.n or 2000, a.seed or 20261114
        coverage(a)
    elif a.mode == "power":
        a.n, a.seed = a.n or 500, a.seed or 20261115
        power(a)
    elif a.mode == "boundary":
        a.n, a.seed = a.n or 2000, a.seed or 20261116
        boundary(a)
    elif a.mode == "power21":
        a.n, a.seed = a.n or 500, a.seed or 20261117
        power21(a)
    else:
        summary(a)
