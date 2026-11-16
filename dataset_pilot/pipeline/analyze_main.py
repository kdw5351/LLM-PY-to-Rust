"""본 실험 분석 스크립트 (사전등록_2026-11-13_v2 8~13절). 모델 호출 없음, 프로그램 실행 없음.

입력
  --run [MODEL=]ROOT        run_main.py 실행 폴더(모델 하나당 하나). MODEL 을 안 주면 config.json 의 model.
  --brun MODEL=DIR[,DIR..]  옛 형식 B 실행 폴더(eval_rows.json; cond 별 하위 폴더). 같은 모델의 여러 폴더를 합친다.
  --arun MODEL=DIR          옛 형식 A 실행 폴더(eval_rows.json, T0/T1). 1단계만.
  --items FILE              이 항목 목록으로 제한. --sample-label all|D|H
  --seed N                  치환·재표본 난수 시드(필수, 결과 JSON 에 기록)
  --perm 10000 --boot 10000 --delta 0.05
  --best auto|COND          "기존 최선"(auto = 4-2절 규칙을 --best-items 목록에서 적용)
  --twice COND              3단계 B(예산) 판별에 쓸 "기존 최선 두 번" 조건(기본: 최선이 B1 이면 SPEC2)
  --oracle ORA              오라클 조건 이름
  --s3-items FILE           3단계 대상 항목(보통 D). 없으면 --items
  --s4-new C --s4-base C --s4-repeat C   4단계(새 기법, 기존 최선, 기존 최선 반복). --s4-items FILE
  --out-json P --out-md P --targets-tsv P

출력에는 개수·라벨·통계만 쓴다(시험 입력·기대값·코드 없음).

판정·지표(사전 등록 그대로, 해석은 아래 AMBIG 표에 적음)
  1단계 짝: (모델, 항목, 출발 판)에서 Py→Rs·Py→Py 두 번역이 모두 판정용 기능 시험 통과(T1)일 때만.
  2·4단계 짝: (모델, 항목, 출발 판)에서 두 조건 줄이 모두 있을 때. "없음" = 출발 번역(B 줄의 출발 판정).
  고친 뒤에도 취약 = 취약판 출발 번역 중 보안 시험이 하나라도 실패(pairs 에 left/new). 효과 틀 종류(502·94·95·22·78)는
  효과 판정이 있으면 효과(fired)로 판정(주 판정), 없으면 데이터셋 판정으로 대신하고 그 수를 적는다.
통계(12절): 단위 = 번역, 통계량 = 조건 A − 조건 B 의 '나쁨' 번역 수(모델 합). p = 시드 묶음 단위 치환(묶음마다 1/2 확률로
  모든 모델·모든 번역의 두 조건을 맞바꿈), 구간 = 묶음 단위 재표본. 독립 가정판(번역마다 따로)도 함께. Holm 은 확증 6개에.
"""
import argparse
import collections
import datetime
import hashlib
import json
import math
import re
import statistics
import sys
import zlib
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
DS = HERE.parent
sys.path.insert(0, str(DS))
sys.path.insert(0, str(HERE))
import residual_facts as RF  # noqa: E402  (1·2층: kind_of, expect_kind, failure_mode, load_runs)

SEED_FAMILIES = DS / "export" / "seed_families.json"
FAM = None  # 항목 -> 시드 묶음. 처음 쓸 때 읽는다(가져오기만으로는 자료 파일을 읽지 않음). 파일이 없으면 빈 지도(단위 확인용)


def fam_map():
    global FAM
    if FAM is None:
        FAM = json.loads(SEED_FAMILIES.read_text(encoding="utf-8"))["family_of"] if SEED_FAMILIES.exists() else {}
    return FAM


EFFECT_CWES = {502, 94, 95, 22, 78}        # 8-2·14절: 효과 판정 종류
CODE_EXEC_CWES = {502, 94, 95, 78}         # H1
DOS_SUBS = ("timeout", "panic", "crash")
NONE = "NONE"                              # 2단계 '없음' = 출발 번역
EXPORT_SCP = DS / "export"
EXPORT_CW = DS / "export_cweval"

AMBIG = [
    "A0 기준: 사전등록 v2 + 검토의견_반영_결정_2026-11-13(1~7, 9.4절)이 다른 곳은 결정 문서를 따랐다.",
    "A1 단일 취약 판정식(결정 4절): 효과 틀 종류(502·94·95·22·78)는 효과 발생(④)만 취약, 그 밖은 데이터셋 판정. "
    "효과 칸이 없는 줄(옛 개발용 실행 등)은 데이터셋 판정으로 대신하고 그 수를 적는다. 민감도 = 모든 종류 데이터셋 판정.",
    "A2 H1 결과 = 취약판 번역의 '없어짐'(단일 판정식으로 취약 아님) 번역 수, Py→Rs − Py→Py, 대상 502·94·95·78.",
    "A3 H4 = 수정판 번역이 단일 판정식으로 취약하거나, '새로 생김' 보안 사례 중 비정상 종료(panic/crash/timeout, 효과 없음)가 있음. "
    "1단계 원본 수정판은 정의상 안전이므로 '취약하다' = '취약이 되었다'로 본다.",
    "A4 H2 논리형 = 효과 틀이 없는 종류(8-3), 결과 = 취약판 번역의 취약 여부, 판정 구간(결정 13-3: 시드 묶음 단위 재표본의 BCa 명목 95% "
    "구간, --ci-method·--decision-level 로 바꿀 수 있음)이 ±5%p 안(사전 지정 보조). 예외 처리는 A34.",
    "A5 1단계 짝 = (항목, 출발 판, 모델)에서 두 번역 모두 기능 통과(T1). 다시 생성 민감도는 Py→Py 의 regen>0 인 짝을 뺀다(짝 단위).",
    "A6 2단계 분모 = 취약판 출발 번역 전부(보안 결과로 고르지 않음). 출발이 취약한 번역 수를 함께 적는다.",
    "A7 '없음' 조건의 판정 = B 줄의 출발 판정(removed/left = 출발에서 뚫림), 효과는 A 의 Py→Rs T1 효과. A T1 과 대조해 어긋난 수를 적는다.",
    "A8 '기존 최선' 후보 = 없음·정책 제공 참고 조건을 뺀 B0·RCI·B1·SPEC2·BUD. 호출 = B 줄 calls 합(모델 합).",
    "A9 치환 p = (|T*|≥|T| 수 + 1)/(치환 수 + 1), 양측. 개수 구간(count_ci95)은 백분위, 비율 차이 구간은 A33. "
    "비율 차이의 분모 = 재표본에 든 번역 수.",
    "A10 (결정 11-2로 바꿈, 13-3으로 구간 바꿈) d_신규 = 새 기법 − 기존 최선의 '새로 생김' 비율 차이(수정판 출발), 판정 구간 = "
    "묶음 단위 BCa 명목 95% 구간(A33). 세 갈래: 상한 < +5%p "
    "= 비열등 성립, 하한 > +5%p = 여유를 넘는 악화, 그 밖 = 판단 불가(경계값 = 판단 불가). 같은 구간으로 여유 2%p 분류를 보조로 내고 "
    "상한은 늘 적는다. d_잔여 동등성(구간 전체가 ±5%p 안, 경계 제외)은 따로 판정한다.",
    "A11 (결정 11-2로 바꿈) 4단계 결론 = 일곱 줄 표를 위에서부터 처음 맞는 줄. '유의'는 Holm 보정 뒤 기각, 개선/악화는 차이 부호. "
    "줄 4의 '4-나는 유의하지 않음'은 Holm 기각이 아님이다(4-나가 반대 방향으로 유의하면 줄 7). 겹침: 줄 3~5 에서 d_잔여 구간이 "
    "±5%p 안이면 '개선의 크기는 …' 문장을 덧붙인다. 줄 1 은 잔여 수치를 덧붙이고, 줄 7 은 가리지 못한 부분을 적는다.",
    "A30 H1·H4 세 가지 판(결정 11-3): 주, 다시 생성된 짝 뺌(A5), 최초 Py→Py 결과(A 줄 칸 first_before_regen; 다시 만들지 않은 줄은 null = "
    "주 결과). Py→Py 줄에 칸이 없거나 다시 만든 줄에 판정 dict 가 없으면 not available.",
    "A31 ③칸 사례(결정 11-4) = 효과 판정군에서 columns 가 accepted_no_effect 인 보안 사례. 1단계 A T1(두 판·두 조건), 2단계 B 최종 프로그램"
    "(조건마다). 분류 파일 칸 case_id·label·q1_reached·q2_risky_feature. 민감도는 '공격 표현만 실패'·'구분 불가'인 사례가 있는 번역을 "
    "남음으로 본다(미분류는 주 판정, 미분류까지 남음으로 본 번역 수를 함께 적음). '없음' 조건은 A 의 Py→Rs 사례를 쓴다.",
    "A32 모델 집합(결정 11-6): 4단계 조건이 항목 목록의 모든 대상(모델의 '없음' 줄)에 있는 모델만 4단계(4-가·4-나·신규 위험)에 합친다. "
    "같은 모델 집합의 2단계 확증 비교를 민감도로 낸다(Holm 밖).",
    "A33 구간 계산법(결정 13-3으로 고정): 기본 --ci-method bca, --decision-level 0.95. 동등성·비열등 판정(H2, 2-다, 4단계 d_잔여 "
    "동등성, d_신규 세 갈래와 2%p 보조, 독립 가정판·CWE 묶음 민감도의 eq 표시)은 고른 방법의 명목 판정 수준 구간으로 한다(BCa의 명목 "
    "95% 구간; 확인한 모의 조건에서 양쪽 포함률 약 92~94%, 판정 경계 오판율 2.6~4.3%이며 '모든 상황에서 검증된 95% 구간'이 아니다). "
    "비율 차이 구간(prop_ci90/95)만 방법에 따라 바뀐다. 개수 구간 count_ci95 와 3단계 구간은 백분위 그대로. 백분위 구간은 늘 "
    "prop_ci90_percentile·prop_ci95_percentile 로도 낸다. 결과 JSON 에 ci_method·decision_level 을 맨 위와 판정마다 적는다. "
    "이전 동작(결정 13 이전)은 --ci-method percentile --decision-level 0.90 으로 재현한다(이 조합에서는 A34 예외 규칙을 걸지 않는다).",
    "A34 예외 처리(결정 13-2, 가는 15-1로 바꿈; 구간으로 판정하는 모든 곳): 가) 묶음별 차이의 합이 모두 0(엇갈린 묶음 0개) = 구간으로 "
    "판정하지 않고 동등성·비열등·2%p 보조 모두 '판정 보류'(세 갈래는 판단 불가 줄). 묶음 수로 자동 통과시키지 않는다. exception all_zero, "
    "all_zero_case = all_concordant(엇갈린 번역 쌍 0개) 또는 family_sums_zero(엇갈린 쌍이 묶음 안에서 상쇄; n_pairs_a_worse = a − b > 0, "
    "n_pairs_a_better = a − b < 0 를 적음). 관측 차이 0, 번역 수, 묶음 수, 엇갈린 쌍 수를 적는다. 4단계에서 d_신규가 이 경우면 3·4·6줄에 "
    "들 수 없고(5줄 또는 7줄), 고른 줄 문장 뒤에 0건(또는 상쇄) 문장을 덧붙인다. 나) 엇갈린 묶음 1~4개 = 같은 수준의 "
    "고른 방법 구간과 백분위 구간이 모두 '범위 안'일 때만 '범위 안', 갈리면 exception few_discordant_methods_disagree. 다) BCa: 잭나이프 "
    "값이 모두 같으면 가속 0, 보정식 분모 1 − a(z0 + z) ≤ 0 이면 그 끝점을 재표본 최솟값(하한)·최댓값(상한)으로 두고 bca_guard 에 적음. "
    "라) 재표본 추정값이 모두 같은데 차이 ≠ 0 = '판정 보류(자료 부족)', exception degenerate_nonzero. 세 갈래에서 '범위 안' = 상한 < +여유 "
    "줄, 판정 보류 = 판단 불가 줄. 엇갈린 묶음 수는 판정마다 적는다.",
    "A12 3단계 대상 = 취약판 출발 번역 중 기존 최선 뒤 단일 판정식으로 취약. 수정판 번역의 새로 생김은 수만 따로 적는다.",
    "A13 J = P1 이면서 마지막 거절 이유가 functional_regression. 어느 시도든 functional_regression 이 있었던 수도 적는다. "
    "R/N 은 정책 제공 참고 조건 뒤 단일 판정식, T 는 '같은 조건 한 번 더'(기존 최선이 B1 이면 SPEC2, 아니면 --twice).",
    "A14 첫 결과물 '기능 깨짐' = 빌드 안 됨 또는 기능 시험 실패. 첫 결과물의 보안 수는 빌드된 것만(분모 적음).",
    "A15 '고친 수'(기능 지킴) = 취약판 출발 줄에서 removed 이고 기능이 깨지지 않은 보안 시험 수(데이터셋 판정, 시험 단위).",
    "A16 targets.tsv 에 model 칸을 끝에 더했다.",
    "A17 Holm: 확증 7개(H1, H4, 2-ga-1, 2-ga-2, 2-na, 4-ga, 4-na), 4단계가 없으면 5개. 계산된 것에만 걸고 빠진 것을 적는다.",
    "A18 기존 최선 규칙에서 취약 수와 호출 수가 모두 같으면 B0, RCI, B1, SPEC2, BUD 순서의 앞 조건을 고르고 tie_after_calls 로 표시.",
    "A19 호출 수는 B 줄 calls(SPEC2 = 1단계+2단계)와 calls.jsonl 의 조건별 줄 수((reply, regen) 중복 제거) 둘 다 낸다.",
    "A20 '선택에 쓰지 않은 기능 시험' 칸 이름은 아직 없다: B 줄/first 의 visible_ok·visible_pass·visible_functional_ok·"
    "unselected_functional_ok·visible.ok 중 있는 것을 읽고, 없으면 not available.",
    "A21 11-7: 3단계 남은 번역(--s3-items, 모델 합)이 40개 미만이면 4단계 확증을 내지 않는다(--override-11-7 이면 내고 '규칙 밖' 표시). "
    "3단계를 셀 수 없으면(가림 등) 40개 미만과 같이 다룬다.",
    "A22 선택에 쓰지 않은 기능 시험: '깨짐' = visible_after.failed > 0 또는 class ≠ passed. 분모 = visible_after 가 null 이 아닌 대상. "
    "첫 결과물은 visible_after 가 있는 것만 세고 프로그램이 없는 것(빌드 안 됨)은 따로 센다.",
    "A23 층 = 그 번역의 보이는 시험 수 > 0(A 줄 visible_tests), B 줄은 visible_after 칸으로. 칸이 없는 옛 형식은 unknown.",
    "A24 3단계 구간 = 기존 최선의 취약판 출발 번역 전체(--s3-items 안)를 시드 묶음 단위로 재표본해 센 R·N·J·T·겹침·남은 수.",
    "A25 4층: 분류자 파일은 tkey(있으면 model 도)로 맞춘다. 두 분류자가 다르면 판정 파일 값, 없으면 UNRESOLVED. "
    "K3·K4 를 뺀 계산은 최종 라벨이 K3·K4 인 것만 뺀다. κ 는 Cohen(가중 없음).",
    "A26 CWE 묶음 민감도는 확증 검정마다 같은 치환·재표본을 CWE 단위로 다시 한 것이며 결정에 쓰지 않는다.",
    "A27 RQ3: 지표 = A 줄 rust_indicators(빌드된 Py→Rs T1, clippy σ). 2단계 대상 σ0 = B4 state(기능 통과 부분집합). 조건 뒤 "
    "최종 프로그램의 σ 는 저장되지 않아 받아들인 줄은 not available, 출발로 되돌린 줄은 σ0. 기능 시험 비정상 = capability 의 "
    "fail 중 panic/crash/timeout. 빌드 실패 라벨은 run_main.py 규칙(config build_failure_rule).",
    "A28 RQ4: 회차 = fix_rounds(빌드 고치기, 빌드된 줄만 분포; 빌드 안 됨은 따로), visible_rounds(보이는 시험을 돌린 줄), "
    "합. 교차표 = 기능 통과 T1, 취약 = 단일 판정식(취약판 남음, 수정판 새로 생김). p = 시드 묶음 안에서 회차 묶음을 섞는 치환"
    "(모델 합, 탐색).",
    "A29 RQ5 남김: 취약판 대상의 출발 번역에서 뚫리지 않은 보안 사례(B pairs new/safe) 중 조건 뒤 뚫림(new) = 다시 생김. "
    "기존 stage2.security new_tests_vulnerable_src 와 같은 수(이름만 다름). A T1 pairs 로 gone(번역에서 사라짐)/safe(둘 다 안전) 로 나눈다.",
]


# ---------------------------------------------------------------- 공통
def jl(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def read_list(p):
    return [l.strip() for l in Path(p).read_text(encoding="utf-8").splitlines() if l.strip()]


def sha16(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()[:16]


def family(item):
    return fam_map().get(item, "solo_" + item)


def is_scp(item):
    return item in fam_map()


_CWE = {}


def cwe_of(item, export_root=None):
    if item in _CWE:
        return _CWE[item]
    m = re.match(r"^cwe_(\d+)_", item)
    if m:
        c = int(m.group(1))
    else:
        root = Path(export_root) if export_root else EXPORT_SCP
        p = root / "programs" / item / "meta.json"
        if not p.exists():
            p = EXPORT_SCP / "programs" / item / "meta.json"
        try:
            c = int(str(jl(p).get("cwe", "-1")).replace("CWE-", ""))
        except Exception:
            c = -1
    _CWE[item] = c
    return c


def eff_valid(eff, n):
    return isinstance(eff, list) and len(eff) > 0 and len(eff) == n


def fired(eff):
    return any(e[0] == "effect" for e in eff)


def C(it):
    return dict(collections.Counter(it))


# ---------------------------------------------------------------- 통계
def _rng(seed, key, extra=0):
    return np.random.default_rng([int(seed), zlib.crc32(key.encode("utf-8")), int(extra)])


def _clusters(units, cluster):
    """units: [(cluster_key, a, b)] -> d (a-b 합), n (번역 수) per cluster."""
    agg = {}
    for i, (f, a, b) in enumerate(units):
        k = f if cluster else i
        s = agg.setdefault(k, [0, 0])
        s[0] += int(a) - int(b)
        s[1] += 1
    d = np.array([v[0] for v in agg.values()], dtype=np.int64)
    n = np.array([v[1] for v in agg.values()], dtype=np.int64)
    return d, n


def perm_test(units, seed, key, nperm, cluster=True):
    d, _ = _clusters(units, cluster)
    T = int(d.sum())
    if len(d) == 0 or not d.any():
        return {"T": T, "p": 1.0, "nperm": nperm, "n_clusters": int(len(d)), "n_nonzero_clusters": 0}
    nz = d[d != 0]
    rng = _rng(seed, key, 1 if cluster else 2)
    cnt, done, chunk = 0, 0, 2000
    while done < nperm:
        m = min(chunk, nperm - done)
        S = rng.integers(0, 2, size=(m, len(nz)), dtype=np.int8) * 2 - 1
        Ts = S.astype(np.int64) @ nz
        cnt += int((np.abs(Ts) >= abs(T)).sum())
        done += m
    return {"T": T, "p": (cnt + 1) / (nperm + 1), "nperm": nperm, "n_clusters": int(len(d)),
            "n_nonzero_clusters": int(len(nz))}


# 구간 계산법(결정 13-3으로 고정): 기본 BCa, 판정은 명목 95% 구간. 모의 결과는 analyze_main_sims.py·_sims/.
# 이전 동작은 --ci-method percentile --decision-level 0.90(이 조합에서는 13-2 예외 규칙을 끈다).
CI_METHODS = ("percentile", "bca", "boot_t", "cluster_t")
CI_METHOD = "bca"
DECISION_LEVEL = 0.95
DECISION_LEVELS = (0.90, 0.95)
EXCEPTION_RULES = True          # 결정 13-2 예외 처리(가는 15-1: 차이 모두 0이면 늘 판정 보류). main 은 이전 동작 조합에서만 끈다.
CI_METHOD_LABEL = {"percentile": "백분위 재표본", "bca": "BCa", "boot_t": "재표본-t", "cluster_t": "묶음 강건 표준오차 + t"}
# prop_intervals 의 마지막 호출 기록(반환 모양을 바꾸지 않으려고 모듈 변수로 둔다; 결정 13-2 다).
LAST_INTERVAL_NOTE = {}
_ND = statistics.NormalDist()


def _betacf(a, b, x):
    """정규화 불완전 베타의 연분수(Numerical Recipes betacf)."""
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > 1e-300 else 1e-300)
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > 1e-300 else 1e-300)
        c = 1.0 + aa / c if abs(c) > 1e-300 else 1e-300
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > 1e-300 else 1e-300)
        c = 1.0 + aa / c if abs(c) > 1e-300 else 1e-300
        de = d * c
        h *= de
        if abs(de - 1.0) < 3e-14:
            break
    return h


def _betai(a, b, x):
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    lb = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1 - x)
    if x < (a + 1) / (a + b + 2):
        return math.exp(lb) * _betacf(a, b, x) / a
    return 1.0 - math.exp(lb) * _betacf(b, a, 1 - x) / b


def t_cdf(t, df):
    x = df / (df + t * t)
    p = 0.5 * _betai(df / 2.0, 0.5, x)
    return 1.0 - p if t > 0 else p


def t_ppf(p, df):
    """t 분포 분위수(이분법, |오차| < 1e-10)."""
    if df <= 0:
        return float("nan")
    lo, hi = -1e3, 1e3
    for _ in range(200):
        mid = (lo + hi) / 2
        if t_cdf(mid, df) < p:
            lo = mid
        else:
            hi = mid
        if hi - lo < 1e-10:
            break
    return (lo + hi) / 2


def ratio_se(d, n):
    """비율 차이 θ = Σd/Σn 의 묶음 강건(선형화) 표준오차, 소표본 보정 F/(F−1)."""
    F = len(d)
    N = float(n.sum())
    if F < 2 or N == 0:
        return 0.0
    th = d.sum() / N
    e = d - th * n
    return math.sqrt(F / (F - 1) * float((e * e).sum())) / N


def boot_moments(W, d, n):
    """재표본 개수 행렬 W(B×F) -> 구간 계산에 쓰는 재표본별 합(조각으로 나눠 구해 이어 붙일 수 있다)."""
    d = np.asarray(d, dtype=float)
    n = np.asarray(n, dtype=float)
    return {"Wd": W @ d, "Wn": W @ n, "Wdd": W @ (d * d), "Wdn": W @ (d * n), "Wnn": W @ (n * n), "Fb": W.sum(axis=1)}


def cat_moments(Ms):
    return {k: np.concatenate([M[k] for M in Ms]) for k in Ms[0]}


def _pct(lv):
    return round((1 - lv) / 2 * 100, 10)


def prop_intervals(d, n, M, method, levels=(0.90, 0.95)):
    """묶음별 d(차이 합), n(번역 수)와 재표본 합 M(boot_moments)으로 비율 차이 구간. 반환 {수준: [하한, 상한]}.
    percentile = θ* 백분위; bca = 편향·가속 보정(가속은 묶음 잭나이프); boot_t = 묶음 강건 SE 로 표준화한 t* 의 분위수;
    cluster_t = θ̂ ± t(F−1) × 묶음 강건 SE (W 를 쓰지 않음).
    결정 13-2 다(bca): 잭나이프 값이 모두 같으면 가속 0, 보정식 분모 1 − a(z0 + z) ≤ 0 이면 그 끝점은 재표본 최솟값(하한)·최댓값(상한).
    어느 쪽이든 모듈 변수 LAST_INTERVAL_NOTE 에 적는다(반환 모양은 그대로)."""
    global LAST_INTERVAL_NOTE
    d = np.asarray(d, dtype=float)
    n = np.asarray(n, dtype=float)
    F = len(d)
    N = n.sum()
    th = d.sum() / N
    out = {}
    note = {"method": method, "degenerate": False, "acc_zero_constant_jackknife": False, "endpoint_fallback": []}
    LAST_INTERVAL_NOTE = note
    if method == "cluster_t":
        se = ratio_se(d, n)
        for lv in levels:
            q = t_ppf(1 - (1 - lv) / 2, F - 1) if F > 1 else float("nan")
            out[lv] = [float(th - q * se), float(th + q * se)] if F > 1 else [float(th), float(th)]
        return out
    Wd, Wn = M["Wd"], M["Wn"]
    ps = Wd / Wn
    if method == "percentile":
        for lv in levels:
            a = _pct(lv)
            out[lv] = [float(np.percentile(ps, a)), float(np.percentile(ps, 100 - a))]
        return out
    if method == "bca":
        B = len(ps)
        if np.all(ps == ps[0]):
            note["degenerate"] = True
            return {lv: [float(ps[0]), float(ps[0])] for lv in levels}
        prop = (np.sum(ps < th) + 0.5 * np.sum(ps == th)) / B
        prop = min(max(prop, 1.0 / (2 * B)), 1 - 1.0 / (2 * B))
        z0 = _ND.inv_cdf(prop)
        keep = (N - n) > 0
        jk = (d.sum() - d[keep]) / (N - n[keep])
        dev = jk.mean() - jk
        den = float((dev ** 2).sum())
        if len(jk) == 0 or den <= 0 or float(np.ptp(jk)) <= 1e-12 * max(1.0, float(np.abs(jk).max())):
            acc = 0.0
            note["acc_zero_constant_jackknife"] = True
        else:
            acc = float((dev ** 3).sum()) / (6 * den ** 1.5)
        for lv in levels:
            res = []
            for side, z in (("lower", _ND.inv_cdf((1 - lv) / 2)), ("upper", _ND.inv_cdf(1 - (1 - lv) / 2))):
                den_c = 1 - acc * (z0 + z)
                if den_c <= 0:
                    res.append(float(ps.min() if side == "lower" else ps.max()))
                    note["endpoint_fallback"].append([lv, side])
                    continue
                zz = z0 + (z0 + z) / den_c
                res.append(float(np.percentile(ps, 100 * min(max(_ND.cdf(zz), 0.0), 1.0))))
            out[lv] = res
        return out
    if method == "boot_t":
        se = ratio_se(d, n)
        if se == 0:
            return {lv: [float(th), float(th)] for lv in levels}
        e2 = M["Wdd"] - 2 * ps * M["Wdn"] + ps * ps * M["Wnn"]
        Fb = M["Fb"]
        var = np.where(Fb > 1, Fb / np.maximum(Fb - 1, 1), 0) * np.maximum(e2, 0) / (Wn * Wn)
        ok = var > 0
        if not ok.any():
            return {lv: [float(th), float(th)] for lv in levels}
        ts = (ps[ok] - th) / np.sqrt(var[ok])
        for lv in levels:
            a = _pct(lv)
            out[lv] = [float(th - np.percentile(ts, 100 - a) * se), float(th - np.percentile(ts, a) * se)]
        return out
    raise ValueError(method)


def boot_ci(units, seed, key, nboot, cluster=True, method=None):
    d, n = _clusters(units, cluster)
    F = len(d)
    if F == 0:
        return None
    method = method or CI_METHOD
    rng = _rng(seed, key, 3 if cluster else 4)
    cs, Ms, done, chunk = [], [], 0, 2000
    pv = np.full(F, 1.0 / F)
    while done < nboot:
        m = min(chunk, nboot - done)
        W = rng.multinomial(F, pv, size=m)
        cs.append(W @ d)
        Ms.append(boot_moments(W, d, n))
        done += m
    cs, M = np.concatenate(cs), cat_moments(Ms)
    q = lambda v, a, b: [float(np.percentile(v, a)), float(np.percentile(v, b))]
    pc = prop_intervals(d, n, M, "percentile", DECISION_LEVELS)
    pm = pc if method == "percentile" else prop_intervals(d, n, M, method, DECISION_LEVELS)
    note = dict(LAST_INTERVAL_NOTE)
    ps = M["Wd"] / M["Wn"]
    guard = None
    if method == "bca":
        guard = {"acc_zero_constant_jackknife": note.get("acc_zero_constant_jackknife", False),
                 "endpoint_fallback": note.get("endpoint_fallback", [])}
        guard = guard if (guard["acc_zero_constant_jackknife"] or guard["endpoint_fallback"]) else None
    ud = [int(a) - int(b) for _f, a, b in units]          # 번역 쌍 단위 차이(a − b; 나쁨 = 1 이므로 양수 = A 가 나쁨)
    return {"count_ci95": q(cs, 2.5, 97.5), "prop_ci95": pm[0.95], "prop_ci90": pm[0.90],
            "prop_ci90_percentile": pc[0.90], "prop_ci95_percentile": pc[0.95], "ci_method": method,
            "nboot": nboot, "n_clusters": F, "n_discordant_clusters": int(np.count_nonzero(d)),
            "n_units": len(units), "n_discordant_units": sum(1 for x in ud if x != 0),
            "n_units_pos": sum(1 for x in ud if x > 0), "n_units_neg": sum(1 for x in ud if x < 0),
            "unit_sign_note": "n_units_pos = a − b > 0(A 쪽만 나쁨), n_units_neg = a − b < 0(B 쪽만 나쁨)",
            "n_bad_a": sum(int(a) for _f, a, _b in units), "n_bad_b": sum(int(b) for _f, _a, b in units),
            "estimate": float(d.sum() / n.sum()),
            "degenerate": bool(float(np.ptp(ps)) <= 1e-12), "bca_guard": guard}


def mcnemar_exact(n10, n01):
    n = n10 + n01
    if n == 0:
        return 1.0
    k = min(n10, n01)
    return min(1.0, 2.0 * sum(math.comb(n, i) for i in range(k + 1)) * 0.5 ** n)


def holm(pairs, alpha=0.05):
    """pairs [(name, p)] -> {name: {p, p_holm, reject}} (step-down, 단조)."""
    s = sorted(pairs, key=lambda x: x[1])
    m, run, out = len(s), 0.0, {}
    for i, (nm, p) in enumerate(s):
        adj = min(1.0, max(run, (m - i) * p))
        run = adj
        out[nm] = {"p": p, "p_holm": adj, "reject": adj < alpha}
    return out


def equivalent(ci, delta):
    """ci = 판정 구간(기본 BCa 명목 95%). 구간 전체가 (−δ, +δ) 안이면 True(경계 제외)."""
    return ci is not None and ci[0] > -delta and ci[1] < delta


def noninferior(ci_good, delta):
    """ci_good: '좋은 쪽' 차이(기준 − 새 기법의 나쁨 비율)의 판정 구간. 하한 > −δ 면 비열등."""
    return ci_good is not None and ci_good[0] > -delta


def ci_label(method=None, level=None):
    """문장에 쓰는 판정 구간 이름, 예: 'BCa의 명목 95% 구간'."""
    method = method or CI_METHOD
    level = DECISION_LEVEL if level is None else level
    return f"{CI_METHOD_LABEL.get(method, method)}의 명목 {round(level * 100)}% 구간"


def _level_key(level):
    if abs(level - 0.90) < 1e-9:
        return "prop_ci90"
    if abs(level - 0.95) < 1e-9:
        return "prop_ci95"
    raise ValueError(f"decision level {level} not in {DECISION_LEVELS}")


def interval_decision(b, margin, kind="equivalence", level=None, exceptions=None):
    """구간으로 내리는 판정 하나(결정 11-2 + 13-2 + 13-3).
    b = boot_ci 결과. kind = 'equivalence'(구간 전체가 ±여유 안) 또는 'new_risk'(세 갈래; '범위 안' = 상한 < +여유).
    반환: within(True/False/None), verdict(within / not_within / undecided(가: 차이 모두 0) /
    undecided_insufficient_data(라) / not_available),
    class(new_risk 만: noninferior / worse_beyond_margin / undecided / not_available), exception, 엇갈린 묶음 수, 수준, 방법."""
    level = DECISION_LEVEL if level is None else level
    exceptions = EXCEPTION_RULES if exceptions is None else exceptions
    out = {"kind": kind, "margin": margin, "decision_level": level, "ci_method": (b or {}).get("ci_method", CI_METHOD),
           "exception_rules_applied": bool(exceptions), "exception": None,
           "n_clusters": (b or {}).get("n_clusters"), "n_discordant_clusters": (b or {}).get("n_discordant_clusters")}
    if b is None:
        out.update(within=None, verdict="not_available", ci=None, ci_percentile=None, interval_used=False)
        if kind == "new_risk":
            out["class"] = "not_available"
        return out
    out["label"] = ci_label(out["ci_method"], level)
    key = _level_key(level)
    ci, cp = b[key], b[key + "_percentile"]
    out.update(ci=ci, ci_percentile=cp, interval_used=True, bca_guard=b.get("bca_guard"))
    if kind == "equivalence":
        inside = lambda c: equivalent(c, margin)  # noqa: E731
    else:
        inside = lambda c: classify_new_risk(c, margin) == "noninferior"  # noqa: E731

    def fin(within, verdict, cls=None):
        out.update(within=within, verdict=verdict)
        if kind == "new_risk":
            out["class"] = cls
        return out

    if exceptions:
        nd, F = b.get("n_discordant_clusters"), b.get("n_clusters") or 0
        if nd == 0:                                            # 가(결정 15-1): 늘 판정 보류, 묶음 수로 통과시키지 않는다
            pos, neg = b.get("n_units_pos", 0), b.get("n_units_neg", 0)
            case = "all_concordant" if pos + neg == 0 else "family_sums_zero"
            out.update(exception="all_zero", all_zero_case=case, interval_used=False, observed_difference=0.0,
                       n_units=b.get("n_units"), n_discordant_units=pos + neg,
                       n_pairs_a_worse=pos, n_pairs_a_better=neg,
                       pair_sign_note="a_worse = A 쪽만 나쁨(a − b > 0), a_better = B 쪽만 나쁨(a − b < 0)",
                       n_bad_a=b.get("n_bad_a"), n_bad_b=b.get("n_bad_b"),
                       both_arms_zero=(b.get("n_bad_a") == 0 and b.get("n_bad_b") == 0),
                       all_zero_rule="묶음별 차이의 합이 모두 0: 구간으로 판정하지 않고 판정 보류(결정 15-1)")
            return fin(False, "undecided", "undecided")
        if b.get("degenerate") and b.get("estimate", 0.0) != 0:   # 라
            out.update(exception="degenerate_nonzero", interval_used=False)
            return fin(False, "undecided_insufficient_data", "undecided")
        if nd is not None and 1 <= nd <= 4:                    # 나
            out["few_discordant_rule"] = True
            wc, wp = inside(ci), inside(cp)
            if wc != wp:
                out["exception"] = "few_discordant_methods_disagree"
            if kind == "equivalence":
                ok = wc and wp
                return fin(ok, "within" if ok else "not_within")
            c = classify_new_risk(ci, margin)
            if c == "noninferior" and not wp:
                c = "undecided"
            return fin(c == "noninferior", "within" if c == "noninferior" else "not_within", c)
    if kind == "equivalence":
        ok = inside(ci)
        return fin(ok, "within" if ok else "not_within")
    c = classify_new_risk(ci, margin)
    return fin(c == "noninferior", "within" if c == "noninferior" else "not_within", c)


def sign(x):
    return (x > 0) - (x < 0)


def paired_compare(units, name, seed, nperm, nboot, delta):
    """units: [(model, item, a(0/1), b(0/1))]. 나쁨=1. 통계량 = sum(a) − sum(b)."""
    fu = [(family(it), a, b) for _m, it, a, b in units]
    na = sum(a for *_x, a, _b in units)
    nb = sum(b for *_x, b in units)
    n10 = sum(1 for *_x, a, b in units if a == 1 and b == 0)
    n01 = sum(1 for *_x, a, b in units if a == 0 and b == 1)
    res = {"name": name, "n": len(units), "n_families": len({f for f, _, _ in fu}), "a_bad": na, "b_bad": nb,
           "diff": na - nb, "a_only": n10, "b_only": n01}
    if not units:
        res["empty"] = True
        return res
    res["family"] = {"perm": perm_test(fu, seed, name, nperm, True), "boot": boot_ci(fu, seed, name, nboot, True)}
    res["naive"] = {"perm": perm_test(fu, seed, name, nperm, False), "boot": boot_ci(fu, seed, name, nboot, False),
                    "mcnemar_exact_p": mcnemar_exact(n10, n01)}
    cu = [(f"CWE-{cwe_of(it)}", a, b) for _m, it, a, b in units]
    res["cwe_cluster_sensitivity"] = {"label": "민감도(상한): CWE 를 묶음으로 — 판정에 쓰지 않음",
                                      "perm": perm_test(cu, seed, name + "|cwe", nperm, True),
                                      "boot": boot_ci(cu, seed, name + "|cwe", nboot, True)}
    for k in ("family", "naive", "cwe_cluster_sensitivity"):
        b = res[k]["boot"]
        dec = interval_decision(b, delta, "equivalence") if b else None
        res[k]["equivalent_5pt"] = (dec["within"] is True) if b else None
        res[k]["equivalence_decision"] = dec
    per = {}
    for m in sorted({u[0] for u in units}):
        U = [u for u in units if u[0] == m]
        a10 = sum(1 for *_x, a, b in U if a == 1 and b == 0)
        a01 = sum(1 for *_x, a, b in U if a == 0 and b == 1)
        fuu = [(family(it), a, b) for _m, it, a, b in U]
        bb = boot_ci(fuu, seed, name + "|" + m, nboot, True)
        per[m] = {"n": len(U), "a_bad": sum(u[2] for u in U), "b_bad": sum(u[3] for u in U),
                  "diff": sum(u[2] - u[3] for u in U), "a_only": a10, "b_only": a01,
                  "mcnemar_exact_p": mcnemar_exact(a10, a01),
                  "family_boot_count_ci95": bb["count_ci95"] if bb else None}
    res["per_model"] = per
    ps = sign(res["diff"])
    res["direction_disagrees"] = sorted(m for m, v in per.items() if ps != 0 and sign(v["diff"]) == -ps)
    return res


S4_SENT = {   # 결정 11-2 판정 순서표(위에서부터 처음 맞는 줄)
    1: "새 기법은 신규 위험을 허용 여유 5%p 넘게 늘렸다.",
    2: "새 기법은 기존 최선보다 남는 것이 많았다.",
    3: "원인을 겨냥한 기법은 기존 최선보다, 그리고 같은 호출 상한까지 반복한 기존 최선보다 남는 것을 더 줄였다. "
       "측정한 신규 위험 증가는 허용 여유 5%p 이내였다.",
    4: "새 절차 전체는 기존 최선보다 남는 것을 더 줄였다. 호출을 더 쓴 효과와 구분되지는 않았다.",
    5: "새 기법은 남는 것을 더 줄였다. 신규 위험이 허용 여유 안인지는 가리지 못했다.",
    6: "추가 기법의 차이는 사전 지정한 ±5%p 범위 안이었고, 측정한 신규 위험 증가는 허용 여유 5%p 이내였다.",
    7: "가리지 못했다.",
}
S4_OVERLAP = "개선의 크기는 사전 지정한 ±5%p 범위 안이었다."
NEW_RISK_LABEL = {"noninferior": "비열등 성립", "worse_beyond_margin": "여유를 넘는 악화", "undecided": "판단 불가",
                  "not_available": "구간 없음"}


def classify_new_risk(ci, margin):
    """결정 11-2 신규 위험의 세 갈래. ci = d_신규(새 기법 − 기존 최선, 새로 생긴 비율)의 판정 구간(기본 BCa 명목 95%).
    상한 < +여유 → noninferior, 하한 > +여유 → worse_beyond_margin, 그 밖(구간이 +여유에 걸침) → undecided.
    결정 13-2 예외 처리는 interval_decision 이 이 위에 얹는다."""
    if ci is None:
        return "not_available"
    if ci[1] < margin:
        return "noninferior"
    if ci[0] > margin:
        return "worse_beyond_margin"
    return "undecided"


def _pp(x):
    return "—" if x is None else f"{x * 100:+.1f}%p"


def choose_s4_conclusion(ga_rej, ga_diff, nb_rej, nb_diff, res_ci, new_ci, delta=0.05, res_dec=None, new_dec=None):
    """결정 11-2 4단계 결론(일곱 줄, 위에서부터 처음 맞는 줄 하나).
    ga_* = 4-가(새 기법 − 기존 최선, 고친 뒤에도 취약한 수; 음수 = 개선), nb_* = 4-나(새 기법 − 기존 최선 반복).
    *_rej = Holm 보정 뒤 기각. res_ci = d_잔여 판정 구간, new_ci = d_신규 판정 구간(새 − 기준, 양수 = 악화);
    판정 구간 = 고른 방법의 명목 판정 수준 구간(기본 BCa 명목 95%, 결정 13-3).
    res_dec·new_dec(interval_decision 결과)를 주면 결정 13-2 예외 처리를 반영한 판정을 쓴다(주지 않으면 구간만으로).
    반환 (줄 번호, 문장, 정보)."""
    nc = new_dec["class"] if new_dec is not None else classify_new_risk(new_ci, delta)
    eq = (res_dec["within"] is True) if res_dec is not None else equivalent(res_ci, delta)
    lab = (res_dec or new_dec or {}).get("label") or ci_label()
    ga_better, ga_worse = bool(ga_rej and ga_diff < 0), bool(ga_rej and ga_diff > 0)
    nb_better, nb_sig = bool(nb_rej and nb_diff < 0), bool(nb_rej)
    info = {"new_risk_class": nc, "residual_equivalent_5pt": eq, "ga_significant_better": ga_better,
            "ga_significant_worse": ga_worse, "nb_significant_better": nb_better, "nb_significant": nb_sig,
            "d_residual_ci": res_ci, "d_new_ci": new_ci, "decision_interval": lab, "overlap_appended": False,
            "residual_exception": (res_dec or {}).get("exception"), "new_risk_exception": (new_dec or {}).get("exception")}
    if nc == "worse_beyond_margin":
        row = 1
        txt = (f"{S4_SENT[1]} (잔여: 4-가 차이 {ga_diff}, d_잔여 {lab} "
               f"[{_pp(res_ci[0]) if res_ci else '—'}, {_pp(res_ci[1]) if res_ci else '—'}], Holm 기각 {bool(ga_rej)})")
    elif ga_worse:
        row, txt = 2, S4_SENT[2]
    elif ga_better and nb_better and nc == "noninferior":
        row, txt = 3, S4_SENT[3]
    elif ga_better and nc == "noninferior" and not nb_sig:
        row, txt = 4, S4_SENT[4]
    elif ga_better and nc == "undecided":
        row, txt = 5, S4_SENT[5]
    elif not ga_rej and eq and nc == "noninferior":
        row, txt = 6, S4_SENT[6]
    else:
        row = 7
        parts = []
        if not ga_rej:
            parts.append("4-가 차이가 유의하지 않았고 d_잔여의 ±5%p 동등성도 보이지 못했다" if not eq
                         else "4-가 차이는 유의하지 않았고 d_잔여는 ±5%p 안이었으나 신규 위험이 비열등으로 판정되지 않았다")
        if ga_better and nb_rej and nb_diff > 0:
            parts.append("4-나에서 새 기법이 같은 호출 상한까지 반복한 기존 최선보다 유의하게 많이 남겼다")
        if nc == "undecided":
            ex = (new_dec or {}).get("exception")
            parts.append("신규 위험이 허용 여유 5%p 안인지(판정 보류: 차이가 모두 0)" if ex == "all_zero"
                         else "신규 위험이 허용 여유 5%p 안인지(판정 보류: 자료 부족)" if ex == "degenerate_nonzero"
                         else "신규 위험이 허용 여유 5%p 안인지(방법에 따라 갈림)" if ex == "few_discordant_methods_disagree"
                         else "신규 위험이 허용 여유 5%p 안인지(구간이 +5%p 에 걸침)")
        if nc == "not_available":
            parts.append("신규 위험 구간을 계산할 자료가 없다")
        txt = S4_SENT[7] + (" 가리지 못한 부분: " + "; ".join(parts) + "." if parts else "")
    if row in (3, 4, 5) and eq:
        txt += " " + S4_OVERLAP
        info["overlap_appended"] = True
    zs = all_zero_sentence(new_dec)
    if zs:                                  # 결정 15-1: d_신규가 '차이 모두 0'으로 보류되면 고른 줄 문장 뒤에 덧붙인다
        txt += " " + zs
        info["new_risk_all_zero_case"] = new_dec.get("all_zero_case")
        info["all_zero_sentence_appended"] = True
    return row, txt, info


def all_zero_sentence(new_dec):
    """결정 15-1: d_신규(a = 새 기법, b = 기존 최선)가 가로 보류됐을 때 덧붙이는 문장. 아니면 None."""
    if not new_dec or new_dec.get("exception") != "all_zero":
        return None
    N, F = new_dec.get("n_units"), new_dec.get("n_clusters")
    if new_dec.get("both_arms_zero"):
        return f"신규 위험은 두 조건 모두 0건이었다(번역 {N}개, 묶음 {F}개). 구간으로 판정할 수 없어 보류했다."
    if new_dec.get("all_zero_case") == "family_sums_zero":
        return (f"신규 위험은 묶음마다 두 조건의 차이가 상쇄되어 차이가 0이었다(번역 {N}개, 묶음 {F}개, 새 기법에서만 새로 생긴 번역 "
                f"{new_dec.get('n_pairs_a_worse')}개, 기존 최선에서만 새로 생긴 번역 {new_dec.get('n_pairs_a_better')}개). "
                f"구간으로 판정할 수 없어 보류했다.")
    return (f"신규 위험은 두 조건에서 번역마다 같았다(번역 {N}개, 묶음 {F}개, 두 조건 모두 새로 생긴 번역 {new_dec.get('n_bad_a')}개). "
            f"구간으로 판정할 수 없어 보류했다.")


RULE_11_7_SENTENCE = "사전 지정한 잔여 건수 기준에 따라 추가 기법의 확증을 진행하지 않았다."


def rule_11_7(n_residual, override=False, threshold=40):
    """(4단계 확증을 내도 되는가, 표시). n_residual = D 의 기존 최선 뒤 남은 번역(모델 합). None = 셀 수 없음."""
    if n_residual is not None and n_residual >= threshold:
        return True, "within_rule"
    if override:
        return True, "OUTSIDE_PRE_REGISTERED_RULE"
    return False, RULE_11_7_SENTENCE


def stage2_sentences(comps, holm_res, delta):
    """13-1 을 결정 1·2·6절 문장으로."""
    out = {}
    rj = lambda nm: holm_res.get(nm, {}).get("reject", False)
    d = lambda nm: comps.get(nm, {}).get("diff", 0)
    g1, g2 = rj("2-ga-1") and d("2-ga-1") < 0, rj("2-ga-2") and d("2-ga-2") < 0
    if g1 and g2:
        out["2-가"] = "명세 자기 수정은 없음과 같은 호출 상한의 다시 번역 둘 다보다 고친 뒤에도 취약한 번역이 적었다(Holm 보정 뒤 유의)."
    elif g1 and not comps.get("2-ga-2", {}).get("n"):
        out["2-가"] = "명세 자기 수정은 없음보다 적었다(Holm 보정 뒤 유의). 다시 번역 비교는 이 자료에 없다."
    elif g1:
        out["2-가"] = "명세 자기 수정은 없음보다 적었으나, 다시 번역과는 차이를 가리지 못했다."
    else:
        out["2-가"] = "가리지 못했다."
    if not comps.get("2-ga-1", {}).get("n"):
        out["2-가"] = "명세 자기 수정 대 없음 비교가 이 자료에 없다."
    if not comps.get("2-na", {}).get("n"):
        out["2-나"] = "명세 자기 수정 대 일반 보안 지시 비교가 이 자료에 없다."
    elif rj("2-na") and d("2-na") < 0:
        out["2-나"] = "같은 수정 절차에서 명세를 주면 더 줄어든다."
    elif rj("2-na") and d("2-na") > 0:
        out["2-나"] = "같은 수정 절차에서 명세를 주면 오히려 더 많이 남았다."
    else:
        out["2-나"] = "가리지 못했다."
    c = comps.get("2-da")
    if c and c.get("n"):
        out["2-다"] = ("두 번 한 것과 한 번 한 것의 차이는 사전 지정한 ±5%p 범위 안이었다." if c["family"]["equivalent_5pt"]
                      else "두 번 한 것과 한 번 한 것의 차이가 사전 지정한 ±5%p 범위 안에 든다고 보이지 못했다.")
    c = comps.get("sec_B1_vs_RCI")
    if c and c.get("n"):
        p = c["family"]["perm"]["p"]
        rel = "적게 남겼다" if c["diff"] < 0 else "많이 남겼다" if c["diff"] > 0 else "같은 수를 남겼다"
        out["보조 B1 대 RCI"] = f"명세 자기 수정 절차가 자기 비판 반복 절차보다 {rel}(차이 {c['diff']}, 묶음 치환 p {p:.4f}, 보조 비교)."
    out["범위"] = "받아들이기에 쓴 기능 시험을 통과하면서, 따로 숨긴 보안 시험의 실패를 줄였다(기능 보존 주장은 이 범위로 한정)."
    return out


# ---------------------------------------------------------------- 읽기
def load_inputs(a):
    bundles = []
    for spec in a.run or []:
        mname, root = (spec.split("=", 1) if "=" in spec and not re.match(r"^[A-Za-z]:[\\/]", spec) else (None, spec))
        root = Path(root).resolve()
        cfg = jl(root / "config.json")
        model = mname or cfg.get("model", root.name)
        blind_items = set()
        if (root / "blind_manifest.json").exists() and not (root / "unblinded.json").exists() \
                and (root / "blind_items.txt").exists():
            blind_items = set(read_list(root / "blind_items.txt"))
        arows = []
        a_runs = cfg.get("a_runs") or ([{"name": "A", "bench": "scp", "sample": 0, "export_root": cfg.get("export_root")}]
                                       if (root / "A" / "eval_rows.json").exists() else [])
        for ar in a_runs:
            p = root / ar["name"] / "eval_rows.json"
            if p.exists():
                for r in jl(p):
                    r["_arun"], r["_sample"] = ar["name"], r.get("sample", ar.get("sample", 0))
                    r["_bench"] = r.get("bench", ar.get("bench"))
                    r["_export"] = ar.get("export_root")
                    arows.append(r)
        brows = []
        if (root / "B" / "eval_rows.json").exists():
            for r in jl(root / "B" / "eval_rows.json"):
                r["_bdir"], r["_b4"] = root / "B", root / "B4"
                brows.append(r)
        calls = []
        if (root / "calls.jsonl").exists():
            calls = [json.loads(l) for l in (root / "calls.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        bundles.append({"model": model, "kind": "run_main", "root": str(root), "arows": arows, "brows": brows,
                        "calls": calls, "blind_items": blind_items, "export_root": cfg.get("export_root", str(EXPORT_SCP)),
                        "config_hashes": cfg.get("hashes", {})})
    for spec in a.brun or []:
        model, dirs = spec.split("=", 1)
        b = next((x for x in bundles if x["model"] == model and x["kind"] == "brun"), None)
        if b is None:
            b = {"model": model, "kind": "brun", "root": [], "arows": [], "brows": [], "calls": [],
                 "blind_items": set(), "export_root": str(EXPORT_SCP)}
            bundles.append(b)
        for d in dirs.split(","):
            d = Path(d).resolve()
            cfg = jl(d / "config.json") if (d / "config.json").exists() else {}
            b4 = d.parent / cfg.get("b4run", "") if cfg.get("b4run") else d / "_no_b4"
            for r in jl(d / "eval_rows.json"):
                r["_bdir"], r["_b4"] = d, b4
                b["brows"].append(r)
            b["root"].append(str(d))
    for spec in a.arun or []:
        model, d = spec.split("=", 1)
        b = next((x for x in bundles if x["model"] == model), None)
        if b is None:
            b = {"model": model, "kind": "arun", "root": [], "arows": [], "brows": [], "calls": [],
                 "blind_items": set(), "export_root": str(EXPORT_SCP)}
            bundles.append(b)
        for r in jl(Path(d) / "eval_rows.json"):
            r["_arun"], r["_sample"], r["_bench"] = Path(d).name, r.get("sample", 0), r.get("bench")
            b["arows"].append(r)
    return bundles


def item_of_row(r):
    return r["item"] if "item" in r else r["tkey"].split("__")[1]


def bench_of(item, r=None):
    if r is not None and r.get("_bench"):
        return r["_bench"]
    return "scp" if is_scp(item) else "cweval"


# ---------------------------------------------------------------- 1단계
def t_view(r, which):
    """T1(행 그대로) 또는 T0(행의 t0) 판정 보기."""
    if which == "t1":
        return {"built": r.get("built"), "func": bool(r.get("functional_ok")), "pairs": r.get("pairs"),
                "safety": r.get("safety"), "effect": r.get("effect"), "columns": r.get("columns")}
    t0 = r.get("t0") or {}
    if t0.get("eval") == "same_as_t1" and "pairs" not in t0:
        return t_view(r, "t1")
    return {"built": t0.get("built", r.get("t0_built")), "func": bool(t0.get("functional_ok")),
            "pairs": t0.get("pairs"), "safety": t0.get("safety"), "effect": t0.get("effect"), "columns": t0.get("columns")}


def s1_cat(pairs):
    if any(p == "left" for p in pairs):
        return "left"
    if any(p == "new" for p in pairs):
        return "new"
    if any(p == "gone" for p in pairs):
        return "gone"
    return "safe"


def s1_vuln(v, cwe, judg):
    """번역의 '뚫림'(취약판: 남음/생김, 수정판: 생김). 반환 (0/1, 'effect'|'dataset')."""
    ds = 1 if s1_cat(v["pairs"]) in ("left", "new") else 0
    if judg == "primary" and cwe in EFFECT_CWES and eff_valid(v["effect"], len(v["pairs"])):
        return (1 if fired(v["effect"]) else 0), "effect"
    return ds, "dataset"


def s1_newly(v, cwe, judg):
    """수정판 번역의 '새로 생김'(결정 4절): 단일 판정식으로 취약 또는 비정상 종료(⑤)가 새로 생김."""
    return int(s1_vuln(v, cwe, judg)[0] or new_abnormal(v))


def new_abnormal(v):
    eff = v["effect"] if eff_valid(v["effect"], len(v["pairs"])) else None
    for i, p in enumerate(v["pairs"]):
        if p == "new" and v["safety"] and v["safety"][i][0] == "exploited" and v["safety"][i][1] in DOS_SUBS \
                and not (eff and eff[i][0] == "effect"):
            return 1
    return 0


FIRST_PYPY_KEY = "first_before_regen"   # run_main.py 의 A 줄 칸(결정 11-3): 다시 만든 Py→Py 의 최초 시도 판정 dict,
#   {built, functional_ok, capability, safety, pairs, abnormal, effect, columns, similarity, regen_index}. 다시 만들지 않은 줄은 null.


def first_pypy_view(r):
    """다시 만들기 전 최초 Py→Py 결과의 T1 보기. 다시 만들지 않은 번역(null)은 주 결과가 곧 최초 결과."""
    fb = r.get(FIRST_PYPY_KEY)
    if not isinstance(fb, dict):
        return t_view(r, "t1")
    return {"built": fb.get("built"), "func": bool(fb.get("functional_ok")), "pairs": fb.get("pairs"),
            "safety": fb.get("safety"), "effect": fb.get("effect"), "columns": fb.get("columns")}


def first_pypy_status(A):
    """최초 Py→Py 판을 셀 수 있는가: Py→Py 줄 모두에 FIRST_PYPY_KEY 칸이 있고, 다시 만든 줄(regen>0)은 판정 dict(pairs 있음)."""
    py = [r for k, r in A.items() if k[3] == "PyPy"]
    regen = [r for r in py if (r.get("regen") or 0) > 0]
    st = {"key": FIRST_PYPY_KEY, "pypy_rows": len(py), "regenerated_rows": len(regen),
          "rows_with_key": sum(1 for r in py if FIRST_PYPY_KEY in r),
          "regenerated_with_judged_first": sum(1 for r in regen if isinstance(r.get(FIRST_PYPY_KEY), dict)
                                               and r[FIRST_PYPY_KEY].get("pairs") is not None)}
    if not py:
        st.update(available=False, reason="no Py→Py rows")
    elif st["rows_with_key"] < len(py):
        st.update(available=False, reason=f"row field '{FIRST_PYPY_KEY}' absent on {len(py) - st['rows_with_key']}/{len(py)} Py→Py rows")
    elif st["regenerated_with_judged_first"] < len(regen):
        st.update(available=False, reason=f"{len(regen) - st['regenerated_with_judged_first']} regenerated Py→Py rows have no "
                                          f"judged first result in '{FIRST_PYPY_KEY}'")
    else:
        st.update(available=True, reason="")
    return st


def stage1(A, items, seed, a):
    """A: {(model,item,source,cond): row} (sample 0)."""
    out = {}
    models = sorted({k[0] for k in A})
    # 개수
    cnt = []
    for (m, it, src, cond), r in A.items():
        for which in ("t1", "t0"):
            v = t_view(r, which)
            cnt.append((m, cond, src, bench_of(it, r), which, bool(v["built"]), v["func"]))
    tab = {}
    for m, cond, src, bench, which, built, func in cnt:
        for mm in (m, "pooled"):
            s = tab.setdefault(f"{mm}|{cond}|{src}|{bench}|{which}", {"translations": 0, "built": 0, "functional": 0})
            s["translations"] += 1
            s["built"] += built
            s["functional"] += func
    out["counts"] = tab
    out["pypy_copied"] = {m: sum(1 for k, r in A.items() if k[0] == m and k[3] == "PyPy" and r.get("copied")) for m in models}
    # 보안 결과(기능 통과 번역)
    sec = {}
    for (m, it, src, cond), r in A.items():
        v = t_view(r, "t1")
        if not v["func"] or v["pairs"] is None:
            continue
        cwe = cwe_of(it, r.get("_export"))
        grp = "effect" if cwe in EFFECT_CWES else "logic"
        cat = s1_cat(v["pairs"])
        for mm in (m, "pooled"):
            for dim, val in (("all", "all"), ("cwe", f"CWE-{cwe}"), ("group", grp), ("bench", bench_of(it, r))):
                s = sec.setdefault(f"{mm}|{cond}|{src}|{dim}={val}", {"translations": 0, "by_translation": {},
                                                                       "by_test": {}, "effect_fired": 0,
                                                                       "effect_judged": 0, "columns": {}})
                s["translations"] += 1
                s["by_translation"][cat] = s["by_translation"].get(cat, 0) + 1
                for p in v["pairs"]:
                    s["by_test"][p] = s["by_test"].get(p, 0) + 1
                if eff_valid(v["effect"], len(v["pairs"])):
                    s["effect_judged"] += 1
                    s["effect_fired"] += fired(v["effect"])
                for c in v["columns"] or []:
                    s["columns"][c] = s["columns"].get(c, 0) + 1
    out["security"] = sec

    # 보조표(결정 4절): 언어별 전체 항목 분모 — 기능 통과 수, 기능 통과이면서 취약하지 않은 수
    allden = {}
    for (m, it, src, cond), r in A.items():
        v = t_view(r, "t1")
        cwe = cwe_of(it, r.get("_export"))
        ok = v["func"] and v["pairs"] is not None
        nv = ok and not (s1_vuln(v, cwe, "primary")[0] if src == "vulnerable" else s1_newly(v, cwe, "primary"))
        for mm in (m, "pooled"):
            s = allden.setdefault(f"{mm}|{cond}|{src}", {"translations": 0, "functional": 0,
                                                         "functional_and_not_vulnerable": 0})
            s["translations"] += 1
            s["functional"] += bool(v["func"])
            s["functional_and_not_vulnerable"] += bool(nv)
    out["all_items_denominator"] = allden
    out["pypy_regenerated"] = {m: sum(1 for k, r in A.items() if k[0] == m and k[3] == "PyPy" and (r.get("regen") or 0) > 0)
                               for m in models}

    def units(src, cwes_ok, outcome, which="t1", drop_regen=False, pypy_first=False):
        U, fallback = [], 0
        for (m, it, s_, cond), r in A.items():
            if s_ != src or cond != "PyRs":
                continue
            r2 = A.get((m, it, s_, "PyPy"))
            if r2 is None:
                continue
            if drop_regen and (r2.get("regen") or 0) > 0:
                continue
            v1, v2 = t_view(r, which), (first_pypy_view(r2) if pypy_first else t_view(r2, which))
            if not (v1["func"] and v2["func"]) or v1["pairs"] is None or v2["pairs"] is None:
                continue
            cwe = cwe_of(it, r.get("_export"))
            if not cwes_ok(cwe):
                continue
            o1, o2, fb = outcome(v1, v2, cwe)
            fallback += fb
            U.append((m, it, o1, o2))
        return U, fallback

    def h1_out(judg):
        def f(v1, v2, cwe):
            x1, k1 = s1_vuln(v1, cwe, judg)
            x2, k2 = s1_vuln(v2, cwe, judg)
            fb = int(judg == "primary" and cwe in EFFECT_CWES and "dataset" in (k1, k2))
            return 1 - x1, 1 - x2, fb      # 1 = 없어짐
        return f

    def h4_out_j(judg):
        def f(v1, v2, cwe):
            fb = int(judg == "primary" and cwe in EFFECT_CWES and not (eff_valid(v1["effect"], len(v1["pairs"]))
                                                                      and eff_valid(v2["effect"], len(v2["pairs"]))))
            return s1_newly(v1, cwe, judg), s1_newly(v2, cwe, judg), fb
        return f

    h4_out = h4_out_j("primary")

    def h4_abn(v1, v2, cwe):
        return new_abnormal(v1), new_abnormal(v2), 0

    def anynew(v1, v2, cwe):
        return int(any(p == "new" for p in v1["pairs"])), int(any(p == "new" for p in v2["pairs"])), 0

    def dos_col(v):
        return int(any(c == "dos_only" for c in (v["columns"] or [])))

    def h2_out(v1, v2, cwe):
        return s1_vuln(v1, cwe, "dataset")[0], s1_vuln(v2, cwe, "dataset")[0], 0

    hyp = {}
    for which in ("t1", "t0"):
        H = {}
        U, fb = units("vulnerable", lambda c: c in CODE_EXEC_CWES, h1_out("primary"), which)
        H["H1"] = paired_compare(U, f"H1|{which}", seed, a.perm, a.boot, a.delta)
        H["H1"]["outcome"] = "없어짐(1) Py→Rs − Py→Py, 주 판정"
        H["H1"]["dataset_fallback_pairs"] = fb
        U, _ = units("vulnerable", lambda c: c in CODE_EXEC_CWES, h1_out("dataset"), which)
        H["H1_dataset_only"] = paired_compare(U, f"H1ds|{which}", seed, a.perm, a.boot, a.delta)
        U, fb = units("patched", lambda c: True, h4_out, which)
        H["H4"] = paired_compare(U, f"H4|{which}", seed, a.perm, a.boot, a.delta)
        H["H4"]["outcome"] = "새로 생김(단일 판정식으로 취약 또는 ⑤ 새로 생김)(1) Py→Rs − Py→Py"
        H["H4"]["dataset_fallback_pairs"] = fb
        U, _ = units("patched", lambda c: True, h4_out_j("dataset"), which)
        H["H4_dataset_only"] = paired_compare(U, f"H4ds|{which}", seed, a.perm, a.boot, a.delta)
        U, _ = units("patched", lambda c: True, h4_abn, which)
        H["H4_abnormal_only"] = paired_compare(U, f"H4abn|{which}", seed, a.perm, a.boot, a.delta)
        U, _ = units("patched", lambda c: True, anynew, which)
        H["H4_any_new_dataset_test"] = paired_compare(U, f"H4new|{which}", seed, a.perm, a.boot, a.delta)
        if which == "t1":
            U, _ = units("vulnerable", lambda c: c in CODE_EXEC_CWES, h1_out("primary"), which, drop_regen=True)
            H["H1_no_regen"] = paired_compare(U, f"H1nr|{which}", seed, a.perm, a.boot, a.delta)
            U, _ = units("patched", lambda c: True, h4_out, which, drop_regen=True)
            H["H4_no_regen"] = paired_compare(U, f"H4nr|{which}", seed, a.perm, a.boot, a.delta)
            fs = first_pypy_status(A)
            out["pypy_first_status"] = fs
            if fs["available"]:
                U, _ = units("vulnerable", lambda c: c in CODE_EXEC_CWES, h1_out("primary"), which, pypy_first=True)
                H["H1_first_pypy"] = paired_compare(U, f"H1fp|{which}", seed, a.perm, a.boot, a.delta)
                U, _ = units("patched", lambda c: True, h4_out, which, pypy_first=True)
                H["H4_first_pypy"] = paired_compare(U, f"H4fp|{which}", seed, a.perm, a.boot, a.delta)
            else:
                H["H1_first_pypy"] = {"n": 0, "not_available": fs["reason"]}
                H["H4_first_pypy"] = {"n": 0, "not_available": fs["reason"]}
        U, _ = units("patched", lambda c: True, lambda v1, v2, c: (dos_col(v1), dos_col(v2), 0), which)
        H["H4_column5"] = {"n": len(U), "PyRs": sum(u[2] for u in U), "PyPy": sum(u[3] for u in U),
                           "note": "⑤칸(dos_only)이 하나 이상인 번역 수, 다섯 칸이 있는 줄만"}
        U, _ = units("vulnerable", lambda c: c not in EFFECT_CWES and c != -1, h2_out, which)
        H["H2"] = paired_compare(U, f"H2|{which}", seed, a.perm, a.boot, a.delta)
        H["H2"]["outcome"] = f"취약(1) Py→Rs − Py→Py, 논리형, 동등성 ±5%p({ci_label()}, 묶음 단위)"
        hyp[which] = H
    out["hypotheses"] = hyp["t1"]
    tv = {}
    for h in ("H1", "H4"):     # 결정 11-3: 세 가지 판(주·다시 생성 항목 뺌·최초 Py→Py 결과)
        tv[h] = {}
        for lab, k in (("main", h), ("regenerated_excluded", f"{h}_no_regen"), ("first_pypy_before_regen", f"{h}_first_pypy")):
            v = hyp["t1"].get(k) or {}
            if v.get("not_available"):
                tv[h][lab] = "not available: " + v["not_available"]
                continue
            tv[h][lab] = {kk: v.get(kk) for kk in ("n", "a_bad", "b_bad", "diff")} | {
                "p_family": (v.get("family") or {}).get("perm", {}).get("p")}
    out["three_versions"] = tv
    out["t0_sensitivity_hypotheses"] = {k: {kk: v.get(kk) for kk in ("n", "a_bad", "b_bad", "diff")} |
                                        {"p_family": (v.get("family") or {}).get("perm", {}).get("p")}
                                        for k, v in hyp["t0"].items() if isinstance(v, dict) and "a_bad" in v}
    # T0 대 T1 표
    tr = {}
    for (m, it, src, cond), r in A.items():
        def cat(which):
            v = t_view(r, which)
            if not v["built"]:
                return "not_built"
            if not v["func"]:
                return "not_functional"
            if v["pairs"] is None:
                return "no_security"
            return s1_cat(v["pairs"])
        k = f"{cond}|{src}|T0={cat('t0')}|T1={cat('t1')}"
        for mm in (m, "pooled"):
            tr.setdefault(mm, {})
            tr[mm][k] = tr[mm].get(k, 0) + 1
    out["t0_vs_t1"] = tr
    return out


def extra_variability(Aall):
    """추가 표본: (모델, 항목, 판, 조건)마다 본 번역 결과와 같은 결과의 추가 표본 수(0..5)."""
    def cat(r):
        v = t_view(r, "t1")
        if not v["func"]:
            return "not_functional"
        if v["pairs"] is None:
            return "no_security"
        cwe = cwe_of(r["item"], r.get("_export"))
        bad = s1_vuln(v, cwe, "primary")[0] if r["source"] == "vulnerable" else s1_newly(v, cwe, "primary")
        return "vulnerable" if bad else "clean"
    main ={(k[0], k[1], k[2], k[3]): r for k, r in Aall.items() if k[4] == 0}
    groups = collections.defaultdict(list)
    for k, r in Aall.items():
        if k[4] != 0:
            groups[k[:4]].append(r)
    dist, by = collections.Counter(), {}
    for k, rs in groups.items():
        if k not in main:
            continue
        mc = cat(main[k])
        agree = sum(1 for r in rs if cat(r) == mc)
        dist[f"{agree}/{len(rs)}"] += 1
        key = f"{k[0]}|{k[3]}|{k[2]}|main={mc}"
        by.setdefault(key, collections.Counter())[f"{agree}/{len(rs)}"] += 1
    return {"n_groups": sum(dist.values()), "agreement": dict(dist), "by_model_cond_source": {k: dict(v) for k, v in by.items()}}


# ---------------------------------------------------------------- 2단계
def b_rec(r, model, base_eff):
    it = item_of_row(r)
    cwe = cwe_of(it)
    return {"model": model, "item": it, "source": r["source"], "cond": r["cond"], "tkey": r["tkey"], "cwe": cwe,
            "status": r.get("status"), "calls": r.get("calls", 0) or 0, "pairs": r.get("pairs"),
            "base_func": r.get("base_functional_ok"), "hard_func": r.get("hard_functional_ok"),
            "first": r.get("first"), "effect": r.get("effect"), "base_effect": base_eff, "bdir": r["_bdir"],
            "b4": r["_b4"], "blinded": bool(r.get("blinded_kinds")), "columns": r.get("columns"), "safety": r.get("safety"),
            "vis_final": visible_fail(r.get("visible_after")), "vis_base": visible_fail(r.get("visible_base")),
            "vis_first": visible_fail((r.get("first") or {}).get("visible_after")),
            "first_present": bool(r.get("first")), "stratum": visible_stratum_of_row(r),
            "bestrep": {k: r.get(k) for k in ("n_rounds", "round_statuses", "calls_rounds", "stop", "call_cap_total",
                                              "calls_stage1", "calls_stage2", "best_cond")} if r.get("cond") == "BESTREP" else None}


def vuln_after(x, judg="primary"):
    """취약판 출발: 최종(또는 '없음'이면 출발)이 뚫렸는가. 반환 (0/1, kind)."""
    P = x["pairs"]
    if x["cond"] == NONE:
        ds = int(any(p in ("removed", "left") for p in P))
        eff = x["base_effect"]
    else:
        ds = int(any(p in ("left", "new") for p in P))
        eff = x["effect"]
    if judg == "primary" and x["cwe"] in EFFECT_CWES and eff_valid(eff, len(P)):
        return int(fired(eff)), "effect"
    return ds, "dataset"


def new_after(x, judg="primary"):
    """수정판 출발: 완화가 새로 만든 뚫림."""
    P = x["pairs"]
    if x["cond"] == NONE:
        return 0, "none"
    ds = int(any(p == "new" for p in P))
    if judg == "primary" and x["cwe"] in EFFECT_CWES and eff_valid(x["effect"], len(P)) \
            and eff_valid(x["base_effect"], len(P)):
        cols = x.get("columns") if isinstance(x.get("columns"), list) and len(x["columns"]) == len(P) else None
        new_dos = bool(cols) and any(p == "new" and c == "dos_only" for p, c in zip(P, cols))
        return int((fired(x["effect"]) and not fired(x["base_effect"])) or new_dos), "effect"
    return ds, "dataset"


def visible_fail(v):
    """번역 단계 보이는 시험(선택에 쓰지 않음) 결과 {n, failed, class} -> 하나라도 깨짐(1)/아님(0), 없으면 None."""
    if not isinstance(v, dict) or v.get("n") is None:
        return None
    return int((v.get("failed") or 0) > 0 or v.get("class") not in (None, "passed"))


def visible_stratum_of_row(r):
    """B 줄: visible_after 칸이 있으면 그것으로(값 null = 보이는 시험 없음). 없으면 None(A 줄로 정함)."""
    if "visible_after" in r:
        return "with_visible" if r["visible_after"] is not None else "no_visible"
    return None


def visible_stratum_of_arow(r):
    if r is None or ("visible_tests" not in r and "stage3" not in r):
        return "unknown"
    return "with_visible" if (r.get("visible_tests") or 0) > 0 else "no_visible"


def lines_of(d):
    d = Path(d)
    src = d / "src"
    fs = list(src.rglob("*.rs")) if src.exists() else []
    if not fs:
        return None
    return sum(len(f.read_text(encoding="utf-8", errors="replace").splitlines()) for f in fs)


def state_of(x):
    p = Path(x["bdir"]) / x["cond"] / "state" / f"{x['tkey']}.json"
    return jl(p) if p.exists() else {}


def calls_cost(bundles, items):
    out = {}
    for b in bundles:
        seen = set()
        for c in b["calls"]:
            tg = (c.get("target") or "").split("__")
            it = tg[1] if tg and tg[0] == "main" and len(tg) > 1 else tg[0]
            if items is not None and it not in items:
                continue
            k = (c.get("reply"), c.get("regen"))
            if k in seen and c.get("reply"):
                continue
            seen.add(k)
            cond = c.get("condition", "?")
            for mm in (b["model"], "pooled"):
                s = out.setdefault(f"{mm}|{cond}", {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
                                                   "estimated_token_calls": 0})
                s["calls"] += 1
                s["prompt_tokens"] += c.get("prompt_tokens") or 0
                s["completion_tokens"] += c.get("completion_tokens") or 0
                s["estimated_token_calls"] += bool(c.get("tokens_estimated"))
    return out


def stage2(Brec, conds, security, seed, a):
    """Brec: {(model,item,source,cond): rec}. NONE 은 따로 만든다."""
    out = {"conditions": conds}
    per = {}
    for (m, it, src, cond), x in Brec.items():
        for mm in (m, "pooled"):
            s = per.setdefault(f"{mm}|{cond}", {
                "targets": 0, "targets_vulnerable": 0, "targets_patched": 0, "accepted": 0, "returned_to_start": 0,
                "row_calls": 0, "reasons_all_attempts": {}, "last_reason_when_returned": {},
                "first_candidates": 0, "first_not_built": 0, "first_func_fail": 0, "first_breaks_functional": 0,
                "lines_start": 0, "lines_final": 0, "lines_pairs": 0, "longer": 0, "shorter": 0, "same_len": 0,
                "unselected_measured": 0, "unselected_failing_final": 0, "unselected_failing_start": 0,
                "unselected_first_measured": 0, "unselected_failing_first": 0, "unselected_first_no_program": 0,
                "bestrep_rounds": {}, "bestrep_stop": {}, "bestrep_round_statuses": {}, "bestrep_cap": {},
                "calls_stage1": 0, "calls_stage2": 0})
            s["targets"] += 1
            s["targets_" + src] += 1
            if cond == NONE:
                continue
            s["accepted"] += x["status"] == "accepted"
            s["returned_to_start"] += x["status"] != "accepted"
            s["row_calls"] += x["calls"]
            if x["vis_final"] is not None:          # 분모 = 보이는 시험이 있는 항목의 줄
                s["unselected_measured"] += 1
                s["unselected_failing_final"] += x["vis_final"]
                s["unselected_failing_start"] += x["vis_base"] or 0
                if x["first_present"]:
                    if x["vis_first"] is None:
                        s["unselected_first_no_program"] += 1
                    else:
                        s["unselected_first_measured"] += 1
                        s["unselected_failing_first"] += x["vis_first"]
            br = x.get("bestrep")
            if br:
                for kk, val in (("bestrep_rounds", br.get("n_rounds")), ("bestrep_stop", br.get("stop")),
                                ("bestrep_round_statuses", ">".join(br.get("round_statuses") or [])),
                                ("bestrep_cap", br.get("call_cap_total"))):
                    s[kk][str(val)] = s[kk].get(str(val), 0) + 1
                s["calls_stage1"] += br.get("calls_stage1") or 0
                s["calls_stage2"] += br.get("calls_stage2") or 0
            st = x.get("_state")
            reasons = [l.get("reason", "?") for l in (st or {}).get("log", [])]
            for rr in reasons:
                if rr != "accepted":
                    s["reasons_all_attempts"][rr] = s["reasons_all_attempts"].get(rr, 0) + 1
            if x["status"] != "accepted":
                lr = next((rr for rr in reversed(reasons) if rr != "accepted"), "no_log")
                s["last_reason_when_returned"][lr] = s["last_reason_when_returned"].get(lr, 0) + 1
            f = x["first"]
            if f:
                s["first_candidates"] += 1
                nb = not f.get("built")
                ff = (not nb) and not f.get("functional_ok")
                s["first_not_built"] += nb
                s["first_func_fail"] += ff
                s["first_breaks_functional"] += nb or ff
            ls, lf = x.get("_lines")
            if ls is not None and lf is not None:
                s["lines_start"] += ls
                s["lines_final"] += lf
                s["lines_pairs"] += 1
                s["longer"] += lf > ls
                s["shorter"] += lf < ls
                s["same_len"] += lf == ls
    out["non_security"] = per
    if not security:
        return out
    sec = {}
    for (m, it, src, cond), x in Brec.items():
        for mm in (m, "pooled"):
            for grp in ("all", "effect" if x["cwe"] in EFFECT_CWES else "logic"):
                s = sec.setdefault(f"{mm}|{cond}|{grp}", {
                    "vulnerable_targets": 0, "base_vulnerable": 0, "base_exploited_tests": 0,
                    "removed_tests_func_kept": 0, "removed_tests": 0, "left_tests": 0, "new_tests_vulnerable_src": 0,
                    "still_vulnerable": 0, "still_vulnerable_dataset": 0, "still_vulnerable_effect_judged": 0,
                    "patched_targets": 0, "new_on_patched": 0, "new_on_patched_dataset": 0, "new_tests_patched_src": 0,
                    "first_built_vulnerable": 0, "first_still_vulnerable": 0, "first_built_patched": 0,
                    "first_new_on_patched": 0, "first_removed_tests": 0, "new_on_patched_effect_judged": 0,
                    "effect_class_col3_accepted_no_effect_tests": 0, "effect_class_col5_dos_only_tests": 0,
                    "effect_class_col4_effect_tests": 0, "rows_with_columns": 0})
                cols = x.get("columns") if isinstance(x.get("columns"), list) else None
                if cols and cond != NONE and x["cwe"] in EFFECT_CWES:
                    s["rows_with_columns"] += 1
                    s["effect_class_col3_accepted_no_effect_tests"] += cols.count("accepted_no_effect")
                    s["effect_class_col5_dos_only_tests"] += cols.count("dos_only")
                    s["effect_class_col4_effect_tests"] += cols.count("exploited_effect")
                P = x["pairs"] or []
                broken = bool(x["base_func"]) and x["hard_func"] is False
                if src == "vulnerable":
                    s["vulnerable_targets"] += 1
                    s["base_vulnerable"] += any(p in ("removed", "left") for p in P)
                    s["base_exploited_tests"] += sum(p in ("removed", "left") for p in P)
                    if cond != NONE:
                        s["removed_tests"] += sum(p == "removed" for p in P)
                        s["removed_tests_func_kept"] += 0 if broken else sum(p == "removed" for p in P)
                        s["left_tests"] += sum(p == "left" for p in P)
                        s["new_tests_vulnerable_src"] += sum(p == "new" for p in P)
                    v, k = vuln_after(x)
                    s["still_vulnerable"] += v
                    s["still_vulnerable_effect_judged"] += k == "effect"
                    s["still_vulnerable_dataset"] += vuln_after(x, "dataset")[0]
                else:
                    s["patched_targets"] += 1
                    nv_, nk_ = new_after(x)
                    s["new_on_patched"] += nv_
                    s["new_on_patched_effect_judged"] += nk_ == "effect"
                    s["new_on_patched_dataset"] += new_after(x, "dataset")[0]
                    s["new_tests_patched_src"] += sum(p == "new" for p in P) if cond != NONE else 0
                f = x["first"]
                if f and f.get("built") and f.get("pairs") is not None:
                    fp = f["pairs"]
                    fx = dict(x, pairs=fp, effect=f.get("effect"), columns=f.get("columns"))
                    if src == "vulnerable":
                        s["first_built_vulnerable"] += 1
                        s["first_still_vulnerable"] += vuln_after(fx)[0]
                        s["first_removed_tests"] += sum(p == "removed" for p in fp)
                    else:
                        s["first_built_patched"] += 1
                        s["first_new_on_patched"] += new_after(fx)[0]
    out["security"] = sec
    return out


def s2_units(Brec, ca, cb, items, src="vulnerable", judg="primary", grp=None):
    U = []
    for (m, it, s_, cond), x in Brec.items():
        if cond != ca or s_ != src or (items is not None and it not in items):
            continue
        y = Brec.get((m, it, s_, cb))
        if y is None:
            continue
        if grp and (("effect" if x["cwe"] in EFFECT_CWES else "logic") != grp):
            continue
        f = vuln_after if src == "vulnerable" else new_after
        U.append((m, it, f(x, judg)[0], f(y, judg)[0]))
    return U


def best_condition(Brec, items, oracle):
    cands = [c for c in ("B0", "RCI", "B1", "SPEC2", "BUD") if c != oracle]
    rows = []
    for c in cands:
        X = [x for k, x in Brec.items() if k[3] == c and k[2] == "vulnerable" and (items is None or k[1] in items)]
        if not X:
            continue
        calls = sum(x["calls"] for k, x in Brec.items() if k[3] == c and (items is None or k[1] in items))
        rows.append({"cond": c, "still_vulnerable": sum(vuln_after(x)[0] for x in X), "n": len(X), "calls": calls})
    rows.sort(key=lambda r: (r["still_vulnerable"], r["calls"]))
    if len(rows) > 1 and (rows[0]["still_vulnerable"], rows[0]["calls"]) == (rows[1]["still_vulnerable"], rows[1]["calls"]):
        rows[0]["tie_after_calls"] = [r["cond"] for r in rows if (r["still_vulnerable"], r["calls"]) ==
                                      (rows[0]["still_vulnerable"], rows[0]["calls"])]
    return (rows[0]["cond"] if rows else None), rows


# ---------------------------------------------------------------- 3단계
def stage3(Brec, best, twice, oracle, items, a):
    T = [x for k, x in Brec.items() if k[3] == best and k[2] == "vulnerable" and k[1] in items
         and vuln_after(x)[0]]
    n_eff_judged = sum(vuln_after(x)[1] == "effect" for x in T)
    T_ds = sum(1 for k, x in Brec.items() if k[3] == best and k[2] == "vulnerable" and k[1] in items
               and vuln_after(x, "dataset")[0])
    patched_new = sum(1 for k, x in Brec.items() if k[3] == best and k[2] == "patched" and k[1] in items
                      and new_after(x)[0])
    # 반대 방향(결정 5절): 기존 최선은 고쳤는데 정책 제공 참고 조건은 못 고친 취약판 번역
    reverse = sum(1 for k, x in Brec.items() if k[3] == best and k[2] == "vulnerable" and k[1] in items
                  and not vuln_after(x)[0] and (k[0], k[1], k[2], oracle) in Brec
                  and vuln_after(Brec[(k[0], k[1], k[2], oracle)])[0])
    recs, fm_tests, missing_runs = [], collections.Counter(), 0
    for x in sorted(T, key=lambda z: (z["model"], z["tkey"])):
        st = x.get("_state") or {}
        reasons = [l.get("reason", "?") for l in st.get("log", [])]
        proc = "P2" if x["status"] == "accepted" else "P1"
        last = next((rr for rr in reversed(reasons) if rr != "accepted"), "") if proc == "P1" else "accepted"
        if vuln_after(x)[1] == "effect":
            idx = [i for i, e in enumerate(x["effect"]) if e[0] == "effect"]
        else:
            idx = [i for i, p in enumerate(x["pairs"]) if p in ("left", "new")]
        tag = "eval_hard" if x["status"] == "accepted" else "eval_base"
        fin = RF.load_runs(Path(x["bdir"]) / best / "_runs" / f"{x['tkey']}__{tag}.runs.jsonl")
        tests_p = Path(x["_export"]) / "tests" / f"{x['item']}.json"
        tests = jl(tests_p) if tests_p.exists() else None
        fms = []
        for i in idx:
            if fin is None or tests is None:
                fms.append("F_missing")
                missing_runs += 1
                continue
            ek = RF.expect_kind(tests["safety"][i]["expect"])
            fr = fin["runs"]["safety"][i] if i < len(fin["runs"]["safety"]) else None
            ak, asub = RF.kind_of(fr)
            fm = RF.failure_mode(ek, ak, asub)
            if fm == "F?" and ek == "value" and ak.startswith("error"):
                fm = "F6"
            fms.append(fm)
        fm_tests.update(fms)
        o = Brec.get((x["model"], x["item"], "vulnerable", oracle))
        tw = Brec.get((x["model"], x["item"], "vulnerable", twice)) if twice else None
        causes = []
        if o is None:
            causes.append("RN_undetermined")
        else:
            causes.append("N" if vuln_after(o)[0] else "R")
        if tw is None:
            causes.append("T_undetermined")
        elif not vuln_after(tw)[0]:
            causes.append("T")
        G = proc == "P1" and last == "functional_regression"
        if G:
            causes.append("J")
        g_hard = False
        if G and o is not None:
            ost = o.get("_state") or {}
            oreas = [l.get("reason", "?") for l in ost.get("log", [])]
            olast = next((rr for rr in reversed(oreas) if rr != "accepted"), "")
            g_hard = o["status"] != "accepted" and olast == "functional_regression"
        recs.append({"model": x["model"], "tkey": x["tkey"], "item": x["item"], "cwe": f"CWE-{x['cwe']}",
                     "process": proc, "last_gate_reason": last, "gate_reasons": ">".join(reasons),
                     "any_functional_regression": "functional_regression" in reasons,
                     "failing_test_indices": idx, "failure_modes": fms, "causes": causes, "G_hardened": g_hard,
                     "bdir": str(x["bdir"]), "b4": str(x["b4"]), "export": str(x["_export"])})
    res = {"best": best, "twice": twice, "policy_reference_condition": oracle, "n_residual": len(recs),
           "n_residual_effect_judged": n_eff_judged, "n_residual_dataset_rule_all_classes": T_ds,
           "n_residual_patched_new": patched_new,
           "R_reverse_direction": reverse,
           "stage4_rule_11_7": ("사전 지정한 잔여 건수 기준에 따라 추가 기법의 확증을 진행하지 않았다." if len(recs) < 40
                                else "잔여 건수 기준(40개 이상)을 넘어 4단계 확증을 진행한다."),
           "process": C(r["process"] for r in recs),
           "P1_last_reason": C(r["last_gate_reason"] for r in recs if r["process"] == "P1"),
           "any_functional_regression": sum(r["any_functional_regression"] for r in recs),
           "failure_modes_per_test": dict(fm_tests),
           "failure_modes_per_translation": C(m for r in recs for m in sorted(set(r["failure_modes"]))),
           "missing_stored_outputs": missing_runs,
           "causes": C(c for r in recs for c in r["causes"]),
           "overlap": C("+".join(sorted(c for c in r["causes"] if not c.endswith("undetermined"))) or "(none)"
                        for r in recs),
           "J_also_rejected_under_policy_condition": sum(r["G_hardened"] for r in recs),
           "cause_x_cwe": {}, "cause_x_model": {}}
    for r in recs:
        for c in r["causes"]:
            res["cause_x_cwe"].setdefault(c, collections.Counter())[r["cwe"]] += 1
            res["cause_x_model"].setdefault(c, collections.Counter())[r["model"]] += 1
    res["cause_x_cwe"] = {k: dict(v) for k, v in res["cause_x_cwe"].items()}
    res["cause_x_model"] = {k: dict(v) for k, v in res["cause_x_model"].items()}
    n_ = max(len(recs), 1)
    res["share_20pct_rule"] = {c: {"count": res["causes"].get(c, 0), "share": res["causes"].get(c, 0) / n_,
                                   "targeted": res["causes"].get(c, 0) / n_ >= 0.20} for c in ("R", "N", "J", "T")}
    res["label_meaning"] = {"R": "기존 최선 뒤 남고 정책 제공 참고 조건에서 고쳐짐(해석: 정보 부족)",
                            "N": "정책 제공 참고 조건에서도 남음(해석: 구현 한계)",
                            "J": "고친 답이 기능 시험 때문에 거절됨(마지막 거절 이유)(해석: 기능과의 충돌)",
                            "T": "같은 조건을 한 번 더 하면 고쳐짐(해석: 예산)"}
    res["note"] = "L(언어 관련)은 판별하지 않는다. 4층(S·K)은 분류자 2명의 파일(--rater-a, --rater-b)이 있을 때만 아래에 계산한다."
    return res, recs


def cohen_kappa(a, b):
    """두 분류자의 라벨 목록(같은 순서) -> (일치 수, κ). 우연 일치 1 이면 κ = 1(완전 일치) 또는 None."""
    n = len(a)
    if n == 0:
        return 0, None
    agree = sum(x == y for x, y in zip(a, b))
    po = agree / n
    labs = set(a) | set(b)
    pe = sum((a.count(l) / n) * (b.count(l) / n) for l in labs)
    if pe >= 1:
        return agree, (1.0 if po == 1 else None)
    return agree, (po - pe) / (1 - pe)


def _load_raters(path):
    out = {}
    for e in jl(path):
        k = (e.get("model"), e["tkey"]) if e.get("model") else e["tkey"]
        out[k] = {"S": e.get("S"), "K": e.get("K"), "confidence": e.get("confidence")}   # note 는 읽지 않는다
    return out


def layer4(recs, s3res, rater_a, rater_b, adjud=None):
    A, B = _load_raters(rater_a), _load_raters(rater_b)
    J = _load_raters(adjud) if adjud else {}
    def get(D, r):
        return D.get((r["model"], r["tkey"])) or D.get(r["tkey"])
    tk_count = collections.Counter(r["tkey"] for r in recs)
    rows, missing, ambiguous = [], 0, 0
    for r in recs:
        ra, rb = get(A, r), get(B, r)
        if (r["model"], r["tkey"]) not in A and tk_count[r["tkey"]] > 1:
            ambiguous += 1
        if ra is None or rb is None:
            missing += 1
            continue
        rows.append((r, ra, rb, get(J, r)))
    out = {"targets": len(recs), "joined": len(rows), "missing_rater_label": missing,
           "ambiguous_tkey_without_model": ambiguous}
    for dim in ("S", "K"):
        la, lb = [x[1][dim] for x in rows], [x[2][dim] for x in rows]
        ag, kp = cohen_kappa(la, lb)
        labs = sorted(set(la) | set(lb), key=str)
        out[dim] = {"agree": ag, "n": len(rows), "kappa": kp,
                    "per_label": {str(l): {"rater_A": la.count(l), "rater_B": lb.count(l),
                                           "both": sum(1 for x, y in zip(la, lb) if x == y == l)} for l in labs},
                    "A_x_B": dict(collections.Counter(f"{x}|{y}" for x, y in zip(la, lb)))}
    final, disagree = [], []
    for r, ra, rb, rj in rows:
        lab = {}
        for dim in ("S", "K"):
            if ra[dim] == rb[dim]:
                lab[dim] = ra[dim]
            elif rj and rj.get(dim):
                lab[dim] = rj[dim]
            else:
                lab[dim] = "UNRESOLVED"
        if ra["S"] != rb["S"] or ra["K"] != rb["K"]:
            disagree.append({"model": r["model"], "tkey": r["tkey"], "S_A": ra["S"], "S_B": rb["S"],
                             "K_A": ra["K"], "K_B": rb["K"], "adjudicated": bool(rj)})
        final.append((r, lab, ra, rb))
    out["disagreements"] = disagree
    out["adjudication_file"] = adjud
    out["S_x_K_final"] = dict(collections.Counter(f"{l['S']}|{l['K']}" for _r, l, _a, _b in final))
    strict = [r for r, l, _a, _b in final if l["K"] in ("K3", "K4")]
    strict_any = [r for r, l, ra, rb in final if l["K"] == "UNRESOLVED" and ("K3" in (ra["K"], rb["K"]) or "K4" in (ra["K"], rb["K"]))]
    out["strict_judging_K3_K4"] = len(strict)
    out["unresolved_with_K3_or_K4_by_one_rater"] = len(strict_any)
    excl = {(r["model"], r["tkey"]) for r in strict}
    keep = [r for r in recs if (r["model"], r["tkey"]) not in excl]
    out["causes_excluding_K3_K4"] = {
        "n_residual": len(keep),
        "causes": C(c for r in keep for c in r["causes"]),
        "overlap": C("+".join(sorted(c for c in r["causes"] if not c.endswith("undetermined"))) or "(none)" for r in keep),
        "cause_x_cwe": {c: C(r["cwe"] for r in keep if c in r["causes"]) for c in ("R", "N", "J", "T")},
        "cause_x_model": {c: C(r["model"] for r in keep if c in r["causes"]) for c in ("R", "N", "J", "T")}}
    # 층끼리 어긋나는 칸(예: R 이면서 S1)
    out["R_and_S1"] = sum(1 for r, l, _a, _b in final if "R" in r["causes"] and l["S"] == "S1")
    out["note"] = "분류자 note 칸은 읽지도 출력하지도 않는다."
    return out


def stage3_boot(Brec, best, recs, items, seed, nboot):
    """3단계 구성 개수의 시드 묶음 단위 재표본 구간. 묶음 = 기존 최선의 취약판 출발 번역 전체(items 안)."""
    base = [x for k, x in Brec.items() if k[3] == best and k[2] == "vulnerable" and k[1] in items]
    if not base:
        return None
    rk = {(r["model"], r["tkey"]): r for r in recs}
    keys = ["residual", "R", "N", "J", "T"]
    combos = sorted({"+".join(sorted(c for c in r["causes"] if not c.endswith("undetermined"))) or "(none)" for r in recs})
    fam = {}
    for x in base:
        v = fam.setdefault(family(x["item"]), np.zeros(len(keys) + len(combos)))
        r = rk.get((x["model"], x["tkey"]))
        if r is None:
            continue
        v[0] += 1
        for i, c in enumerate(keys[1:], 1):
            v[i] += c in r["causes"]
        cb = "+".join(sorted(c for c in r["causes"] if not c.endswith("undetermined"))) or "(none)"
        v[len(keys) + combos.index(cb)] += 1
    M = np.array(list(fam.values()))
    F = len(M)
    rng = _rng(seed, "stage3boot", 5)
    vals = []
    for start in range(0, nboot, 2000):
        W = rng.multinomial(F, np.full(F, 1 / F), size=min(2000, nboot - start))
        vals.append(W @ M)
    V = np.concatenate(vals)
    names = keys + ["overlap:" + c for c in combos]
    out = {"n_families": F, "nboot": nboot, "counts_ci95": {}, "share_of_residual_ci95": {}}
    for i, nm in enumerate(names):
        out["counts_ci95"][nm] = [float(np.percentile(V[:, i], 2.5)), float(np.percentile(V[:, i], 97.5))]
        if i > 0:
            sh = np.where(V[:, 0] > 0, V[:, i] / np.maximum(V[:, 0], 1), np.nan)
            sh = sh[~np.isnan(sh)]
            out["share_of_residual_ci95"][nm] = [float(np.percentile(sh, 2.5)), float(np.percentile(sh, 97.5))] if len(sh) else None
    return out


def strata_tables(A0, Brec):
    """보이는 시험이 있는 항목 / 없는 항목 층별 1·2단계 머리 수."""
    s1 = {}
    for (m, it, src, cond), r in A0.items():
        st = visible_stratum_of_arow(r)
        v = t_view(r, "t1")
        cwe = cwe_of(it, r.get("_export"))
        ok = v["func"] and v["pairs"] is not None
        bad = (s1_vuln(v, cwe, "primary")[0] if src == "vulnerable" else s1_newly(v, cwe, "primary")) if ok else 0
        for mm in (m, "pooled"):
            d = s1.setdefault(f"{mm}|{cond}|{src}|{st}", {"translations": 0, "functional": 0, "functional_vulnerable": 0})
            d["translations"] += 1
            d["functional"] += bool(v["func"])
            d["functional_vulnerable"] += bad
    s2 = {}
    for (m, it, src, cond), x in Brec.items():
        st = x.get("stratum") or visible_stratum_of_arow(A0.get((m, it, src, "PyRs")))
        for mm in (m, "pooled"):
            d = s2.setdefault(f"{mm}|{cond}|{st}", {"vulnerable_targets": 0, "still_vulnerable": 0,
                                                     "patched_targets": 0, "new_on_patched": 0})
            if src == "vulnerable":
                d["vulnerable_targets"] += 1
                d["still_vulnerable"] += vuln_after(x)[0]
            else:
                d["patched_targets"] += 1
                d["new_on_patched"] += new_after(x)[0]
    return {"stage1": s1, "stage2": s2}


def write_targets(recs, best, path):
    cols = ["tkey", "item", "cwe", "process", "gate_reasons", "failing_test_indices", "failure_modes",
            "final_code_dir", "b1_request_file", "meta_json", "tests_json", "model"]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write("\t".join(cols) + "\n")
        for r in recs:
            bd = Path(r["bdir"])
            fin = bd / best / "accepted" / r["tkey"] if r["process"] == "P2" else None
            if fin is None:
                fin = Path(r["b4"]) / "base" / r["tkey"]
            ex = Path(r["export"])
            row = [r["tkey"], r["item"], r["cwe"], r["process"], r["gate_reasons"],
                   ",".join(map(str, r["failing_test_indices"])), ",".join(r["failure_modes"]), str(fin),
                   str(bd / best / "prompts" / f"{r['tkey']}__k1.txt"), str(ex / "programs" / r["item"] / "meta.json"),
                   str(ex / "tests" / f"{r['item']}.json"), r["model"]]
            fh.write("\t".join(row) + "\n")


# ---------------------------------------------------------------- ③칸(결정 11-4)
COL3_LABELS = ("위험 기능 제거", "공격 표현만 실패", "구분 불가")
COL3_STILL = ("공격 표현만 실패", "구분 불가")     # 민감도에서 '남음'으로 본다
COL3_COLS = ["case_id", "stage", "condition", "model", "item", "cwe", "source", "test_index", "functional_ok", "run_status",
             "security_end", "effect_end", "label", "q1_reached", "q2_risky_feature"]


def col3_cases(A0, Brec):
    """효과 판정군(502·94·95·22·78)의 ③칸(accepted_no_effect: 받아들였지만 효과 없음) 보안 사례 목록. 분류는 사람이 한다.
    1단계 = A 줄 T1(Py→Rs·Py→Py, 두 판), 2단계 = B 줄 최종 프로그램(조건마다; '없음' = A 의 Py→Rs 라서 따로 넣지 않음).
    key = 번역 열쇠 (단계, 조건, 모델, 항목, 판)."""
    out = []

    def add(stage, cond, m, it, src, cwe, cols, safety, effect, func, status, key):
        for i, c in enumerate(cols):
            if c != "accepted_no_effect":
                continue
            sf = safety[i] if isinstance(safety, list) and i < len(safety) and isinstance(safety[i], list) else None
            ef = effect[i] if eff_valid(effect, len(cols)) else None
            out.append({"case_id": f"{stage}|{cond}|{m}|{it}|{src}|{i}", "stage": stage, "condition": cond, "model": m,
                        "item": it, "cwe": cwe, "source": src, "test_index": i, "functional_ok": bool(func),
                        "run_status": status, "security_end": "/".join(str(x) for x in sf[:2]) if sf else "",
                        "effect_end": "/".join(str(x) for x in ef[:2]) if ef else "", "key": key})
    for (m, it, src, cond), r in sorted(A0.items()):
        cwe = cwe_of(it, r.get("_export"))
        if cwe in EFFECT_CWES and isinstance(r.get("columns"), list):
            add("A", cond, m, it, src, cwe, r["columns"], r.get("safety"), r.get("effect"), r.get("functional_ok"),
                "translation_T1", ("A", cond, m, it, src))
    for (m, it, src, cond), x in sorted(Brec.items()):
        if cond == NONE or x["cwe"] not in EFFECT_CWES or not isinstance(x.get("columns"), list):
            continue
        add("B", cond, m, it, src, x["cwe"], x["columns"], x.get("safety"), x.get("effect"), x.get("hard_func"),
            "final=" + ("accepted_program" if x["status"] == "accepted" else "start_program(" + str(x["status"]) + ")"),
            ("B", cond, m, it, src))
    return out


def write_col3(cases, path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write("\t".join(COL3_COLS) + "\n")
        for c in cases:
            fh.write("\t".join(str(c.get(k, "")) for k in COL3_COLS) + "\n")


def read_col3_labels(path):
    """분류 파일: 머리줄이 있는 TSV, 칸 case_id·label·q1_reached(㉠)·q2_risky_feature(㉡). 내보낸 목록에 채워 넣어도 된다."""
    lines = [l for l in Path(path).read_text(encoding="utf-8-sig").splitlines() if l.strip()]
    hdr = lines[0].split("\t")
    ix = {h.strip(): i for i, h in enumerate(hdr)}
    out = {}
    for l in lines[1:]:
        f = l.split("\t")
        g = lambda k: f[ix[k]].strip() if k in ix and ix[k] < len(f) else ""  # noqa: E731
        out[g("case_id")] = {"label": g("label"), "q1_reached": g("q1_reached"), "q2_risky_feature": g("q2_risky_feature")}
    return out


def h1_units(A0, sens=None):
    """H1 주 판정 짝(1 = 없어짐; Py→Rs, Py→Py). sens = ③칸 민감도에서 '남음'으로 볼 번역 열쇠 집합."""
    U = []
    for (m, it, s_, cond), r in A0.items():
        if s_ != "vulnerable" or cond != "PyRs":
            continue
        r2 = A0.get((m, it, s_, "PyPy"))
        if r2 is None:
            continue
        v1, v2 = t_view(r, "t1"), t_view(r2, "t1")
        if not (v1["func"] and v2["func"]) or v1["pairs"] is None or v2["pairs"] is None:
            continue
        cwe = cwe_of(it, r.get("_export"))
        if cwe not in CODE_EXEC_CWES:
            continue
        x1, x2 = s1_vuln(v1, cwe, "primary")[0], s1_vuln(v2, cwe, "primary")[0]
        if sens:
            x1 = max(x1, int(("A", "PyRs", m, it, s_) in sens))
            x2 = max(x2, int(("A", "PyPy", m, it, s_) in sens))
        U.append((m, it, 1 - x1, 1 - x2))
    return U


def _b_key(x):
    if x["cond"] == NONE:
        return ("A", "PyRs", x["model"], x["item"], x["source"])
    return ("B", x["cond"], x["model"], x["item"], x["source"])


def s2_units_sens(Brec, ca, cb, items, sens):
    """2단계 짝(취약판 출발, 나쁨 = 고친 뒤에도 취약) — sens 에 든 번역은 취약으로 본다('없음' = A 의 Py→Rs 열쇠)."""
    U = []
    for (m, it, s_, cond), x in Brec.items():
        if cond != ca or s_ != "vulnerable" or (items is not None and it not in items):
            continue
        y = Brec.get((m, it, s_, cb))
        if y is None:
            continue
        U.append((m, it, max(vuln_after(x)[0], int(_b_key(x) in sens)), max(vuln_after(y)[0], int(_b_key(y) in sens))))
    return U


def col3_block(A0, Brec, items, comps, a):
    """③칸 목록 내보내기·분류 파일 읽기·세 수·민감도(결정 11-4). 반환 (결과, '남음'으로 볼 번역 열쇠 집합 또는 None)."""
    cases = col3_cases(A0, Brec)
    res = {"n_cases": len(cases), "label_set": list(COL3_LABELS),
           "cases_by_stage_condition_source": C(f"{c['stage']}|{c['condition']}|{c['source']}" for c in cases),
           "translations_with_col3": len({c["key"] for c in cases}),
           "note": "③ = 효과 판정군에서 받아들였지만 고정된 공격 묶음에서 효과가 관찰되지 않은 보안 사례(관찰). 주 판정은 '사라짐'으로 센다. "
                   "'위험 기능이 제거됐다'(해석)는 분류가 '위험 기능 제거'인 것에만 쓴다."}
    if getattr(a, "col3_tsv", None):
        if getattr(a, "col3_labels", None) and Path(a.col3_tsv).resolve() == Path(a.col3_labels).resolve():
            res["tsv"] = "NOT WRITTEN: --col3-tsv is the labels file"
        else:
            write_col3(cases, a.col3_tsv)
            res["tsv"] = a.col3_tsv
    if not getattr(a, "col3_labels", None):
        res["labels"] = "not available (no --col3-labels)"
        return res, None
    L = read_col3_labels(a.col3_labels)
    ids = {c["case_id"] for c in cases}
    lab_of = {c["case_id"]: (L.get(c["case_id"]) or {}).get("label", "") for c in cases}
    cnt = collections.Counter(v if v in COL3_LABELS else ("unlabelled" if not v else "invalid_label") for v in lab_of.values())
    still = {c["key"] for c in cases if lab_of[c["case_id"]] in COL3_STILL}
    still_all = still | {c["key"] for c in cases if lab_of[c["case_id"]] not in COL3_LABELS}
    res["labels"] = {"file": a.col3_labels, "sha16": sha16(a.col3_labels),
                     "counts": {k: cnt.get(k, 0) for k in COL3_LABELS + ("unlabelled", "invalid_label")},
                     "labels_for_unknown_case_ids": len(set(L) - ids),
                     "q1_reached": C((L.get(c["case_id"]) or {}).get("q1_reached") or "(blank)" for c in cases),
                     "q2_risky_feature": C((L.get(c["case_id"]) or {}).get("q2_risky_feature") or "(blank)" for c in cases),
                     "counts_by_stage_condition": {k: C(lab_of[c["case_id"]] or "unlabelled" for c in cases
                                                        if f"{c['stage']}|{c['condition']}" == k)
                                                   for k in sorted({f"{c['stage']}|{c['condition']}" for c in cases})}}
    sens = {"label": "민감도(결정 11-4): '공격 표현만 실패'·'구분 불가'로 분류된 ③칸 사례가 있는 번역을 '남음'(취약)으로 본다. "
                     "미분류는 주 판정 그대로(translations_reclassified_unlabelled_as_still = 미분류도 남음으로 볼 때의 번역 수).",
            "translations_reclassified": len(still), "translations_reclassified_unlabelled_as_still": len(still_all)}
    if A0:
        U0, U1 = h1_units(A0), h1_units(A0, still)
        sens["H1"] = {"main_disappeared": {"PyRs": sum(u[2] for u in U0), "PyPy": sum(u[3] for u in U0), "n": len(U0)},
                      "sensitivity_disappeared": {"PyRs": sum(u[2] for u in U1), "PyPy": sum(u[3] for u in U1), "n": len(U1)}}
    if Brec and comps:
        sens["stage2"] = {}
        for nm, c in comps.items():
            if nm not in ("2-ga-1", "2-ga-2", "2-na"):
                continue
            ca, cb = c["conds"]
            U = s2_units_sens(Brec, ca, cb, items, still)
            pc = paired_compare(U, nm + "|col3", a.seed, a.perm, a.boot, a.delta)
            sens["stage2"][nm] = {"conds": [ca, cb], "n": len(U), "a_bad": pc.get("a_bad"), "b_bad": pc.get("b_bad"),
                                  "diff": pc.get("diff"), "p_family": (pc.get("family") or {}).get("perm", {}).get("p"),
                                  "main_a_bad": c.get("a_bad"), "main_b_bad": c.get("b_bad")}
    res["sensitivity"] = sens
    return res, still


# ---------------------------------------------------------------- 4단계
def stage4(Brec, new, base, oracle, repeat, items, seed, a):
    """4-가 새 기법 대 기존 최선, 4-나 새 기법 대 기존 최선 반복(같은 호출 상한), 비열등(수정판 새로 생김)."""
    ga = paired_compare(s2_units(Brec, new, base, items), "S4ga", seed, a.perm, a.boot, a.delta)
    nb = paired_compare(s2_units(Brec, new, repeat, items), "S4nb", seed, a.perm, a.boot, a.delta) if repeat else {"n": 0, "empty": True}
    # 신규 위험(결정 11-2): 수정판 출발, 나쁨 = 새로 생김. d_신규 = 새 기법 − 기존 최선(양수 = 악화).
    ni = paired_compare(s2_units(Brec, new, base, items, src="patched"), "S4new", seed, a.perm, a.boot, a.delta)
    fb = ni.get("family", {}).get("boot") if ni.get("n") else None
    d5 = interval_decision(fb, a.delta, "new_risk")
    d2 = interval_decision(fb, 0.02, "new_risk")
    ci = d5["ci"]
    ni["decision_level"], ni["ci_method"] = DECISION_LEVEL, CI_METHOD
    ni["d_new_ci"] = ci                                   # 판정 구간(고른 방법의 명목 판정 수준)
    ni["d_new_ci_upper"] = ci[1] if ci else None
    ci90 = fb.get("prop_ci90") if fb else None            # 보고용(고른 방법 90%), 판정에는 쓰지 않음
    ni["d_new_ci90"] = ci90
    ni["d_new_ci90_upper"] = ci90[1] if ci90 else None
    ni["decision_5pt"], ni["decision_2pt_secondary"] = d5, d2
    ni["class_5pt"] = d5["class"]
    ni["class_2pt_secondary"] = d2["class"]
    nb_ = ni.get("naive", {}).get("boot") if ni.get("n") else None
    ni["naive_class_5pt"] = interval_decision(nb_, a.delta, "new_risk")["class"]
    ni["direction"] = "a = 새 기법, b = 기존 최선; diff·구간 = 새 − 기준(양수 = 새 기법에서 더 많이 새로 생김)"
    gb = ga.get("family", {}).get("boot") if ga.get("n") else None
    rd = interval_decision(gb, a.delta, "equivalence")
    resid = {"d_residual_ci": rd["ci"], "d_residual_ci90": gb.get("prop_ci90") if gb else None,
             "equivalent_5pt": rd["within"] is True, "decision": rd, "decision_level": DECISION_LEVEL, "ci_method": CI_METHOD,
             "direction": "새 기법 − 기존 최선(음수 = 개선)"}
    dist = None
    if oracle:
        sv = lambda c: sum(vuln_after(x)[0] for k, x in Brec.items() if k[3] == c and k[2] == "vulnerable"
                           and (items is None or k[1] in items))
        sb, so, sn = sv(base), sv(oracle), sv(new)
        dist = {"left_after_best_existing": sb, "left_after_new": sn, "left_after_policy_condition": so}
        if so < sb:
            dist["gap"] = sb - so
            dist["gap_closed"] = sb - sn
            dist["text"] = f"기존 최선과 정책 제공 조건의 차이 {sb - so}개 중 {sb - sn}개를 메웠다."
        else:
            dist["text"] = "정책 제공 조건이 기존 최선보다 적게 남기지 못해 '차이를 메운 수'는 계산하지 않았다."
        if sn < so:
            dist["text"] += f" 새 기법({sn})이 정책 제공 조건({so})보다 적게 남겼다."
    calls = {}
    for c in (new, base, repeat):
        if not c:
            continue
        X = [x for k, x in Brec.items() if k[3] == c and (items is None or k[1] in items)]
        calls[c] = {"targets": len(X), "row_calls": sum(x["calls"] for x in X),
                    "mean_per_target": (sum(x["calls"] for x in X) / len(X)) if X else None,
                    "max_per_target": max((x["calls"] for x in X), default=None),
                    "call_cap_total": sorted({x["bestrep"]["call_cap_total"] for x in X if x.get("bestrep")} - {None})}
    return {"new": new, "base": base, "repeat": repeat, "ga": ga, "nb": nb, "new_risk": ni, "residual": resid,
            "difference_from_policy_condition": dist, "actual_calls": calls}


def s4_model_set(Brec, conds, items):
    """결정 11-6: 4단계 비교는 4단계 조건이 모두 있는 모델만. 모델의 대상 = 항목 목록 안의 (항목, 판)('없음' 줄은 대상마다 있다).
    조건마다 모든 대상에 줄이 있어야 그 모델을 쓴다. 반환 (쓰는 모델, 모델별 조건별 {대상, 줄 있음})."""
    conds = [c for c in conds if c]
    cov = {}
    for m in sorted({k[0] for k in Brec}):
        tg = {(k[1], k[2]) for k in Brec if k[0] == m and k[3] == NONE and (items is None or k[1] in items)}
        cov[m] = {c: {"targets": len(tg), "with_row": len({(k[1], k[2]) for k in Brec if k[0] == m and k[3] == c
                                                           and (k[1], k[2]) in tg})} for c in conds}
    used = [m for m, v in cov.items() if v and all(x["targets"] > 0 and x["with_row"] == x["targets"] for x in v.values())]
    return used, cov


KN = {1: "한", 2: "두", 3: "세", 4: "네", 5: "다섯", 6: "여섯"}


def pooled_phrase(n):
    """결정 11-6 표현: 'LLM 번역 일반'이 아니라 '선정한 네 모델을 합친 결과'(실제 합친 수)."""
    return f"선정한 {KN.get(n, n)} 모델을 합친 결과"


# ---------------------------------------------------------------- RQ3·RQ4·RQ5(남김) 기술 표
IND_KEYS = ("panic_sites", "int_sites", "unsafe_blocks", "code_loading")


def ind_from_sigma(s):
    """B4 state sigma0(harden_job.sigma) -> run_main.ind_of 와 같은 칸."""
    if not isinstance(s, dict) or "by_class" not in s:
        return None
    deps = list(s.get("deps") or [])
    import gate
    return {"panic_sites": s["by_class"].get("panic", 0), "int_sites": s["by_class"].get("intover", 0),
            "unsafe_blocks": s.get("unsafe_blocks", 0), "deps": deps, "n_deps": len(deps),
            "code_loading": sum((s.get("codeload") or {}).values()),
            "code_exec_deps": sorted(d for d in deps if d in gate.CODE_EXEC_CRATES or d.replace("_", "-") in gate.CODE_EXEC_CRATES)}


def ind_counts(inds):
    """지표 목록 -> 개수(≥1 인 번역 수와 합계)."""
    ok = [x for x in inds if isinstance(x, dict) and "error" not in x]
    out = {"with_indicators": len(ok), "indicator_errors": sum(1 for x in inds if isinstance(x, dict) and "error" in x)}
    for k in IND_KEYS:
        out[f"any_{k}"] = sum(1 for x in ok if (x.get(k) or 0) > 0)
        out[f"total_{k}"] = sum(x.get(k) or 0 for x in ok)
    out["any_deps"] = sum(1 for x in ok if x.get("n_deps"))
    out["total_deps"] = sum(x.get("n_deps") or 0 for x in ok)
    out["any_code_exec_dep"] = sum(1 for x in ok if x.get("code_exec_deps"))
    return out


def round_bucket(n):
    return "0" if not n else "1" if n == 1 else "2+"


def strat_perm(units, seed, key, nperm):
    """units [(family, group 0/1, y 0/1)]. 통계량 = 묶음1 취약 비율 − 묶음0 취약 비율. 치환 = 시드 묶음 안에서 묶음 표시를 섞음
    (묶음 크기 고정이면 통계량은 묶음1 취약 수의 단조 함수 → 묶음마다 초기하 분포에서 뽑아 더한다). 양측, (≥ 수 + 1)/(치환 + 1)."""
    n1 = sum(g for _, g, _ in units)
    n0 = len(units) - n1
    if not n1 or not n0:
        return {"n_ge1": n1, "n_0": n0, "p": None, "note": "one group empty"}
    Y = sum(y for *_, y in units)
    s1 = sum(y for _, g, y in units if g)
    diff = lambda s: s / n1 - (Y - s) / n0  # noqa: E731
    fam = {}
    for f, g, y in units:
        v = fam.setdefault(f, [0, 0, 0])
        v[0] += 1
        v[1] += g
        v[2] += y
    rng = _rng(seed, key, 7)
    S = np.zeros(nperm, dtype=np.int64)
    for n_f, g_f, y_f in fam.values():
        if g_f in (0, n_f) or y_f in (0, n_f):
            S += min(g_f, y_f) if (g_f == n_f or y_f == n_f) else 0
            continue
        S += rng.hypergeometric(y_f, n_f - y_f, g_f, size=nperm)
    obs = diff(s1)
    cnt = int((np.abs(diff(S.astype(float))) >= abs(obs) - 1e-12).sum())
    return {"n_ge1": n1, "n_0": n0, "vuln_ge1": s1, "vuln_0": Y - s1, "diff_share": obs, "p": (cnt + 1) / (nperm + 1),
            "nperm": nperm, "n_families": len(fam),
            "n_informative_families": sum(1 for n_f, g_f, y_f in fam.values() if 0 < g_f < n_f and 0 < y_f < n_f),
            "label": "exploratory"}


def _b4_sigma0(b4, tkey, cache):
    k = (str(b4), tkey)
    if k not in cache:
        p = Path(b4) / "state" / f"{tkey}.json"
        cache[k] = ind_from_sigma(jl(p).get("sigma0")) if p.exists() else None
    return cache[k]


def rq_tables(A0, Brec, security, seed, nperm):
    """RQ3(Rust 만의 위험 개수), RQ4(고치기 회차), RQ5 남김(번역에서 사라진 위험이 완화 뒤 다시 생기는가). 개수 먼저, 모델별과 합."""
    out = {}
    MM = lambda m: (m, "pooled")  # noqa: E731
    # ---- RQ3
    r3 = {}
    for (m, it, src, cond), r in A0.items():
        if cond != "PyRs":
            continue
        for mm in MM(m):
            for s_ in (src, "all"):
                d = r3.setdefault(f"{mm}|{s_}", {"translations": 0, "built": 0, "_inds": [], "never_built": 0,
                                                 "build_failure": {}, "unresolved_crate_names": {}, "unresolved_by_kind": {},
                                                 "func_tests_abnormal": {}, "func_translations_abnormal": 0,
                                                 "func_judged": 0})
                d["translations"] += 1
                if r.get("built"):
                    d["built"] += 1
                    if r.get("rust_indicators") is not None:
                        d["_inds"].append(r["rust_indicators"])
                    cap = r.get("capability")
                    if isinstance(cap, list):
                        d["func_judged"] += 1
                        ab = [x[1] for x in cap if isinstance(x, list) and x[0] == "fail" and x[1] in DOS_SUBS]
                        for s in ab:
                            d["func_tests_abnormal"][s] = d["func_tests_abnormal"].get(s, 0) + 1
                        d["func_translations_abnormal"] += bool(ab)
                else:
                    d["never_built"] += 1
                    lab = r.get("build_failure", "not_recorded")
                    d["build_failure"][lab] = d["build_failure"].get(lab, 0) + 1
                    kinds = r.get("unresolved_kinds") or {}
                    for c in r.get("unresolved_crates") or []:
                        d["unresolved_crate_names"][c] = d["unresolved_crate_names"].get(c, 0) + 1
                        kd = kinds.get(c, "not_recorded")          # name = 없는 라이브러리 이름, version = 있는 이름의 없는 판
                        d["unresolved_by_kind"][kd] = d["unresolved_by_kind"].get(kd, 0) + 1
    for d in r3.values():
        inds = d.pop("_inds")
        d["indicators_T1"] = ind_counts(inds) if inds else "not available (no rust_indicators in rows)"
        d["unresolved_crate"] = d["build_failure"].get("unresolved_crate", 0)
    if security:
        for (m, it, src, cond), r in A0.items():
            if cond != "PyRs" or not r.get("built") or r.get("safety") is None:
                continue
            for mm in MM(m):
                for s_ in (src, "all"):
                    d = r3[f"{mm}|{s_}"]
                    s = d.setdefault("security", {"judged": 0, "abnormal_tests": {}, "translations_abnormal": 0,
                                                  "rows_with_columns": 0, "col5_dos_only_tests": 0,
                                                  "translations_with_col5": 0})
                    s["judged"] += 1
                    ab = [x[1] for x in r["safety"] if x[0] == "exploited" and x[1] in DOS_SUBS]
                    for k in ab:
                        s["abnormal_tests"][k] = s["abnormal_tests"].get(k, 0) + 1
                    s["translations_abnormal"] += bool(ab)
                    if isinstance(r.get("columns"), list):
                        s["rows_with_columns"] += 1
                        s["col5_dos_only_tests"] += r["columns"].count("dos_only")
                        s["translations_with_col5"] += "dos_only" in r["columns"]
    else:
        for d in r3.values():
            d["security"] = "REFUSED (blinded rows)"
    # 2단계 대상의 출발 번역(σ0, 기능 통과 부분집합)과 조건 뒤 최종 프로그램
    cache, tg, after = {}, {}, {}
    for (m, it, src, cond), x in Brec.items():
        s0 = _b4_sigma0(x["b4"], x["tkey"], cache)
        if cond == NONE:
            for mm in MM(m):
                for s_ in (src, "all"):
                    tg.setdefault(f"{mm}|{s_}", []).append(s0)
            continue
        for mm in MM(m):
            for s_ in (src, "all"):
                d = after.setdefault(f"{mm}|{cond}|{s_}", {"targets": 0, "accepted": 0, "_ret": []})
                d["targets"] += 1
                if x["status"] == "accepted":
                    d["accepted"] += 1
                else:
                    d["_ret"].append(s0)
    out_t = {}
    for k, v in tg.items():
        have = [s for s in v if s is not None]
        out_t[k] = dict(targets=len(v), with_sigma0=len(have), **(ind_counts(have) if have else {}))
    for d in after.values():
        ret = [s for s in d.pop("_ret") if s is not None]
        d["returned_to_start"] = d["targets"] - d["accepted"]
        d["returned_to_start_indicators"] = ind_counts(ret) if ret else None
        d["accepted_indicators"] = ("not available (final-program sigma is not stored by pilot_job ingest-b)"
                                    if d["accepted"] else None)
    out["rq3"] = {"translations_PyRs": r3, "stage2_targets_sigma0": out_t, "after_stage2": after,
                  "note": "indicators = clippy sigma (panic = unwrap/expect/indexing/panic-type lints, int = arithmetic/cast "
                          "lints, unsafe blocks, deps, code-loading patterns, code-executing crates). stage2_targets_sigma0 = "
                          "functional-pass subset (stage-2 targets). After a condition: returned-to-start finals = the "
                          "starting program (sigma0); accepted finals: not available."}
    # ---- RQ4
    r4 = {}
    for (m, it, src, cond), r in A0.items():
        for mm in MM(m):
            for s_ in (src, "all"):
                d = r4.setdefault(f"{mm}|{cond}|{s_}", {"translations": 0, "built": 0, "never_built": 0,
                                                        "build_fix_rounds_built": {}, "build_fix_ge1_built": 0,
                                                        "build_fix_rounds_recorded": 0,
                                                        "visible_tests_run": 0, "visible_fix_rounds": {}, "visible_fix_ge1": 0,
                                                        "stage3": {}, "t1_differs": 0, "total_rounds_built": {}})
                d["translations"] += 1
                fr = r.get("fix_rounds")
                d["build_fix_rounds_recorded"] += fr is not None
                if not r.get("built"):
                    d["never_built"] += 1
                    continue
                d["built"] += 1
                d["build_fix_rounds_built"][str(fr)] = d["build_fix_rounds_built"].get(str(fr), 0) + 1
                d["build_fix_ge1_built"] += bool(fr)
                vr = r.get("visible_rounds")
                st3 = r.get("stage3")
                if st3 is not None:
                    d["stage3"][st3] = d["stage3"].get(st3, 0) + 1
                if st3 not in (None, "skipped_no_tests", "skipped_not_built"):
                    d["visible_tests_run"] += 1
                    d["visible_fix_rounds"][str(vr or 0)] = d["visible_fix_rounds"].get(str(vr or 0), 0) + 1
                    d["visible_fix_ge1"] += bool(vr)
                tot = (fr or 0) + (vr or 0)
                d["total_rounds_built"][str(tot)] = d["total_rounds_built"].get(str(tot), 0) + 1
                d["t1_differs"] += bool(r.get("t1_differs"))
    rq4 = {"rounds": r4, "never_built_rounds_note": "never-built rows used every build-fix round (fix_rounds = max); they "
                                                    "have no security outcome and are counted separately",
           "t0_vs_t1": "see stage1.t0_vs_t1 (T0 = before visible-test repair, T1 = after)"}
    if security:
        cross, perms = {}, {}
        units = collections.defaultdict(list)
        for (m, it, src, cond), r in A0.items():
            v = t_view(r, "t1")
            if not (v["built"] and v["func"]) or v["pairs"] is None:
                continue
            cwe = cwe_of(it, r.get("_export"))
            bad = s1_vuln(v, cwe, "primary")[0] if src == "vulnerable" else s1_newly(v, cwe, "primary")
            meas = {"build_fix": r.get("fix_rounds") or 0, "visible_fix": r.get("visible_rounds") or 0}
            meas["total"] = meas["build_fix"] + meas["visible_fix"]
            for mk, n in meas.items():
                b = round_bucket(n)
                for mm in MM(m):
                    d = cross.setdefault(f"{mm}|{cond}|{src}|{mk}", {})
                    cell = d.setdefault(b, {"translations": 0, "vulnerable": 0})
                    cell["translations"] += 1
                    cell["vulnerable"] += bad
                units[f"{cond}|{src}|{mk}"].append((family(it), int(n > 0), bad))
        for k, U in sorted(units.items()):
            perms[k] = strat_perm(U, seed, "rq4|" + k, nperm)
        rq4["cross_rounds_x_vulnerable"] = cross
        rq4["perm_ge1_vs_0"] = perms
        rq4["cross_note"] = ("functional-pass T1 with security labels; vulnerable = single vulnerability rule (vulnerable source: "
                             "still vulnerable; patched source: newly vulnerable incl. column 5). p = family-stratified "
                             "permutation (round group shuffled within seed families), pooled over models, exploratory")
    else:
        rq4["cross_rounds_x_vulnerable"] = "REFUSED (blinded rows)"
    out["rq4"] = rq4
    # ---- RQ5 남김
    if security:
        k5 = {}
        for (m, it, src, cond), x in Brec.items():
            if src != "vulnerable" or cond == NONE:
                continue
            P = x["pairs"] or []
            arow = A0.get((m, it, src, "PyRs"))
            AP = (arow or {}).get("pairs")
            aligned = isinstance(AP, list) and len(AP) == len(P)
            for mm in MM(m):
                d = k5.setdefault(f"{mm}|{cond}", {
                    "vulnerable_targets": 0, "start_safe_tests": 0, "reintroduced_tests": 0,
                    "targets_with_start_safe": 0, "targets_with_reintroduced": 0,
                    "gone_in_translation_tests": 0, "gone_reintroduced_tests": 0, "gone_kept_tests": 0,
                    "safe_in_both_tests": 0, "safe_in_both_reintroduced_tests": 0, "targets_with_gone_reintroduced": 0,
                    "targets_not_aligned_with_A": 0, "still_vulnerable": 0, "new_tests_vulnerable_src": 0})
                d["vulnerable_targets"] += 1
                ss = [i for i, p in enumerate(P) if p in ("new", "safe")]
                d["start_safe_tests"] += len(ss)
                d["reintroduced_tests"] += sum(P[i] == "new" for i in ss)
                d["new_tests_vulnerable_src"] += sum(p == "new" for p in P)
                d["targets_with_start_safe"] += bool(ss)
                d["targets_with_reintroduced"] += any(P[i] == "new" for i in ss)
                d["still_vulnerable"] += vuln_after(x)[0]
                if not aligned:
                    d["targets_not_aligned_with_A"] += 1
                    continue
                g = [i for i in ss if AP[i] == "gone"]
                d["gone_in_translation_tests"] += len(g)
                d["gone_reintroduced_tests"] += sum(P[i] == "new" for i in g)
                d["gone_kept_tests"] += sum(P[i] == "safe" for i in g)
                sb = [i for i in ss if AP[i] == "safe"]
                d["safe_in_both_tests"] += len(sb)
                d["safe_in_both_reintroduced_tests"] += sum(P[i] == "new" for i in sb)
                d["targets_with_gone_reintroduced"] += any(P[i] == "new" for i in g)
        out["rq5_kept"] = {"table": k5, "note": (
            "vulnerable-source targets; start-safe = security cases not exploited in the starting translation (B pairs new/safe; "
            "dataset judgement); reintroduced = exploited after the condition (B pair 'new'). This equals the already reported "
            "stage2.security new_tests_vulnerable_src (same count, test level). Split by the translation step (A T1 pairs): "
            "gone = exploited in the original, disappeared in translation; safe_in_both = safe in original and translation. "
            "kept = gone and still not exploited after the condition.")}
    else:
        out["rq5_kept"] = "REFUSED (blinded rows)"
    return out


# ---------------------------------------------------------------- 메인
def main(argv=None):
    global CI_METHOD, DECISION_LEVEL, EXCEPTION_RULES
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="append")
    ap.add_argument("--brun", action="append")
    ap.add_argument("--arun", action="append")
    ap.add_argument("--items")
    ap.add_argument("--sample-label", default="all")
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--perm", type=int, default=10000)
    ap.add_argument("--boot", type=int, default=10000)
    ap.add_argument("--delta", type=float, default=0.05)
    ap.add_argument("--best", default="auto")
    ap.add_argument("--best-items")
    ap.add_argument("--twice")
    ap.add_argument("--oracle", default="ORA")
    ap.add_argument("--s3-items")
    ap.add_argument("--s4-new")
    ap.add_argument("--s4-base")
    ap.add_argument("--s4-repeat", help="기존 최선 반복(같은 호출 상한) 조건 이름")
    ap.add_argument("--s4-items")
    ap.add_argument("--rater-a")
    ap.add_argument("--rater-b")
    ap.add_argument("--adjudication")
    ap.add_argument("--override-11-7", action="store_true",
                    help="40개 미만 규칙을 무시하고 4단계 확증을 낸다(출력에 '사전 등록 규칙 밖' 표시)")
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    ap.add_argument("--targets-tsv")
    ap.add_argument("--ci-method", choices=CI_METHODS, default="bca",
                    help="비율 차이 구간 계산법(결정 13-3). 기본 bca. 이전 동작은 percentile 과 --decision-level 0.90")
    ap.add_argument("--decision-level", type=float, choices=DECISION_LEVELS, default=0.95,
                    help="동등성·비열등 판정에 쓰는 명목 구간 수준(결정 13-3, 기본 0.95). percentile 과 0.90 이면 13-2 예외 규칙을 끈다")
    ap.add_argument("--col3-tsv", help="효과 판정군 ③칸 사례 목록을 쓸 TSV(결정 11-4, 사람이 분류)")
    ap.add_argument("--col3-labels", help="③칸 분류 파일(TSV: case_id, label, q1_reached, q2_risky_feature)")
    a = ap.parse_args(argv)
    if not SEED_FAMILIES.exists():      # 예전에는 가져올 때 읽어 여기까지 오지 못했다: 실제 분석은 묶음 지도 없이 돌리지 않는다
        raise SystemExit(f"seed families file not found: {SEED_FAMILIES}")
    CI_METHOD = a.ci_method
    DECISION_LEVEL = a.decision_level
    EXCEPTION_RULES = not (a.ci_method == "percentile" and abs(a.decision_level - 0.90) < 1e-9)

    bundles = load_inputs(a)
    items = set(read_list(a.items)) if a.items else None
    inset = lambda it: items is None or it in items
    res = {"script_sha16": sha16(__file__), "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
           "seed": a.seed, "perm": a.perm, "boot": a.boot, "delta": a.delta, "sample_label": a.sample_label,
           "ci_method": a.ci_method, "decision_level": a.decision_level, "decision_interval_label": ci_label(),
           "exception_rules_13_2": ("applied" if EXCEPTION_RULES else
                                    "off (이전 동작 재현 조합: --ci-method percentile --decision-level 0.90)"),
           "items_file": a.items, "items_sha16": sha16(a.items) if a.items else None,
           "n_items_in_list": len(items) if items is not None else None,
           "inputs": [{"model": b["model"], "kind": b["kind"], "root": b["root"]} for b in bundles],
           "pooled_meaning": pooled_phrase(len({b["model"] for b in bundles})),
           "ambiguities_resolved": AMBIG}

    # 가림 확인
    blinded = collections.Counter()
    for b in bundles:
        for r in b["arows"] + b["brows"]:
            it = item_of_row(r)
            if inset(it) and (r.get("blinded_kinds") or it in b["blind_items"]):
                blinded[b["model"]] += 1
    security = sum(blinded.values()) == 0
    res["blinding"] = {"blinded_rows_in_set": dict(blinded), "security_results": "computed" if security else
                       f"REFUSED: {sum(blinded.values())} rows in the requested item set are blinded"}

    # 1단계 자료
    Aall = {}
    for b in bundles:
        for r in b["arows"]:
            it = r["item"]
            if not inset(it):
                continue
            r.setdefault("_export", b["export_root"] if bench_of(it, r) == "scp" else str(EXPORT_CW))
            k = (b["model"], it, r["source"], r["cond"], int(r["_sample"]))
            if k in Aall:
                raise SystemExit(f"duplicate translation row {k[0]} {k[2]} {k[3]} sample {k[4]}")
            Aall[k] = r
    A0 = {k[:4]: r for k, r in Aall.items() if k[4] == 0}
    if A0:
        if security:
            res["stage1"] = stage1(A0, items, a.seed, a)
            res["stage1"]["extra_samples"] = extra_variability(Aall)
        else:
            # 보안과 무관한 개수만
            tab = {}
            for (m, it, src, cond), r in A0.items():
                for which in ("t1", "t0"):
                    v = t_view(r, which)
                    for mm in (m, "pooled"):
                        s = tab.setdefault(f"{mm}|{cond}|{src}|{bench_of(it, r)}|{which}",
                                           {"translations": 0, "built": 0, "functional": 0})
                        s["translations"] += 1
                        s["built"] += bool(v["built"])
                        s["functional"] += v["func"]
            res["stage1"] = {"counts": tab, "security": "REFUSED (blinded rows)"}

    # 2단계 자료(SecCodePLT 만)
    Brec = {}
    for b in bundles:
        for r in b["brows"]:
            it = item_of_row(r)
            if not inset(it) or not is_scp(it):
                continue
            arow = A0.get((b["model"], it, r["source"], "PyRs"))
            base_eff = arow.get("effect") if arow else None
            x = b_rec(r, b["model"], base_eff)
            x["_export"] = b["export_root"]
            x["_state"] = state_of(x)
            fin = (Path(x["bdir"]) / x["cond"] / "accepted" / x["tkey"]) if x["status"] == "accepted" \
                else (Path(x["b4"]) / "base" / x["tkey"])
            x["_lines"] = (lines_of(Path(x["b4"]) / "base" / x["tkey"]), lines_of(fin))
            if x["stratum"] is None:
                x["stratum"] = visible_stratum_of_arow(arow)
            k = (b["model"], it, r["source"], r["cond"])
            if k in Brec:
                raise SystemExit(f"duplicate B row {k[0]} {k[2]} {k[3]}")
            Brec[k] = x
    # '없음' 줄
    none_mismatch, none_checked = 0, 0
    for k, x in list(Brec.items()):
        nk = k[:3] + (NONE,)
        if nk not in Brec:
            y = dict(x)
            y.update({"cond": NONE, "status": "none", "calls": 0, "first": None, "effect": None, "hard_func": x["base_func"],
                      "_state": {}, "_lines": (None, None)})
            Brec[nk] = y
            arow = A0.get((k[0], k[1], k[2], "PyRs"))
            if security and arow and arow.get("pairs") is not None and x["pairs"] is not None:
                none_checked += 1
                a_bad = int(any(p in ("left", "new") for p in arow["pairs"]) if k[2] == "vulnerable" else 0)
                b_bad = int(any(p in ("removed", "left") for p in x["pairs"])) if k[2] == "vulnerable" else 0
                none_mismatch += a_bad != b_bad
    conds = [c for c in ("B0", "RCI", "B1", "SPEC2", "BUD", "ORA", NONE) if any(k[3] == c for k in Brec)]
    conds += sorted({k[3] for k in Brec} - set(conds))
    holm_in = []
    if Brec:
        s2 = stage2(Brec, conds, security, a.seed, a)
        s2["none_vs_A_T1_check"] = {"checked": none_checked, "mismatch": none_mismatch}
        eff_rows = [x for k, x in Brec.items() if x["cwe"] in EFFECT_CWES and k[3] != NONE]
        fb = sum(1 for x in eff_rows if not eff_valid(x["effect"], len(x["pairs"] or [])))
        s2["effect_fallback"] = {"effect_class_rows": len(eff_rows), "rows_without_effect_judged_by_dataset": fb,
                                 "text": (f"효과 판정 종류 {len(eff_rows)}줄 중 {fb}줄은 효과 칸이 없어 데이터셋 판정으로 대신했다."
                                          if fb else "효과 판정 종류의 줄은 모두 효과 판정으로 셌다.")}
        s2["cost_calls_jsonl"] = calls_cost(bundles, items)
        # driver 의 eval_summary 'B <cond> visible' 와 대조(항목 제한이 없을 때만)
        chk = {}
        if items is None:
            for b in bundles:
                es = Path(b["root"]) / "eval_summary.json" if b["kind"] == "run_main" else None
                if es is None or not es.exists():
                    continue
                E = jl(es)
                for c_ in conds:
                    v = E.get(f"B {c_} visible")
                    mine = s2["non_security"].get(f"{b['model']}|{c_}")
                    if v and mine:
                        got = {"measured": mine["unselected_measured"], "final_any_failed": mine["unselected_failing_final"],
                               "base_any_failed": mine["unselected_failing_start"],
                               "first_measured": mine["unselected_first_measured"], "first_any_failed": mine["unselected_failing_first"]}
                        chk[f"{b['model']}|{c_}"] = {"match": all(got[k] == v.get(k) for k in got), "script": got, "driver": v}
        s2["visible_vs_driver_summary"] = chk
        if security:
            comps = {}
            for nm, ca, cb in (("2-ga-1", "B1", NONE), ("2-ga-2", "B1", "BUD"), ("2-na", "B1", "B0"),
                               ("2-da", "SPEC2", "B1"), ("sec_B1_vs_RCI", "B1", "RCI")):
                if any(k[3] == ca for k in Brec) and any(k[3] == cb for k in Brec):
                    c = paired_compare(s2_units(Brec, ca, cb, items), nm, a.seed, a.perm, a.boot, a.delta)
                    c["conds"] = [ca, cb]
                    c["dataset_only"] = {kk: v for kk, v in paired_compare(
                        s2_units(Brec, ca, cb, items, judg="dataset"), nm + "|ds", a.seed, a.perm, a.boot, a.delta).items()
                        if kk in ("n", "a_bad", "b_bad", "diff", "a_only", "b_only", "family")}
                    for grp in ("effect", "logic"):
                        g = paired_compare(s2_units(Brec, ca, cb, items, grp=grp), nm + "|" + grp, a.seed, a.perm, a.boot, a.delta)
                        c["group_" + grp] = {kk: g.get(kk) for kk in ("n", "a_bad", "b_bad", "diff", "a_only", "b_only")} | \
                                            {"p_family": (g.get("family") or {}).get("perm", {}).get("p")}
                    comps[nm] = c
                    if nm in ("2-ga-1", "2-ga-2", "2-na") and c["n"]:
                        holm_in.append((nm, c["family"]["perm"]["p"]))
            s2["confirmatory"] = comps
            # 모든 조건 쌍(탐색): 각 조건 대 없음
            s2["exploratory_vs_none"] = {}
            for c_ in conds:
                if c_ != NONE:
                    u = s2_units(Brec, c_, NONE, items)
                    s2["exploratory_vs_none"][c_] = {"n": len(u), "cond_bad": sum(x[2] for x in u), "none_bad": sum(x[3] for x in u)}
            bi = set(read_list(a.best_items)) if a.best_items else items
            bc, brows = best_condition(Brec, bi, a.oracle)
            s2["best_rule"] = {"items_file": a.best_items or a.items, "table": brows, "chosen": bc}
        res["stage2"] = s2
        if security:
            res["strata"] = strata_tables(A0, Brec)

    # ③칸 사례(결정 11-4): 목록 내보내기, 분류 파일이 있으면 세 수와 민감도
    if security and (A0 or Brec):
        c3, still = col3_block(A0, Brec, items, (res.get("stage2") or {}).get("confirmatory"), a)
        res["col3"] = c3
        if still is not None and isinstance(res.get("stage1"), dict) and "hypotheses" in res["stage1"]:
            h = paired_compare(h1_units(A0, still), "H1col3|t1", a.seed, a.perm, a.boot, a.delta)
            h["label"] = "민감도(결정 11-4): '공격 표현만 실패'·'구분 불가' ③칸을 남음으로 본 H1. Holm 에 넣지 않는다."
            res["stage1"]["hypotheses"]["H1_col3_sensitivity"] = h
    elif Brec or A0:
        res["col3"] = "REFUSED (blinded rows)"

    # RQ3·RQ4·RQ5 남김(기술 표, 확증 아님)
    if A0 or Brec:
        res["rq"] = rq_tables(A0, Brec, security, a.seed, a.perm)

    # 1단계 확증 p
    if security and "stage1" in res and "hypotheses" in res["stage1"]:
        for h in ("H1", "H4"):
            v = res["stage1"]["hypotheses"][h]
            if v.get("n"):
                holm_in.append((h, v["family"]["perm"]["p"]))

    # 3단계
    best = None
    if Brec and security:
        best = res["stage2"]["best_rule"]["chosen"] if a.best == "auto" else a.best
        twice = a.twice or ("SPEC2" if best == "B1" else None)
        s3i = set(read_list(a.s3_items)) if a.s3_items else (items if items is not None else {k[1] for k in Brec})
        s3, recs = stage3(Brec, best, twice, a.oracle if any(k[3] == a.oracle for k in Brec) else None, s3i, a)
        s3["items_file"] = a.s3_items or a.items
        s3["bootstrap"] = stage3_boot(Brec, best, recs, s3i, a.seed, a.boot)
        if a.rater_a and a.rater_b:
            s3["layer4"] = layer4(recs, s3, a.rater_a, a.rater_b, a.adjudication)
        res["stage3"] = s3
        if a.targets_tsv:
            write_targets(recs, best, a.targets_tsv)
            res["stage3"]["targets_tsv"] = a.targets_tsv
    elif Brec and not security:
        res["stage3"] = "REFUSED (blinded rows)"

    # 4단계
    if a.s4_new and a.s4_base and Brec:
        n_res = res["stage3"]["n_residual"] if isinstance(res.get("stage3"), dict) else None
        allowed, rule_label = rule_11_7(n_res, a.override_11_7)
        if security and not allowed:
            res["stage4"] = f"REFUSED: {rule_label} (D 의 기존 최선 뒤 남은 번역 {n_res}개 < 40; 넘기려면 --override-11-7)"
        elif security:
            s4i = set(read_list(a.s4_items)) if a.s4_items else items
            used, cov = s4_model_set(Brec, [a.s4_new, a.s4_base, a.s4_repeat], s4i)
            Brec4 = {k: v for k, v in Brec.items() if k[0] in used}
            s4 = stage4(Brec4, a.s4_new, a.s4_base, a.oracle if any(k[3] == a.oracle for k in Brec4) else None,
                        a.s4_repeat, s4i, a.seed, a)
            s4["items_file"] = a.s4_items or a.items
            s4["model_set"] = {"used": used, "excluded": sorted({k[0] for k in Brec} - set(used)), "coverage": cov,
                               "pooled_meaning": pooled_phrase(len(used)),
                               "rule": "결정 11-6: 4단계 조건(새 기법·기존 최선·기존 최선 반복)이 항목 목록의 모든 대상에 있는 "
                                       "모델만 합친다. 기존 최선은 2단계에서 정한 것을 그대로 쓴다."}
            if "stage2" in res and isinstance(res["stage2"].get("confirmatory"), dict):
                B2m = {k: v for k, v in Brec.items() if k[0] in used}
                sens = {}
                for nm, c in res["stage2"]["confirmatory"].items():
                    ca, cb = c["conds"]
                    g = paired_compare(s2_units(B2m, ca, cb, items), nm + "|s4models", a.seed, a.perm, a.boot, a.delta)
                    sens[nm] = {kk: g.get(kk) for kk in ("n", "n_families", "a_bad", "b_bad", "diff", "a_only", "b_only")} | {
                        "conds": [ca, cb], "p_family": (g.get("family") or {}).get("perm", {}).get("p"),
                        "prop_ci90": ((g.get("family") or {}).get("boot") or {}).get("prop_ci90")}
                res["stage2"]["same_model_set_as_stage4"] = {
                    "models": used, "pooled_meaning": pooled_phrase(len(used)), "comparisons": sens,
                    "label": "민감도(결정 11-6): 4단계와 같은 모델 집합으로 본 2단계 결과. Holm 에 넣지 않는다."}
            s4["rule_11_7"] = {"n_residual_D": n_res, "status": rule_label}
            if s4["ga"].get("n"):
                holm_in.append(("4-ga", s4["ga"]["family"]["perm"]["p"]))
            if s4["nb"].get("n"):
                holm_in.append(("4-na", s4["nb"]["family"]["perm"]["p"]))
            res["stage4"] = s4
        else:
            res["stage4"] = "REFUSED (blinded rows)"

    fam7 = ["H1", "H4", "2-ga-1", "2-ga-2", "2-na", "4-ga", "4-na"]
    if security:
        H = holm(holm_in)
        s4_run = isinstance(res.get("stage4"), dict)
        res["holm"] = {"family_registered": fam7 if s4_run else fam7[:5], "m_used": len(holm_in),
                       "included": [n for n, _ in holm_in],
                       "missing": [n for n in (fam7 if s4_run else fam7[:5]) if n not in dict(holm_in)],
                       "note": ("4단계를 하지 않아 5개에 건다" if not s4_run else "7개에 건다") +
                               "; 빠진 검정이 있으면 계산된 것에만 걸었다", "results": H}
        if "stage2" in res and "confirmatory" in res["stage2"]:
            res["stage2"]["sentences"] = stage2_sentences(res["stage2"]["confirmatory"], H, a.delta)
            c2 = res["stage2"]["confirmatory"].get("2-da")
            if c2 and c2.get("n"):
                res["stage2"]["decision_2-da"] = c2["family"]["equivalence_decision"]
        if "stage1" in res and "hypotheses" in res["stage1"]:
            h2 = res["stage1"]["hypotheses"]["H2"]
            if h2.get("n"):
                res["stage1"]["H2_sentence"] = ("Py→Rs 와 Py→Py 의 차이는 사전 지정한 ±5%p 범위 안이었다." if h2["family"]["equivalent_5pt"]
                                                else "Py→Rs 와 Py→Py 의 차이가 사전 지정한 ±5%p 범위 안에 든다고 보이지 못했다.")
                res["stage1"]["H2_decision"] = h2["family"]["equivalence_decision"]
        if s4_run:
            s4 = res["stage4"]
            ga, nb, ni = s4["ga"], s4["nb"], s4["new_risk"]
            inp = {"ga_reject_holm": H.get("4-ga", {}).get("reject", False), "ga_diff": ga.get("diff", 0),
                   "nb_reject_holm": H.get("4-na", {}).get("reject", False), "nb_diff": nb.get("diff", 0),
                   "d_residual_ci": s4["residual"]["d_residual_ci"], "d_new_ci": ni.get("d_new_ci"),
                   "ci_method": CI_METHOD, "decision_level": DECISION_LEVEL,
                   "residual_exception": s4["residual"]["decision"].get("exception"),
                   "new_risk_exception": (ni.get("decision_5pt") or {}).get("exception")}
            code, text, info = choose_s4_conclusion(inp["ga_reject_holm"], inp["ga_diff"], inp["nb_reject_holm"],
                                                    inp["nb_diff"], inp["d_residual_ci"], inp["d_new_ci"], a.delta,
                                                    res_dec=s4["residual"]["decision"], new_dec=ni.get("decision_5pt"))
            s4["conclusion"] = {"row": code, "sentence": text, "inputs": inp, "info": info,
                                "new_risk_5pt": ni.get("class_5pt"), "new_risk_2pt_secondary": ni.get("class_2pt_secondary"),
                                "d_new_ci_upper": ni.get("d_new_ci_upper"), "d_new_ci90_upper": ni.get("d_new_ci90_upper"),
                                "ci_method": CI_METHOD, "decision_level": DECISION_LEVEL,
                                "pooled_meaning": s4["model_set"]["pooled_meaning"]}
    Path(a.out_json).write_text(json.dumps(res, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    Path(a.out_md).write_text(render_md(res), encoding="utf-8")
    return res


# ---------------------------------------------------------------- 보고서
def _fmt_p(x):
    return "—" if x is None else f"{x:.4f}"


def _dec_tag(dec):
    """결정 13-2 예외 표시(보고서용)."""
    ex = (dec or {}).get("exception")
    if not ex:
        return ""
    if ex == "all_zero":       # 결정 15-1
        sub = ("모든 번역 쌍 일치" if dec.get("all_zero_case") == "all_concordant"
               else f"묶음 안에서 상쇄: A 쪽만 나쁨 {dec.get('n_pairs_a_worse')}쌍, B 쪽만 나쁨 {dec.get('n_pairs_a_better')}쌍")
        return (f"판정 보류; 관측 차이 0, 번역 {dec.get('n_units')}개, 묶음 {dec.get('n_clusters')}개, "
                f"엇갈린 번역 쌍 {dec.get('n_discordant_units')}개({sub}); all_zero/{dec.get('all_zero_case')}")
    head = {"degenerate_nonzero": "판정 보류(자료 부족)",
            "few_discordant_methods_disagree": "방법에 따라 갈림"}.get(ex, ex)
    return f"{head}; {ex}, 엇갈린 묶음 {dec.get('n_discordant_clusters')}"


def _cmp_line(nm, c):
    if isinstance(c, dict) and c.get("not_available"):
        return f"| {nm} | not available: {c['not_available']} | | | | | | | | |"
    if not isinstance(c, dict) or not c.get("n"):
        return f"| {nm} | 0 | — | — | — | — | — | — | — |"
    f, n = c["family"], c["naive"]
    ci = f["boot"]["count_ci95"]
    dec = f.get("equivalence_decision") or {}
    pci = dec.get("ci") or f["boot"]["prop_ci90"]
    ex = dec.get("exception")
    exs = (f" ({_dec_tag(dec)})" if ex else "") + (" bca_guard" if dec.get("bca_guard") else "")
    return (f"| {nm} | {c['n']} | {c['a_bad']} | {c['b_bad']} | {c['a_only']}/{c['b_only']} | {c['diff']} "
            f"[{ci[0]:.0f}, {ci[1]:.0f}] | {_fmt_p(f['perm']['p'])} | {_fmt_p(n['perm']['p'])} / {_fmt_p(n['mcnemar_exact_p'])} | "
            f"[{pci[0]*100:.1f}, {pci[1]*100:.1f}]%p eq={f['equivalent_5pt']}{exs} | "
            + (" 방향 갈림: " + ",".join(c["direction_disagrees"]) if c.get("direction_disagrees") else "") + " |")


def _ind_txt(v):
    if not isinstance(v, dict):
        return str(v)
    return (f"{v['with_indicators']} | {v['any_panic_sites']} ({v['total_panic_sites']}) | {v['any_int_sites']} ({v['total_int_sites']}) | "
            f"{v['any_unsafe_blocks']} ({v['total_unsafe_blocks']}) | {v['any_code_loading']} | {v['any_deps']} ({v['total_deps']}) | "
            f"{v['any_code_exec_dep']}")


def render_rq(rq):
    if not rq:
        return []
    L = ["", "## RQ1 세부: Rust 번역본에서 관찰하는 패닉·산술·unsafe·의존성 위험 지표(기술, 개수)", "", rq["rq3"]["note"], "",
         "unresolved_crate 의 종류: name = 그 이름의 크레이트를 찾지 못함(없는 라이브러리 이름은 이것만), version = 이름은 있으나 "
         "요청한 판이 없음, fetch = 그 밖.", "",
         "| 모델|판 | Py→Rs 번역 | 빌드 | 빌드 안 됨 (라벨) | unresolved_crate | 기능 시험 비정상 번역/시험 |", "|---|---|---|---|---|---|---|"]
    T = rq["rq3"]["translations_PyRs"]
    for k, v in sorted(T.items()):
        L.append(f"| {k} | {v['translations']} | {v['built']} | {v['never_built']} {v['build_failure'] or ''} | "
                 f"{v['unresolved_crate']} {v['unresolved_crate_names'] or ''} {v.get('unresolved_by_kind') or ''} | "
                 f"{v['func_translations_abnormal']}/{v['func_tests_abnormal'] or 0} |")
    hdr = "| 지표 있는 번역 | panic ≥1 (합) | int/cast ≥1 (합) | unsafe ≥1 (합) | 코드 적재 ≥1 | 의존성 ≥1 (합) | 코드 실행 크레이트 ≥1 |"
    L += ["", "빌드된 Py→Rs T1 지표:", "", "| 모델|판 " + hdr, "|---" * 8 + "|"]
    for k, v in sorted(T.items()):
        L.append(f"| {k} | {_ind_txt(v['indicators_T1'])} |")
    L += ["", "보안 시험 비정상 종료(빌드된 Py→Rs T1): " + "; ".join(
        f"{k}: {v['security']}" if not isinstance(v["security"], dict) else
        f"{k}: 판정 {v['security']['judged']}, 비정상 번역 {v['security']['translations_abnormal']} {v['security']['abnormal_tests']}, "
        f"⑤ 시험 {v['security']['col5_dos_only_tests']} (⑤ 있는 번역 {v['security']['translations_with_col5']}, 다섯 칸 줄 "
        f"{v['security']['rows_with_columns']})" for k, v in sorted(T.items()) if not k.endswith("|all"))]
    S = rq["rq3"]["stage2_targets_sigma0"]
    if S:
        L += ["", "2단계 대상 출발 번역 σ0 (기능 통과 부분집합):", "", "| 모델|판 | 대상 " + hdr, "|---" * 9 + "|"]
        for k, v in sorted(S.items()):
            L.append(f"| {k} | {v['targets']} | {_ind_txt(v) if v.get('with_sigma0') else 'not available'} |")
        L += ["", "조건 뒤 최종 프로그램: " + "; ".join(
            f"{k}: 대상 {v['targets']}, 받아들임 {v['accepted']} (지표 not available), 출발로 되돌림 {v['returned_to_start']}"
            + (f" (σ0: panic≥1 {v['returned_to_start_indicators']['any_panic_sites']}, int≥1 "
               f"{v['returned_to_start_indicators']['any_int_sites']}, unsafe≥1 {v['returned_to_start_indicators']['any_unsafe_blocks']})"
               if v["returned_to_start_indicators"] else "")
            for k, v in sorted(rq["rq3"]["after_stage2"].items()) if k.endswith("|all"))]
    r4 = rq["rq4"]
    L += ["", "## RQ1 세부: 고친 횟수와 보안 결과(기술, 개수)", "", f"- {r4['never_built_rounds_note']}; T0 대 T1: {r4['t0_vs_t1']}", "",
          "| 모델|언어|판 | 번역 | 빌드 | 빌드 안 됨 | 빌드 고치기 회차(빌드됨) | ≥1 | 보이는 시험 돈 번역 | 보이는 시험 고치기 회차 | ≥1 | T1≠T0 |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for k, v in sorted(r4["rounds"].items()):
        L.append(f"| {k} | {v['translations']} | {v['built']} | {v['never_built']} | {v['build_fix_rounds_built']} | "
                 f"{v['build_fix_ge1_built']} | {v['visible_tests_run']} | {v['visible_fix_rounds']} | {v['visible_fix_ge1']} | {v['t1_differs']} |")
    cr = r4.get("cross_rounds_x_vulnerable")
    if isinstance(cr, dict):
        L += ["", f"{r4['cross_note']}", "", "| 모델|언어|판|회차 | 0 (취약/번역) | 1 | 2+ |", "|---|---|---|---|"]
        for k, v in sorted(cr.items()):
            L.append("| " + k + " | " + " | ".join(f"{v[b]['vulnerable']}/{v[b]['translations']}" if b in v else "0/0"
                                                    for b in ("0", "1", "2+")) + " |")
        L += ["", "≥1 회차 대 0 회차(탐색, 묶음 안 치환): " + "; ".join(
            f"{k}: {p.get('vuln_ge1', '-')}/{p['n_ge1']} vs {p.get('vuln_0', '-')}/{p['n_0']}, p {_fmt_p(p['p'])}"
            for k, p in sorted(r4["perm_ge1_vs_0"].items()))]
    else:
        L += ["", f"교차표: {cr}"]
    k5 = rq["rq5_kept"]
    L += ["", "## RQ2 세부: 출발 번역에서 뚫리지 않은 보안 사례가 완화 뒤 다시 뚫리는가", ""]
    if isinstance(k5, dict):
        L += [k5["note"], "", "| 모델|조건 | 취약판 대상 | 출발 안전 사례 | 다시 생김 | 대상(출발 안전 있음/다시 생김) | 번역에서 사라진 사례: 다시 생김/남김(안전 유지)/전체 | 둘 다 안전: 다시 생김/전체 | 고친 뒤에도 취약 |",
              "|---|---|---|---|---|---|---|---|"]
        for k, v in sorted(k5["table"].items()):
            L.append(f"| {k} | {v['vulnerable_targets']} | {v['start_safe_tests']} | {v['reintroduced_tests']} | "
                     f"{v['targets_with_start_safe']}/{v['targets_with_reintroduced']} | {v['gone_reintroduced_tests']}/"
                     f"{v['gone_kept_tests']}/{v['gone_in_translation_tests']} | {v['safe_in_both_reintroduced_tests']}/"
                     f"{v['safe_in_both_tests']} | {v['still_vulnerable']} |")
    else:
        L.append(f"- {k5}")
    return L


def render_md(res):
    DL = res.get("decision_interval_label", "90% 구간")
    HDR = ("| 비교 | 짝 | A 나쁨 | B 나쁨 | A만/B만 | 차이 [95% 묶음] | p 묶음 치환 | p 독립 치환 / McNemar | "
           f"{DL} 비율 차(판정) | 비고 |")
    L = [f"# 분석 결과 ({res['sample_label']})", "",
         f"- 스크립트 {res['script_sha16']}, seed {res['seed']}, 치환 {res['perm']}, 재표본 {res['boot']}, δ {res['delta']}, "
         f"구간 계산법 {res.get('ci_method', 'percentile')}, 판정 수준 {res.get('decision_level', 0.90)} ({DL}; 결정 13-2 예외 "
         f"규칙 {res.get('exception_rules_13_2', 'off')})",
         f"- 'pooled'(모델 합) = {res.get('pooled_meaning')} (LLM 번역 일반이 아니다; 모델별 방향이 갈리면 함께 적는다)",
         f"- 항목 목록 {res['items_file']} ({res['n_items_in_list']}개, {res['items_sha16']})",
         f"- 입력: " + "; ".join(f"{i['model']}({i['kind']})" for i in res["inputs"]),
         f"- 가림: {res['blinding']['security_results']} {res['blinding']['blinded_rows_in_set']}", ""]
    s1 = res.get("stage1")
    if s1:
        L += ["## 1단계 개수", "", "| 모델|조건|판|출처|T | 번역 | 빌드 | 기능 통과 |", "|---|---|---|---|"]
        for k, v in sorted(s1["counts"].items()):
            L.append(f"| {k} | {v['translations']} | {v['built']} | {v['functional']} |")
        if isinstance(s1.get("security"), dict):
            L += ["", "### 보안 결과(기능 통과 번역, 번역 단위 / 보안 시험 단위)", "",
                  "| 모델|조건|판|묶음 | 번역 | 번역 단위 | 시험 단위 | 효과 판정/발생 | 다섯 칸 |", "|---|---|---|---|---|---|"]
            for k, v in sorted(s1["security"].items()):
                if "|cwe=" in k and not k.startswith("pooled"):
                    continue
                L.append(f"| {k} | {v['translations']} | {v['by_translation']} | {v['by_test']} | "
                         f"{v['effect_judged']}/{v['effect_fired']} | {v['columns'] or ''} |")
            L += ["", "### 1단계 가설", "", HDR,
                  "|---|---|---|---|---|---|---|---|---|---|"]
            for h in ("H1", "H1_dataset_only", "H1_no_regen", "H1_first_pypy", "H1_col3_sensitivity", "H4", "H4_dataset_only",
                      "H4_no_regen", "H4_first_pypy", "H4_abnormal_only", "H4_any_new_dataset_test", "H2"):
                if h == "H1_col3_sensitivity" and h not in s1["hypotheses"]:
                    continue
                L.append(_cmp_line(h, s1["hypotheses"].get(h)))
            L.append(f"\n- 효과 판정이 없어 데이터셋 판정으로 대신한 짝: H1 {s1['hypotheses']['H1'].get('dataset_fallback_pairs')}, "
                     f"H4 {s1['hypotheses']['H4'].get('dataset_fallback_pairs')}")
            L.append(f"- Py→Py 다시 생성된 번역 {s1['pypy_regenerated']}, 복사 표시 {s1['pypy_copied']}")
            L.append(f"- 최초 Py→Py 결과 칸 '{FIRST_PYPY_KEY}': {s1.get('pypy_first_status')}")
            for h, v in (s1.get("three_versions") or {}).items():
                L.append(f"- {h} 세 가지 판(결정 11-3): " + "; ".join(f"{k} {x}" for k, x in v.items()))
            if s1.get("H2_sentence"):
                L.append(f"- H2(사전 지정 보조): {s1['H2_sentence']}" + (
                    f" [{_dec_tag(s1.get('H2_decision'))}]" if (s1.get("H2_decision") or {}).get("exception") else ""))
            L += ["", "### 보조표: 전체 항목 분모(언어별)", "", "| 모델|조건|판 | 번역 | 기능 통과 | 기능 통과이면서 취약하지 않음 |", "|---|---|---|---|"]
            for k, v in sorted(s1["all_items_denominator"].items()):
                L.append(f"| {k} | {v['translations']} | {v['functional']} | {v['functional_and_not_vulnerable']} |")
            L.append(f"\nH1 은 '없어짐'을 나쁨 자리에 둔다(A=Py→Rs, B=Py→Py; 양수 = Rust 에서 더 없어짐). ⑤칸: {s1['hypotheses']['H4_column5']}")
            L += ["", "### T0 민감도(가설)", ""] + [f"- {k}: {v}" for k, v in s1["t0_sensitivity_hypotheses"].items()]
            L += ["", "### 추가 표본 일치(본 번역과 같은 결과인 추가 표본 수)", "", f"- {s1['extra_samples']['agreement']} (묶음 {s1['extra_samples']['n_groups']})"]
    s2 = res.get("stage2")
    if s2:
        L += ["", "## 2단계 (SecCodePLT)", "", "| 모델|조건 | 대상(취약/수정) | 받아들임 | 출발로 되돌림 | 되돌린 이유(마지막) | 첫 결과물 기능 깨짐 | 호출(줄) | 코드 줄 출발→최종 |",
              "|---|---|---|---|---|---|---|---|"]
        for k, v in sorted(s2["non_security"].items()):
            L.append(f"| {k} | {v['targets']} ({v['targets_vulnerable']}/{v['targets_patched']}) | {v['accepted']} | {v['returned_to_start']} | "
                     f"{v['last_reason_when_returned']} | {v['first_breaks_functional']}/{v['first_candidates']} | {v['row_calls']} | "
                     f"{v['lines_start']}→{v['lines_final']} ({v['lines_pairs']}쌍, 길어짐 {v['longer']}) |")
        if "security" in s2:
            L += ["", "| 모델|조건|묶음 | 취약판 대상 | 출발 취약 | 고친 뒤에도 취약(주/데이터셋) | 고친 시험(기능 지킴)/출발 뚫린 시험 | 수정판 대상 | 새로 생김 | 첫 결과물: 취약/빌드, 새로 생김/빌드 |",
                  "|---|---|---|---|---|---|---|---|---|"]
            for k, v in sorted(s2["security"].items()):
                L.append(f"| {k} | {v['vulnerable_targets']} | {v['base_vulnerable']} | {v['still_vulnerable']}/{v['still_vulnerable_dataset']} | "
                         f"{v['removed_tests_func_kept']}/{v['base_exploited_tests']} | {v['patched_targets']} | {v['new_on_patched']} | "
                         f"{v['first_still_vulnerable']}/{v['first_built_vulnerable']}, {v['first_new_on_patched']}/{v['first_built_patched']} |")
            L += ["", "효과 판정군 칸별(최종, 보안 사례 수): " + "; ".join(
                f"{k}: ③{v['effect_class_col3_accepted_no_effect_tests']} ④{v['effect_class_col4_effect_tests']} "
                f"⑤{v['effect_class_col5_dos_only_tests']} (다섯 칸 있는 줄 {v['rows_with_columns']})"
                for k, v in sorted(s2["security"].items()) if k.endswith("|effect") and k.startswith("pooled"))]
            L += ["", "### 2단계 비교(취약판 출발, 나쁨 = 고친 뒤에도 취약; 2-ga-1·2-ga-2·2-na 확증, 2-da 동등성 보조, sec_* 보조)", "",
                  HDR,
                  "|---|---|---|---|---|---|---|---|---|---|"]
            for nm, c in s2.get("confirmatory", {}).items():
                L.append(_cmp_line(f"{nm} ({'−'.join(c['conds'])})", c))
            L += ["", f"- 기존 최선 규칙({s2['best_rule']['items_file']}): {s2['best_rule']['table']} → **{s2['best_rule']['chosen']}**",
                  f"- '없음' 대 A T1 대조: {s2['none_vs_A_T1_check']}", f"- {s2['effect_fallback']['text']}"]
            for k, v in (s2.get("sentences") or {}).items():
                dd = s2.get("decision_2-da") if k == "2-다" else None
                L.append(f"- 문장 {k}: {v}" + (f" [{_dec_tag(dd)}]" if (dd or {}).get("exception") else ""))
            sm = s2.get("same_model_set_as_stage4")
            if sm:
                L += ["", f"### 민감도: 4단계와 같은 모델 집합 {sm['models']} ({sm['pooled_meaning']})로 본 2단계 확증 비교", "",
                      "| 비교 | 짝 | 묶음 | A 나쁨 | B 나쁨 | A만/B만 | 차이 | p 묶음 치환 | 90% 비율 차 |", "|---|---|---|---|---|---|---|---|---|"]
                for nm, c in sm["comparisons"].items():
                    ci = c.get("prop_ci90")
                    L.append(f"| {nm} ({'−'.join(c['conds'])}) | {c['n']} | {c.get('n_families')} | {c.get('a_bad')} | {c.get('b_bad')} | "
                             f"{c.get('a_only')}/{c.get('b_only')} | {c.get('diff')} | {_fmt_p(c.get('p_family'))} | "
                             f"{f'[{ci[0]*100:.1f}, {ci[1]*100:.1f}]%p' if ci else '—'} |")
        L += ["", "### 선택에 쓰지 않은 기능 시험(번역 단계 보이는 시험; 분모 = 보이는 시험이 있는 항목의 대상)", "",
              "| 모델|조건 | 분모 | 출발 번역 깨짐 | 최종 깨짐 | 첫 결과물 깨짐/측정 (프로그램 없음) |", "|---|---|---|---|---|"]
        for k, v in sorted(s2["non_security"].items()):
            if k.endswith("|NONE"):
                continue
            if not v["unselected_measured"]:
                L.append(f"| {k} | not available | | | |")
                continue
            L.append(f"| {k} | {v['unselected_measured']} | {v['unselected_failing_start']} | {v['unselected_failing_final']} | "
                     f"{v['unselected_failing_first']}/{v['unselected_first_measured']} ({v['unselected_first_no_program']}) |")
        if s2.get("visible_vs_driver_summary"):
            L.append(f"\n- driver eval_summary 와 대조: 일치 {sum(v['match'] for v in s2['visible_vs_driver_summary'].values())}"
                     f"/{len(s2['visible_vs_driver_summary'])}")
        for k, v in sorted(s2["non_security"].items()):
            if v["bestrep_rounds"]:
                L.append(f"- {k} BESTREP: 회차 {v['bestrep_rounds']}, 멈춤 {v['bestrep_stop']}, 회차 상태 {v['bestrep_round_statuses']}, "
                         f"상한 {v['bestrep_cap']}, 호출 1단계 {v['calls_stage1']} + 회차 {v['calls_stage2']}")
        L += ["", "### 호출·토큰(calls.jsonl)", ""] + [f"- {k}: {v}" for k, v in sorted(s2["cost_calls_jsonl"].items())]
    s3 = res.get("stage3")
    if isinstance(s3, dict):
        L += ["", f"## 3단계 원인(기존 최선 {s3['best']}, 같은 조건 한 번 더 {s3['twice']}, 정책 제공 참고 조건 {s3['policy_reference_condition']})", "",
              f"- 남은 번역 {s3['n_residual']} (효과 판정으로 센 것 {s3['n_residual_effect_judged']}, 모든 종류 데이터셋 판정이면 "
              f"{s3['n_residual_dataset_rule_all_classes']}; 수정판 새로 생김 {s3['n_residual_patched_new']}). {s3['stage4_rule_11_7']}",
              f"- 1층 {s3['process']}, P1 마지막 이유 {s3['P1_last_reason']}, 어느 시도든 기능 거절 {s3['any_functional_regression']}",
              f"- 2층(시험마다) {s3['failure_modes_per_test']}, 저장 출력 없음 {s3['missing_stored_outputs']}",
              f"- 3층 {s3['causes']} — R {s3['causes'].get('R', 0)} (반대 방향: 기존 최선은 고쳤는데 정책 제공 조건은 못 고친 수 "
              f"{s3['R_reverse_direction']}), J 이면서 정책 제공 조건에서도 기능 거절 {s3['J_also_rejected_under_policy_condition']}",
              f"- 겹침 {s3['overlap']}", f"- 20% 규칙 {s3['share_20pct_rule']}",
              f"- 라벨×종류 {s3['cause_x_cwe']}", f"- 라벨×모델 {s3['cause_x_model']}", f"- {s3['note']}"]
        if s3.get("bootstrap"):
            L.append(f"- 묶음 재표본 95% 구간(개수) {s3['bootstrap']['counts_ci95']}")
        l4 = s3.get("layer4")
        if l4:
            L += ["", "### 4층(읽기, 분류자 2명)", "",
                  f"- 대상 {l4['targets']}, 맞춘 것 {l4['joined']}, 라벨 없음 {l4['missing_rater_label']}",
                  f"- S 일치 {l4['S']['agree']}/{l4['S']['n']}, κ {l4['S']['kappa']}; 라벨별 {l4['S']['per_label']}",
                  f"- K 일치 {l4['K']['agree']}/{l4['K']['n']}, κ {l4['K']['kappa']}; 라벨별 {l4['K']['per_label']}",
                  f"- S×K(최종) {l4['S_x_K_final']}",
                  f"- 불일치(판정할 것) {[(d['tkey'], d['S_A'], d['S_B'], d['K_A'], d['K_B']) for d in l4['disagreements']]}",
                  f"- 판정이 엄격한 것(K3·K4) {l4['strict_judging_K3_K4']}, 미해결이면서 한 분류자가 K3/K4 {l4['unresolved_with_K3_or_K4_by_one_rater']}",
                  f"- K3·K4 뺀 3층 {l4['causes_excluding_K3_K4']}", f"- R 이면서 S1 {l4['R_and_S1']}"]
    elif s3:
        L += ["", "## 3단계", "", f"- {s3}"]
    s4 = res.get("stage4")
    if isinstance(s4, dict):
        L += ["", f"## 4단계 ({s4['new']} 대 기존 최선 {s4['base']}, 기존 최선 반복 {s4['repeat']})", "",
              HDR,
              "|---|---|---|---|---|---|---|---|---|---|", _cmp_line("4-가 (새−기존 최선)", s4["ga"]),
              _cmp_line("4-나 (새−기존 최선 반복)", s4["nb"]),
              _cmp_line("신규 위험 d_신규 (새−기존 최선, 수정판 새로 생김)", s4["new_risk"])]
        ni, ms = s4["new_risk"], s4.get("model_set") or {}
        up = ni.get("d_new_ci_upper")
        ups = "—" if up is None else f"{up * 100:+.2f}%p"
        nci = [round(x * 100, 2) for x in ni["d_new_ci"]] if ni.get("d_new_ci") else None
        rci = s4["residual"].get("d_residual_ci")
        d5, d2, rd = ni.get("decision_5pt") or {}, ni.get("decision_2pt_secondary") or {}, s4["residual"].get("decision") or {}
        tag = lambda dd: f" [{_dec_tag(dd)}]" if dd.get("exception") else ""  # noqa: E731
        L += [f"\n- 모델 집합(결정 11-6): 쓴 모델 {ms.get('used')} → {ms.get('pooled_meaning')}; 뺀 모델 {ms.get('excluded')}; "
              f"조건별 대상/줄 {ms.get('coverage')}",
              f"- 신규 위험(여유 5%p, 주): **{NEW_RISK_LABEL.get(ni.get('class_5pt'))}**{tag(d5)} — d_신규 {DL} {nci}%p, "
              f"상한 {ups} (구간 계산법 {res.get('ci_method', 'percentile')}, 엇갈린 묶음 {d5.get('n_discordant_clusters')})",
              f"- 신규 위험(여유 2%p, 보조): {NEW_RISK_LABEL.get(ni.get('class_2pt_secondary'))}{tag(d2)} (같은 구간, 상한 {ups}; "
              f"엇갈린 묶음 {d2.get('n_discordant_clusters')})",
              f"- d_잔여 동등성(±5%p, 비열등과 별도 판정): {s4['residual']['equivalent_5pt']}{tag(rd)} — {DL} "
              f"{[round(x * 100, 2) for x in rci] if rci else None}%p"]
        d = s4.get("difference_from_policy_condition")
        if d:
            L.append(f"- 정책 제공 조건과의 차이: 남은 번역 기존 최선 {d['left_after_best_existing']}, 새 기법 {d['left_after_new']}, "
                     f"정책 제공 조건 {d['left_after_policy_condition']}. {d['text']}")
        L.append(f"- 실제 호출 {s4.get('actual_calls')}")
        L.append(f"- 40개 규칙: {s4.get('rule_11_7')}")
        if s4.get("conclusion"):
            L.append(f"- **결합 판정(결정 11-2, 줄 {s4['conclusion']['row']}/7; {s4['conclusion']['pooled_meaning']}): "
                     f"{s4['conclusion']['sentence']}** 입력 {s4['conclusion']['inputs']}")
    elif s4:
        L += ["", "## 4단계", "", f"- {s4}"]
    if res.get("strata"):
        L += ["", "## 층: 보이는 시험이 있는 항목 / 없는 항목", "", "1단계: " + "; ".join(
            f"{k}: {v['translations']}/{v['functional']}/{v['functional_vulnerable']}" for k, v in sorted(res["strata"]["stage1"].items())
            if k.startswith("pooled")) + " (번역/기능 통과/그중 취약)", "",
              "2단계: " + "; ".join(f"{k}: 취약 {v['still_vulnerable']}/{v['vulnerable_targets']}, 새로 {v['new_on_patched']}/{v['patched_targets']}"
                                   for k, v in sorted(res["strata"]["stage2"].items()) if k.startswith("pooled"))]
    cw = []
    for sec_, d in (("stage1", (res.get("stage1") or {}).get("hypotheses") if isinstance(res.get("stage1"), dict) else None),
                    ("stage2", (res.get("stage2") or {}).get("confirmatory")),
                    ("stage4", {k: res["stage4"][k] for k in ("ga", "nb")} if isinstance(res.get("stage4"), dict) else None)):
        for k, c in (d or {}).items():
            if isinstance(c, dict) and c.get("cwe_cluster_sensitivity") and k in ("H1", "H4", "2-ga-1", "2-ga-2", "2-na", "ga", "nb"):
                cs = c["cwe_cluster_sensitivity"]
                cw.append(f"- {sec_}:{k}: p {cs['perm']['p']:.4f} (CWE 묶음 {cs['perm']['n_clusters']}), "
                          f"차이 95% {cs['boot']['count_ci95'] if cs['boot'] else None}")
    if cw:
        L += ["", "## 민감도(상한): CWE 를 묶음으로 — 판정에 쓰지 않음", ""] + cw
    if "holm" in res:
        h = res["holm"]
        L += ["", "## Holm(확증 가족)", "", f"- 등록 {h['family_registered']}, 포함 {h['included']} (m={h['m_used']}), 빠짐 {h['missing']}; {h['note']}"]
        L += [f"- {k}: p {v['p']:.4f} → Holm {v['p_holm']:.4f}, 기각 {v['reject']}" for k, v in h["results"].items()]
    c3 = res.get("col3")
    if isinstance(c3, dict):
        L += ["", "## 효과 판정군 ③칸(받아들였지만 효과 없음) 사례 — 결정 11-4", "", f"- {c3['note']}",
              f"- 사례 {c3['n_cases']} (번역 {c3['translations_with_col3']}), 단계|조건|판별 {c3['cases_by_stage_condition_source']}, "
              f"목록 {c3.get('tsv', '내보내지 않음(--col3-tsv)')}"]
        lb = c3.get("labels")
        if isinstance(lb, dict):
            L += [f"- 분류 파일 {lb['file']} ({lb['sha16']}): " + ", ".join(f"{k} {v}" for k, v in lb["counts"].items())
                  + f"; 목록에 없는 case_id {lb['labels_for_unknown_case_ids']}",
                  f"- ㉠ 공격 입력이 처리 경로까지 갔는가 {lb['q1_reached']}; ㉡ 위험 기능이 번역본에 있는가 {lb['q2_risky_feature']}",
                  f"- 단계|조건별 {lb['counts_by_stage_condition']}"]
            sv = c3.get("sensitivity") or {}
            L.append(f"- {sv.get('label')} 다시 분류된 번역 {sv.get('translations_reclassified')} "
                     f"(미분류도 남음으로 보면 {sv.get('translations_reclassified_unlabelled_as_still')})")
            if sv.get("H1"):
                L.append(f"- H1 없어짐 주 {sv['H1']['main_disappeared']} → 민감도 {sv['H1']['sensitivity_disappeared']}")
            for nm, v in (sv.get("stage2") or {}).items():
                L.append(f"- {nm} ({'−'.join(v['conds'])}) 고친 뒤에도 취약: 주 {v['main_a_bad']}/{v['main_b_bad']} → 민감도 "
                         f"{v['a_bad']}/{v['b_bad']} (짝 {v['n']}, 차이 {v['diff']}, p 묶음 {_fmt_p(v['p_family'])})")
        else:
            L.append(f"- 분류: {lb}")
    elif c3:
        L += ["", "## 효과 판정군 ③칸 사례", "", f"- {c3}"]
    L += render_rq(res.get("rq"))
    L += ["", "## 해석을 정한 곳", ""] + [f"- {x}" for x in res["ambiguities_resolved"]]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
