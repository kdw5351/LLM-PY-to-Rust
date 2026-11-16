# 분석 동결 전 모의실험 (결정 11-5)

스크립트 analyze_main_sims.py 4bdca667cb2489cc, analyze_main.py 828bdbd705571c7f. 모델 호출 없음. 실제 결과를 쓰지 않았다.

## B1 구간 포함률

- 자료 2000벌/칸, 재표본 1000번/자료, seed 20261114. 모델 4개(효과 고정), 묶음·항목 상관 모형 = analyze_main_checks 와 같은 꼴 {'sd_family': 1.0, 'sd_item': 0.7, 'tau_family': 1.0, 'tau_item': 0.5, 'rho_shared_uniform': 0.7, 'model_effects_fixed': [-0.57515, -0.1593, 0.1593, 0.57515], 'n_models': 4}.
- 설정: conf_scp715 항목 715, 묶음 317 (최대 31); holdout_scp440 항목 440, 묶음 194 (최대 31); conf_effect_classes 항목 137, 묶음 62 (최대 3)
- 시나리오(참 비율 A/B): rate20_diff0 0.20/0.20 (다시 잰 값 0.1999/0.2005); rate20_diff3 0.23/0.20 (다시 잰 값 0.2299/0.2005); rate1_diff0 0.01/0.01 (다시 잰 값 0.0100/0.0100); rate1_diff3 0.04/0.01 (다시 잰 값 0.0400/0.0100)

| 설정 | 시나리오 | percentile 90% | bca 90% | boot_t 90% | cluster_t 90% | percentile 95% | bca 95% | boot_t 95% | cluster_t 95% |
|---|---|---|---|---|---|---|---|---|---|
| conf_effect_classes | rate1_diff0 | 88.5 ± 0.7 | 83.5 ± 0.8 | 79.7 ± 0.9 | 87.5 ± 0.7 | 93.8 | 88.0 | 86.1 | 95.0 |
| conf_effect_classes | rate1_diff3 | 87.3 ± 0.7 | 87.8 ± 0.7 | 90.0 ± 0.7 | 87.4 ± 0.7 | 92.5 | 93.0 | 94.3 | 93.0 |
| conf_effect_classes | rate20_diff0 | 89.1 ± 0.7 | 88.3 ± 0.7 | 88.8 ± 0.7 | 89.5 ± 0.7 | 93.5 | 92.9 | 93.2 | 94.3 |
| conf_effect_classes | rate20_diff3 | 87.5 ± 0.7 | 86.4 ± 0.8 | 87.4 ± 0.7 | 88.4 ± 0.7 | 93.2 | 92.2 | 93.2 | 94.0 |
| conf_scp715 | rate1_diff0 | 90.8 ± 0.6 | 89.7 ± 0.7 | 88.1 ± 0.7 | 90.1 ± 0.7 | 94.8 | 93.7 | 92.9 | 94.8 |
| conf_scp715 | rate1_diff3 | 87.5 ± 0.7 | 87.2 ± 0.7 | 88.2 ± 0.7 | 87.5 ± 0.7 | 93.1 | 92.8 | 93.5 | 93.2 |
| conf_scp715 | rate20_diff0 | 87.8 ± 0.7 | 85.5 ± 0.8 | 87.0 ± 0.8 | 88.0 ± 0.7 | 93.5 | 92.1 | 93.0 | 94.2 |
| conf_scp715 | rate20_diff3 | 87.4 ± 0.7 | 86.0 ± 0.8 | 86.8 ± 0.8 | 88.3 ± 0.7 | 93.5 | 91.6 | 93.4 | 94.3 |
| holdout_scp440 | rate1_diff0 | 91.2 ± 0.6 | 88.5 ± 0.7 | 86.8 ± 0.8 | 90.5 ± 0.7 | 95.5 | 93.5 | 93.2 | 95.5 |
| holdout_scp440 | rate1_diff3 | 88.5 ± 0.7 | 88.1 ± 0.7 | 89.2 ± 0.7 | 88.9 ± 0.7 | 93.9 | 93.0 | 94.6 | 93.5 |
| holdout_scp440 | rate20_diff0 | 89.2 ± 0.7 | 87.1 ± 0.7 | 88.3 ± 0.7 | 89.5 ± 0.7 | 94.3 | 92.3 | 93.8 | 94.5 |
| holdout_scp440 | rate20_diff3 | 88.9 ± 0.7 | 86.7 ± 0.8 | 88.5 ± 0.7 | 89.8 ± 0.7 | 94.0 | 91.7 | 93.7 | 94.3 |

90% 구간에서 참값이 상한 위로 빠진 비율(비열등 판정의 위험 쪽, %): conf_effect_classes|rate1_diff0: percentile 5.6, bca 8.6, boot_t 10.5, cluster_t 6.2; conf_effect_classes|rate1_diff3: percentile 9.8, bca 7.6, boot_t 6.1, cluster_t 10.3; conf_effect_classes|rate20_diff0: percentile 5.8, bca 6.3, boot_t 5.9, cluster_t 5.5; conf_effect_classes|rate20_diff3: percentile 7.5, bca 8.0, boot_t 7.4, cluster_t 7.0; conf_scp715|rate1_diff0: percentile 5.0, bca 5.5, boot_t 6.2, cluster_t 5.2; conf_scp715|rate1_diff3: percentile 8.8, bca 7.5, boot_t 7.0, cluster_t 9.2; conf_scp715|rate20_diff0: percentile 6.9, bca 8.1, boot_t 7.2, cluster_t 6.7; conf_scp715|rate20_diff3: percentile 6.8, bca 7.2, boot_t 6.8, cluster_t 6.3; holdout_scp440|rate1_diff0: percentile 4.5, bca 5.9, boot_t 7.0, cluster_t 5.0; holdout_scp440|rate1_diff3: percentile 7.8, bca 6.6, boot_t 6.0, cluster_t 8.2; holdout_scp440|rate20_diff0: percentile 5.9, bca 7.0, boot_t 6.3, cluster_t 5.7; holdout_scp440|rate20_diff3: percentile 6.5, bca 7.5, boot_t 6.6, cluster_t 5.9

### 규칙 적용

| 방법 | 최소 칸 | 평균 | 설정별 평균 | 모든 칸 ≥ 89% | 설정 평균 모두 ≥ 89% |
|---|---|---|---|---|---|
| percentile | 87.3 (conf_effect_classes|rate1_diff3) | 88.6 | conf_effect_classes 88.1, conf_scp715 88.3, holdout_scp440 89.5 | False | False |
| bca | 83.5 (conf_effect_classes|rate1_diff0) | 87.1 | conf_effect_classes 86.5, conf_scp715 87.1, holdout_scp440 87.6 | False | False |
| boot_t | 79.7 (conf_effect_classes|rate1_diff0) | 87.4 | conf_effect_classes 86.5, conf_scp715 87.5, holdout_scp440 88.2 | False | False |
| cluster_t | 87.4 (conf_effect_classes|rate1_diff3) | 88.8 | conf_effect_classes 88.2, conf_scp715 88.5, holdout_scp440 89.7 | False | False |

- 모든 칸 기준으로 규칙을 만족하는 방법 [] → **None**
- 설정별 평균 기준 [] → None
- 모든 칸에서 89%를 넘는 방법이 없다. 최소 칸이 가장 높은 방법: cluster_t
- analyze_main.py 기본값은 바꾸지 않았다(검토 뒤 바꾼다).

## B2 비교별 검정력

- 자료 500벌/격자점, 치환 1000번/자료(본 분석 10,000번보다 적다), seed 20261115. 검정 = 묶음 단위 부호 뒤집기 치환(양측), 모델 4개 합. Holm 칸 = alpha/7 = 0.00714 (Holm's first step = Bonferroni; the actual Holm threshold for a test lies between alpha/7 and alpha depending on how many other tests are rejected first).
- 가정(개발용 실행에서 본 값을 바탕으로 정한 것, 결과가 아님): {'func_pass_PyRs': 0.85, 'func_pass_PyPy': 0.95, 'base_vulnerable_share_of_targets': 0.85, 'still_vulnerable_share_of_base_vulnerable_B1': 0.2, 'H1_disappeared_PyPy': 0.2, 'H1_disappeared_PyPy_alt': 0.45, 'H4_newly_PyPy': 0.01, 'H4_newly_PyPy_alts': [0.005, 0.02]}

| 비교 | 항목 | 묶음 | 예상 짝/번역 | 기준 비율 | 80% 검정력 차이 α=0.05 (%p) | Holm α/7 (%p) |
|---|---|---|---|---|---|---|
| H1 | 135 | 60 | 436 | 0.2 | 8.21 | 11.0 |
| H1 | 135 | 60 | 436 | 0.45 | 9.98 | 13.33 |
| H4 | 735 | 337 | 2374 | 0.01 | 0.91 | 1.23 |
| H4 | 735 | 337 | 2374 | 0.005 | 0.8 | 0.95 |
| H4 | 735 | 337 | 2374 | 0.02 | 1.24 | 1.59 |
| 2-ga-1 | 715 | 317 | 2431 | 0.85 | 0.5 | 0.5 |
| 2-ga-2 | 715 | 317 | 2431 | 0.2 | 3.13 | 3.97 |
| 2-na | 715 | 317 | 2431 | 0.2 | 3.08 | 3.9 |
| 4-ga | 440 | 194 | 1496 | 0.2 | 3.73 | 4.66 |
| 4-na | 440 | 194 | 1496 | 0.2 | 3.74 | 4.62 |

비교마다의 설명: H1: 취약판, 코드 실행류(502·94·95·78), 두 언어 기능 통과 쌍; 나쁨 = 없어짐; A = Py→Rs = 기준 + Δ; H4: 수정판, 735 전체, 두 언어 기능 통과 쌍; 나쁨 = 새로 생김; A = Py→Rs = 기준 + Δ; 2-ga-1: 기능 통과 취약판 출발 Py→Rs; B1 대 없음(출발 그대로); Δ = 출발 취약 − B1 뒤 취약; 2-ga-2: 같음; B1(20%) 대 다시 번역(20% + Δ); 2-na: 같음; B1(20%) 대 일반 보안 지시(20% + Δ); 4-ga: H 440; 새 기법(20% − Δ) 대 기존 최선(20%); 4-na: H 440; 새 기법(20% − Δ) 대 기존 최선 반복(20%)

