# run_main.py 출력 형식 (분석 스크립트용)

`<root>` = `run_main.py --root` 폴더. 모든 JSON 은 UTF-8. 개수·판정만 있고 시험 입력·기대값은 없다(답 파일 `replies/` 제외).

## 실행 폴더 전체

| 파일 | 내용 |
| --- | --- |
| `config.json` | 고정 설정: `model`, `provider`, `client`, `temperature`, `max_tokens`, `seed`, `seed_supported`, `stage1`(protocol·요청문 판·조건·`pypy_regen`·`extra_samples`), `a_runs`(번역 실행 목록), `gate_setup`, `stage2`(아래), `stage2_excluded`(CWEval 항목과 이유), `excluded_items`, `n_blind`, `cargo_fetch`(`network`/`offline`), `rust_indicators`·`build_failure_rule`(아래 번역 줄 칸의 규칙 글), `hashes`(코드·요청문 틀·항목 목록 SHA-256 앞 16자), 시험용 `fake_visible_break`·`fake_repair_break`·`fake_bud_fail`·`fake_pypy_rewrite`(`init --fake-pypy-rewrite <key>[,...]`: 그 Py→Py 답은 원본 끝에 의미 없는 대입 줄을 붙여 유사도 0.90 미만, 다시 만들지 않는다)·`fake_build_fail`(`init --fake-build-fail <key>[,...]`: 실행 A 의 그 번역은 답의 Cargo.toml 에 받을 수 없는 크레이트가 들어가고 빌드 고치기 답도 같아 끝까지 빌드되지 않는다) |
| `indicators/`(번역 실행 폴더 안), `_indicators_work/` | 구조 지표 저장(개수·이름만), 잴 때 쓰는 임시 복사본(끝나면 지운다) |

`config.json` 의 `stage2`:

| 칸 | 뜻 |
| --- | --- |
| `conds` | 2단계 조건 목록. `init --rep-call-cap N` 을 주면 끝에 `BESTREP` |
| `settings` | pilot_job.py prep-b 에 주는 key=value (`gate=unified`, `gate_functional=dataset`, `gate_rules=v2`, `call_cap=6`; BESTREP 이 있으면 `best_cond=<cond>`, `rep_call_cap=<N>`). `B/config.json` 에 그대로 들어간다 |
| `bud_sampling` | BUD 다시 번역 호출(`translate`·`retry`)의 `temperature`(0.8)와 `seed`(실행 seed + 10·k, k = 시도 1..6; `seeds` = 실제 값 목록). 컴파일 수정은 실행 온도·seed |
| `bud_final` | BUD 최종 결과 규칙: 받아들이기를 처음 통과한 다시 번역(거기서 멈춤), 상한 안에 없으면 출발 번역 |
| `visible_after` | 선택에 쓰지 않은 기능 평가 설명(`used_for_selection: false`, `blinded: false`) |
| `bestrep` | `{best_cond, rep_call_cap, rule}` 또는 null(BESTREP 없음) |
| `items.txt`, `items_scp.txt`, `items_cw.txt`, `blind_items.txt`, `extra_items.txt` | 항목 목록(전체·SecCodePLT·CWEval·가림·추가 표본) |
| `calls.jsonl` | 모델 호출 한 줄씩(아래) |
| `blind_manifest.json` | 가린 항목 결과물 해시: `entries`{상대 경로: sha256}, `entries_sha256`, `blind_items` |
| `unblinded.json` | `eval --unblind` 성공 시각과 확인한 manifest 해시(있으면 가림이 풀린 것) |
| `eval_summary.json` | 끝 요약(개수). `B <cond> visible` = `{measured, final_any_failed, base_any_failed, first_measured, first_any_failed}`(보이는 시험이 하나라도 깨진 프로그램 수) |
| `_visible_after/` | 보이는 시험 실행 작업 폴더(평가 때마다 새로 만든다) |
| `effect_rows.json` | 효과 판정 원자료 `[{key, effect}]`, key = `<run>\|<번역 키>\|t1/t0/first`(`first` = 다시 만든 Py→Py 의 최초 시도) 또는 `B\|<cond>\|<tkey>\|final/first` |
| `drift.jsonl` | `--allow-drift` 로 돌린 명령과 달라진 해시 |
| `run.log` | 진행 기록(개수만) |

## 번역 실행 폴더 (`A`, `Acw`, `A_s1`..`A_s5`, `Acw_s1`..`Acw_s5`)

`A*` = SecCodePLT, `Acw*` = CWEval. `_s<k>` = 추가 표본 k(temperature 0.8, 2단계로 보내지 않음). 폴더 모양은 `tr_driver.py` 와 같다
(`prompts/<key>__r<n>.txt`, `replies/<key>__r<n>.md`, `state/`, `logs/<key>.json`, `solutions/<key>/` = T1, `t0/<key>/` = T0, `vcand/`).
번역 키 `<key>` = `<item>__<source>__<cond>` (source = vulnerable/patched, cond = PyRs/PyPy). `regen/<key>/g<n>/` = 다시 만든 Py→Py 의 지난 시도.

`eval_rows.json` 한 줄 = 번역 하나:

| 칸 | 뜻 |
| --- | --- |
| `item`, `source`, `cond`, `arun`, `bench`(`scp`/`cweval`), `sample`(0 = 본 번역, 1..5 = 추가 표본) | 열쇠. 표본까지 합친 열쇠 = (`arun` 또는 `sample`, `item`, `source`, `cond`) |
| `built`, `fix_rounds`, `calls`, `completion_tokens`, `copied`, `similarity_to_source` | 빌드·고치기 기록(eval_run.py 그대로) |
| `regen`, `regen_history` | Py→Py 만: 다시 만든 횟수(0..3), 지난 시도마다 `{attempt, similarity, built}`. `copied` = 마지막 시도도 0.90 이상 |
| `protocol`, `stage3`, `visible_tests`, `visible_pass`, `visible_classes`, `visible_rounds`, `visible_repair_triggered`, `t1_from`, `t1_differs`, `t0_built`, `calls_per_stage` | 번역 3단계(tf1) 기록 |
| `functional_ok`, `capability` | 기능 시험(주 결과 T1) |
| `safety`, `pairs`, `abnormal` | 보안 시험 판정 `[[verdict, sub]...]`, 짝 `gone/left/new/safe/invalid`. **가린 항목은 없음** |
| `effect` | 효과 판정 `[[effect/no_effect, sub]...]` (효과 시험 파일이 있는 항목만, 가린 항목은 없음) |
| `columns` | 다섯 칸(`rejected_spec/rejected_other/accepted_no_effect/exploited_effect/dos_only/invalid`), 보안 시험 수 = 효과 시험 수일 때만 |
| `first_before_regen` | 검토의견_반영_결정 11-3: 다시 만들기 전 최초 Py→Py 결과(`eval` 때만 있는 칸; `eval_rows_functional.json` 에는 없다). 다시 만든 번역(`regen` ≥ 1)이면 최초 시도 `regen/<key>/g0/solutions/<key>/`(유사도를 잰 바로 그 프로그램 = 그 시도의 빌드 고치기·보이는 시험 고치기 뒤 T1)을 주 번역과 같은 스크립트·같은 가림 규칙으로 판정한 `{built, functional_ok, capability, safety, pairs, abnormal, effect, columns, similarity, regen_index: 0}`(`similarity` = `regen_history[0].similarity`; 가린 항목은 `--unblind` 전까지 `safety`·`pairs`·`abnormal`·`effect`·`columns` 없음; 최초 시도 파일은 `regen/*` 로 blind manifest 에 들어 있다). 다시 만들지 않은 번역(Py→Rs 전부, `regen = 0` 인 Py→Py)은 `null`: 그때는 주 결과가 곧 최초 결과다(같은 값을 두 번 싣지 않는다). 판정 작업 폴더 `<run>/_first_eval/`(logs·solutions 복사본, 평가 때마다 새로 만든다; T0 는 돌리지 않는다). 효과 판정 원자료 키 `<run>\|<번역 키>\|first` |
| `t0` | T0 판정 `{built, eval: run/same_as_t1, functional_ok, capability, safety, pairs, abnormal, effect, columns}` (같은 가림 규칙) |
| `blinded_kinds` | 있으면 가린 항목: 돌린 시험 종류(`["capability"]`). 이 줄에는 보안 칸이 없다 |
| `sim_to_patched`, `sim_to_vulnerable` | SecCodePLT Py→Py 취약판만(eval_run.py 그대로) |
| `rust_indicators` | 빌드된 Py→Rs 만(T1). 구조 지표(보안 시험 아님, 가림과 무관, `eval` 때 만든다): `panic_sites`(clippy panic 계열: unwrap·expect·직접 인덱싱·panic·unreachable·todo·unimplemented), `int_sites`(intover: 산술·as 변환 경고), `unsafe_blocks`, `deps`(Cargo.toml [dependencies] 이름), `n_deps`, `code_loading`(process::Command·libloading·pyo3 패턴 합), `codeload`(패턴별), `code_exec_deps`(gate.CODE_EXEC_CRATES 에 든 의존성), `by_class`(σ 전체), `source` = `gate_sigma0`(B4/state 의 σ0 를 다시 씀: B4/base/<tkey> 의 Cargo.toml·src/main.rs 가 같을 때) / `clippy`(harden_job.sigma 를 임시 복사본에서 돌림, 빌드 볼륨은 번역 빌드와 같은 이름). 실패하면 `{error, source}`. 값은 `<run>/indicators/<key>.<t1\|t0>.json` 에 두고 다시 쓴다 |
| `t0.rust_indicators` | T0 가 빌드됐을 때: T1 과 다르면(t1_differs) T0 에서 따로 잰 값, 같으면 T1 값에 `same_as_t1: true` |
| `build_failure` | 빌드되지 않은 Py→Rs 만. `logs/<key>.json` 의 `build_log_tail`(마지막 빌드 시도, 끝 1500자)에서 처음 맞는 규칙: `timeout`(줄 하나가 `timed out` = Docker 900초 상한, 받기·빌드 어느 쪽이든) → `unresolved_crate`(cargo 가 의존성 이름·판을 찾거나 받지 못함: `no matching package named`, `failed to select a version for the requirement`, `failed to get \`x\` as a dependency`, `failed to load source for dependency`, `failed to download`, `could not find \`x\` in registry`) → `compile_error`(rustc·cargo 의 `error:`/`error[E....]:` 줄) → `other`(그 밖, `no code block in reply` 포함). 규칙 글은 `config.json` `build_failure_rule`. Py→Py 는 분류하지 않는다 |
| `unresolved_kinds` | `build_failure = unresolved_crate` 일 때 `{크레이트: name / version / fetch}`. name = 그 이름의 크레이트를 찾지 못함(`no matching package named`, `could not find … in registry`) = '없는 라이브러리 이름'은 이것만 센다. version = 이름은 있으나 요청한 판이 없음(`failed to select a version for the requirement`). fetch = 그 밖. 여러 종류에 걸리면 name > version > fetch (2026-11-14 추가) |
| `unresolved_crates` | `build_failure = unresolved_crate` 일 때 오류 글에서 뽑은 크레이트 이름 목록(이름만) |

**`unresolved_crate` 주의:** `cargo_fetch = offline` 이면 받기도 `--network none` 이라 받아 둔 크레이트만 쓸 수 있다. 이때 실제로 있지만 받아 두지 않은 크레이트와 없는 크레이트를 구별할 수 없다(둘 다 `no matching package named`). 이 라벨은 `cargo_fetch = network` 일 때만 '없는 라이브러리 이름'(RQ3)의 뜻을 가진다.

**고치기 회차(RQ4) — 이미 있는 칸:** `fix_rounds` = 빌드 고치기 회차(0..5; 빌드되지 않은 번역은 5 = 모두 씀), `visible_rounds` = 보이는 시험 고치기 회차(0..5, 3단계를 돌린 번역만 0 초과), `calls_per_stage` = `{translate: 1, build_fix: fix_rounds, visible_fix: visible_rounds}`, `stage3` = `not_triggered`/`passed`/`exhausted`/`skipped_no_tests`/`skipped_not_built`. Py→Rs·Py→Py 모두 같은 칸이고 단계(번역 실행 폴더)와 언어(`cond`)로 나뉜다. Py→Py 의 다시 만들기(`regen`)는 회차가 아니라 처음부터 다시 한 횟수다(지난 시도의 회차는 `regen/<key>/g<n>/logs`).

CWEval(`bench = cweval`): `capability` = CWEval functionality 시험(이름 순), `safety` = security 시험(passed → blocked, 그 밖 → exploited),
짝은 export_cweval/originals_runs.jsonl 의 같은 판과 시험 이름으로 맞춘다. 보이는 시험이 없어 `stage3 = skipped_no_tests`.

`eval_rows_functional.json` = 2단계 대상 고르기 때의 기능 시험만 판정(모든 줄에 `blinded_kinds`). `A/targets.json` = 2단계 대상.

## 2단계 (`B/`, `B4/`)

`B/eval_rows.json` 한 줄 = (조건, 대상). 대상 키 `tkey` = `main__<item>__<source>` (출발 = `A/solutions/<item>__<source>__PyRs`).

| 칸 | 뜻 |
| --- | --- |
| `cond` | B0, RCI, B1, SPEC2, BUD, ORA, BESTREP(있으면) ("없음" 조건 = 출발 번역 = A 의 T1 줄) |
| `status` | accepted / harden_failed (SPEC2: 1단계 상태를 따름; BESTREP: 1단계나 어느 회차든 받아들여졌으면 accepted) |
| `calls` | 고치기 호출 수(비판·컴파일 수정 포함, SPEC2·BESTREP = 1단계 + 2단계 전체) |
| `calls_stage1`, `calls_stage2`, `stage1_status`, `stage2_status` | SPEC2·BESTREP (BESTREP 의 `calls_stage2` = 모든 회차 합, `stage2_status` = 마지막 회차) |
| `best_cond`, `call_cap_total`, `n_rounds`, `round_statuses`, `calls_rounds`, `stop`, `rounds` | BESTREP 만. `call_cap_total` = `rep_call_cap`. `stop` = `cap_reached`(전체 호출 = 상한) / `next_round_does_not_fit`(남은 호출 < 회차 최소 1, RCI 2). `rounds` 한 줄 = `{round, status, calls, attempts, compile_fixes, critique_calls, signal_calls, truncated_by_cap, reasons}` (`calls` = 그 회차의 모든 호출; `calls_stage1 + sum(calls_rounds) = calls ≤ call_cap_total`) |
| `visible_after` | 최종 프로그램(아래 `effect` 와 같은 프로그램)에 번역 단계 보이는 시험(`visible_root/<item>.json`, 1단계와 같은 파일)을 돌린 결과 `{n, failed, class}`. `class` = passed / failed / runtime / loop (translate.classify_visible: 첫 실패 시험의 분류) / compile(실행 파일 없음). 보이는 시험이 없는 항목은 null. **받아들이기·조건 진행에 쓰지 않는다**(평가 때만 돈다). 기능 시험이라 가린 항목에도 있다 |
| `visible_base` | 같은 시험을 출발 번역(`B4/base/<tkey>`)에 돌린 결과(같은 모양) |
| `base_functional_ok`, `hard_functional_ok` | 출발 코드·최종 프로그램의 기능 시험 |
| `pairs` | 출발 → 최종 짝 `removed/left/new/safe/invalid`. **가린 항목은 없음** |
| `effect`, `columns` | 최종 프로그램(accepted 이면 `B/<cond>/accepted/<tkey>`, 아니면 `B4/base/<tkey>`)의 효과 판정·다섯 칸 |
| `first` | 받아들이기 전 첫 후보(B0·RCI·B1·ORA·SPEC2 2단계·BESTREP 1회차; BUD 없음): `{built, functional_ok, pairs, effect, columns, visible_after}` 또는 `{built: false, visible_after: null}`. 첫 후보 프로그램 = `B/<cond>/first_candidate/<tkey>/` |
| `blinded_kinds` | 가린 항목 표시(그때 `pairs`·`first.pairs`·`effect` 없음; `visible_after` 는 있음) |

`init` 인자(2단계): `--rep-call-cap N`(BESTREP 을 켠다, 대상 하나의 전체 호출 상한), `--best-cond B0|B1|ORA|RCI`(기본 B1).
시험용(가짜 모델만): `--fake-repair-break <cond>:<tkey>[,...]` = 그 조건·대상의 고치기 답(`repair`/`retry`)이 마지막 보이는 시험 하나에서만 다른 값을 낸다.
`--fake-bud-fail N[,<tkey>=M,...]` = BUD 다시 번역 시도 k ≤ N(그 대상은 M)의 답에 코드가 없다(빌드 실패 → 다음 시도).

조건별 상태 `B/<cond>/state/<tkey>.json`: `log`(시도마다 `{k, built, compile_fixes, reason}` — 거절 이유; BESTREP 은 지금 회차만), `first`, `chain`
(`stage1`, `stage2`(요청 종류), `stage1_status`, `stage1_calls`, `stage2_calls`, `stage2_status`; BESTREP 은 더해서 `cap`, `rounds`, `stop`), BESTREP `round`, `truncated`.

BUD 최종 결과: 받아들이기를 처음 통과한 다시 번역이 최종이고 그 조건은 거기서 멈춘다(pilot_job.py ingest-b 의 accepted 갈래).
시도 상한(`call_cap` = 6, 컴파일 수정 호출도 센다) 안에 통과가 없으면 출발 번역이 최종(status harden_failed, `B4/base/<tkey>`).

BESTREP 태그: 1회차는 다른 조건과 같은 `k<k>[f<f>][c]`, 2회차부터 `r<n>k<k>[f<f>][c]` (요청 `B/BESTREP/prompts/<tkey>__<tag>.txt`).
회차는 직전 회차의 최종 프로그램(`B/BESTREP/accepted/<tkey>`; 처음엔 `B/<best_cond>/accepted/<tkey>` 복사)에서 시작하고, 요청문은
best_cond 자신의 요청문(RCI 면 비판부터). 회차 안의 규칙(K=3, 컴파일 수정 2, call_cap 6)은 best_cond 그대로이고, 다음 호출이 전체 상한을
넘으면 그 회차를 끊는다(`truncated_by_cap`). 받아들이기는 모든 조건과 같다(원래 번역의 σ0·A0·B4 조건 확인, 데이터셋 기능 시험).

## 4단계 새 조건 붙이는 곳

새 기법 `NEW` 는 이어 붙인 조건으로 붙인다(1단계 = 같은 실행의 기존 최선 결과, 2단계 = 새 기법).

1. `pipeline/pilot_job.py` `chain_of(conf, c)` 에 `NEW` 를 더한다: `{stage1: conf["best_cond"], stage2: "NEW", cap: <전체 호출 상한 또는 None>, repeat: False}`,
   그리고 `REPEAT_CHAINS` 처럼 이름을 `is_chain` 이 알게 한다(`FIRST_CANDIDATE_CONDS` 에도 넣으면 첫 후보가 저장된다).
2. 같은 파일 `stage2_request` 의 `builders` 에 `"NEW": lambda: request_new(run, st, cur)` 를 넣는다(요청 만드는 함수 = 조건이 주는 것).
3. 신호 단계(선택): 고치기 전에 모델에게 신호를 받는 호출은 RCI 비판처럼 상태 `phase = "signal"`(태그 끝 `s`, calls.jsonl `step = "signal"`)으로
   두고 호출 수를 `st["signal_calls"]` 에 센다. 이 수는 고치기 상한(`own_calls`, `call_cap`)에는 들지 않고 `total_calls`·`calls`·`calls_stage2`·
   전체 상한(`cap`)에는 든다. calls.jsonl 에는 모든 호출이 한 줄씩 남는다.
4. 전체 호출 상한: run_main.py init 인자로 받아 `stage2.settings` 에 `key=value` 로 넣고(BESTREP 의 `rep_call_cap` 처럼), `chain_of` 가 그
   값을 `cap` 으로 돌려준다. 값은 `config.json` `stage2.settings`/`B/config.json` 과 행의 `call_cap_total` 에 남는다. 4-나 대조는
   `--rep-call-cap` 을 새 기법의 `cap` 과 같게 준다.
5. run_main.py `init` 에서 `stage2.conds` 에 이름을 더하고 `RUN_MAIN_FORMATS.md` 를 고친다. 평가(`eval-b`, `visible_after`, 효과 판정)는 조건 이름에 상관없이 돈다.
받아들이기 준비 `B4/state/<tkey>.json`: `checklist`, `considered`, `ok0`, `d0`, `A0`, `sigma0`.

검사 목록 상태 `B4/checklist_validity.json`(검토의견_반영_결정 15-2): `{항목: {state, condition_like, readable, stated, inferred, reply_chars}}`.
`condition_like` = `CHECK` 로 시작하는 줄(대소문자 무시) 또는 `->` 가 든 줄 수, `readable` = 그 가운데 `CHECK n` 과 stated/inferred 표기를
읽은 줄 수. `state` 는 `none_claimed`(조건처럼 보이는 줄 0) / `parsed`(모두 읽음) / `unreadable`(하나라도 못 읽음). 답 내용은 싣지 않는다.
`gate` 는 검사 목록 답이 다 있으면 조건 확인 요청을 만들기 전에 이 파일을 다시 쓰고 세 상태의 개수를 run.log 에 적는다(`status` 에도 나온다).
**`unreadable` 이 하나라도 있으면 그때마다 멈춘다**(--allow-drift 와 무관, 넘기는 옵션 없음). 고치는 것은 읽는 쪽뿐이다(요청문·답은 그대로).

## calls.jsonl (모델 호출 한 줄)

`ts`, `model`, `condition`(`A:PyRs`, `A_s3:PyPy`, `Acw:PyRs`, `gate`, `B0`..`ORA`, `BESTREP`), `target`(번역 키·tkey·항목), `step`
(`translate` / `build-fix` / `visible-fix` / `checklist` / `probe` / `critique` / `signal` / `repair` / `compile-fix` / `retry`; BUD 의 다시 번역은
첫 번 `translate`, 그 뒤 `retry`), `prompt_tokens`, `completion_tokens`, `tokens_estimated`(true = 글자/4 어림), `wall_s`, `cached`,
`reply`(답 파일 상대 경로), `n_messages`, `temperature`, `seed`, `sample`, `regen`, 2단계 호출만 `b_round`(회차, BESTREP 외 1)와 `attempt`(시도 k).
BUD 의 `translate`·`retry` 줄은 `temperature` 0.8, `seed` = 실행 seed + 10·`attempt`.
같은 (`reply`, `regen`) 가 두 번 있으면 이어 돌릴 때의 캐시 적중이다(`cost` 는 한 번만 센다).
