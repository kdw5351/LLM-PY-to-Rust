# LLM-PY-to-Rust

**LLM 기반 Python→Rust 코드 이전의 보안 변화와 완화 기법 평가**

LLM으로 기존 Python 코드를 Rust로 옮길 때 알려진 취약점이 어떻게 되는지 실행 시험으로 잽니다.
- 넘어가는가, 사라지는가, 새로 생기는가를 봅니다.
- 기존 완화 절차가 그것을 얼마나 줄이는지, 그 뒤에도 남는 것은 왜 남는지를 봅니다.
- 남는 원인을 겨냥한 방법이 따로 떼어 둔 표본에서도 효과가 있는지 확인합니다.

> *An empirical study of how LLM-based Python→Rust migration changes known vulnerabilities (kept / removed / introduced), measured by executing dataset security tests and effect tests, with a Python→Python rewrite as control. Existing mitigations are compared under one acceptance gate and call cap, residual failures are classified, and a cause-targeted technique is confirmed on a held-out split. Documents are in Korean.*

- **자료**
  - SecCodePLT 715항목: 취약판과 수정판 Python, 그리고 보안 시험
  - CWEval 20항목
- **모델 4종:** Claude Sonnet 5.5, GPT-4o, Qwen2.5-Coder-32B, Qwen2.5-Coder-14B
- **용어**
  - 받아들이기 기준: 고친 코드를 채택하기 전에 기능 시험 등을 통과해야 한다는 규칙. 모든 조건에 같은 기준을 씁니다.
  - 호출 상한: 번역 하나를 고치는 데 쓸 수 있는 모델 호출 수. 모든 조건이 6번입니다.

## 진행 상태 (2026-11-16)

| 단계 | 하는 일 | 대상 | 코드 | 개발용 실행 | 확증 실행 |
| --- | --- | --- | --- | --- | --- |
| 1. 보안 변화 | 취약판·수정판 Python을 Rust로 번역하고, Python→Python 재작성과 비교 | 735항목 | 있음(본 모델 점검 남음) | 69항목 | 지도교수·예산 승인 대기 |
| 2. 기존 완화 비교 | 같은 받아들이기 기준, 같은 호출 상한에서 비교 | SecCodePLT 715항목 | 있음(본 모델 점검 남음) | 69항목 | 승인 대기 |
| 3. 원인 분류 | 완화 뒤에도 남는 번역을 조건을 바꿔 돌린 결과로 분류 | 원인 분석용 D 중 SecCodePLT 275항목 | 일부 | 11개 | 승인 대기 |
| 4. 원인 겨냥 완화 | 3단계 결과로 만든 방법을 고정해 검증 | 검증용 H 중 SecCodePLT 440항목 | 기법 미정 | – | 승인 대기 |

- **사전 등록:** [preregistration/](preregistration/)에 있습니다. 확증 실행 전에 최종본을 고정하고 태그를 붙입니다.
- **확증 실행 전에 할 일:** 평가·실행 도구를 고칩니다. 대상은 효과 시험 누락 점검, 두 언어에서 같은 결과를 같게 세는 판정, 출력 잘림, 후속 조건 추가 경로, 호출 상한 집계, 응답 기록입니다.

## 저장소 구성

```
preregistration/   사전 등록(가설, 판정 규칙, 통계, 결론 문장)
docs/              실험 설계서, 원인 분류 절차, 데이터 받기, 안전 수칙
dataset_pilot/     실험·판정·분석 코드 (실험에 쓴 폴더 이름 그대로)
pyrs-pilot/        dataset_pilot 이 읽는 공용 하네스, 요청문, Docker 파일
manifests/         해시: 확증용 분할 목록, 코드 스냅숏 (항목 이름은 올리지 않음)
results/dev/       개발용 69항목의 집계표 (탐색용, 확증 결과 아님)
```

확증 결과는 실행 뒤 `results/stage1/` ~ `results/stage4/`에 채웁니다.

## 코드

`dataset_pilot/`과 `pyrs-pilot/`은 실험할 때의 폴더 이름과 상대 위치를 그대로 두었습니다. 코드 안의 경로와 해시 확인(`run_main.py`의 `FROZEN_FILES`)이 이 구조를 전제로 합니다. 데이터셋과 실행 결과 폴더(`dataset_pilot/export/`, `split_*/`, `usable/` 등)는 같은 자리에 로컬로만 두고 올리지 않습니다.

| 파일 | 하는 일 |
| --- | --- |
| `dataset_pilot/run_main.py`, `RUN_MAIN_FORMATS.md` | 본 실행 드라이버(준비 → 번역 → 완화 → 판정, 가림과 해시 확인 포함)와 기록 형식 |
| `dataset_pilot/pipeline/translate.py` | Py→Rs, Py→Py 번역 요청과 빌드 고치기 |
| `dataset_pilot/pipeline/pilot_job.py`, `harden_item_job.py`, `harden_job.py` | 2단계 완화 조건, 받아들이기 준비, 그 공용 함수 |
| `dataset_pilot/pipeline/gate.py` | 받아들이기 기준 |
| `dataset_pilot/pipeline/runner.py`, `judge.py`, `eval_run.py` | 네트워크 없는 컨테이너에서 시험(효과 시험 포함)을 돌리고 판정 |
| `dataset_pilot/pipeline/model_client.py`, `models.json` | 모델 호출과 비용 기록. 유료 모델은 승인 전까지 꺼져 있음 |
| `dataset_pilot/pipeline/analyze_main.py`, `analyze_main_checks.py`, `analyze_main_sims.py` | 확증 분석(묶음 단위 짝 검정, Holm, BCa 구간)과 그 점검·모의실험 |
| `dataset_pilot/pipeline/make_split.py`, `make_split_dh.py` | 개발용·확증용 분할, 원인 분석용(D)·검증용(H) 분할 |
| `dataset_pilot/pipeline/effect_job.py` | 효과 시험을 만들고 원본 Python으로 승인하는 도구. 공격 입력 틀(`effect_templates.py`)이 없어 이 저장소만으로는 돌지 않음 |
| `dataset_pilot/pipeline/exec_trace.py` | 실행 기록(strace) 수집과 분류. 4단계 후보 부품 |
| `dataset_pilot/dev_summary_table.py`, `dev_judgment_recount.py` | 개발용 결과를 저장된 기록에서 다시 세는 스크립트 |
| `pyrs-pilot/harness/`, `pyrs-pilot/prompts/` | 하네스 공용 코드와 요청문. 사전 등록 5절이 고정한 요청문이 여기 있음 |

`dataset_pilot/pipeline/`에는 개발 중에 쓰고 지금은 쓰지 않는 스크립트도 남아 있습니다(`run_f1.py`, `agent_job.py`, `b3_job.py` 등).

## 데이터

- **SecCodePLT:** 이용 조건 동의가 필요한 자료라 이 저장소에 넣지 않습니다.
- **CWEval:** 공식 저장소에서 받습니다.
- **분할 목록:** 항목 이름이라 올리지 않습니다. 대신 [manifests/split_sha256.txt](manifests/split_sha256.txt)에 해시를 남겼고, 사전 등록 2-1절 표의 값과 같습니다.
- 받는 순서와 지금 공개본만으로 다시 만들 수 없는 것은 [docs/DATA_ACCESS.md](docs/DATA_ACCESS.md)에 적었습니다.

## 실행 환경

- 시험은 Docker 이미지 안에서 네트워크 없이 돌립니다.
  - Rust 빌드: `pyrs-pilot/rust`. `pyrs-pilot/docker/Dockerfile.rust`로 만듭니다.
  - 시험 실행: `pyrs-seccodeplt-runner`. 사전 등록 2절에 이미지 digest를 적었습니다. 이 이미지를 만드는 파일은 정리해서 추가할 예정입니다.
- 모델 호출에 쓰는 API 키는 환경 변수로만 받습니다.

## 이 저장소에 없는 것과 이유

| 없는 것 | 이유 |
| --- | --- |
| 데이터셋 내용(과제 글, 시험 입력·기대값), 항목 이름 목록 | SecCodePLT 이용 조건상 다시 배포할 수 없음 |
| 모델이 만든 번역·수정 코드, 실행 기록 | 데이터셋 코드에서 나온 것이라, 이용 조건을 확인한 뒤 공개 범위를 정함 |
| 효과 시험과 그 공격 입력 틀 | 오용될 수 있음. 효과 판정은 무해한 표식만 남기는 입력을 격리 환경에서만 씀 |
| 연구 중 작업 문서(검토 의견 정리, 이전 설계 이력 등) | 사전 등록과 설계서의 변경 절이 참조하지만 공개하지 않음. 필요한 결정은 사전 등록 본문에 반영됨 |
| API 키, 로컬 설정 | 키는 환경 변수로만 받음 |

## 안전 수칙

모델이 만든 코드는 네트워크를 끊은 격리 컨테이너에서만 실행합니다(`--network none`). 자세한 것은 [docs/SECURITY.md](docs/SECURITY.md)에 있습니다.

## 개발용 결과 (탐색용)

[results/dev/](results/dev/)에 있습니다.
- 작은 모델(Claude Haiku 5.5) 하나로 69항목을 돌렸고, 번역은 항목마다 1개, 실행은 조건마다 1번입니다.
- 절차와 비교 조건을 정하는 데만 썼고, 확증 결론에는 쓰지 않습니다.
- 숫자는 데이터셋 보안 시험의 판정이고, 실제 공격 효과를 센 것이 아닙니다.

## 라이선스

정하는 중입니다.
