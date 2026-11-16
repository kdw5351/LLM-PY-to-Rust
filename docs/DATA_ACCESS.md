# 데이터 받기

이 저장소에는 데이터셋 내용이 없습니다.

## SecCodePLT
1. 공식 배포처(Hugging Face의 SecCodePLT 데이터셋)에서 이용 조건에 동의하고 받습니다.
2. 항목별 파일로 풀어 `dataset_pilot/seccodeplt_items/`에 둡니다. 내보내기 도구(`dataset_pilot/scripts/seccodeplt_*.py`, `dataset_pilot/pipeline/export_items.py`)는 항목별 JSON 폴더를 입력으로 받습니다. 받은 파일을 항목별 JSON으로 푸는 단계는 정리해서 추가할 예정입니다.
3. 내보내면 `dataset_pilot/export/`에 과제 글, 시험, 원본 프로그램이 생깁니다. 이 폴더들은 `.gitignore`로 막혀 있습니다.

## CWEval
공식 저장소에서 받아 `dataset_pilot/cweval/`에 둡니다. 확증용으로 쓰는 것은 Python 과제 20개이고, 1단계에만 씁니다.

## 분할
- 시드
  - 개발용과 확증용 분할: 20261112 (`make_split.py`)
  - 원인 분석용(D)과 검증용(H) 분할: 20261113 (`make_split_dh.py`)
- `make_split.py`는 데이터셋만으로는 만들 수 없는 입력을 읽습니다. 하나는 개발에 이미 쓴 항목 목록이고, 다른 하나는 원본 재현을 통과한 항목 목록입니다. 둘 다 항목 이름이라 공개하지 않습니다.
- 그래서 지금 공개본만으로는 분할을 처음부터 다시 만들 수 없습니다. [manifests/split_sha256.txt](../manifests/split_sha256.txt)의 해시는 같은 목록을 가진 사람이 그 목록이 맞는지 확인하는 용도입니다.

## 올리지 않는 것
다시 배포하지 않는 것은 데이터셋 내용, 항목 이름 목록, 그리고 데이터셋 코드에서 나온 모델 출력입니다. 결과는 집계표와 익명 번호(D01 등)로만 올립니다.
