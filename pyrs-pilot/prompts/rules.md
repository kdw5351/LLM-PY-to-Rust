# 공통 방어 규칙 𝒢 (제안서 7절 표와 같은 번호·문장)

하네스는 표시된 결함 종류에 해당하는 규칙만 골라 넣는다(`harness/classes.py`의 `RULE_TO_CLASSES`). 각 규칙은 `RULE n:` 줄 하나로 시작하고, 그 줄부터 다음 `RULE` 줄 전까지가 규칙 본문이다.

RULE 1: 외부 입력에서 온 값에 unwrap·expect를 쓰지 않고 Result로 오류를 넘긴다. (Do not call unwrap or expect on values derived from external input; propagate errors with Result.)
RULE 2: 배열을 직접 인덱싱하지 않고 get과 범위 확인을 쓴다. (Do not index slices or arrays directly; use get and explicit bounds checks.)
RULE 3: 길이·위치·크기 계산은 checked 연산으로 하고 실패하면 오류로 처리한다. (Compute lengths, offsets and sizes with checked arithmetic and treat failure as an error.)
RULE 4: 작은 자료형으로 바꿀 때 as 대신 try_from을 쓴다. (Convert to narrower integer types with try_from, not as.)
RULE 5: 입력이 정한 크기만큼 메모리를 잡기 전에 상한을 확인한다. (Check an upper bound before allocating memory whose size comes from the input.)
RULE 6: 데이터만 읽는 파일 처리를 유지하고 코드를 실행하는 방식으로 바꾸지 않는다. (Keep data-only file parsing; never switch to a loader that can execute code.)
RULE 7: 오류는 패닉이 아니라 명세가 정한 오류 종료 코드로 끝낸다. (On error, exit with the error exit code the specification defines instead of panicking.)

## 규칙 ↔ 결함 종류 대응표 (제안서 rev 723)

| 규칙 | 결함 종류(class) |
| --- | --- |
| 1 | panic (248) |
| 2 | panic (248) |
| 3 | intover (190) |
| 4 | intover (190) |
| 5 | dos (400) |
| 6 | 항상 포함 (표시된 종류와 무관; Rust 의 장점을 지키는 안전장치) |
| 7 | panic (248) |

규칙 6 외에 해당하는 규칙이 없고 검사 목록도 쓰지 않는 조건이면 코드를 고치지 않고 그대로 둔다.
