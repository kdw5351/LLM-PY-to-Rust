# prompts/ — 하네스가 모델에 보내는 모든 지시문

파일마다 `{...}` 자리표시자를 하네스가 채운다. 모델에 보낸 최종 문자열은 결과 디렉터리의 `_prompts/` 아래에 그대로 저장된다(제안서 5절 "모든 프롬프트, 응답, 수정 기록을 원본 그대로 저장").

| 파일 | 쓰는 곳 | 자리표시자 |
| --- | --- | --- |
| `system_generate.md` | Py, Rs, C 조건의 system 메시지 | `{lang}` |
| `system_translate.md` | Py→Py, Py→Rs, T-secure 조건의 system 메시지 | `{lang}` |
| `user_generate.md` | Py, Rs, C 조건의 user 메시지 | `{spec}`, `{conventions}`, `{contract}` |
| `user_translate.md` | Py→Py, Py→Rs의 user 메시지. 두 조건이 대상 언어만 다른 같은 지시문을 쓴다 | `{lang}`, `{source_files}`, `{spec}`, `{conventions}`, `{contract}` |
| `user_translate_secure.md` | T-secure(보안 지시 옮기기). `user_translate.md` + 규칙 전체 + 같은 명세에서 뽑은 검사 목록 𝒞_t | 위와 같음 + `{rules}`, `{checklist}` |
| `fix_build.md` | 컴파일·import 오류 수정 요청 | `{kind}`, `{error}`, `{files}` |
| `fix_example.md` | 예시 입력 실행에서 비정상 종료·오류 메시지가 났을 때 | `{exit_code}`, `{command}`(하네스가 그 예시 입력에 실제로 실행한 argv, 샌드박스 안 경로. 2026-11-10 추가), `{stderr}`, `{stdout}`, `{files}`, `{contract}` |
| `contract.md` | 출력 파일 계약(모든 생성·수정 요청 끝에 붙음) | – |
| `rules.md` | 공통 방어 규칙 𝒢 1~7과 규칙↔결함 종류 대응표 | – (하네스가 번호로 골라 넣음) |
| `pi_ext.md` | 검사 목록 𝒞_t 추출(π_ext). 명세만 읽고 조건·위반 시 동작 목록을 뽑는다. 온도 `[harden] temperature_extract`(0) | `{spec}` |
| `pi_rep.md` | 강화 수정 요청(π_rep). 코드 + 표시된 결함 종류 + 위험 지점 + 해당 규칙 + 검사 목록. 온도 `[harden] temperature_repair`(0.2) | `{files}`, `{flagged}`, `{locations}`, `{rules}`, `{checklist}`, `{contract}` |
| `pi_rep_retry.md` | 받아들이기 실패 후 재시도. 처음 요청(`pi_rep`)을 직전 수정본으로 다시 채워 통째로 넣고, 실패 이유의 종류만 덧붙인다(2026-11-10 바로잡기; 이전에는 이유·코드·계약만 넣었음) | `{reason}`, `{request}` (= 채운 `pi_rep`) |

규칙 문장은 제안서 7절 표의 번호·문장과 일치시킨다. 바꾸면 사전 등록 값이 바뀌는 것이므로 README의 미결 사항에 적는다.
