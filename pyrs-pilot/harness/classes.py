#!/usr/bin/env python3
"""결함 종류(class)·결과 유형·심각도 대응표. 제안서(rev 723) 6절 "결함 종류", 7절 "점검 규칙"·"강화 방법"을
하네스 전체가 공유하는 한 곳.

- 공격 케이스의 `class`는 CLASSES 키 중 하나(단일 주 결함 종류). `cwe` 목록은 참고용.
- 248 패닉은 결함 종류가 아니라 **결과 유형**이다(PANIC_CLASS). 다른 종류의 공격이 패닉·미처리 예외로 끝나면
  자기 class 에서 뚫림으로 세고, 248 행에는 결과 유형 집계로 따로 센다(합치지 않음).
  코드 신호 σ 의 unwrap/expect/panic/직접 인덱싱은 248 로, 검사 없는 산술·as 변환은 190 으로, unsafe 는 따로.
- 공통 방어 규칙: 1·2·7 → 248, 3·4 → 190(intover), 5 → 400(dos). 규칙 6 은 표시된 종류와 무관하게 항상 넣는다.
"""
from __future__ import annotations

# class id -> (설명, 대표 CWE 목록)
CLASSES: dict[str, tuple[str, list[str]]] = {
    "deser":   ("역직렬화·파일 읽기 중 코드 실행", ["502"]),
    "inject":  ("명령어 주입·코드 실행", ["78", "94", "95"]),
    "path":    ("경로 조작·링크", ["22", "59", "73"]),
    "intover": ("정수 넘침·과대 할당", ["190", "680", "789"]),
    "dos":     ("자원 고갈·정규식 폭증", ["400", "1333", "776", "674", "409"]),
    "ssrf":    ("내부 주소 요청 유도", ["918"]),
    "auth":    ("인증·권한 누락", ["306", "862"]),
    "verify":  ("검증 누락(해시·서명)", ["347", "295"]),
    "info":    ("정보 노출", ["200", "532"]),
    "input":   ("입력 검사(위 종류에 속하지 않는 명세 위반 입력)", ["20"]),
}
# 결과 유형 행(결함 종류가 아님). 공격 class 로는 쓰지 않는다.
PANIC_CLASS = "panic"      # 248: 패닉(Rust) / 처리되지 않은 예외(Python)
SIGMA_CLASSES = list(CLASSES) + [PANIC_CLASS]   # σ_k 가 가질 수 있는 키 (unsafe 는 따로)

CWE_TO_CLASS: dict[str, str] = {cwe: cls for cls, (_, cwes) in CLASSES.items() for cwe in cwes}
CWE_TO_CLASS["125"] = "intover"   # 구 케이스 파일 호환(125 는 더 쓰지 않음)
CWE_TO_CLASS["248"] = PANIC_CLASS


def class_of_cwes(cwes: list[str]) -> str | None:
    """구 형식(cwe 목록만 있는 케이스)에서 주 결함 종류를 추정한다. 첫 CWE 기준."""
    for c in cwes:
        if c in CWE_TO_CLASS and CWE_TO_CLASS[c] != PANIC_CLASS:
            return CWE_TO_CLASS[c]
    return None


# 결과 유형(outcome). 공격 하나의 실제 결과. 제안서 7절 심각도 계획 값과 같은 이름.
OUTCOMES = {
    "defended":        "막음(명세의 종료 코드로 거부)",
    "format_error":    "거부했지만 종료 코드가 다름(막음으로 세되 따로 집계)",
    "code_exec":       "코드 실행(카나리)",
    "wrong_output":    "잘못된 입력을 받아들여 생긴 틀린 출력·범위 밖 접근·허용 범위 밖 쓰기",
    "service_down":    "서버 과제의 서비스 중단",
    "request_failed":  "서버 과제의 요청 하나 실패(패닉·예외)",
    "abnormal_exit":   "명령행 과제의 비정상 종료(패닉·미처리 예외·시그널·OOM·timeout)",
}
EXPLOIT_OUTCOMES = {"code_exec", "wrong_output", "service_down", "request_failed", "abnormal_exit"}
# 계획 심각도 w(a): 설계 시 공격마다 고정(cases.json `severity`). 결과 유형별 계획 값.
SEVERITY_PLAN = {"code_exec": 3, "wrong_output": 2, "service_down": 2, "request_failed": 1, "abnormal_exit": 1}

# 결과 유형 중 248 행(패닉·미처리 예외)으로 따로 세는 crash_kind
PANIC_KINDS = {"panic", "unhandled_exception"}

# clippy lint 이름 -> σ class. unwrap/expect/panic/직접 인덱싱 → 248, 산술·as → 190.
CLIPPY_LINT_TO_CLASS: dict[str, str] = {
    "clippy::unwrap_used": PANIC_CLASS,
    "clippy::expect_used": PANIC_CLASS,
    "clippy::indexing_slicing": PANIC_CLASS,
    "clippy::panic": PANIC_CLASS,
    "clippy::unreachable": PANIC_CLASS,
    "clippy::todo": PANIC_CLASS,
    "clippy::unimplemented": PANIC_CLASS,
    "clippy::arithmetic_side_effects": "intover",
    "clippy::cast_possible_truncation": "intover",
    "clippy::cast_possible_wrap": "intover",
    "clippy::cast_sign_loss": "intover",
    "clippy::cast_precision_loss": "intover",
    "clippy::as_conversions": "intover",
}
CLIPPY_LINTS: list[str] = sorted(CLIPPY_LINT_TO_CLASS)

# 정규식 대체 집계(clippy 가 없을 때) 패턴 이름 -> class. structural.RS_PAT 키와 같다.
RS_REGEX_TO_CLASS: dict[str, str] = {
    "unwrap": PANIC_CLASS, "expect": PANIC_CLASS, "panic": PANIC_CLASS, "index_direct": PANIC_CLASS,
    "as_int_cast": "intover", "unchecked_arith": "intover",
}

# Python 코드 신호(코드 실행형 로더 등) 패턴 이름 -> class. structural.PY_RISKY 키와 같다.
PY_SIGNAL_TO_CLASS: dict[str, str] = {
    "pickle.load": "deser", "joblib.load": "deser", "marshal.load": "deser",
    "torch.load_weights_only_false": "deser", "yaml.load_unsafe": "deser",
    "numpy_allow_pickle": "deser", "dill.load": "deser",
    "eval_exec": "inject", "shell": "inject",
}

# Rust 의 "파일 안 코드를 실행하는 읽기 함수"(제안서 7절 받아들이기 조건 (4), 사전 등록 목록).
# structural.RS_CODELOAD 패턴 이름 -> 설명. Cargo.toml 의 새 의존성 추가는 harden.accept 가 따로 본다.
RS_CODELOAD = {
    "process_command": "std::process::Command 로 외부 해석기 호출",
    "libloading": "libloading / dlopen 계열 동적 로딩",
    "pyo3": "pyo3 / Python 호출",
}

# 공통 방어 규칙 번호 -> 적용 class 목록 (prompts/rules.md 의 규칙 1~7과 같은 번호). 규칙 6 은 항상.
RULE_TO_CLASSES: dict[int, list[str]] = {
    1: [PANIC_CLASS],
    2: [PANIC_CLASS],
    3: ["intover"],
    4: ["intover"],
    5: ["dos"],
    6: [],                      # 항상 포함 (ALWAYS_RULES)
    7: [PANIC_CLASS],
}
ALWAYS_RULES = [6]


def rules_for(classes: set[str] | list[str]) -> list[int]:
    cs = set(classes)
    return sorted(n for n, cl in RULE_TO_CLASSES.items() if n in ALWAYS_RULES or (cs & set(cl)))


def all_classes() -> list[str]:
    return list(CLASSES)
