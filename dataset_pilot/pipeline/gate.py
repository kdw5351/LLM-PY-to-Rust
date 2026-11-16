"""공통 받아들이기 기준 G* (Downloads/공통받아들이기기준_2026-11-12.md 3절).

모든 강화 조건(B0·B1·예산 대조·B3·B4)이 같은 함수로 후보를 받아들인다.
쓰는 정보는 방법이 가진 것뿐이다: 빌드 결과, clippy σ(출발 코드 σ0 대비), 조건 확인 입력 결과.
데이터셋 기능 시험·보안 시험·security_policy 는 쓰지 않는다.

순서(바꾸지 않음):
  1 build  2 functional_regression(A0⊆A)  3 loader_changed  4 risk_points_increased(출발 코드 대비)
  5 security_regression(출발 코드에서 막던 조건 d0=1 을 계속 막음)
'진전'(겨냥한 것이 나아졌는가)은 여기 넣지 않는다. 방법 안의 다시 시도 신호로만 쓴다.
"""
SIGMA_CLASSES = None  # 처음 부를 때 harness.classes 에서 채운다


def _classes():
    global SIGMA_CLASSES
    if SIGMA_CLASSES is None:
        import harden_job as hj  # noqa: WPS433 (늦은 import: 하네스 경로 설정을 harden_job 이 한다)
        SIGMA_CLASSES = list(hj.SIGMA_CLASSES)
    return SIGMA_CLASSES


def _norm(d):
    return {str(k): bool(v) for k, v in (d or {}).items()}


# 규칙 버전 2 (본실행_준비완료기준_2026-11-12.md A2·A3, 사용자 결정 2026-11-12. 개발용 변경)
#  - 위험 지점: 패닉 계열(unwrap·expect·직접 인덱싱·panic → class "panic")과 unsafe 만 늘지 않게 한다.
#    산술·as 경고(intover 등)는 검사 코드를 더하면 늘어나므로 거절하지 않고 기록만 한다.
#  - 의존성: 코드를 실행할 수 있는 크레이트만 거절한다. 그 밖의 새 크레이트는 허용하고 기록한다.
PANIC_CLASSES_V2 = ["panic"]
CODE_EXEC_CRATES = {  # 다른 언어 해석기·동적 로딩·프로세스 실행·스크립트 엔진 (사전 등록 목록)
    "pyo3", "cpython", "rustpython", "rustpython-vm", "inline-python",
    "libloading", "dlopen", "dlopen2", "libc", "nix", "winapi", "windows", "windows-sys",
    "wasmtime", "wasmer", "wasmi", "rhai", "mlua", "rlua", "hlua", "deno_core", "v8", "rusty_v8",
    "boa_engine", "quick-js", "rquickjs", "duct", "subprocess", "xshell", "cmd_lib", "run_script",
}


def rules(conf):
    return (conf or {}).get("gate_rules", "v1")


def check(built, sigma0, sigma1, A0, A1, d0, d1, classes=None, N0=None, N1=None, func_ok=None, rules="v1"):
    """(accepted: bool, reason: str, detail: dict).
    func_ok: 데이터셋 기능 시험(capability)을 후보가 모두 통과했는가. 받아들이기의 기능 확인을 '다 잡게' 만드는 주 신호.
      기능 시험은 보안 판정이 아니므로 보안 오라클을 누설하지 않는다. 모델은 시험을 보지 못하고 하네스만 본다(이유 종류만 돌려줌).
    A0/A1: 조건 확인 정상 입력 일치 번호. N0/N1: 정상 입력 묶음 번호. 보조 신호로 함께 본다."""
    if not built:
        return False, "build", {}
    if func_ok is False:
        return False, "functional_regression", {"by": "dataset_capability"}
    if not set(map(str, A0 or [])) <= set(map(str, A1 or [])):
        lost = sorted(set(map(str, A0 or [])) - set(map(str, A1 or [])))
        return False, "functional_regression", {"lost_normal_inputs": lost}
    if N0 is not None and not set(map(str, N0)) <= set(map(str, N1 or [])):
        lost = sorted(set(map(str, N0)) - set(map(str, N1 or [])))
        return False, "functional_regression", {"lost_normal_inputs_n": lost}
    notes = {}
    c0, c1 = sigma0.get("codeload", {}), sigma1.get("codeload", {})
    new_load = [k for k, v in c1.items() if v > c0.get(k, 0)]
    new_deps = sorted(set(sigma1.get("deps", [])) - set(sigma0.get("deps", [])))
    if rules == "v2":
        exec_deps = [d for d in new_deps if d.replace("_", "-") in CODE_EXEC_CRATES or d in CODE_EXEC_CRATES]
        if new_load or exec_deps:
            return False, "loader_changed", {"new_codeload": new_load, "new_exec_deps": exec_deps}
        if new_deps:
            notes["new_deps_allowed"] = new_deps
    elif new_load or new_deps:
        return False, "loader_changed", {"new_codeload": new_load, "new_deps": new_deps}
    cls = classes if classes is not None else _classes()
    inc = [k for k in cls if sigma1["by_class"].get(k, 0) > sigma0["by_class"].get(k, 0)]
    if rules == "v2":
        blocking = [k for k in inc if k in PANIC_CLASSES_V2]
        if inc and len(blocking) < len(inc):
            notes["risk_increase_recorded"] = [k for k in inc if k not in PANIC_CLASSES_V2]
        inc = blocking
    if sigma1.get("unsafe_blocks", 0) > sigma0.get("unsafe_blocks", 0):
        inc.append("unsafe")
    if inc:
        return False, "risk_points_increased", {"increased": inc}
    b0, b1 = _norm(d0), _norm(d1)
    lost_d = sorted(n for n, v in b0.items() if v and not b1.get(n, False))
    if lost_d:
        return False, "security_regression", {"conditions_no_longer_enforced": lost_d}
    return True, "accepted", notes


def enabled(conf):
    return (conf or {}).get("gate") == "unified"


def use_functional(conf):
    return (conf or {}).get("gate_functional") == "dataset"


def call_cap(conf):
    """번역 한 개당 고치기 모델 호출 상한 C. 없으면 None(상한 없음)."""
    return (conf or {}).get("call_cap")


def over_cap(conf, calls):
    c = call_cap(conf)
    return c is not None and calls >= c
