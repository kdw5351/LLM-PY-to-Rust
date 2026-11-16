"""데이터셋 시험 종류 고르기(가림, 실험설계서_4단계_2026-11-13.md 2절). run_main.py 가 쓴다.

환경 변수 두 개로 고른다. 둘 다 없으면 아무것도 바꾸지 않는다(기존 실행과 같은 동작).
  PYRS_TEST_KINDS   : 돌릴 시험 종류(쉼표). capability / safety / effect. 예: "capability" = 기능 시험만.
  PYRS_KINDS_SCOPE  : 항목 목록 파일. 있으면 위 제한을 이 항목들에만 건다(나머지 항목은 모든 종류). 없으면 모든 항목.
제한된 항목은 걸러 낸 시험 파일(빠진 종류는 빈 목록, 효과 시험 파일 없음)을 따로 만들어 컨테이너에 그 폴더만 넣는다.
그래서 runner.py 는 빠진 종류의 시험 입력을 받지 못한다(실행 자체가 일어나지 않는다).
"""
import json
import os
import shutil
from pathlib import Path

ALL_KINDS = ("capability", "safety", "effect")


def kinds():
    v = os.environ.get("PYRS_TEST_KINDS")
    if not v:
        return None
    ks = tuple(k for k in ALL_KINDS if k in {x.strip() for x in v.split(",")})
    return ks


def scope():
    v = os.environ.get("PYRS_KINDS_SCOPE")
    if not v:
        return None
    return set(Path(v).read_text(encoding="utf-8").split())


def active():
    return kinds() is not None


def restricted(item):
    """이 항목의 시험 종류가 제한되는가."""
    k = kinds()
    if k is None or set(k) >= set(ALL_KINDS):
        return False
    s = scope()
    return s is None or item in s


def allowed(item):
    return kinds() if restricted(item) else ALL_KINDS


def load_tests(export, item):
    """판정에 쓸 시험 사전. 제한된 항목은 빠진 종류를 빈 목록으로 둔다."""
    t = json.load(open(Path(export) / "tests" / f"{item}.json", encoding="utf-8"))
    if restricted(item):
        a = allowed(item)
        t = {**t, **{k: (t.get(k, []) if k in a else []) for k in ("capability", "safety")}}
    return t


def stage(dest, items, export):
    """제한이 하나라도 걸려 있으면 dest 에 항목별 시험 파일을 쓰고 dest 를 돌려준다. 제한이 없으면 None(기존 /x/tests 그대로).
    제한 없는 항목은 원래 파일을 그대로 복사한다(export/tests 에는 효과 시험 파일이 없으므로 효과 시험도 돌지 않는다)."""
    if not active() or not any(restricted(i) for i in items):
        return None
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for i in sorted(set(items)):
        src = Path(export) / "tests" / f"{i}.json"
        if restricted(i):
            (dest / f"{i}.json").write_text(json.dumps(load_tests(export, i)), encoding="utf-8")
        else:
            shutil.copy(src, dest / f"{i}.json")
    return dest.resolve()


def marker(item):
    """제한된 항목의 결과에 붙일 표시(보안 결과가 없음을 분명히 한다)."""
    return {"blinded_kinds": list(allowed(item))} if restricted(item) else {}
