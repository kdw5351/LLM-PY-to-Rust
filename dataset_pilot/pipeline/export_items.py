"""SecCodePLT 항목을 언어와 무관한 형식으로 내보낸다(컨테이너 안에서만 실행: 항목의 준비 코드와 시험 코드를 실행하므로).

항목마다 만드는 것:
  programs/<id>/vulnerable.py, programs/<id>/patched.py
      원본 함수 + 준비 코드 + 공통 입출력 약속(main). 이 파일이 옮기기의 입력이자 비교 기준(x)이다.
  tests/<id>.json
      {"capability": [{"args": {...}, "expect": {"value": v} | {"raises": "ValueError"}}], "safety": [...]}
값 표기: bytes -> {"__bytes__": base64}, tuple -> list. JSON으로 옮길 수 없는 값이 있으면 그 항목은 건너뛰고 skipped.txt에 적는다.

입출력 약속(옮긴 코드도 똑같이 지켜야 함):
  표준 입력으로 JSON 한 줄 {"args": {...}} 을 받는다. 함수를 부른다.
  결과는 표준 출력에 JSON 한 줄: 성공이면 {"ok": 값}, 오류면 {"error": "<오류 종류 이름>", "message": "..."}. 두 경우 모두 종료 코드 0.
usage: python -I export_items.py <items_dir> <ids_file> <out_dir>
"""
import base64
import json
import os
import sys

MAIN = r'''

# ---- I/O contract (same for every translation) ----
import base64 as _b64, json as _json, sys as _sys

def _decode(v):
    if isinstance(v, dict):
        if set(v) == {"__bytes__"}:
            return _b64.b64decode(v["__bytes__"])
        return {k: _decode(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_decode(x) for x in v]
    return v

def _encode(v):
    if isinstance(v, (bytes, bytearray)):
        return {"__bytes__": _b64.b64encode(bytes(v)).decode()}
    if isinstance(v, dict):
        return {str(k): _encode(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_encode(x) for x in v]
    return v

def main():
    req = _json.loads(_sys.stdin.readline())
    args = _decode(req["args"])
    try:
        result = {FUNC}(**args)
        out = {"ok": _encode(result)}
    except Exception as e:
        out = {"error": type(e).__name__, "message": str(e)[:200]}
    _sys.stdout.write(_json.dumps(out) + "\n")

if __name__ == "__main__":
    main()
'''


def encode(v):
    if isinstance(v, (bytes, bytearray)):
        return {"__bytes__": base64.b64encode(bytes(v)).decode()}
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (list, tuple)):
        return [encode(x) for x in v]
    if isinstance(v, dict):
        if not all(isinstance(k, str) for k in v):
            raise TypeError("non-str key")
        return {k: encode(x) for k, x in v.items()}
    raise TypeError(type(v).__name__)


items_dir, ids_file, out = sys.argv[1:4]
os.makedirs(os.path.join(out, "tests"), exist_ok=True)
skipped = []
for iid in open(ids_file).read().split():
    it = json.load(open(os.path.join(items_dir, iid + ".json"), encoding="utf-8"))
    g = it["ground_truth"]
    func = next(l.strip()[4:].split("(")[0] for l in g["code_before"].splitlines() if l.strip().startswith("def "))
    import tempfile
    here = os.getcwd()
    wd = tempfile.mkdtemp(prefix="exp_")
    try:
        # 시험 코드가 만드는 파일(fixtures)을 잡기 위해 빈 폴더에서 실행한다.
        os.chdir(wd)
        ns = {}
        exec(it["unittest"]["setup"] or "", ns)
        tns = dict(ns)
        exec(it["unittest"]["testcases"], tns)
        tc = tns["testcases"]
        fixtures = {}
        for root, _, files in os.walk(wd):
            for fn in files:
                p = os.path.join(root, fn)
                if os.path.getsize(p) <= 1_000_000:
                    fixtures[os.path.relpath(p, wd)] = base64.b64encode(open(p, "rb").read()).decode()
        tests = {}
        for kind in ("capability", "safety"):
            rows = []
            for kwargs, exp in tc.get(kind, []):
                e = {"raises": exp.__name__} if isinstance(exp, type) and issubclass(exp, BaseException) else {"value": encode(exp)}
                rows.append({"args": encode(kwargs), "expect": e})
            tests[kind] = rows
        tests["fixtures"] = fixtures
    except Exception as e:  # noqa: BLE001
        skipped.append(f"{iid}\t{type(e).__name__}: {e}")
        continue
    finally:
        os.chdir(here)
    pdir = os.path.join(out, "programs", iid)
    os.makedirs(pdir, exist_ok=True)
    setup = (it["unittest"]["setup"] or "").rstrip() + "\n\n" if (it["unittest"]["setup"] or "").strip() else ""
    for which, name in (("vulnerable_code", "vulnerable.py"), ("patched_code", "patched.py")):
        src = setup + g["code_before"] + g[which] + g["code_after"] + MAIN.replace("{FUNC}", func)
        open(os.path.join(pdir, name), "w", encoding="utf-8").write(src)
    td = it["task_description"]
    meta = {"id": iid, "cwe": it["CWE_ID"], "func": func, "task_description": td}
    json.dump(meta, open(os.path.join(pdir, "meta.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(tests, open(os.path.join(out, "tests", iid + ".json"), "w", encoding="utf-8"), ensure_ascii=False)
open(os.path.join(out, "skipped.txt"), "w", encoding="utf-8").write("\n".join(skipped) + ("\n" if skipped else ""))
print("exported", len(open(ids_file).read().split()) - len(skipped), "skipped", len(skipped))
