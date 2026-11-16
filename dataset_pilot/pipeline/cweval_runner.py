"""컨테이너 안에서만 실행. CWEval 원래 시험 파일을 그대로 돌리되, 과제 모듈 자리에 중계 모듈을 둔다.
중계 모듈은 인자를 JSON으로 바꿔 대상 프로그램(Python 또는 Rust)을 새 프로세스로 실행하고, 결과를 돌려받는다.
오류 응답은 같은 이름의 내장 예외로 다시 던지고, 비정상 종료(패닉·크래시·시간 초과)는 RuntimeError 로 던진다(CWEval 규칙: 시험 실패).
시험 파일 안의 *_unsafe 자체 점검 시험은 돌리지 않는다(-k "not unsafe").
jobs: JSON 줄 {"key","item","lang","path"}. usage: python -I cweval_runner.py <jobs.jsonl> <cweval py dir> <programs dir> <out.jsonl>
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

jobs_file, bench_dir, prog_dir, out_path = sys.argv[1:5]
# 선택 인자 5: 돌릴 표시(쉼표, 기본 functionality,security). run_main.py 가림에서 기능 시험만 돌릴 때 functionality.
MARKS = tuple(sys.argv[5].split(",")) if len(sys.argv) > 5 else ("functionality", "security")

SHIM = r'''
import base64, builtins, json, os, subprocess, sys
PROG = {prog!r}; LANG = {lang!r}; PARAMS = {params!r}; RET = {ret!r}; LOG = {log!r}

def _enc(v):
    if isinstance(v, os.PathLike): return os.fspath(v)
    if isinstance(v, (bytes, bytearray)): return {{"__bytes__": base64.b64encode(bytes(v)).decode()}}
    if isinstance(v, dict): return {{str(k): _enc(x) for k, x in v.items()}}
    if isinstance(v, (list, tuple)): return [_enc(x) for x in v]
    return v

def _dec(v):
    if isinstance(v, dict):
        if set(v) == {{"__bytes__"}}: return base64.b64decode(v["__bytes__"])
        return {{k: _dec(x) for k, x in v.items()}}
    if isinstance(v, list): return [_dec(x) for x in v]
    return v

def _shape(v):
    r = RET.replace(" ", "")
    if r.startswith("Tuple") and isinstance(v, list): return tuple(v)
    if r.startswith("List[Tuple") and isinstance(v, list): return [tuple(x) if isinstance(x, list) else x for x in v]
    return v

def {func}(*args, **kwargs):
    d = dict(zip(PARAMS, args)); d.update(kwargs)
    cmd = [sys.executable, "-I", PROG] if LANG == "python" else [PROG]
    try:
        cp = subprocess.run(cmd, input=json.dumps({{"args": _enc(d)}}) + "\n", capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        open(LOG, "a").write("timeout\n"); raise RuntimeError("abnormal: timeout")
    lines = [l for l in cp.stdout.splitlines() if l.strip()]
    if cp.returncode != 0 or not lines:
        kind = "panic" if (cp.returncode == 101 or "panicked at" in cp.stderr) else "crash"
        open(LOG, "a").write(kind + "\n"); raise RuntimeError("abnormal: " + kind)
    obj = json.loads(lines[-1])
    if "ok" in obj: return _shape(_dec(obj["ok"]))
    exc = getattr(builtins, str(obj.get("error")), None)
    if isinstance(exc, type) and issubclass(exc, BaseException): raise exc(obj.get("message", ""))
    raise Exception(obj.get("message", ""))
'''


def junit(path):
    res = {}
    if not os.path.exists(path):
        return res
    for tc in ET.parse(path).getroot().iter("testcase"):
        bad = any(ch.tag in ("failure", "error") for ch in tc)
        skip = any(ch.tag == "skipped" for ch in tc)
        res[tc.get("name")] = "skipped" if skip else ("failed" if bad else "passed")
    return res


with open(out_path, "w", encoding="utf-8") as out:
    for line in open(jobs_file, encoding="utf-8"):
        if not line.strip():
            continue
        job = json.loads(line)
        meta = json.load(open(os.path.join(prog_dir, job["item"], "meta.json"), encoding="utf-8"))
        wd = tempfile.mkdtemp(prefix="cw_")
        shutil.copy(os.path.join(bench_dir, meta["test_file"]), wd)
        log = os.path.join(wd, "_abnormal.log")
        open(os.path.join(wd, job["item"] + "_task.py"), "w").write(
            SHIM.format(prog=job["path"], lang=job["lang"], params=meta["params"], ret=meta["returns"], log=log, func=meta["func"]))
        rec = {"key": job["key"], "item": job["item"]}
        for mark in MARKS:
            xmlp = os.path.join(wd, mark + ".xml")
            subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-m", mark, "-k", "not unsafe",
                            "--junitxml", xmlp, meta["test_file"]], cwd=wd, capture_output=True, text=True, timeout=600)
            rec[mark] = junit(xmlp)
        rec["abnormal"] = open(log).read().split() if os.path.exists(log) else []
        out.write(json.dumps(rec) + "\n"); out.flush()
        shutil.rmtree(wd, ignore_errors=True)
print("done")
