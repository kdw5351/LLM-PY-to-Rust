"""컨테이너 안에서만 실행. 프로그램 목록의 각 프로그램에 그 항목의 시험을 하나씩(새 프로세스로) 넣고 결과를 기록한다.
판정은 하지 않는다(judge.py가 한다).
jobs 파일: JSON 줄마다 {"key": ..., "item": id, "lang": "python"|"rust", "path": 컨테이너 안 경로}
usage: python -I runner.py <jobs.jsonl> <tests_dir> <out.jsonl> [timeout_s=10]

효과 시험(effect): <item>.effect.json 이 있으면 함께 돌린다. 효과 시험은 공격 입력이
실제로 처리됐을 때만 격리 폴더 안에 표식(무작위 토큰 파일)을 남기거나, 심어 둔 비밀 토큰이
출력에 새어 나오는지로 '실제 효과'를 본다. 입력은 data 파일에만 있고, runner 는 실행 뒤
격리 폴더와 stdout 을 들여다볼 뿐이다. 실행 환경은 기존과 같다(네트워크 없음, 매번 새 폴더).
효과 시험 레코드: {"args": {...}, "detect": "file_marker"|"stdout_token", "token": "...",
                   "plant": {"where": "wd_parent"|"wd", "name": "..."}?}
"""
import json
import os
import subprocess
import sys
import tempfile
import time

try:
    import resource   # POSIX 전용. 실제 실행은 Docker(리눅스) 안에서만 한다.
except ImportError:   # Windows 에서 순수 보조 함수만 단위 시험할 때
    resource = None

timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 10.0
MEM = 1024 * 1024 * 1024  # 프로세스당 주소 공간 1GB
SCAN_MAX_FILES = 4000
SCAN_MAX_BYTES = 1 << 20  # 파일마다 최대 1MB만 훑는다


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (MEM, MEM))
    resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))


def _put_fixtures(wd, fixtures):
    import base64
    for rel, b64 in (fixtures or {}).items():   # 시험 코드가 만들어 두는 파일을 매번 새로 놓는다
        p = os.path.join(wd, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(base64.b64decode(b64))


def _exec(lang, path, payload, wd):
    cmd = [sys.executable, "-I", path] if lang == "python" else [path]
    t0 = time.time()
    try:
        cp = subprocess.run(cmd, input=payload, capture_output=True, text=True, timeout=timeout,
                            cwd=wd, preexec_fn=limits, env={"PATH": "/usr/bin:/bin", "HOME": wd})
        return {"rc": cp.returncode, "stdout": cp.stdout[-4000:], "stderr": cp.stderr[-1500:],
                "timed_out": False, "dur": round(time.time() - t0, 3)}
    except subprocess.TimeoutExpired as e:
        return {"rc": None, "stdout": (e.stdout or "")[-2000:] if isinstance(e.stdout, str) else "",
                "stderr": "", "timed_out": True, "dur": round(time.time() - t0, 3)}


def run_one(lang, path, payload, fixtures):
    with tempfile.TemporaryDirectory() as wd:
        _put_fixtures(wd, fixtures)
        return _exec(lang, path, payload, wd)


def _token_in_tree(root, token, names_only=False):
    """격리 폴더 안에서 토큰이 파일/디렉터리 이름이나 내용에 나타나는지 본다(실행이 남긴 표식).
    names_only=True 면 이름만 본다. 카나리아의 입력 파일(픽스처·tar)은 토큰을 내용에 담고 있으므로,
    실행이 '만든' 표식(디렉터리/파일 이름)만 세려면 내용 검사를 꺼야 한다."""
    tb = token.encode()
    seen = 0
    for base, dirs, files in os.walk(root):
        if any(token in d for d in dirs):   # 디렉터리 이름 표식(파일을 안 만드는 양성 카나리아)
            return True
        for name in files:
            seen += 1
            if seen > SCAN_MAX_FILES:
                return False
            if token in name:
                return True
            if names_only:
                continue
            fp = os.path.join(base, name)
            try:
                if os.path.islink(fp) or not os.path.isfile(fp):
                    continue
                with open(fp, "rb") as fh:
                    if tb in fh.read(SCAN_MAX_BYTES):
                        return True
            except OSError:
                continue
    return False


def run_effect(lang, path, test, fixtures):
    """효과 시험 하나. 공격 값이 실제로 실행되면 표식이 생기거나 비밀 토큰이 출력에 샌다."""
    token = test["token"]
    detect = test["detect"]
    with tempfile.TemporaryDirectory() as wd:
        _put_fixtures(wd, fixtures)
        _put_fixtures(wd, test.get("fixtures"))   # 효과별 덮어쓰기(502 파일형·CWE-22 tar 등)
        plant = test.get("plant")
        if plant:   # 경로 조작용: 프로그램이 읽어서는 안 되는 자리에 비밀 토큰을 둔다
            where = os.path.dirname(wd) if plant["where"] == "wd_parent" else wd
            pp = os.path.join(where, plant["name"])
            try:
                with open(pp, "w", encoding="utf-8") as fh:
                    fh.write(token)
            except OSError:
                pp = None
        else:
            pp = None
        payload = json.dumps({"args": test["args"]}) + "\n"
        run = _exec(lang, path, payload, wd)
        if detect in ("file_marker", "name_marker"):
            # name_marker: 실행이 만든 디렉터리/파일 '이름'만 본다(카나리아 입력 파일의 내용은 무시).
            fired = _token_in_tree(wd, token, names_only=(detect == "name_marker"))
        elif detect == "stdout_token":
            fired = token in (run.get("stdout") or "")
        else:
            fired = False
        if pp:
            try:
                os.remove(pp)
            except OSError:
                pass
    run["fired"] = fired
    run["detect"] = detect
    return run


def main():
    jobs_file, tests_dir, out_path = sys.argv[1:4]
    with open(out_path, "w", encoding="utf-8") as out:
        for line in open(jobs_file, encoding="utf-8"):
            if not line.strip():
                continue
            job = json.loads(line)
            tp = os.path.join(tests_dir, job["item"] + ".json")
            tests = json.load(open(tp, encoding="utf-8")) if os.path.exists(tp) else {}  # CWEval 은 tests json 이 없다(효과만)
            rec = {"key": job["key"], "item": job["item"], "lang": job["lang"], "runs": {}}
            for kind in ("capability", "safety"):
                rec["runs"][kind] = [run_one(job["lang"], job["path"], json.dumps({"args": t["args"]}) + "\n",
                                             tests.get("fixtures"))
                                     for t in tests.get(kind, [])]
            eff_dir = os.environ.get("EFFECT_DIR", tests_dir)
            eff_path = os.path.join(eff_dir, job["item"] + ".effect.json")
            if os.path.exists(eff_path):
                eff = json.load(open(eff_path, encoding="utf-8"))
                rec["runs"]["effect"] = [run_effect(job["lang"], job["path"], t, tests.get("fixtures"))
                                         for t in eff.get("effect", [])]
            out.write(json.dumps(rec) + "\n")
            out.flush()
    print("done")


if __name__ == "__main__":
    main()
