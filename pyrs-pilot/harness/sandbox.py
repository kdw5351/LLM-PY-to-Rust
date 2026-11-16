#!/usr/bin/env python3
"""격리: 빌드 단계와 실행 단계를 나눈다 (제안서 5절 "빌드와 실행을 나눈다").

빌드 단계(의존성 설치·컴파일·clippy)는 날짜 고정 레지스트리 사본(미러)에만 접속한다.
실행 단계(기능·공격·예시 입력)는 네트워크를 완전히 막는다.

mode = "docker": 두 단계를 각각 컨테이너로 돈다.
  - 빌드: `--network pyrs-registry`(internal 네트워크, 외부 접속 불가)에 붙은 미러 컨테이너(docker/README.md)만 보인다.
    PIP_INDEX_URL / CARGO 레지스트리 설정을 미러로 돌린다. build.rs도 이 안에서 돈다.
  - 실행: `--network none --memory --pids-limit --read-only`(소스 ro, /scratch rw).
mode = "local": 호스트에서 그대로 실행. 격리가 없으므로 LLM 생성 코드를 돌리기 전에 경고를 찍고
  `--i-know-local-is-unsafe` 플래그(또는 PYRS_LOCAL_UNSAFE_OK=1)를 요구한다.
  Python 의존성은 호스트 site-packages가 아니라 해답 디렉터리 안의 venv(_venv/)에만 설치한다.

빌드 산출물로 Cargo.lock(생성 코드 디렉터리에 cargo가 만든 것)과 pip_freeze.txt를 해답 디렉터리에 남긴다.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_LOCAL_WARNED = False


class LocalUnsafeError(RuntimeError):
    pass


def require_local_ok(cfg: dict, flag_ok: bool) -> None:
    """local 모드에서 LLM 생성 코드를 실행하기 전 호출. 플래그 없으면 예외."""
    global _LOCAL_WARNED
    if cfg["sandbox"]["mode"] != "local":
        return
    ok = flag_ok or os.environ.get("PYRS_LOCAL_UNSAFE_OK") == "1"
    msg = ("[경고] sandbox.mode = \"local\": LLM이 생성한 코드를 이 PC에서 격리 없이 실행한다. "
           "메모리·네트워크·파일 시스템 격리가 없다. 참조 해답 검증이나 오프라인 데모 외에는 docker 모드를 써라.")
    if not _LOCAL_WARNED:
        print(msg, file=sys.stderr)
        _LOCAL_WARNED = True
    if not ok:
        raise LocalUnsafeError("local 모드 실행에는 --i-know-local-is-unsafe 플래그(또는 PYRS_LOCAL_UNSAFE_OK=1)가 필요하다")


# ------------------------------------------------------------------ build stage
def python_exe_for(sol: Path, mode: str) -> str:
    """해답 실행에 쓸 파이썬. local 모드에서 _venv가 있으면 그 파이썬."""
    if mode == "local":
        v = sol / "_venv"
        cand = v / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if cand.exists():
            return str(cand)
    return sys.executable


def build_python(sol: Path, cfg: dict) -> tuple[bool, str]:
    """import·문법 확인 + 의존성 설치(격리 venv). (ok, log)"""
    sb = cfg["sandbox"]
    mode = sb["mode"]
    reqs = sol / "requirements.txt"
    log = ""
    need = reqs.exists() and reqs.read_text(encoding="utf-8").strip()
    if need:
        if mode == "docker":
            ok, log = _docker_build(sol, "python", cfg)
            if not ok:
                return False, log
        else:
            if not sb.get("local_pip", False):
                return False, ("requirements.txt has packages but [sandbox] local_pip = false; "
                               "dependencies are not installed on the host. Use docker mode.")
            ok, log = _local_venv_install(sol, reqs, sb)
            if not ok:
                return False, log
    if mode == "docker":
        return _docker_python_check(sol, cfg, log)
    py = python_exe_for(sol, mode)
    r = subprocess.run([py, "-m", "py_compile", str(sol / "main.py")], capture_output=True, text=True)
    if r.returncode != 0:
        return False, log + r.stderr
    # import 오류도 빌드 실패로 본다(제안서: Python은 import·문법 오류). 모듈 import만, 실행은 하지 않는다.
    r = subprocess.run([py, "-c", IMPORT_CHECK_SRC], cwd=sol, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return False, log + "ModuleNotFoundError / import failure:\n" + r.stdout + r.stderr
    _save_pip_freeze(sol, py)
    return True, log


# import 점검: main.py 의 최상위 import 모듈을 import 만 해 본다(실행은 하지 않음). local·docker 공통.
IMPORT_CHECK_SRC = ("import ast,sys,importlib; src=open('main.py',encoding='utf-8').read(); t=ast.parse(src);"
                    "mods=set();\n"
                    "for n in ast.walk(t):\n"
                    "  if isinstance(n,ast.Import): mods.update(a.name.split('.')[0] for a in n.names)\n"
                    "  elif isinstance(n,ast.ImportFrom) and n.module and n.level==0: mods.add(n.module.split('.')[0])\n"
                    "bad=[]\n"
                    "for m in sorted(mods):\n"
                    "  try: importlib.import_module(m)\n"
                    "  except Exception as e: bad.append(f'{m}: {type(e).__name__}: {e}')\n"
                    "print('\\n'.join(bad)); sys.exit(1 if bad else 0)")


def _docker_python_check(sol: Path, cfg: dict, log: str) -> tuple[bool, str]:
    """docker 모드: 문법(py_compile)·import 점검과 pip freeze 를 실행에 쓰는 것과 같은 이미지 안에서 한다
    (2026-11-11 수정. 이전에는 Windows 호스트의 Python 으로 돌아 resource 같은 Linux 전용 표준 모듈이 import 실패가 됐고,
    pip_freeze.txt 도 호스트 Python 의 목록으로 덮어썼다). 실패 메시지 형식은 local 과 같다.
    _venv(빌드 컨테이너가 requirements 로 만든 것)가 있으면 그 Python, 없으면 이미지의 python. 네트워크 없음."""
    sb = cfg["sandbox"]
    name = container_name()
    script = ('PY=python; [ -x /work/_venv/bin/python ] && PY=/work/_venv/bin/python; cd /work; '
              '$PY -m py_compile main.py 2>/tmp/compile.err || { cat /tmp/compile.err >&2; exit 10; }; '
              '$PY -c "$PYRS_IMPORT_CHECK" || exit 11; '
              '$PY -m pip freeze --disable-pip-version-check > /work/pip_freeze.txt 2>/dev/null; exit 0')
    cmd = ["docker", "run", "--rm", "--init", "--name", name, "--network", "none",
           "-v", f"{sol.resolve()}:/work", "-e", "PYTHONPYCACHEPREFIX=/tmp/pycache", "-e", "PYTHONDONTWRITEBYTECODE=1",
           "-e", f"PYRS_IMPORT_CHECK={IMPORT_CHECK_SRC}",
           "--memory", sb.get("build_mem_limit", "2g"), "--pids-limit", str(sb["pids_limit"]),
           sb["python_image"], "sh", "-c", script]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    except subprocess.TimeoutExpired:
        docker_rm(name)
        return False, log + "python check timed out"
    out, err = r.stdout or "", r.stderr or ""
    if r.returncode == 10:
        return False, log + err
    if r.returncode == 11:
        return False, log + "ModuleNotFoundError / import failure:\n" + out + err
    if r.returncode != 0:
        return False, log + f"python check container failed (exit {r.returncode}):\n" + out + err
    return True, log


def effective_requirements(sol: Path, reqs: Path, sb: dict) -> tuple[Path, list[str]]:
    """표준 라이브러리 모듈 이름(json, struct …)을 requirements.txt 에 적는 모델이 있다. pip 는 이를 거부하므로
    [sandbox] strip_stdlib_requirements = true 면 그 줄을 빼고 설치한다(빠진 이름은 기록). 원본 파일은 그대로 둔다."""
    lines = [l for l in reqs.read_text(encoding="utf-8").splitlines()]
    if not sb.get("strip_stdlib_requirements", True):
        return reqs, []
    std = {m.lower() for m in getattr(sys, "stdlib_module_names", set())}
    keep, stripped = [], []
    for l in lines:
        name = re.split(r"[<>=!~\[; ]", l.strip(), 1)[0].lower().replace("-", "_")
        if name and not l.strip().startswith("#") and name in std:
            stripped.append(l.strip())
        else:
            keep.append(l)
    if not stripped:
        return reqs, []
    out = sol / "_venv_requirements.txt"
    out.write_text("\n".join(keep) + "\n", encoding="utf-8")
    return out, stripped


def _local_venv_install(sol: Path, reqs: Path, sb: dict) -> tuple[bool, str]:
    venv = sol / "_venv"
    if not venv.exists():
        r = subprocess.run([sys.executable, "-m", "venv", str(venv)], capture_output=True, text=True)
        if r.returncode != 0:
            return False, "venv creation failed:\n" + r.stderr
    py = python_exe_for(sol, "local")
    reqs, stripped = effective_requirements(sol, reqs, sb)
    note = f"stdlib names stripped from requirements.txt: {stripped}\n" if stripped else ""
    if not reqs.read_text(encoding="utf-8").strip():
        return True, note + "no third-party requirements left\n"
    cmd = [py, "-m", "pip", "install", "-q", "--disable-pip-version-check", "-r", str(reqs)]
    idx = sb.get("pip_index_url")
    if idx:
        cmd += ["--index-url", idx]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=sb.get("build_timeout_s", 900))
    if r.returncode != 0:
        return False, note + "pip install failed:\n" + (r.stdout + r.stderr)[-3000:]
    return True, note + "pip install ok (local venv, host network — not a dated mirror)\n"


def _save_pip_freeze(sol: Path, py: str) -> None:
    try:
        r = subprocess.run([py, "-m", "pip", "freeze", "--disable-pip-version-check"],
                           capture_output=True, text=True, timeout=120)
        (sol / "pip_freeze.txt").write_text(r.stdout, encoding="utf-8")
    except Exception:
        pass


def build_rust(sol: Path, cfg: dict) -> tuple[bool, str]:
    sb = cfg["sandbox"]
    if sb["mode"] == "docker":
        return _docker_build(sol, "rust", cfg)
    env = dict(os.environ)
    env["CARGO_TERM_COLOR"] = "never"
    env.setdefault("CARGO_NET_OFFLINE", "false")
    try:
        r = subprocess.run(["cargo", "build", "--release"], cwd=sol, capture_output=True, text=True,
                           env=env, timeout=sb["build_timeout_s"])
    except subprocess.TimeoutExpired:
        return False, "cargo build timed out"
    log = (r.stdout + r.stderr)[-6000:]
    exe = sol / "target" / "release" / ("app.exe" if os.name == "nt" else "app")
    return exe.exists() and r.returncode == 0, log


def build_c(sol: Path, cfg: dict) -> tuple[bool, str]:
    from harness import runner  # lazy: find_gcc
    gcc = runner.find_gcc()
    srcs = sorted(str(p) for p in sol.glob("*.c")) or sorted(str(p) for p in sol.glob("src/*.c"))
    if not srcs:
        return False, "no C source"
    exe = sol / ("app.exe" if os.name == "nt" else "app")
    r = subprocess.run([gcc, *srcs, "-O1", "-o", str(exe.resolve())], cwd=sol,
                       capture_output=True, text=True, timeout=cfg["sandbox"]["build_timeout_s"])
    return exe.exists(), (r.stdout + r.stderr)[-4000:]


def build(sol: Path, lang: str, cfg: dict) -> tuple[bool, str]:
    if lang == "python":
        return build_python(sol, cfg)
    if lang == "rust":
        return build_rust(sol, cfg)
    if lang == "c":
        return build_c(sol, cfg)
    raise ValueError(lang)


def cmd_prefix(sol: Path, lang: str, cfg: dict) -> list[str]:
    """빌드가 끝난 해답을 실행하는 명령 접두사(local 모드). docker 모드는 run_docker가 만든다."""
    mode = cfg["sandbox"]["mode"]
    if lang == "python":
        return [python_exe_for(sol, mode), str((sol / "main.py").resolve())]
    if lang == "rust":
        return [str((sol / "target" / "release" / ("app.exe" if os.name == "nt" else "app")).resolve())]
    if lang == "c":
        return [str((sol / ("app.exe" if os.name == "nt" else "app")).resolve())]
    raise ValueError(lang)


# ------------------------------------------------------------------- docker
def _docker_run_build(sb: dict, image: str, net: str, mounts: list[str], env: list[str], script: str) -> tuple[int, str]:
    name = container_name()
    cmd = ["docker", "run", "--rm", "--init", "--name", name, "--network", net, *mounts, *env,
           "--memory", sb.get("build_mem_limit", "2g"), "--pids-limit", str(sb["pids_limit"]),
           image, "sh", "-c", script]
    try:
        # text 디코딩은 UTF-8 고정. 미지정이면 Windows 기본(cp949)으로 디코드하다 도커/빌드 출력의
        # 비-cp949 바이트(예: 코드 주석의 — → ✓)에서 리더 스레드가 죽어 stdout/stderr 가 None 이 되고
        # (r.stdout + r.stderr) 가 TypeError 로 과제 전체를 멈춘다. errors="replace" 로 손실 없이 이어 간다.
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=sb["build_timeout_s"])
        return r.returncode, ((r.stdout or "") + (r.stderr or ""))[-6000:]
    except subprocess.TimeoutExpired:
        docker_rm(name)
        return 124, "docker build stage timed out"


def _docker_build(sol: Path, lang: str, cfg: dict) -> tuple[bool, str]:
    """빌드 컨테이너. Python 은 PyPI 캐시 프록시(proxpi)만 보는 internal 네트워크.
    Rust 는 두 단계: (1) fetch — 네트워크 허용으로 cargo fetch(또는 Cargo.lock+캐시가 있으면 건너뜀),
    (2) build — internal 네트워크 + CARGO_NET_OFFLINE=true 로 cargo build. docker/README.md 참고."""
    sb = cfg["sandbox"]
    image = sb["python_image"] if lang == "python" else sb["rust_image"]
    reg = sb.get("registry_network", "pyrs-registry")
    if lang == "python":
        mounts = ["-v", f"{sol.resolve()}:/work"]
        env = ["-e", f"PIP_INDEX_URL={sb.get('pip_index_url') or 'http://pypi-mirror:5000/index/'}",
               "-e", "PIP_TRUSTED_HOST=pypi-mirror", "-e", "PIP_DISABLE_PIP_VERSION_CHECK=1"]
        req_file = "requirements.txt"
        if (sol / "requirements.txt").exists():
            eff, _ = effective_requirements(sol, sol / "requirements.txt", sb)
            req_file = eff.name
        script = ("set -e; cd /work; python -m venv /work/_venv >/dev/null; "
                  f"if [ -s {req_file} ]; then /work/_venv/bin/pip install -q -r {req_file}; fi; "
                  "/work/_venv/bin/python -m py_compile main.py; /work/_venv/bin/pip freeze > pip_freeze.txt")
        code, log = _docker_run_build(sb, image, reg, mounts, env, script)
        return code == 0, log
    # Rust: fetch (network) then offline build.
    mounts = ["-v", f"{sol.resolve()}:/work", "-v", f"{sb['cargo_cache_volume']}:/usr/local/cargo/registry"]
    fetch_net = sb.get("fetch_network", "bridge")
    log = ""
    has_lock = (sol / "Cargo.lock").exists()
    # fetch 단계: Cargo.lock 이 이미 있고 캐시 볼륨에 받아 두었으면 건너뛸 수 있다. 안전하게 항상 fetch 를 시도하되 실패는 무시한다.
    fcode, flog = _docker_run_build(sb, image, fetch_net, mounts, ["-e", "CARGO_TERM_COLOR=never"],
                                    "set -e; cd /work; cargo fetch --locked 2>/dev/null || cargo fetch")
    log += "[fetch]\n" + flog + "\n"
    # build 단계: internal 네트워크 + 오프라인. fetch 가 실패해도 캐시/Cargo.lock 만으로 빌드되는지 본다.
    bcode, blog = _docker_run_build(sb, image, reg, mounts,
                                    ["-e", "CARGO_TERM_COLOR=never", "-e", "CARGO_NET_OFFLINE=true"],
                                    "set -e; cd /work; cargo build --release --offline")
    log += "[build]\n" + blog
    ok = bcode == 0 and (sol / "target" / "release" / "app").exists()
    if not ok and not has_lock:
        log += "\n(참고: Cargo.lock 이 없어 오프라인 빌드가 실패했을 수 있다. fetch 단계에서 lock 을 만들었는지 확인하라.)"
    return ok, log


def docker_prog(sol: Path, lang: str) -> list[str]:
    """docker 실행 컨테이너 안에서 해답을 띄우는 명령 접두사(컨테이너 안 경로)."""
    if lang == "python":
        return ["/work/_venv/bin/python", "/work/main.py"] if (sol / "_venv").exists() else ["python", "/work/main.py"]
    if lang == "rust":
        return ["/work/target/release/app"]
    return ["/work/app"]


def program_argv(sol: Path, lang: str, cfg: dict, args: list[str]) -> list[str]:
    """해답 프로세스가 실제로 받는 argv(docker 는 컨테이너 안 경로, local 은 호스트 경로).
    수정 피드백(fix_example)의 {command} 에 쓴다. docker run 옵션은 넣지 않는다."""
    if cfg["sandbox"]["mode"] == "docker":
        return docker_prog(sol, lang) + list(args)
    return cmd_prefix(sol, lang, cfg) + list(args)


def container_name() -> str:
    return "pyrs_" + os.urandom(6).hex()


def docker_rm(name: str) -> None:
    """컨테이너를 강제로 없앤다(고아 방지). Popen.terminate()는 docker CLI만 죽이므로 이걸 따로 부른다."""
    try:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
    except Exception:
        pass


def out_volume_begin(scratch: Path, cfg: dict) -> str | None:
    """2026-11-11: 컨테이너 안의 /scratch/out 을 대소문자를 구분하는 docker 볼륨(ext4)으로 둔다.
    호스트 scratch 는 Windows 폴더라 대소문자를 구분하지 않아 Z.txt 와 z.txt 가 한 파일이 됐다(실행 환경 Linux 와 다름).
    볼륨을 만들고 호스트 out/ 에 미리 놓인 파일(setup)이 있으면 넣는다. 실행 뒤 out_volume_end 가 밖으로 복사한다.
    프로그램 컨테이너 자체(명령·시간 측정)는 바뀌지 않는다. [sandbox] out_case_sensitive = false 면 쓰지 않는다."""
    sb = cfg["sandbox"]
    out = scratch / "out"
    if sb["mode"] != "docker" or not sb.get("out_case_sensitive", True) or not out.is_dir():
        return None
    vol = "pyrs_out_" + os.urandom(6).hex()
    r = subprocess.run(["docker", "volume", "create", vol], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("docker volume create failed: " + r.stderr)
    if any(out.iterdir()):
        r = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{out.resolve()}:/h",
                            "-v", f"{vol}:/v", sb["python_image"], "sh", "-c", "cp -a /h/. /v/"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
        if r.returncode != 0:
            raise RuntimeError("copy into out volume failed: " + (r.stdout or "") + (r.stderr or ""))
    return vol


def out_volume_end(vol: str | None, scratch: Path, cfg: dict) -> dict:
    """볼륨의 out/ 을 호스트 scratch/out 으로 되돌리고 볼륨을 지운다. 호스트 쪽 판정(files_exist, files_json,
    dest_empty, no_outside_write 등)은 그대로 호스트 파일을 본다. 호스트가 대소문자를 구분하지 않아 합쳐지는
    경로가 있으면 case_collisions 로 돌려준다(그 경우 호스트에는 둘 중 하나만 남는다)."""
    if not vol:
        return {}
    sb = cfg["sandbox"]
    out = scratch / "out"
    out.mkdir(parents=True, exist_ok=True)
    info: dict = {}
    try:
        r = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{out.resolve()}:/h",
                            "-v", f"{vol}:/v", sb["python_image"], "sh", "-c",
                            "find /h -mindepth 1 -delete; cp -a /v/. /h/; cd /v && find . -mindepth 1"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
        paths = [l[2:] for l in (r.stdout or "").split("\n") if l.startswith("./")]
        seen: dict[str, list[str]] = {}
        for p in paths:
            seen.setdefault(p.lower(), []).append(p)
        coll = [v for v in seen.values() if len(v) > 1]
        if coll:
            info["case_collisions"] = coll[:20]
        if r.returncode != 0:
            info["copy_out_error"] = ((r.stdout or "")[-300:] + (r.stderr or "")[-500:])
    finally:
        subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True, timeout=60)
    return info


def run_docker(sol: Path, lang: str, args: list[str], scratch: Path, cfg: dict, timeout: int,
               server: bool = False, port: int | None = None, mem_limit: str | None = None,
               name: str | None = None, out_volume: str | None = None) -> dict | subprocess.Popen:
    """실행 컨테이너: 네트워크 없음, 메모리·PID 제한, 소스 읽기 전용. CLI면 결과 dict, 서버면 Popen.
    mem_limit 은 과제별 설정([tasks_cfg.<task>] mem_limit)이 있으면 그 값, 없으면 [sandbox] mem_limit.
    name 은 docker --name. 서버는 호출자가 지어 넘기고 끝날 때 docker_rm(name) 으로 없앤다(터미네이트로는 안 죽음).
    --init 으로 PID 1 이 자식을 거둔다. {fx}/{out}/{tool} 은 호출자가 이미 컨테이너 경로(/scratch/..., /tools/...)로 치환해 넘긴다."""
    sb = cfg["sandbox"]
    image = sb["python_image"] if lang == "python" else sb["rust_image"]
    tools = (ROOT / "tools").resolve()
    mem = mem_limit or sb["mem_limit"]
    name = name or container_name()
    vol_own = (not server) and out_volume is None   # CLI 실행은 여기서 볼륨을 만들고 지운다(서버는 ServerSession 이)
    if vol_own:
        out_volume = out_volume_begin(scratch, cfg)
    cmd = ["docker", "run", "--rm", "--init", "--name", name, "--network", "none",
           "--memory", mem, "--memory-swap", mem,
           "--pids-limit", str(sb["pids_limit"]), "--read-only",
           "-v", f"{sol.resolve()}:/work:ro", "-v", f"{scratch.resolve()}:/scratch",
           *(["-v", f"{out_volume}:/scratch/out"] if out_volume else []),
           "-v", f"{tools}:/tools:ro", "-e", "CANARY_DIR=/scratch/canary",
           "-e", "PATH=/tools:/usr/local/bin:/usr/bin:/bin", "-w", "/scratch"]
    if server and port:
        # 서버 과제: internal 네트워크(외부 차단). 포트는 매핑하지 않는다(internal 네트워크는 호스트로 publish 가
        # 닿지 않음 — 직접 확인). 프로브가 같은 네트워크의 컨테이너로 서버 이름:포트에 접속한다(net_probe.py).
        cmd[cmd.index("none")] = sb.get("run_network", "pyrs-run")
    full = cmd + [image] + docker_prog(sol, lang) + args
    if server:
        return subprocess.Popen(full, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    t0 = time.time()
    timed_out = False
    try:
        r = subprocess.run(full, capture_output=True, timeout=timeout)
        out, err, code = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired as e:
        out, err, code, timed_out = e.stdout or b"", e.stderr or b"", None, True
        docker_rm(name)   # --rm 은 정상 종료 때만 지운다. timeout 이면 컨테이너가 남으므로 강제로 없앤다.
    dur = round(time.time() - t0, 3)   # 프로그램 컨테이너만 잰다(볼륨 복사 시간은 넣지 않음)
    vinfo = out_volume_end(out_volume, scratch, cfg) if vol_own else {}
    return {"stdout": out, "stderr": err, "exit_code": code, "timed_out": timed_out,
            "duration_s": dur, **({"out_volume": vinfo} if vinfo else {})}


def container_paths(cfg: dict) -> dict:
    """docker 모드에서 프로그램에 넘길 자리표시자 치환값. {fx}/{out} 은 컨테이너 안 경로."""
    return {"{fx}": "/scratch/fixtures", "{out}": "/scratch/out", "{tool}": "/tools/wordcount"}


def wait_container_running(name: str, timeout: float = 10.0) -> bool:
    """docker exec 하기 전에 컨테이너가 실제로 올라올 때까지 기다린다(run 직후의 경쟁 회피)."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip() == "true":
                return True
            if r.returncode == 0 and r.stdout.strip() == "false":
                return False   # 이미 끝났다(크래시 등)
        except Exception:
            pass
        time.sleep(0.1)
    return False


def net_probe(cfg: dict, server_name: str, payload: dict) -> dict:
    """서버 과제 프로브: 실행 중인 서버 컨테이너 안에서(docker exec) tools/net_probe.py 를 돌린다.
    서버와 같은 네트워크 네임스페이스라 서버가 127.0.0.1 에 바인드해도 닿고, 외부 네트워크는 여전히 막힌 채다.
    입력은 /scratch/_probe_in.json(서버 컨테이너에 rw 로 마운트된 케이스 scratch). 결과 JSON(dict), 실패하면 {}.
    python3 은 두 이미지(python:3.12-slim, rust:slim+python3) 모두에 있다."""
    import json as _json
    # 입력 파일은 호출자가 이미 /scratch 에 보이도록 scratch 에 써 둔다(write_probe_input 사용).
    cmd = ["docker", "exec", server_name, "python3", "/tools/net_probe.py", "/scratch/_probe_in.json"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=cfg["sandbox"]["server_step_timeout_s"] * 4 + 20)
    except subprocess.TimeoutExpired:
        return {}
    if r.stdout is None:
        return {}
    try:
        return _json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        return {}


def docker_available() -> bool:
    return shutil.which("docker") is not None
