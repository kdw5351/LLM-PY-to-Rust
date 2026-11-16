#!/usr/bin/env python3
"""서버 과제(T3)용 러너. 해답 서버를 띄우고 HTTP step을 실행한 뒤 오라클을 판정한다.

결과 유형(outcome):
  service_down   서버 프로세스가 죽었거나 step 뒤 /health 가 200이 아님
  request_failed 서버는 살아 있는데 표준 오류에 패닉·트레이스백(요청 하나 실패)
  code_exec      카나리 실행
  wrong_output   허용 밖 쓰기 / 카나리 HTTP 도달 / 거부해야 할 요청을 2xx 로 받아들임
  format_error   거부는 했지만(4xx/5xx) 기대한 상태 코드와 다름 — 막음으로 세되 따로 집계
  defended
공격 케이스의 reach_check(steps + expect)가 실패하면 status=invalid.
"""
from __future__ import annotations

import base64
import json
import os
import shlex
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PANIC = ("panicked at", "thread 'main' panicked")
TRACE = ("Traceback (most recent call last):",)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def http(method: str, url: str, headers: dict, body: bytes | None, timeout: float):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()


def wait_ready(base: str, path: str, proc: subprocess.Popen, timeout=15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        st, _ = http("GET", base + path, {}, None, 2.0)
        if st == 200:
            return True
        time.sleep(0.15)
    return False


def tool_path() -> str:
    return str((ROOT / "tools" / ("wordcount.cmd" if os.name == "nt" else "wordcount")).resolve())


def build_body(step: dict):
    if "json" in step:
        return json.dumps(step["json"]).encode(), "application/json"
    if "body_text" in step:
        return step["body_text"].encode(), "application/json"
    if "body_bytes_zero" in step:
        return b"\x00" * int(step["body_bytes_zero"]), "application/json"
    if "json_large_b64" in step:
        n = int(step["json_large_b64"])
        payload = {"filename": step.get("filename", "big.bin"),
                   "content_base64": base64.b64encode(b"\x00" * n).decode()}
        return json.dumps(payload).encode(), "application/json"
    if "body_json_pad" in step:
        # 정확히 total_bytes 바이트인 **유효한** JSON 본문 {"<field>": "aaa…"}. 0바이트 채움(비-JSON)과 달리
        # JSON 파싱만으로는 거를 수 없어, 본문 크기 상한 검사가 실제로 동작하는지 시험한다.
        spec = step["body_json_pad"]
        field = spec.get("field", "text")
        total = int(spec["total_bytes"])
        envelope = json.dumps({field: ""})            # 예: {"text": ""}
        pad = max(0, total - len(envelope))
        body = json.dumps({field: "a" * pad}).encode()   # 길이 = len(envelope) + pad = total
        return body, "application/json"
    return None, "application/json"


class ServerSession:
    """서버 하나를 띄우고 step을 보내는 컨텍스트."""

    def __init__(self, server_spec: dict, sol: Path, lang: str, scratch: Path, cfg: dict, mem_limit: str | None = None):
        from harness import sandbox  # lazy
        self.scratch = scratch
        (scratch / "out").mkdir(parents=True, exist_ok=True)
        (scratch / "canary").mkdir(exist_ok=True)
        self.port = free_port()
        self.api_key = "k_" + os.urandom(8).hex()
        self.cfg = cfg
        self.docker = cfg["sandbox"]["mode"] == "docker"
        self.name = None
        # docker 모드는 컨테이너 안 경로(/scratch/out, /tools/wordcount), local 은 호스트 경로.
        if self.docker:
            mapping = {"{port}": str(self.port), "{api_key}": self.api_key,
                       "{out}": "/scratch/out", "{tool}": "/tools/wordcount"}
        else:
            mapping = {"{port}": str(self.port), "{api_key}": self.api_key,
                       "{out}": (scratch / "out").resolve().as_posix(),
                       "{tool}": Path(tool_path()).as_posix()}
        args = list(server_spec["args"])
        for k, v in mapping.items():
            args = [a.replace(k, v) for a in args]
        self.ready_path = server_spec.get("ready_path", "/health")
        self.sandbox = sandbox
        self.argv = sandbox.program_argv(sol, lang, cfg, args)   # 수정 피드백 {command} 용(실제로 띄운 argv)
        # 서버는 127.0.0.1 에 바인드할 수 있으므로 프로브는 서버 컨테이너 안에서(docker exec) 127.0.0.1 로 접속한다.
        self.base = f"http://127.0.0.1:{self.port}"
        self.out_vol = None
        self.out_volume_info: dict = {}
        if self.docker:
            self.name = sandbox.container_name()
            self.out_vol = sandbox.out_volume_begin(scratch, cfg)   # 2026-11-11: /scratch/out 대소문자 구분
            self.proc = sandbox.run_docker(sol, lang, args, scratch, cfg, 0, server=True, port=self.port,
                                           mem_limit=mem_limit, name=self.name, out_volume=self.out_vol)
        else:
            env = dict(os.environ)
            env["CANARY_DIR"] = str(scratch / "canary")
            env["PATH"] = str(ROOT / "tools") + os.pathsep + env.get("PATH", "")
            self.proc = subprocess.Popen(sandbox.cmd_prefix(sol, lang, cfg) + args, cwd=scratch, env=env,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.step_to = cfg["sandbox"]["server_step_timeout_s"]

    # ------------------------------------------------- transport (host vs in-network probe)
    def _concrete(self, step: dict):
        """(method, path, headers, body_bytes) — auth 주입·본문 생성을 호스트에서 한다."""
        auth = step.get("auth", False)
        headers = dict(step.get("headers", {}))
        if auth is True:
            headers["X-API-Key"] = self.api_key
        elif auth == "wrong":
            headers["X-API-Key"] = "wrong_" + self.api_key
        elif auth == "empty":
            headers["X-API-Key"] = ""
        body, ctype = build_body(step)
        if body is not None:
            headers.setdefault("Content-Type", ctype)
        return step["method"], step["path"], headers, body

    def _probe(self, payload: dict) -> dict:
        (self.scratch / "_probe_in.json").write_text(json.dumps(payload), encoding="utf-8")
        return self.sandbox.net_probe(self.cfg, self.name, payload)

    def _send(self, reqs):
        """[(method, path, headers, body)] -> [(status, body_bytes)]. local 은 호스트 http, docker 는 exec 프로브 1회."""
        if not reqs:
            return []
        if not self.docker:
            return [http(m, self.base + p, h, b, self.step_to) for (m, p, h, b) in reqs]
        payload = {"mode": "send", "base": self.base, "timeout": self.step_to,
                   "requests": [{"method": m, "path": p, "headers": h,
                                 "body_b64": base64.b64encode(b).decode() if b is not None else None}
                                for (m, p, h, b) in reqs]}
        res = self._probe(payload)
        out = []
        resp = res.get("responses", [{} for _ in reqs])
        for r in resp:
            st = r.get("status")
            out.append((st, base64.b64decode(r["body_b64"]) if r.get("body_b64") else b""))
        while len(out) < len(reqs):            # 프로브 실패 시 나머지는 미응답으로
            out.append((None, b""))
        return out

    def ready(self) -> bool:
        if self.proc.poll() is not None:
            return False
        if not self.docker:
            return wait_ready(self.base, self.ready_path, self.proc)
        if not self.sandbox.wait_container_running(self.name, 10.0):
            return False   # 컨테이너가 안 올라오거나 바로 죽음
        res = self._probe({"mode": "wait", "base": self.base, "path": self.ready_path, "timeout": 15})
        return bool(res.get("ready"))

    def run_steps(self, steps: list[dict]) -> tuple[list[str], list[str]]:
        """(violations, outcomes). 기대와 다른 응답을 결과 유형으로 분류한다."""
        viol, outs = [], []
        responses = self._send([self._concrete(s) for s in steps])
        for i, (step, (st, data)) in enumerate(zip(steps, responses)):
            exp = step.get("expect", {})
            want = [exp["status"]] if "status" in exp else list(exp.get("status_in", []))
            if want and st not in want:
                viol.append(f"step{i} status {st} not in {want}")
                if st is None:
                    outs.append("service_down")
                elif all(w >= 400 for w in want) and st >= 400:
                    outs.append("format_error")      # 거부는 했지만 코드가 다름
                elif all(w >= 400 for w in want) and st < 400:
                    outs.append("wrong_output")      # 거부해야 할 요청을 받아들임
                else:
                    outs.append("wrong_output")
            if "json" in exp and st is not None:
                try:
                    got = json.loads(data)
                    for k, v in exp["json"].items():
                        if got.get(k) != v:
                            viol.append(f"step{i} json {k}={got.get(k)} != {v}")
                            outs.append("format_error" if (st >= 400) else "wrong_output")
                except Exception:
                    viol.append(f"step{i} response not JSON")
                    outs.append("format_error" if (st or 0) >= 400 else "wrong_output")
        return viol, outs

    def alive(self) -> bool:
        if self.proc.poll() is not None:
            return False
        st, _ = self._send([("GET", "/health", {}, None)])[0]
        return st == 200

    def close(self) -> str:
        # docker 모드: Popen.terminate()는 docker CLI 클라이언트만 죽이고 컨테이너는 남으므로 docker rm -f 로 먼저 없앤다.
        if self.docker and self.name:
            from harness import sandbox
            sandbox.docker_rm(self.name)
        self.proc.terminate()
        try:
            _, err = self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            _, err = self.proc.communicate()
        if self.docker and self.out_vol:
            from harness import sandbox
            self.out_volume_info = sandbox.out_volume_end(self.out_vol, self.scratch, self.cfg)
            self.out_vol = None
        return (err or b"").decode("utf-8", "replace")


def _crash(serr: str, exit_code) -> str | None:
    if any(m in serr for m in PANIC) or exit_code == 101:
        return "panic"
    if any(m in serr for m in TRACE):
        return "unhandled_exception"
    return None


def run_one(case: dict, server_spec: dict, sol: Path, lang: str, scratch_root: Path,
            cfg: dict, is_attack: bool, task: str = "") -> dict:
    from harness.classes import EXPLOIT_OUTCOMES, PANIC_KINDS
    from harness.runner import DOCKER_KILLED_EXIT, apply_killed_rule, base_record, task_cfg, worst
    rec = base_record(case)
    mem = task_cfg(cfg, task).get("mem_limit")
    # 도달 확인 입력: 같은 요청에서 악성 부분만 정상 값으로 바꾼 steps. 실패하면 무효.
    if is_attack and case.get("reach_check"):
        rc = case["reach_check"]
        scratch = scratch_root / (case["id"] + "__reach")
        if scratch.exists():
            shutil.rmtree(scratch, ignore_errors=True)
        sess = ServerSession(server_spec, sol, lang, scratch, cfg, mem)
        try:
            rviol = [] if sess.ready() else ["server did not become ready"]
            if not rviol:
                rviol, _ = sess.run_steps(rc.get("steps", []))
                if not sess.alive():
                    rviol.append("server died during reach check")
        finally:
            sess.close()
        rec["reach"] = {"ok": not rviol, "violations": rviol}
        if rviol:
            rec.update({"status": "invalid", "invalid_reason": "reach_check_failed", "outcome": None, "violations": [],
                        "crash_kind": None, "crash_class": None, "panic_outcome": False})
            return rec

    scratch = scratch_root / case["id"]
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    sess = ServerSession(server_spec, sol, lang, scratch, cfg, mem)
    viol: list[str] = []
    outs: list[str] = []
    down = False
    rc_before_close = None   # close() 가 컨테이너를 강제로 지우므로(137) 그 전에 스스로 죽었는지 본다
    oracles = case.get("oracles", [])
    try:
        if not sess.ready():
            viol.append("server did not become ready")
            down = True
        else:
            step_viol, step_outs = sess.run_steps(case.get("steps", []))
            if is_attack and "steps_expect" not in oracles:
                rec["step_notes"] = step_viol      # 참고 정보. 판정은 오라클로
            else:
                viol += step_viol
                outs += step_outs
            if not sess.alive():
                down = True
                if "server_alive" in oracles or not is_attack:
                    viol.append("server_alive: /health not 200 after steps")
        rc_before_close = sess.proc.poll()
    finally:
        serr = sess.close()
    kind = _crash(serr, sess.proc.returncode)
    if kind is None and down and rc_before_close == DOCKER_KILLED_EXIT and cfg["sandbox"]["mode"] == "docker":
        kind = "killed"   # 서버가 요청 처리 중 메모리 한도 등으로 강제 종료됨(2026-11-10 측정 고정)
    crash_class = "service_down" if down else ("request_failed" if kind else None)
    if down:
        outs.append("service_down")
    if is_attack:
        if "canary_absent" in oracles and (scratch / "canary" / "hit").exists():
            viol.append("canary_absent: canary executed"); outs.append("code_exec")
        if "canary_http_absent" in oracles and (scratch / "canary" / "http_hit").exists():
            viol.append("canary_http_absent: endpoint hit"); outs.append("wrong_output")
        if "no_outside_write" in oracles:
            allowed = (scratch / "out").resolve()
            # canary/ 와 하네스 내부 파일(_probe_in.json)은 프로그램이 쓴 것이 아니므로 제외한다.
            outside = [str(p.relative_to(scratch)) for p in scratch.rglob("*")
                       if p.is_file() and not str(p.resolve()).startswith(str(allowed))
                       and "canary" not in p.parts and not p.name.startswith("_probe")]
            if outside:
                viol.append(f"no_outside_write: {outside[:5]}"); outs.append("wrong_output")
        if kind and not down:
            viol.append(f"request_failed: {kind}"); outs.append("request_failed")
        outcome = worst(outs)
        status = "exploited" if outcome in EXPLOIT_OUTCOMES else "defended"
    else:
        exp = case.get("expect", {})
        for rel in exp.get("files_exist", []):
            if not (scratch / rel).exists():
                viol.append(f"missing file {rel}")
        for rel in exp.get("files_absent", []):
            if (scratch / rel).exists():
                viol.append(f"unexpected file {rel}")
        if kind:
            viol.append(f"crash: {kind}")
        status = "fail" if viol else "pass"
        outcome = None
    rec.update({"status": status, "outcome": outcome, "violations": viol, "crash_kind": kind,
                "crash_class": crash_class, "panic_outcome": kind in PANIC_KINDS, "stderr_tail": serr[-800:]})
    if getattr(sess, "out_volume_info", None):
        rec["out_volume"] = sess.out_volume_info
    if is_attack:
        apply_killed_rule(rec)
    return rec


def run_server_cases(spec: dict, sol: Path, lang: str, task_dir: Path, scratch_root: Path,
                     cfg: dict, is_attack: bool) -> list[dict]:
    server_spec = spec["server"]
    return [run_one(c, server_spec, sol, lang, scratch_root, cfg, is_attack, task_dir.name) for c in spec.get("cases", [])]


def run_example_server(ex: dict, sol: Path, lang: str, task_dir: Path, scratch_root: Path, cfg: dict) -> dict:
    """서버 과제의 예시 입력: 서버를 띄우고 steps 하나를 보낸다. 준비 실패·죽음·패닉이면 abnormal."""
    scratch = scratch_root / "example"
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    sess = ServerSession(ex["server"], sol, lang, scratch, cfg)
    try:
        if not sess.ready():
            abnormal, note = True, "server did not become ready (no 200 on /health within 15s)"
        else:
            sess.run_steps(ex.get("steps", []))
            abnormal = not sess.alive()
            note = "server died after the example request" if abnormal else ""
    finally:
        serr = sess.close()
    kind = _crash(serr, sess.proc.returncode)
    return {"abnormal": abnormal or bool(kind), "exit_code": sess.proc.returncode, "crash_kind": kind,
            "stderr": (note + "\n" + serr)[-3000:], "command": shlex.join(sess.argv)}
