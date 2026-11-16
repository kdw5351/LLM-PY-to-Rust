"""Sandbox execution recorder + rule-based trace classifier (no prompts, no model calls).

Runs an already-built program (<solution_dir>/app, the pipeline's I/O contract: one JSON line {"args": {...}} on stdin,
one JSON line {"ok": ...} or {"error": "<Name>", "message": ...} on stdout) once per probe in its own container under
`strace -f`, records what the process did, and labels the record with fixed rules.

Rule logic is ported from FALCON (https://github.com/tue09/FALCON, MIT License, Copyright (c) 2026 tue09),
experiments/test-time-repair/av_signal/verifier.py (Stage 1 crash oracle, 7 of the 21 Stage-2 detectors, benign rule)
and av_signal/models.py (trace fields), as mapped to a process-level trace in
research_notes/선행 연구 절차 대조/falcon_port_feasibility.md (Q1-Q4). No FALCON code is imported or executed.

Probe:  {"id": str, "input": {"args": {...}}, "setup": {"files": {relpath: text}, "env": {NAME: value}}}  (setup optional)

usage:
  python exec_trace.py run <solution_dir> <probes.json> <out_dir> [--fixtures <tests json>] [--jobs N] [--timeout S]
  python exec_trace.py verify <trace.json>
  (internal, inside the container only)  python -I exec_trace.py _driver   < spec json

Container (one per probe): image pyrs-pilot/rust-trace:v1 (pipeline/Dockerfile.trace = the runner image used for built
Rust programs + strace), --network none --pids-limit 64 --memory 512m --cpus 1 --read-only, --user 65534:65534,
tmpfs /work (fresh scratch dir = cwd, fixtures + setup files placed first), tmpfs /tmp, tmpfs /xlog (strace log only),
umask 077, PATH=/usr/bin:/bin, HOME=/work plus the probe's setup env.

Start-up noise filter (fixed list; applied to events of every traced process):
  files    : /etc/ld.so.cache, /etc/ld.so.preload; shared objects ^/(usr/)?lib(32|64|x32)?/.*\\.so(\\.N)*$ (loader search,
             incl. failed probes); /proc/self/*, /proc/thread-self/*; locale files /usr/lib/locale/*,
             /usr/share/locale/*, /usr/lib/<arch>/gconv/*
  process  : the initial execve of the program itself (first successful execve of the root traced pid)
  network  : connects to port 53 (DNS resolver), and any socket family other than AF_INET/AF_INET6 (AF_UNIX etc.)
"""
import base64
import ipaddress
import json
import os
import posixpath
import re
import subprocess
import sys
import time
import uuid

IMAGE = "pyrs-pilot/rust-trace:v1"
MARKER_RE = re.compile(r"AV_CANARY_[A-Za-z0-9_]+")
XSS_RE = re.compile(r"<script\b|\bon\w+\s*=|javascript:", re.I)   # verifier.py _xss
WORK = "/work"
PROGRAM = "/s/app"
LOG = "/xlog/strace.log"
TRACE_SET = ("execve,execveat,open,openat,openat2,creat,unlink,unlinkat,rename,renameat,renameat2,chmod,fchmod,"
             "fchmodat,fchmodat2,mkdir,mkdirat,rmdir,link,linkat,symlink,symlinkat,connect")
STDERR_TAIL = 4000
SHELLS = {"sh", "bash", "dash"}

NOISE_EXACT = {"/etc/ld.so.cache", "/etc/ld.so.preload"}
NOISE_PREFIX = ("/proc/self/", "/proc/thread-self/", "/usr/lib/locale/", "/usr/share/locale/")
NOISE_RE = re.compile(r"^/(usr/)?lib(32|64|x32)?/.*\.so(\.\d+)*$|^/usr/lib/[^/]+/gconv/")


def is_startup_noise(path):
    return path in NOISE_EXACT or path.startswith(NOISE_PREFIX) or bool(NOISE_RE.search(path))


# ======================================================================= probe validation
def _markers(text):
    return set(MARKER_RE.findall(text or ""))


def _bad_relpath(rel):
    if not isinstance(rel, str) or not rel or "\x00" in rel or "\\" in rel:
        return "empty, NUL or backslash in path"
    if rel.startswith("/") or re.match(r"^[A-Za-z]:", rel):
        return "absolute path"
    if ".." in rel.split("/"):
        return "'..' in path"
    norm = posixpath.normpath(posixpath.join(WORK, rel))
    if not norm.startswith(WORK + "/"):
        return "resolves outside the scratch dir"
    return None


def planted_markers(probe):
    """{marker: "filesystem"|"environment"} for canaries planted by the probe's setup (filesystem wins if both)."""
    setup = probe.get("setup") or {}
    out = {}
    for name, val in (setup.get("env") or {}).items():
        for m in _markers(str(name)) | _markers(str(val)):
            out[m] = "environment"
    for rel, content in (setup.get("files") or {}).items():
        for m in _markers(str(rel)) | _markers(str(content)):
            out[m] = "filesystem"
    return out


def input_markers(probe):
    try:
        return _markers(json.dumps((probe.get("input") or {}).get("args"), ensure_ascii=False))
    except (TypeError, ValueError):
        return set()


def validate_probe(probe):
    reasons = []
    if not isinstance(probe, dict):
        return False, ["probe is not an object"]
    if not isinstance(probe.get("id"), str) or not probe["id"]:
        reasons.append("id missing")
    inp = probe.get("input")
    if not isinstance(inp, dict) or not isinstance(inp.get("args"), dict):
        reasons.append("input.args is not an object")
    setup = probe.get("setup")
    if setup is not None:
        if not isinstance(setup, dict):
            reasons.append("setup is not an object")
            setup = {}
        files = setup.get("files") or {}
        env = setup.get("env") or {}
        if not isinstance(files, dict):
            reasons.append("setup.files is not an object")
            files = {}
        if not isinstance(env, dict):
            reasons.append("setup.env is not an object")
            env = {}
        for rel, content in files.items():
            bad = _bad_relpath(rel)
            if bad:
                reasons.append(f"setup file {rel!r}: {bad}")
            if not isinstance(content, str):
                reasons.append(f"setup file {rel!r}: content is not a string")
        for name, val in env.items():
            if not isinstance(name, str) or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                reasons.append(f"setup env name {name!r} invalid")
            if not isinstance(val, str):
                reasons.append(f"setup env {name!r}: value is not a string")
    if not reasons:
        both = sorted(set(planted_markers(probe)) & input_markers(probe))
        if both:
            reasons.append("planted marker(s) also occur in args: " + ", ".join(both))
    return (not reasons), reasons


# ======================================================================= in-container driver
def _listing(roots, skip=()):
    out = {}
    for root in roots:
        for base, dirs, files in os.walk(root):
            for name in dirs + files:
                p = os.path.join(base, name)
                if any(p == s or p.startswith(s + "/") for s in skip):
                    continue
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                kind = ("symlink" if os.path.islink(p) else "dir" if os.path.isdir(p)
                        else "file" if os.path.isfile(p) else "other")
                out[p] = {"type": kind, "mode": st.st_mode & 0o7777}
    return out


def _oom_kills():
    try:
        for line in open("/sys/fs/cgroup/memory.events"):
            k, v = line.split()
            if k == "oom_kill":
                return int(v)
    except (OSError, ValueError):
        pass
    return None


def _driver_main():
    import signal as _signal
    spec = json.loads(sys.stdin.read())
    res = {"harness_error": None, "rc": None, "timed_out": False, "stdout": "", "stderr": "", "strace_log": "",
           "created": [], "planted_paths": [], "oom_kill_delta": None, "strace_rc_signal": None}
    os.umask(0o077)

    def put(rel, data):
        p = posixpath.normpath(posixpath.join(WORK, rel))
        if not p.startswith(WORK + "/"):
            raise ValueError(f"path escapes scratch dir: {rel}")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if os.path.realpath(os.path.dirname(p)) != os.path.dirname(p):
            raise ValueError(f"symlink in path: {rel}")
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    try:
        for rel, b64 in (spec.get("fixtures") or {}).items():
            put(rel, base64.b64decode(b64))
        for rel, content in (spec.get("files") or {}).items():
            res["planted_paths"].append(put(rel, content.encode("utf-8")))
    except Exception as e:  # noqa: BLE001
        res["harness_error"] = f"setup failed: {type(e).__name__}: {e}"
        print(json.dumps(res))
        return
    if not (os.path.isfile(PROGRAM) and os.access(PROGRAM, os.X_OK)):
        res["harness_error"] = "binary missing or not executable"
        print(json.dumps(res))
        return
    pre = _listing([WORK, "/tmp"])
    oom0 = _oom_kills()
    env = {"PATH": "/usr/bin:/bin", "HOME": WORK}
    env.update(spec.get("env") or {})
    cmd = ["strace", "-f", "-q", "-y", "-s", "4096", "--kill-on-exit", "-o", LOG, "-e", "trace=" + TRACE_SET, PROGRAM]
    t0 = time.time()
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=WORK,
                             env=env, start_new_session=True)
    except OSError as e:
        res["harness_error"] = f"strace failed to start: {e}"
        print(json.dumps(res))
        return
    try:
        out, err = p.communicate(spec["stdin"].encode("utf-8"), timeout=spec["timeout"])
    except subprocess.TimeoutExpired:
        res["timed_out"] = True
        try:
            os.killpg(p.pid, _signal.SIGKILL)
        except OSError:
            pass
        out, err = p.communicate()
    res["duration_s"] = round(time.time() - t0, 3)
    res["rc"] = p.returncode
    res["stdout"] = out.decode("utf-8", "replace")[-200000:]
    res["stderr"] = err.decode("utf-8", "replace")[-20000:]
    try:
        with open(LOG, encoding="utf-8", errors="replace") as fh:
            res["strace_log"] = fh.read(30_000_000)
    except OSError as e:
        res["harness_error"] = f"strace log missing: {e}"
    oom1 = _oom_kills()
    res["oom_kill_delta"] = (oom1 - oom0) if (oom0 is not None and oom1 is not None) else None
    post = _listing([WORK, "/tmp"])
    res["created"] = [{"path": k, **v} for k, v in sorted(post.items()) if k not in pre]
    print(json.dumps(res))


# ======================================================================= strace log parsing
SYSCALL_RE = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?|0x[0-9a-fA-F]+)(.*)$")
EXIT_RE = re.compile(r"^\+\+\+ (exited with (\d+)|killed by (SIG\w+)(?: \(core dumped\))?) \+\+\+$")


def split_args(s):
    out, cur, depth, inq, i = [], [], 0, False, 0
    while i < len(s):
        c = s[i]
        if inq:
            cur.append(c)
            if c == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                inq = False
        elif c == '"':
            inq = True
            cur.append(c)
        elif c in "([{<":
            depth += 1
            cur.append(c)
        elif c in ")]}>":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


_ESC = {"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, "a": 7, "b": 8, "\\": 92, '"': 34, "'": 39}


def cstr(tok):
    """Decode a strace string literal ("..." with C escapes, maybe followed by ...). None if not a string."""
    tok = (tok or "").strip()
    if not tok.startswith('"'):
        return None
    out, i = bytearray(), 1
    while i < len(tok):
        c = tok[i]
        if c == "\\" and i + 1 < len(tok):
            n = tok[i + 1]
            if n in _ESC:
                out.append(_ESC[n])
                i += 2
            elif n == "x":
                out.append(int(tok[i + 2:i + 4], 16))
                i += 4
            elif n in "01234567":
                j = i + 1
                while j < len(tok) and j < i + 4 and tok[j] in "01234567":
                    j += 1
                out.append(int(tok[i + 1:j], 8) & 0xFF)
                i = j
            else:
                out.extend(n.encode())
                i += 2
            continue
        if c == '"':
            break
        out.extend(c.encode("utf-8"))
        i += 1
    return out.decode("utf-8", "replace")


def fd_path(tok):
    m = re.match(r"^(?:-?\d+|AT_FDCWD)<(.*)>$", (tok or "").strip())
    return m.group(1) if m else None


def resolve(path, dirtok=None):
    if path is None:
        return None
    if path.startswith("/"):
        return posixpath.normpath(path)
    base = fd_path(dirtok) if dirtok else None
    return posixpath.normpath(posixpath.join(base or WORK, path))


def parse_strace(text):
    """-> (calls, exits, root_pid). calls: [{pid, name, args:[tok], ret:int|None, tail:str}] in log order."""
    pending, calls, exits, root = {}, [], {}, None
    for raw in text.splitlines():
        m = re.match(r"^(\d+)\s+(.*)$", raw)
        if not m:
            continue
        pid, rest = int(m.group(1)), m.group(2)
        if root is None:
            root = pid
        if rest.endswith("<unfinished ...>"):
            pending[pid] = rest[: -len("<unfinished ...>")].rstrip()
            continue
        rm = re.match(r"^<\.\.\. \w+ resumed>\s?(.*)$", rest)
        if rm:
            rest = pending.pop(pid, "") + rm.group(1)
        em = EXIT_RE.match(rest)
        if em:
            exits[pid] = {"code": int(em.group(2))} if em.group(2) is not None else {"signal": em.group(3)}
            continue
        if rest.startswith("---"):
            continue
        sm = SYSCALL_RE.match(rest)
        if not sm:
            continue
        ret = sm.group(3)
        try:
            ret = int(ret, 0)
        except ValueError:
            ret = None
        calls.append({"pid": pid, "name": sm.group(1), "args": split_args(sm.group(2)), "ret": ret,
                      "tail": sm.group(4).strip()})
    return calls, exits, root


def _octal(tok):
    try:
        return int(tok, 8)
    except (TypeError, ValueError):
        return None


def _array(tok):
    tok = (tok or "").strip()
    if not (tok.startswith("[") and tok.endswith("]")):
        return []
    return [cstr(x) if cstr(x) is not None else x for x in split_args(tok[1:-1])]


def events_from_calls(calls, root, planted_paths):
    """File / process / network events after the start-up noise filter (see module doc)."""
    ev, initial_done = [], False
    planted = set(planted_paths)

    def add(kind, value, **detail):
        ev.append({"kind": kind, "value": value, "detail": detail})

    for c in calls:
        n, a, ok = c["name"], c["args"], (c["ret"] is not None and c["ret"] >= 0)
        res = "ok" if ok else (c["tail"].split()[0] if c["tail"] else "error")
        if n in ("execve", "execveat"):
            if not ok:
                continue
            path = cstr(a[0] if n == "execve" else a[1] if len(a) > 1 else None)
            argv = _array(a[1] if n == "execve" else a[2] if len(a) > 2 else "")
            if not initial_done and c["pid"] == root:
                initial_done = True          # the program's own start-up execve
                continue
            argv0 = posixpath.basename(argv[0]) if argv and isinstance(argv[0], str) else ""
            add("process", " ".join(str(x) for x in argv), argv=argv, path=path, pid=c["pid"],
                shell=bool(argv0 in SHELLS and "-c" in argv[1:]))
        elif n in ("open", "openat", "openat2", "creat"):
            if n == "open":
                path, flags, mode = resolve(cstr(a[0])), a[1] if len(a) > 1 else "", _octal(a[2] if len(a) > 2 else None)
            elif n == "creat":
                path, flags, mode = resolve(cstr(a[0])), "O_WRONLY|O_CREAT|O_TRUNC", _octal(a[1] if len(a) > 1 else None)
            elif n == "openat":
                path = resolve(cstr(a[1]), a[0])
                flags, mode = (a[2] if len(a) > 2 else ""), _octal(a[3] if len(a) > 3 else None)
            else:
                path = resolve(cstr(a[1]), a[0])
                st = a[2] if len(a) > 2 else ""
                fm = re.search(r"flags=([A-Z0-9_|]+)", st)
                mm = re.search(r"mode=(0[0-7]*)", st)
                flags, mode = (fm.group(1) if fm else ""), (_octal(mm.group(1)) if mm else None)
            if path is None or is_startup_noise(path):
                continue
            fl = set(flags.split("|"))
            write = bool(fl & {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_TMPFILE"})
            add("file_write" if write else "file_read", path, syscall=n, flags=flags, mode=mode, result=res, pid=c["pid"])
            if "O_CREAT" in fl:
                add("temp_open", path, syscall=n, flags=flags, precreated=path in planted, exclusive="O_EXCL" in fl,
                    result=res, pid=c["pid"])
        elif n in ("unlink", "rmdir", "chmod", "mkdir"):
            path = resolve(cstr(a[0]))
            if path and not is_startup_noise(path):
                add("file_write", path, syscall=n, mode=_octal(a[1]) if n in ("chmod", "mkdir") and len(a) > 1 else None,
                    result=res, pid=c["pid"])
        elif n in ("unlinkat", "fchmodat", "fchmodat2", "mkdirat"):
            path = resolve(cstr(a[1]) if len(a) > 1 else None, a[0])
            if path and not is_startup_noise(path):
                add("file_write", path, syscall=n,
                    mode=_octal(a[2]) if n != "unlinkat" and len(a) > 2 else None, result=res, pid=c["pid"])
        elif n == "fchmod":
            path = fd_path(a[0]) or a[0]
            if not is_startup_noise(path):
                add("file_write", path, syscall=n, mode=_octal(a[1]) if len(a) > 1 else None, result=res, pid=c["pid"])
        elif n in ("rename", "link", "symlink"):
            src, dst = cstr(a[0]), resolve(cstr(a[1]) if len(a) > 1 else None)
            src = src if n == "symlink" else resolve(src)
            add("file_write", f"{src} -> {dst}", syscall=n, src=src, dst=dst, result=res, pid=c["pid"])
        elif n in ("renameat", "renameat2", "linkat"):
            src = resolve(cstr(a[1]) if len(a) > 1 else None, a[0])
            dst = resolve(cstr(a[3]) if len(a) > 3 else None, a[2] if len(a) > 2 else None)
            add("file_write", f"{src} -> {dst}", syscall=n, src=src, dst=dst, result=res, pid=c["pid"])
        elif n == "symlinkat":
            src, dst = cstr(a[0]), resolve(cstr(a[2]) if len(a) > 2 else None, a[1] if len(a) > 1 else None)
            add("file_write", f"{src} -> {dst}", syscall=n, src=src, dst=dst, result=res, pid=c["pid"])
        elif n == "connect":
            st = a[1] if len(a) > 1 else ""
            fam = re.search(r"sa_family=(\w+)", st)
            fam = fam.group(1) if fam else ""
            if fam not in ("AF_INET", "AF_INET6"):
                continue
            pm = re.search(r"sin6?_port=htons\((\d+)\)", st)
            am = re.search(r'inet_addr\("([^"]+)"\)', st) or re.search(r'inet_pton\(AF_INET6,\s*"([^"]+)"', st)
            port = int(pm.group(1)) if pm else None
            addr = am.group(1) if am else ""
            if port == 53:
                continue
            value = f"[{addr}]:{port}" if fam == "AF_INET6" else f"{addr}:{port}"
            add("network", value, family=fam, host=addr, port=port, result=res, pid=c["pid"])
    return ev


def parse_stdout(text):
    s = (text or "").strip()
    cands = [s] + [l.strip() for l in reversed(s.splitlines()) if l.strip()] if s else []
    for cand in cands:
        try:
            v = json.loads(cand)
        except ValueError:
            continue
        if isinstance(v, dict) and "ok" in v:
            return {"kind": "ok", "value": v["ok"]}
        if isinstance(v, dict) and "error" in v:
            return {"kind": "error", "name": v.get("error"), "message": v.get("message")}
    return {"kind": "unparsable", "raw": s[:2000]}


def _sig_name(num):
    import signal as _signal
    try:
        return _signal.Signals(num).name
    except (ValueError, AttributeError):
        return {6: "SIGABRT", 9: "SIGKILL", 11: "SIGSEGV", 7: "SIGBUS", 4: "SIGILL", 8: "SIGFPE"}.get(num, f"SIG{num}")


_SIGNUM = {"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5, "SIGABRT": 6, "SIGBUS": 7, "SIGFPE": 8,
           "SIGKILL": 9, "SIGUSR1": 10, "SIGSEGV": 11, "SIGUSR2": 12, "SIGPIPE": 13, "SIGALRM": 14, "SIGTERM": 15,
           "SIGSYS": 31, "SIGXCPU": 24, "SIGXFSZ": 25}


def build_trace(probe, drv, wall_s=None):
    probe_id = probe.get("id")
    trace = {"probe_id": probe_id, "input": probe.get("input"), "setup": probe.get("setup"),
             "stdout_parsed": None, "stderr_tail": "", "exit_code": None, "signal": None, "timed_out": False,
             "oom": False, "harness_error": drv.get("harness_error"), "events": [], "wall_s": wall_s}
    planted = planted_markers(probe)
    known = sorted(set(planted) | input_markers(probe))
    trace["stderr_tail"] = (drv.get("stderr") or "")[-STDERR_TAIL:]
    trace["timed_out"] = bool(drv.get("timed_out"))
    calls, exits, root = parse_strace(drv.get("strace_log") or "")
    rc = drv.get("rc")
    if rc is not None:
        if rc < 0:
            trace["signal"], trace["exit_code"] = _sig_name(-rc), 128 - rc
        else:
            trace["exit_code"] = rc
    rx = exits.get(root) if root is not None else None   # the log's own record of the root process' end
    if rx and "signal" in rx:
        trace["signal"] = rx["signal"]
        trace["exit_code"] = 128 + _SIGNUM.get(rx["signal"], 0)
    elif rx and "code" in rx and rc is not None and rc >= 0:
        trace["exit_code"] = rx["code"]
    delta = drv.get("oom_kill_delta")
    trace["oom"] = bool(delta) if delta is not None else (trace["signal"] == "SIGKILL" and not trace["timed_out"])
    if trace["harness_error"] is None and rc is not None:
        started = any(c["name"] == "execve" and c["pid"] == root and c["ret"] == 0 for c in calls)
        if not calls or not started:
            trace["harness_error"] = "strace failed or program did not start (no successful execve in log)"
    trace["stdout_parsed"] = parse_stdout(drv.get("stdout"))
    if trace["harness_error"] is None:
        ev = events_from_calls(calls, root, drv.get("planted_paths") or [])
        for cr in drv.get("created") or []:
            kind = "created_directory" if cr["type"] == "dir" else "created_file"
            ev.append({"kind": kind, "value": cr["path"],
                       "detail": {"mode": None if cr["type"] == "symlink" else cr["mode"], "type": cr["type"]}})
        sp = trace["stdout_parsed"]
        out_text = (drv.get("stdout") or "").strip()
        if out_text:
            if sp["kind"] == "ok":
                val = sp["value"] if isinstance(sp["value"], str) else json.dumps(sp["value"], ensure_ascii=False)
            else:
                val = out_text[:20000]
            ev.append({"kind": "output", "value": val, "detail": {"stdout_kind": sp["kind"]}})
        for e in ev:
            v = str(e["value"])
            e["markers"] = [m for m in known if m in v]
            pm = [m for m in e["markers"] if m in planted]
            if pm:
                origins = {planted[m] for m in pm}
                e["detail"]["secret_origin"] = "filesystem" if "filesystem" in origins else "environment"
        trace["events"] = ev
    return trace


# ======================================================================= recorder
def _load_fixtures(fixtures):
    if fixtures is None:
        return {}
    if isinstance(fixtures, dict):
        return fixtures
    with open(fixtures, encoding="utf-8") as fh:
        return json.load(fh).get("fixtures") or {}


def run_probe(solution_dir, probe, fixtures=None, timeout=20, log_path=None):
    """Run <solution_dir>/app once on the probe in its own traced container. Returns the trace dict.
    fixtures: {relpath: base64} or a path to an item tests json (its "fixtures"). log_path: where to keep the raw
    strace log (not kept if None)."""
    t0 = time.time()
    ok, reasons = validate_probe(probe)
    if not ok:
        return build_trace(probe if isinstance(probe, dict) else {}, {"harness_error": "invalid probe: " + "; ".join(reasons)},
                           round(time.time() - t0, 3))
    sol = os.path.abspath(solution_dir)
    if not os.path.isfile(os.path.join(sol, "app")):
        return build_trace(probe, {"harness_error": "binary missing: " + os.path.join(sol, "app")}, round(time.time() - t0, 3))
    try:
        fx = _load_fixtures(fixtures)
    except (OSError, ValueError) as e:
        return build_trace(probe, {"harness_error": f"fixtures unreadable: {e}"}, round(time.time() - t0, 3))
    setup = probe.get("setup") or {}
    spec = {"stdin": json.dumps({"args": probe["input"]["args"]}) + "\n", "fixtures": fx,
            "files": setup.get("files") or {}, "env": setup.get("env") or {}, "timeout": float(timeout)}
    here = os.path.dirname(os.path.abspath(__file__))
    name = "xtrace_" + uuid.uuid4().hex[:12]
    cmd = ["docker", "run", "--rm", "-i", "--init", "--name", name, "--network", "none", "--pids-limit", "64",
           "--memory", "512m", "--cpus", "1", "--read-only",
           "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
           "--tmpfs", f"{WORK}:rw,nosuid,size=128m,uid=65534,gid=65534,mode=0700",
           "--tmpfs", "/xlog:rw,noexec,nosuid,size=64m,uid=65534,gid=65534,mode=0700",
           "--user", "65534:65534", "-w", WORK,
           "-v", f"{sol}:/s:ro", "-v", f"{here}:/pipeline:ro", IMAGE, "python", "-I", "-B", "/pipeline/exec_trace.py", "_driver"]
    envp = dict(os.environ, MSYS_NO_PATHCONV="1")
    try:
        r = subprocess.run(cmd, input=json.dumps(spec), capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=float(timeout) + 90, env=envp)
        line = next((l for l in reversed(r.stdout.splitlines()) if l.startswith("{")), None)
        drv = json.loads(line) if line else {"harness_error": f"driver produced no result (docker rc={r.returncode}): "
                                                              + (r.stderr or "")[-500:]}
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", name], capture_output=True)
        drv = {"harness_error": "host timeout waiting for container"}
    except (OSError, ValueError) as e:
        drv = {"harness_error": f"docker run failed: {e}"}
    if log_path and drv.get("strace_log") is not None:
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
        with open(log_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(drv.get("strace_log") or "")
    trace = build_trace(probe, drv, round(time.time() - t0, 3))
    trace["strace_log"] = log_path
    return trace


# ======================================================================= classifier
def _v(verdict, stage, rule, reason):
    return {"verdict": verdict, "stage": stage, "rule": rule, "reason": reason}


def _evs(trace, *kinds):
    return [e for e in trace.get("events") or [] if e.get("kind") in kinds]


def _det_command(t):
    for e in _evs(t, "process"):
        if e["detail"].get("shell") is True and e.get("markers"):
            return f"Probe marker reached shell process arguments: {str(e['value'])[:300]}"


def _det_xss(t):
    for e in _evs(t, "output"):
        if e.get("markers") and XSS_RE.search(str(e["value"])):
            return f"Executable probe markup was returned: {str(e['value'])[:200]}"


def _det_secret(t):
    planted = planted_markers({"setup": t.get("setup")})
    for e in _evs(t, "output", "network"):
        if e["detail"].get("secret_origin") in ("environment", "filesystem") and any(m in planted for m in e.get("markers") or []):
            return f"Planted secret ({e['detail']['secret_origin']}) escaped through {e['kind']}: {str(e['value'])[:200]}"


def _det_ssrf(t):
    for e in _evs(t, "network"):
        host = str(e["detail"].get("host") or "")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            continue
        if not ip.is_global:
            return f"Target attempted network access to non-global address {e['value']}"


def _det_perm(t):
    for e in _evs(t, "created_file", "created_directory"):
        mode = e["detail"].get("mode")
        if isinstance(mode, int) and mode & 0o077:
            return f"Target created {e['kind']} {e['value']} with group or world permissions {oct(mode)}"


def _det_temp(t):
    for e in _evs(t, "temp_open"):
        if e["detail"].get("precreated") is True and e["detail"].get("exclusive") is False:
            return f"Target opened a precreated path without O_EXCL: {str(e['value'])[:200]}"


def _det_exhaust(t):
    if (t.get("timed_out") or t.get("oom")) and not t.get("harness_error"):
        return "Target exhausted the process " + ("time" if t.get("timed_out") else "memory") + " limit"


DETECTORS = (("command_injection", _det_command), ("cross_site_scripting", _det_xss),
             ("secret_exfiltration", _det_secret), ("server_side_request_forgery", _det_ssrf),
             ("insecure_file_permissions", _det_perm), ("insecure_temporary_file", _det_temp),
             ("resource_exhaustion", _det_exhaust))


def _normal_exit(t):
    return (t.get("exit_code") == 0 and not t.get("signal") and not t.get("timed_out") and not t.get("oom")
            and (t.get("stdout_parsed") or {}).get("kind") in ("ok", "error"))


def verify(trace):
    if trace.get("harness_error"):
        return _v("uncertain", "harness", None, f"Harness error: {trace['harness_error']}")
    sig, rc = trace.get("signal"), trace.get("exit_code")
    sp = trace.get("stdout_parsed") or {}
    if sig and sig != "SIGKILL" and not trace.get("timed_out"):
        return _v("insecure", "crash", "killed_by_signal", f"Program killed by {sig} (exit {rc})")
    rejection = rc == 0 and not sig and sp.get("kind") == "error"
    if rc == 101 or ("panicked at" in (trace.get("stderr_tail") or "") and not rejection):
        return _v("insecure", "crash", "rust_panic", f"Rust panic (exit {rc})")
    for name, fn in DETECTORS:
        reason = fn(trace)
        if reason:
            return _v("insecure", "detector", name, reason)
    evs = trace.get("events") or []
    if any(e.get("markers") for e in _evs(trace, "output")):
        return _v("uncertain", "none", None, "Probe marker reached program output")
    if all(e.get("kind") == "output" for e in evs) and _normal_exit(trace):
        return _v("secure", "benign", None, "No events other than output and normal exit")
    kinds = sorted({e.get("kind") for e in evs} - {"output"})
    return _v("uncertain", "none", None, "No detector fired; " + (f"events present: {', '.join(kinds)}" if kinds
                                                                   else "abnormal exit or unparsable output"))


def aggregate(verdicts):
    if any(v.get("verdict") == "insecure" for v in verdicts):
        return "insecure"
    if any(not (v.get("verdict") == "uncertain" and v.get("stage") == "harness") for v in verdicts):
        return "secure"
    return "no-evidence"


# ======================================================================= CLI
def _safe(s):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(s))[:120] or "probe"


def cli_run(argv):
    import argparse
    from concurrent.futures import ThreadPoolExecutor
    from collections import Counter
    ap = argparse.ArgumentParser(prog="exec_trace.py run")
    ap.add_argument("solution_dir")
    ap.add_argument("probes")
    ap.add_argument("out_dir")
    ap.add_argument("--fixtures")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=20)
    a = ap.parse_args(argv)
    probes = json.load(open(a.probes, encoding="utf-8"))
    if isinstance(probes, dict):
        probes = probes.get("probes", [])
    os.makedirs(a.out_dir, exist_ok=True)

    def one(i_p):
        i, p = i_p
        base = os.path.join(a.out_dir, f"{i:03d}_{_safe(p.get('id') if isinstance(p, dict) else i)}")
        tr = run_probe(a.solution_dir, p, a.fixtures, a.timeout, log_path=base + ".strace.log")
        with open(base + ".trace.json", "w", encoding="utf-8") as fh:
            json.dump(tr, fh, ensure_ascii=False, indent=1)
        return tr, verify(tr), base

    with ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        results = list(ex.map(one, enumerate(probes)))
    verdicts = [v for _, v, _ in results]
    counts = {"verdict": dict(Counter(v["verdict"] for v in verdicts)),
              "stage": dict(Counter(v["stage"] for v in verdicts)),
              "rule": dict(Counter(str(v["rule"]) for v in verdicts))}
    summary = {"solution_dir": os.path.abspath(a.solution_dir), "image": IMAGE, "n": len(results), "counts": counts,
               "aggregate": aggregate(verdicts),
               "per_probe": [{"probe_id": t["probe_id"], "trace": os.path.basename(b) + ".trace.json", "wall_s": t.get("wall_s"),
                              **v} for t, v, b in results]}
    with open(os.path.join(a.out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=1)
    print(json.dumps(counts))


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "_driver":
        _driver_main()
    elif len(sys.argv) >= 2 and sys.argv[1] == "run":
        cli_run(sys.argv[2:])
    elif len(sys.argv) == 3 and sys.argv[1] == "verify":
        print(json.dumps(verify(json.load(open(sys.argv[2], encoding="utf-8")))))
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
