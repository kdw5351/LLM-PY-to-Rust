#!/usr/bin/env python3
"""과제별 메모리 한도 산정용: 참조 구현(python, rust)을 기능 테스트의 올바른 입력으로 돌려 피크 RSS 를 잰다.

제안서 6절: 과제별 메모리 한도 = 두 언어 참조 구현의 정상 입력 피크 메모리의 2배.
측정값을 config.toml [tasks_cfg.<task>] mem_limit 에 적는다. psutil 이 있으면 자식 프로세스 폴링으로,
없으면 Linux/macOS 의 resource.getrusage(RUSAGE_CHILDREN) 로 잰다(Windows 는 psutil 필요: pip install psutil).

    python -m harness.measure_memory [--tasks T1_safetensors_header ...]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness import runner, sandbox  # noqa: E402

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


def peak_rss(cmd: list[str], cwd: Path, env: dict, timeout: int) -> int | None:
    """바이트 단위 피크 RSS(자식 포함). 잴 수 없으면 None."""
    if psutil is not None:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ps = psutil.Process(proc.pid)
        peak = 0
        stop = threading.Event()

        def poll():
            nonlocal peak
            while not stop.is_set():
                try:
                    total = ps.memory_info().rss + sum(c.memory_info().rss for c in ps.children(recursive=True))
                    peak = max(peak, total)
                except Exception:
                    pass
                time.sleep(0.01)
        t = threading.Thread(target=poll, daemon=True)
        t.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
        stop.set()
        t.join()
        return peak
    if os.name != "nt":
        import resource
        before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        unit = 1024 if sys.platform != "darwin" else 1
        return max(after, before) * unit
    return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", nargs="*", default=None)
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    cfg = runner.load_config()
    if psutil is None and os.name == "nt":
        print("psutil 이 없어 Windows 에서는 잴 수 없다. `pip install psutil` 뒤 다시 실행.")
        return 1
    out = {}
    for task in args.tasks or cfg["run"]["tasks"]:
        task_dir = ROOT / "tasks" / task
        func, _ = runner.load_cases(task_dir)
        if "server" in func:
            print(f"{task}: 서버 과제는 이 스크립트로 재지 않는다(수동).")
            continue
        peaks = {}
        for lang in ("python", "rust"):
            sol = task_dir / "reference" / lang
            if not (sol / ("main.py" if lang == "python" else "Cargo.toml")).exists():
                continue
            ok, _ = sandbox.build(sol, lang, cfg)
            if not ok:
                print(f"{task} {lang}: build failed")
                continue
            worst = 0
            for c in func["cases"]:
                scratch = runner._fresh_scratch(ROOT / "results" / "_scratch" / "mem", f"{task}_{lang}_{c['id']}")
                mapping = runner._mapping(scratch)
                runner.stage_scratch(task_dir, c, scratch, mapping)
                env = dict(os.environ)
                env["CANARY_DIR"] = str(scratch / "canary")
                env["PATH"] = str(ROOT / "tools") + os.pathsep + env.get("PATH", "")
                pk = peak_rss(sandbox.cmd_prefix(sol, lang, cfg) + runner.subst(c["args"], mapping), scratch, env,
                              cfg["sandbox"]["timeout_s"])
                worst = max(worst, pk or 0)
            peaks[lang] = worst
        if peaks:
            mx = max(peaks.values())
            rec = {"peak_mb": {k: round(v / 2**20, 1) for k, v in peaks.items()},
                   "suggested_mem_limit": f"{max(64, int(2 * mx / 2**20) + 1)}m"}
            out[task] = rec
            print(f"{task}: peak {rec['peak_mb']} MB -> mem_limit = \"{rec['suggested_mem_limit']}\"")
    (ROOT / "results" / "memory_limits.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print("저장: results/memory_limits.json — 값을 config.toml [tasks_cfg.<task>] mem_limit 에 적는다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
