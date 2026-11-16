"""번역(실험 A) 드라이버. 번역 3단계 프로토콜 tf1 (완화조건_재설계_2026-11-13.md 2절, SafeTrans 순서)과 옛 방식(off)을 함께 돌린다.
모델을 부르지 않는다. 답은 다른 에이전트가 파일로 쓴다. hk6_driver.py 는 고치지 않는다(이 파일이 그 실험 A 부분을 대신한다).

  1 번역       : 요청 그대로(translate.prompt, 기본 v2). prompts/<key>__r0.txt  (key = item__source__cond)
  2 빌드 고치기 : 최신 코드 + 최신 컴파일 오류(translate.fix_prompt). 최대 3번(off) / 5번(tf1).
  3 보이는 시험 : tf1 만. 빌드된 번역에 <visible_root>/<item>.json 의 시험을 돌린다(runner.py, Docker --network none, 10초).
                 passed 가 아니면 첫 실패 시험의 분류(failed/runtime/loop/compile)로 SafeTrans 요청문 하나(translate.visible_fix_prompt).
                 최대 5번. 받은 답마다 다시 빌드·시험. passed 이거나 5번이면 멈춘다.
  요청 번호 r 은 세 단계를 이어서 센다. r>0 요청은 이어지는 대화다: [r0 요청] → [답 r-1 (최신 코드)] → [요청 r]. 쌓인 기록은 보내지 않는다.
  T0 = 2단계 끝의 프로그램(<run>/t0/<key>/, 항상 저장). T1 = 3단계에서 passed 한 후보, 없으면 3단계에서 마지막으로 빌드된 후보,
  그것도 없으면 T0. T1 은 solutions/<key>/ 에 둔다(다음 단계가 읽는 자리). 평가는 eval_run.py 가 T1(주 결과)과 T0(row["t0"])를 판정한다.

요청 묶음(manifest): <prefix>_batches/A<round>_<group>_NN.txt, 한 줄 = "<요청 .txt 절대 경로>\\t<답 .md 절대 경로>", 묶음당 최대 28줄.
  group = vul / pat (Py→Rs), pypy_vul / pypy_pat (Py→Py). 취약판·수정판은 같은 묶음에 넣지 않는다.
실행 폴더는 <root>/<prefix>_A (hk6_A 와 같은 배치). eval 이 targets.json 을 쓰므로 hk6_driver.py --prefix <prefix> b4-init 부터 이어 쓸 수 있다.
내보내기 폴더: init 때의 환경 변수 PYRS_EXPORT_ROOT(없으면 export/)를 config.json 에 적고, 이후 명령은 그 값을 쓴다.
출력은 개수와 키만. 시험 입력·기대값은 출력하지 않는다.

usage (dataset_pilot 폴더에서):
  python tr_driver.py init  --items <ids file> [--protocol tf1|off] [--visible-root visible_tests] [--conds PyRs[,PyPy]]
  python tr_driver.py round [--jobs 4]      (반복: 답이 오면 다시 실행, DONE 이 나올 때까지)
  python tr_driver.py status
  python tr_driver.py eval  [--force]
  공통 선택: --prefix <이름> (실행 폴더 <prefix>_A, 묶음 <prefix>_batches), --root <폴더> (기본: 이 파일의 폴더)
시험용 환경 변수 TR_FETCH_OFFLINE=1: cargo fetch 컨테이너도 --network none 으로(받아 둔 크레이트만 씀). 기본은 기존 빌드 그대로.
"""
import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HOME = Path(__file__).resolve().parent
PIPE = HOME / "pipeline"
MAXLINES = 28
DEFAULT_MODEL = "claude-code-subagent(sonnet)"     # pilot_job.py ingest-a 와 같은 기본값(config "model" 로 바꿈)


def jl(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def js(p, d):
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    Path(p).write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def vp(source):
    return "vul" if source == "vulnerable" else "pat"


def lang_of(cond):
    return "rust" if cond == "PyRs" else "python"


# ---------- 내보내기 폴더와 모듈 ----------
def use_export(conf):
    """config 의 내보내기 폴더를 환경 변수로 고정한 뒤 파이프라인 모듈을 읽는다."""
    want = conf.get("export_root")
    env = os.environ.get("PYRS_EXPORT_ROOT")
    if want:
        if env and Path(env).resolve() != Path(want).resolve():
            sys.exit(f"PYRS_EXPORT_ROOT differs from this run's export_root ({want})")
        if Path(want).resolve() != (HOME / "export").resolve():
            os.environ["PYRS_EXPORT_ROOT"] = want
    sys.path.insert(0, str(PIPE))
    import translate as t
    import harden_job as hj
    if os.environ.get("TR_FETCH_OFFLINE") == "1":
        real = t.docker

        def docker_offline(args, timeout=900):
            a = list(args)
            if "--network" in a and a[a.index("--network") + 1] == "bridge":
                a[a.index("--network") + 1] = "none"
                a[a.index(t.RUST_IMAGE):a.index(t.RUST_IMAGE)] = ["-e", "CARGO_NET_OFFLINE=true"]
            return real(a, timeout)
        t.docker = docker_offline
    return t, hj


def build_iso(t, hj, sol, key):
    """pilot_job.build_iso 와 같다: 번역마다 따로 쓰는 빌드 볼륨, 빌드 전 소스 수정 시각 갱신(hj.build)."""
    t.TARGET_VOL = "dsp-pilot-" + hashlib.sha256(str(key).encode()).hexdigest()[:12]
    return hj.build(sol)


def check(t, hj, sol, key, lang):
    return build_iso(t, hj, sol, key) if lang == "rust" else t.check_py(sol)


def write_code(t, sol, text, lang):
    return t.write_rust(sol, text) if lang == "rust" else t.write_py(sol, text)


def src_files(sol, lang):
    names = ("Cargo.toml", "src/main.rs") if lang == "rust" else ("main.py",)
    return [(Path(sol) / n).read_bytes() if (Path(sol) / n).exists() else None for n in names]


# ---------- 묶음 (hk6_driver.py 와 같은 규칙) ----------
def manifested(bdir):
    out = set()
    for f in bdir.glob("*.txt"):
        for l in f.read_text(encoding="utf-8").splitlines():
            if "\t" in l:
                out.add(l.split("\t", 1)[0])
    return out


def next_round(bdir, letter):
    ns = [int(m.group(1)) for f in bdir.glob(f"{letter}*_*.txt") if (m := re.match(rf"^{letter}(\d+)_", f.name))]
    return max(ns, default=0) + 1


def write_manifests(bdir, entries, name_of):
    bdir.mkdir(parents=True, exist_ok=True)
    seen = manifested(bdir)
    groups = collections.defaultdict(list)
    for g, p, r in entries:
        p, r = str(Path(p).resolve()), str(Path(r).resolve())
        if p not in seen:
            Path(r).parent.mkdir(parents=True, exist_ok=True)
            groups[g].append(f"{p}\t{r}")
    written = []
    for g in sorted(groups):
        lines = sorted(groups[g])
        i = 0
        for k in range(0, len(lines), MAXLINES):
            while True:
                i += 1
                f = bdir / f"{name_of(g)}_{i:02d}.txt"
                if not f.exists():
                    break
            f.write_text("\n".join(lines[k:k + MAXLINES]) + "\n", encoding="utf-8")
            written.append((f.name, len(lines[k:k + MAXLINES])))
    for n, c in written:
        print(f"  manifest {n}: {c} lines")
    if not written:
        print("  (no new manifests)")
    return written


def group_of(key):
    _, source, cond = key.split("__")
    return vp(source) if cond == "PyRs" else f"pypy_{vp(source)}"


# ---------- 상태 ----------
def keys_of(A):
    keys = collections.defaultdict(set)
    for p in (A / "prompts").glob("*__r*.txt"):
        k, r = p.stem.rsplit("__r", 1)
        keys[k].add(int(r))
    return keys


def next_reply(A, key, rounds):
    """이 번역에서 지금 받아들일 답의 round(없으면 None). hk6_driver.a_next_reply 와 같다."""
    if (A / "logs" / f"{key}.json").exists():
        return None
    sp = A / "state" / f"{key}.json"
    done = {c["round"] for c in jl(sp)["calls"]} if sp.exists() else set()
    for r in sorted(rounds):
        if r in done:
            continue
        return r if (A / "replies" / f"{key}__r{r}.md").exists() else None
    return None


def pending(A):
    """답을 기다리는 요청 [(group, prompt, reply)]."""
    out = []
    for k, rs in sorted(keys_of(A).items()):
        if (A / "logs" / f"{k}.json").exists():
            continue
        r = max(rs)
        if not (A / "replies" / f"{k}__r{r}.md").exists():
            out.append((group_of(k), A / "prompts" / f"{k}__r{r}.txt", A / "replies" / f"{k}__r{r}.md"))
    return out


# ---------- 답 하나 받기 (자식 프로세스: 빌드 볼륨 이름이 전역 값이라 번역마다 따로 돈다) ----------
def finish(A, conf, st, key, lang, t):
    sol = A / "solutions" / key
    if lang == "python" and st.get("built"):
        src = (Path(conf["source_root"]) / st["item"] / f"{st['source']}.py").read_text(encoding="utf-8")
        st["similarity"] = round(t.similarity(src, (sol / "main.py").read_text(encoding="utf-8")), 3)
        st["copied"] = st["similarity"] >= 0.90
    js(A / "state" / f"{key}.json", st)
    js(A / "logs" / f"{key}.json", st)


def finish_tf(A, conf, st, key, lang, t, t1_dir=None, t1_from="t0"):
    """T1 을 solutions/<key> 에 두고 기록을 마친다."""
    sol, t0 = A / "solutions" / key, A / "t0" / key
    if t1_dir is not None:
        if sol.exists():
            shutil.rmtree(sol)
        shutil.copytree(t1_dir, sol)
    st["t1_from"] = t1_from
    st["t1_differs"] = bool(st.get("t0_built")) and src_files(sol, lang) != src_files(t0, lang)
    vs = st.get("visible", [])                  # 첫 칸 = T0 의 분류, 그 뒤 = 3단계 후보마다
    st["visible_classes"] = [v["class"] for v in vs]
    st["visible_rounds"] = sum(1 for v in vs if v["candidate"] != "t0")
    st["visible_repair_triggered"] = st["visible_rounds"] > 0
    if not st.get("t0_built"):
        st["visible_pass"] = False              # 빌드되지 않음(보이는 시험을 돌리지 않음)
    elif not vs:
        st["visible_pass"] = None               # 보이는 시험 없음(3단계 건너뜀)
    else:                                       # T1 으로 고른 프로그램의 분류
        st["visible_pass"] = next(v["class"] for v in vs if v["candidate"] == t1_from) == "passed"
    st["calls_per_stage"] = {"translate": 1, "build_fix": st["fix_rounds"], "visible_fix": st["visible_rounds"]}
    finish(A, conf, st, key, lang, t)
    print("DONE", "built" if st["built"] else "not_built", "visible", st.get("stage3"), "classes",
          ",".join(st["visible_classes"]) or "-", "t1", t1_from, "differs", st["t1_differs"])


def visible_step(A, conf, st, key, lang, t, sol, cand_tag):
    """sol 에 보이는 시험을 돌려 분류를 기록한다. 반환: (분류, 첫 실패 시험, 그 실행 기록)."""
    tests = t.load_visible(conf["visible_root"], st["item"])
    runs = t.run_visible(A / "_visible" / key / cand_tag, sol, lang, st["item"], tests)
    cls, first, per = t.classify_visible(tests, runs)
    st.setdefault("visible", []).append({"candidate": cand_tag, "built": True, "class": cls, "first_fail": first,
                                         "per_test": dict(collections.Counter(per))})
    return cls, (tests[first] if first is not None else None), (runs[first] if first is not None else None)


def ask_visible(A, st, key, lang, t, rnd, cls, test=None, run=None, blog=None):
    (A / "prompts" / f"{key}__r{rnd + 1}.txt").write_text(
        t.visible_fix_prompt(lang, cls, test=test, run=run, build_log=blog), encoding="utf-8")
    js(A / "state" / f"{key}.json", st)
    print("VFIX", rnd + 1, cls)


def ingest_one(A, key, rnd):
    conf = jl(A / "config.json")
    t, hj = use_export(conf)
    tf = conf.get("translate_protocol") == t.TF1
    item, source, cond = key.split("__")
    lang = lang_of(cond)
    sol = A / "solutions" / key
    sp = A / "state" / f"{key}.json"
    st = jl(sp) if sp.exists() else {"item": item, "source": source, "cond": cond, "model": conf.get("model", DEFAULT_MODEL),
                                     "calls": [], "regen": 0, "copied": False, "source_dir": conf["source_dir"]}
    if tf:
        st.setdefault("protocol", t.TF1)
    text = (A / "replies" / f"{key}__r{rnd}.md").read_text(encoding="utf-8")
    stage3 = tf and st.get("stage3") == "running"
    call = {"kind": "translate" if rnd == 0 else ("visible_fix" if stage3 else "fix"), "round": rnd, "response": text}
    if tf:
        call["stage"] = 1 if rnd == 0 else (3 if stage3 else 2)
    st["calls"].append(call)

    if stage3:                                     # ---- 3단계: 보이는 시험으로 고치기 ----
        tag = f"r{rnd}"
        cdir = A / "vcand" / key / tag
        if cdir.exists():
            shutil.rmtree(cdir)
        wrote = write_code(t, cdir, text, lang)
        built, blog = check(t, hj, cdir, key, lang) if wrote else (False, "no code block in reply")
        if built:
            cls, test, run = visible_step(A, conf, st, key, lang, t, cdir, tag)
        else:
            cls, test, run = "compile", None, None
            st["visible"].append({"candidate": tag, "built": False, "class": "compile", "first_fail": None,
                                  "build_log_tail": blog[-1500:]})
        k = sum(1 for v in st["visible"] if v["candidate"] != "t0")
        if cls == "passed":
            st["stage3"] = "passed"
            return finish_tf(A, conf, st, key, lang, t, cdir, tag)
        if k >= t.MAX_VISIBLE_FIX:
            st["stage3"] = "exhausted"
            last = [v["candidate"] for v in st["visible"] if v["candidate"] != "t0" and v["built"]]
            if last:
                return finish_tf(A, conf, st, key, lang, t, A / "vcand" / key / last[-1], last[-1])
            return finish_tf(A, conf, st, key, lang, t)
        return ask_visible(A, st, key, lang, t, rnd, cls, test, run, blog)

    # ---- 1·2단계: 번역, 빌드 고치기 (pilot_job.py ingest-a 와 같은 순서) ----
    if rnd == 0 and sol.exists():
        shutil.rmtree(sol)
    wrote = write_code(t, sol, text, lang)
    if not wrote and not (sol.exists() and any(sol.iterdir())):
        built, blog = False, "no code block in reply"
    else:
        built, blog = check(t, hj, sol, key, lang)
    if not built and rnd < t.MAX_BUILD_FIX[t.TF1 if tf else None]:
        (A / "prompts" / f"{key}__r{rnd + 1}.txt").write_text(t.fix_prompt(lang, blog), encoding="utf-8")
        js(sp, st)
        print("FIX", rnd + 1)
        return
    st.update({"built": built, "fix_rounds": rnd, "build_log_tail": blog[-1500:]})
    if not tf:
        finish(A, conf, st, key, lang, t)
        print("BUILT" if built else "FAILED", "fix_rounds", rnd, "similarity", st.get("similarity"))
        return
    t0 = A / "t0" / key                            # T0: 3단계 직전 프로그램(항상 저장)
    if t0.exists():
        shutil.rmtree(t0)
    if sol.exists():
        shutil.copytree(sol, t0)
    st["t0_built"] = built
    st["t0_dir"] = f"t0/{key}"
    st["visible_tests"] = len(t.load_visible(conf["visible_root"], item))
    if not built:
        st["stage3"] = "skipped_not_built"
        return finish_tf(A, conf, st, key, lang, t)
    if not st["visible_tests"]:
        st["stage3"] = "skipped_no_tests"
        return finish_tf(A, conf, st, key, lang, t)
    cls, test, run = visible_step(A, conf, st, key, lang, t, sol, "t0")
    if cls == "passed":
        st["stage3"] = "not_triggered"
        return finish_tf(A, conf, st, key, lang, t)
    st["stage3"] = "running"
    return ask_visible(A, st, key, lang, t, rnd, cls, test, run)


# ---------- 명령 ----------
def cmd_init(root, prefix, a):
    A, bdir = root / f"{prefix}_A", root / f"{prefix}_batches"
    if (A / "config.json").exists():
        print("A run already initialised (skipping init)")
        conf = jl(A / "config.json")
    else:
        env = os.environ.get("PYRS_EXPORT_ROOT")
        exp = Path(env).resolve() if env else (HOME / "export")
        nc = exp / "programs_nc"
        try:
            src_dir = nc.resolve().relative_to(HOME.resolve()).as_posix()
        except ValueError:
            src_dir = str(nc)
        proto = None if a.protocol == "off" else a.protocol
        conf = {"translate_prompt": a.prompt}
        if proto:
            if not a.visible_root:
                sys.exit("--visible-root is required with a translation protocol")
            conf.update({"translate_protocol": proto, "visible_root": str(Path(a.visible_root).resolve())})
        conf.update({"export_root": str(exp.resolve()), "source_root": str(nc.resolve()), "source_dir": src_dir,
                     "conds": a.conds.split(","), "items_file": str(Path(a.items).resolve())})
        if a.model:
            conf["model"] = a.model
        for d in ("prompts", "replies", "solutions", "logs", "state"):
            (A / d).mkdir(parents=True, exist_ok=True)
        js(A / "config.json", conf)
        t, _ = use_export(conf)
        n = 0
        for item in Path(a.items).read_text().split():
            for source in ("vulnerable", "patched"):
                src = (nc / item / f"{source}.py").read_text(encoding="utf-8")
                for cond in conf["conds"]:
                    (A / "prompts" / f"{item}__{source}__{cond}__r0.txt").write_text(
                        t.prompt(lang_of(cond), src, conf["translate_prompt"]), encoding="utf-8")
                    n += 1
        print("translation requests:", n, "| protocol:", conf.get("translate_protocol", "off"), "| export:", conf["export_root"])
    ent = pending(A)
    if any(str(e[1].resolve()) not in manifested(bdir) for e in ent):
        rnd = next_round(bdir, "A")
        write_manifests(bdir, ent, lambda g: f"A{rnd}_{g}")


def cmd_round(root, prefix, a):
    A, bdir = root / f"{prefix}_A", root / f"{prefix}_batches"
    keys = keys_of(A)
    todo = [(k, r) for k, rs in sorted(keys.items()) if (r := next_reply(A, k, rs)) is not None]
    print("replies to ingest:", len(todo), "(build/run in Docker)")

    def one(kr):
        k, r = kr
        res = subprocess.run([sys.executable, "-X", "utf8", str(Path(__file__).resolve()), "_ingest", str(A), k, str(r)],
                             cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if res.returncode != 0:
            return k, "ERROR", res.stderr.strip().splitlines()[-3:]
        return k, ((res.stdout.strip().splitlines() or ["?"])[-1].split() or ["?"])[0], None
    with ThreadPoolExecutor(max(1, a.jobs)) as ex:
        out = list(ex.map(one, todo))
    print("outcomes:", dict(collections.Counter(o for _, o, _ in out)))
    for k, o, err in out:
        if o == "ERROR":
            print("  error:", k, "|", " / ".join(err or []))
    ent = pending(A)
    new = [e for e in ent if str(e[1].resolve()) not in manifested(bdir)]
    if new:
        rnd = next_round(bdir, "A")
        print(f"new requests: {len(new)} -> round A{rnd}")
        write_manifests(bdir, new, lambda g: f"A{rnd}_{g}")
    keys = keys_of(A)
    fin = sum(1 for k in keys if (A / "logs" / f"{k}.json").exists())
    print(f"translations: {len(keys)}, finished: {fin}, waiting for a reply: {len(ent)}")
    if fin == len(keys):
        print("DONE")


def cmd_status(root, prefix, a):
    A = root / f"{prefix}_A"
    keys = keys_of(A)
    c = collections.Counter()
    for k in keys:
        if (A / "logs" / f"{k}.json").exists():
            c["finished"] += 1
        elif next_reply(A, k, keys[k]) is not None:
            c["reply_ready"] += 1
        else:
            c["waiting"] += 1
    print("translations:", len(keys), dict(c))


def cmd_eval(root, prefix, a):
    A = root / f"{prefix}_A"
    conf = jl(A / "config.json")
    keys = keys_of(A)
    unfinished = [k for k in keys if not (A / "logs" / f"{k}.json").exists()]
    if unfinished and not a.force:
        print(f"{len(unfinished)} translations not finished (run round first, or --force)")
        sys.exit(1)
    env = dict(os.environ)
    if Path(conf["export_root"]).resolve() != (HOME / "export").resolve():
        env["PYRS_EXPORT_ROOT"] = conf["export_root"]
    r = subprocess.run([sys.executable, "-X", "utf8", str(PIPE / "eval_run.py"), f"{prefix}_A"], cwd=root, env=env,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print("ERROR in eval_run; tail:", (r.stdout + r.stderr)[-1500:])
        sys.exit(1)
    rows = jl(A / "eval_rows.json")
    tg = [{"tkey": f"{prefix}__{x['item']}__{x['source']}", "tag": prefix, "item": x["item"], "source": x["source"],
           "base_sol": str((A / "solutions" / f"{x['item']}__{x['source']}__PyRs").resolve())}
          for x in rows if x["cond"] == "PyRs" and x.get("functional_ok")]
    tg.sort(key=lambda x: x["tkey"])
    js(A / "targets.json", tg)       # hk6_driver.py b4-init 이 읽는 형식(hk6_driver.cmd_eval_a 와 같다)
    for cond in conf.get("conds", ["PyRs"]):
        for s in ("vulnerable", "patched"):
            x = [r for r in rows if r["source"] == s and r["cond"] == cond]
            if not x:
                continue
            print(f"[{cond}] {s}: translations {len(x)}, built {sum(1 for r in x if r['built'])}", end="")
            if any(r.get("protocol") for r in x):
                print(f", visible tests present {sum(1 for r in x if r.get('visible_tests'))}, visible-test repair "
                      f"triggered {sum(1 for r in x if r.get('visible_repair_triggered'))}, repaired to passed "
                      f"{sum(1 for r in x if r.get('visible_repair_triggered') and r.get('visible_pass'))}, visible pass (T1) "
                      f"{sum(1 for r in x if r.get('visible_pass'))}, T1!=T0 {sum(1 for r in x if r.get('t1_differs'))}, "
                      f"calls {sum(r['calls'] for r in x)} (stage1/2/3 "
                      f"{'/'.join(str(sum((r.get('calls_per_stage') or {}).get(k, 0) for r in x)) for k in ('translate', 'build_fix', 'visible_fix'))})")
            else:
                print()
            versions = [("T1", lambda r: r)] + ([("T0", lambda r: r.get("t0") or {})] if any(r.get("protocol") for r in x) else [])
            for lab, g in versions:
                fp = [r for r in x if g(r).get("functional_ok")]
                pc = collections.Counter(p for r in fp for p in g(r).get("pairs", []))
                print(f"    {lab}: functional pass {len(fp)}; security tests (functional pass only): gone {pc['gone']}, "
                      f"left {pc['left']}, new {pc['new']}, safe {pc['safe']}, invalid {pc['invalid']}")
    print("targets.json:", len(tg), "targets,", len({x['item'] for x in tg}), "items")


def main():
    if os.environ.get("PYRS_EXPORT_ROOT"):     # 상대 경로는 지금 폴더 기준으로 고정한다(자식 프로세스는 --root 에서 돈다)
        os.environ["PYRS_EXPORT_ROOT"] = str(Path(os.environ["PYRS_EXPORT_ROOT"]).resolve())
    if len(sys.argv) > 1 and sys.argv[1] == "_ingest":
        return ingest_one(Path(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["init", "round", "status", "eval"])
    ap.add_argument("--items", default=None, help="init: item id file")
    ap.add_argument("--protocol", default="tf1", choices=["tf1", "off"])
    ap.add_argument("--visible-root", default=None, help="init (tf1): folder of <item>.json visible tests")
    ap.add_argument("--conds", default="PyRs", help="init: PyRs and/or PyPy (comma)")
    ap.add_argument("--prompt", default="v2", help="init: translation prompt version (translate.PROMPT_VERSIONS)")
    ap.add_argument("--model", default=None, help="init: model label written into state (default as pilot_job.py)")
    ap.add_argument("--prefix", default="tr")
    ap.add_argument("--root", default=str(HOME))
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    if a.cmd == "init" and not a.items:
        ap.error("init needs --items")
    root = Path(a.root).resolve()
    {"init": cmd_init, "round": cmd_round, "status": cmd_status, "eval": cmd_eval}[a.cmd](root, a.prefix, a)


if __name__ == "__main__":
    main()
