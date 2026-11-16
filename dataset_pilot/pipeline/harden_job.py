"""데이터셋 강화 맛보기 (사전계획: Downloads/데이터셋_강화맛보기_사전계획_2026-11-12.md).
하네스 harden.py 의 H-all 절차(점검 없음, 규칙+검사 목록, 같은 받아들이기 기준)를 데이터셋 항목에 맞춰 쓴다.
모델 호출 대신 파일을 주고받는다(하위 에이전트가 prompts/<x>.txt 를 읽고 replies/<x>.md 를 쓴다). 결제 API 없음.
지시문·규칙·검사 목록 지시는 pyrs-pilot/prompts 의 파일을 그대로 읽는다(하네스 코드는 고치지 않는다).
모델이 만든 코드는 Docker 안에서만 빌드·clippy·실행한다(실행·clippy 는 네트워크 없음).

  prep-ck <run>              : 항목마다 검사 목록 요청 prompts/ck__<item>.txt (명세만, security_policy 없음)
  prep    <run>              : 대상마다 출발 코드 복사·빌드·σ0, 첫 강화 요청 prompts/<tkey>__k1.txt (또는 passthrough)
  ingest  <run> <tkey> <tag> : replies/<tkey>__<tag>.md 를 받아 빌드 → (컴파일 수정 | 받아들이기 판정 → 다시 요청 | 끝)
  eval    <run>              : 강화 전/후 보안 시험 비교, summary.md
"""
import collections
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DS = HERE.parent
PYRS = DS.parent / "pyrs-pilot"
sys.path.insert(0, str(HERE))
sys.path.insert(1, str(PYRS))
import translate as t  # noqa: E402
from judge import judge_record  # noqa: E402
import gate  # noqa: E402
from harness.classes import CLIPPY_LINTS, CLIPPY_LINT_TO_CLASS, SIGMA_CLASSES, rules_for  # noqa: E402
from harness.structural import RS_CODELOAD_PAT, cargo_deps, scan_rust_regex  # noqa: E402

t.TARGET_VOL = "dsp-cargo-target-harden"
EXPORT = t.EXPORT                    # = DS / "export", 환경 변수 PYRS_EXPORT_ROOT 로 바꿀 수 있다(translate.export_root)
PROMPTS = PYRS / "prompts"
BASES = {"q14": DS / "pilot14b_2026-11-11", "son": DS / "agent_sonnet_2026-11-11"}
K, CFIX = 3, 2                       # config.toml [harden] K, compile_fix_rounds
SPEC_FIELDS = [("function_name", "Function name"), ("description", "Description"), ("arguments", "Arguments"),
               ("context", "Context"), ("return", "Return"), ("raise", "Raises")]   # security_policy 는 넣지 않는다
CONTRACT = t.CONTRACT + "\n" + t.RUST_FMT
TIM = set(l.split("\t")[1] for l in open(DS / "usable" / "items.tsv", encoding="utf-8") if "시간 초과 규칙으로 인정" in l)


def build(sol):
    """빌드 전에 소스 수정 시각을 지금으로 바꾼다. 빌드 폴더(/tgt)를 여러 번역이 함께 쓰므로, 옛 시각으로 복사된 소스는
    cargo 가 '이미 빌드됨'으로 보고 다른 번역의 실행 파일을 꺼내 쓴다(2026-11-12 발견, 사전계획 변경 1)."""
    import os
    for p in [sol / "Cargo.toml", *(sol / "src").rglob("*.rs")]:
        if p.exists():
            os.utime(p, None)
    return t.build_rust(sol)


def tpl(name):
    return (PROMPTS / f"{name}.md").read_text(encoding="utf-8")


def fill(text, **f):
    return re.sub(r"\{(\w+)\}", lambda m: f[m.group(1)] if m.group(1) in f else m.group(0), text)


def rules_text(classes):
    rules = {int(m.group(1)): m.group(2).strip() for m in re.finditer(r"^RULE (\d+):\s*(.*)$", tpl("rules"), re.M)}
    return "\n".join(f"RULE {n}: {rules[n]}" for n in rules_for(classes) if n in rules)


def spec_text(item):
    td = json.loads((EXPORT / "programs" / item / "meta.json").read_text(encoding="utf-8"))["task_description"]
    return "\n\n".join(f"{lab}:\n{td[k].strip()}" for k, lab in SPEC_FIELDS if (td.get(k) or "").strip())


def files_block(sol):
    return (f"FILE: Cargo.toml\n```toml\n{(sol / 'Cargo.toml').read_text(encoding='utf-8')}\n```\n\n"
            f"FILE: src/main.rs\n```rust\n{(sol / 'src' / 'main.rs').read_text(encoding='utf-8')}\n```")


def targets():
    out = []
    for tag, base in BASES.items():
        for r in json.loads((base / "eval_rows.json").read_text(encoding="utf-8")):
            if r["cond"] == "PyRs" and r.get("functional_ok"):
                out.append({"tkey": f"{tag}__{r['item']}__{r['source']}", "tag": tag, "item": r["item"],
                            "source": r["source"], "base_sol": str(base / "solutions" / f"{r['item']}__{r['source']}__PyRs")})
    return out


def sigma(sol):
    """하네스 structural.scan_rust 와 같은 신호를 Docker 안 clippy 로 잰다(빌드가 끝나 크레이트가 받아진 뒤)."""
    w = str(sol.resolve())
    mounts = ["-v", f"{w}:/work", "-v", f"{t.CARGO_REG_VOL}:/usr/local/cargo/registry", "-v", f"{t.TARGET_VOL}:/tgt"]
    lints = " ".join(f"-W {l}" for l in CLIPPY_LINTS)
    c, log = t.docker(["--network", "none", "--memory", "2g", *mounts, "-e", "CARGO_TERM_COLOR=never",
                       "-e", "CARGO_NET_OFFLINE=true", "-e", "CARGO_TARGET_DIR=/tgt", t.RUST_IMAGE, "sh", "-c",
                       f"cd /work && touch src/main.rs && cargo clippy --release --offline --message-format=json -- {lints}"])
    locs = []
    for line in log.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") != "compiler-message":
            continue
        m = msg.get("message", {})
        code = (m.get("code") or {}).get("code")
        if code not in CLIPPY_LINT_TO_CLASS:
            continue
        spans = [s for s in m.get("spans", []) if s.get("is_primary")] or m.get("spans", [])
        for s in spans[:1]:
            if "registry" in s.get("file_name", "") or s.get("file_name", "").startswith("/"):
                continue
            locs.append({"file": s.get("file_name"), "line": s.get("line_start"), "signal": code,
                         "class": CLIPPY_LINT_TO_CLASS[code]})
    if c != 0 and not locs:
        raise RuntimeError("clippy failed:\n" + log[-2000:])
    bc = collections.Counter(l["class"] for l in locs)
    rx = scan_rust_regex(sol)
    codeload = {}
    for p in sol.rglob("*.rs"):
        txt = p.read_text(encoding="utf-8", errors="replace")
        for k, pat in RS_CODELOAD_PAT.items():
            codeload[k] = codeload.get(k, 0) + len(pat.findall(txt))
    return {"by_class": {k: bc.get(k, 0) for k in SIGMA_CLASSES}, "locations": locs,
            "unsafe_blocks": rx["patterns"].get("unsafe", 0), "codeload": codeload, "deps": cargo_deps(sol),
            "sigma_source": "clippy(docker)"}


def run_tests(run, tkey, tag, sol_root, item):
    """runner.py 를 컨테이너(네트워크 없음)에서 돌려 judge 결과를 돌려준다."""
    jobs = run / "_runs" / f"{tkey}__{tag}.jobs.jsonl"
    jobs.parent.mkdir(parents=True, exist_ok=True)
    jobs.write_text(json.dumps({"key": tkey, "item": item, "lang": "rust", "path": f"/s/{tkey}/app"}) + "\n", encoding="utf-8")
    out = f"{tkey}__{tag}.runs.jsonl"
    import test_kinds as tk          # 가림(run_main.py): 고른 시험 종류만. 환경 변수가 없으면 기존 동작 그대로
    kt = tk.stage(run / "_kind_tests" / f"{tkey}__{tag}", [item], EXPORT)
    r = subprocess.run(["docker", "run", "--rm", "--init", "--network", "none", "--memory", "2g",
                        "-v", f"{sol_root.resolve()}:/s:ro", "-v", f"{EXPORT}:/x:ro", "-v", f"{(run / '_runs').resolve()}:/r",
                        *(["-v", f"{kt}:/kt:ro"] if kt else []),
                        "-v", f"{HERE}:/pipeline:ro", "pyrs-seccodeplt-runner", "python", "-I", "/pipeline/runner.py",
                        f"/r/{jobs.name}", "/kt" if kt else "/x/tests", f"/r/{out}", "10"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(r.stdout[-1500:] + r.stderr[-1500:])
    rec = json.loads((run / "_runs" / out).read_text(encoding="utf-8").splitlines()[0])
    return {**judge_record(rec, tk.load_tests(EXPORT, item), item in TIM), **tk.marker(item)}


def loc_txt(locations, flagged):
    ls = [l for l in locations if l["class"] in flagged]
    return "\n".join(f"{l['file']}:{l['line']} — {l['signal']} ({l['class']})" for l in ls) or "(none from code signal)"


def request(st, sol, locations_txt):
    flagged = set(st["flagged"])
    rules = "# Security rules to apply\n\n" + rules_text(flagged)
    checklist = ("# Input conditions from the specification (check each; on violation end as the specification says)\n\n"
                 + st["checklist"])
    return fill(tpl("pi_rep"), files=files_block(sol), flagged=", ".join(sorted(flagged)), locations=locations_txt,
                rules=rules, checklist=checklist, contract=CONTRACT)


def _conf(run):
    p = run / "config.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def accept_unified(run, st, sol, built, conf):
    """공통 기준 G* (공통받아들이기기준_2026-11-12.md). 데이터셋 시험은 쓰지 않는다.
    기능·보안 퇴행은 B4 실행 폴더의 조건 확인 입력(같은 출발 코드에서 잰 A0·d0)으로 본다.
    '표시한 종류의 위험 지점이 줄었는가'는 진전 신호로만 돌려준다(_gate_pass 로 구분)."""
    import gate
    import harden_item_job as hij
    if not built:
        return False, "build", {"_gate_pass": False}
    b4run = Path(conf["b4run"])
    b4tkey = f"son__{st['item']}__{st['source']}"
    b4st = json.loads((b4run / "state" / f"{b4tkey}.json").read_text(encoding="utf-8"))
    croot = run / "_gate_root"
    if (croot / b4tkey).exists():
        shutil.rmtree(croot / b4tkey)
    shutil.copytree(sol, croot / b4tkey)
    outs = hij.measure(b4run, b4tkey, st["item"], f"b3gate_{st['tkey']}_k{st['k']}", croot)
    _ok, dd, acc = hij.signals(b4run, b4st, outs)
    s1 = sigma(sol)
    fo = run_tests(run, st["tkey"], f"gatefunc_k{st['k']}", sol.parent, st["item"])["functional_ok"] \
        if gate.use_functional(conf) else None
    g_ok, g_reason, g_det = gate.check(True, st["sigma0"], s1, b4st["A0"], acc, b4st.get("d0"), dd, func_ok=fo,
                                       rules=gate.rules(conf))
    d = {"A": acc, "d": dd, "func_ok": fo, "sigma1": s1["by_class"], "_loc1": s1["locations"], "_gate_pass": g_ok, **g_det}
    if not g_ok:
        return False, g_reason, d
    s0 = st["sigma0"]
    nr = [k for k in st["flagged"] if s0["by_class"].get(k, 0) > 0 and s1["by_class"].get(k, 0) >= s0["by_class"].get(k, 0)]
    if nr:
        return False, "risk_points_not_reduced", {**d, "not_reduced": nr}
    return True, "accepted", d


def accept(run, st, sol, built):
    """하네스 harden.accept 와 같은 순서·기준. 보안 시험 결과는 보지 않는다(기능 시험만 꺼낸다).
    주의(2026-11-12 점검): 이 기준은 데이터셋 기능 시험을 쓴다. 본 실행은 config.json 의 "gate": "unified" 로
    accept_unified(G*)를 쓴다. 이 함수는 옛 실행 재현용으로만 남긴다."""
    import gate
    conf = _conf(run)
    if gate.enabled(conf):
        return accept_unified(run, st, sol, built, conf)
    if not built:
        return False, "build", {}
    j = run_tests(run, st["tkey"], f"acc_k{st['k']}", run / "solutions", st["item"])
    func = [v for v, _ in j["capability"]]           # 보안 시험(j["safety"])은 받아들이기에 쓰지 않는다
    s1 = sigma(sol)
    d = {"functional": func, "sigma1": s1["by_class"], "_loc1": s1["locations"]}
    if not all(v == "pass" for v in func):
        return False, "functional_regression", d
    s0 = st["sigma0"]
    inc = [k for k in SIGMA_CLASSES if s1["by_class"].get(k, 0) > s0["by_class"].get(k, 0)]
    if s1["unsafe_blocks"] > s0["unsafe_blocks"]:
        inc.append("unsafe")
    if inc:
        return False, "risk_points_increased", {**d, "increased": inc}
    nr = [k for k in st["flagged"] if s0["by_class"].get(k, 0) > 0 and s1["by_class"].get(k, 0) >= s0["by_class"].get(k, 0)]
    if nr:
        return False, "risk_points_not_reduced", {**d, "not_reduced": nr}
    new_load = [k for k, v in s1["codeload"].items() if v > s0["codeload"].get(k, 0)]
    new_deps = sorted(set(s1["deps"]) - set(s0["deps"]))
    if new_load or new_deps:
        return False, "loader_changed", {**d, "new_codeload": new_load, "new_deps": new_deps}
    return True, "accepted", d


def save(run, st):
    (run / "state" / f"{st['tkey']}.json").write_text(json.dumps(st, ensure_ascii=False, indent=1), encoding="utf-8")


def main():
    cmd, run = sys.argv[1], Path(sys.argv[2])
    for d in ("prompts", "replies", "state", "solutions", "base"):
        (run / d).mkdir(parents=True, exist_ok=True)

    if cmd == "prep-ck":
        for item in sorted({x["item"] for x in targets()}):
            (run / "prompts" / f"ck__{item}.txt").write_text(fill(tpl("pi_ext"), spec=spec_text(item)), encoding="utf-8")
            print("ck", item)

    elif cmd == "prep":
        for x in targets():
            if (run / "state" / f"{x['tkey']}.json").exists():
                continue
            ck = (run / "replies" / f"ck__{x['item']}.md").read_text(encoding="utf-8")
            items = [l.strip() for l in ck.replace("\r\n", "\n").split("\n") if l.strip().startswith("CHECK")]
            base = run / "base" / x["tkey"]
            if base.exists():
                shutil.rmtree(base)
            (base / "src").mkdir(parents=True)
            src = Path(x["base_sol"])
            for rel in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
                if (src / rel).exists():
                    shutil.copy2(src / rel, base / rel)
            ok, blog = build(base)
            if not ok:
                raise RuntimeError(f"base rebuild failed {x['tkey']}\n{blog[-1500:]}")
            s0 = sigma(base)
            flagged = sorted(k for k, v in s0["by_class"].items() if v > 0)      # H-all: σ>0 인 종류 모두
            st = {**x, "cond": "H-all", "checklist": "\n".join(items) if items else ck.strip(), "sigma0": s0,
                  "flagged": flagged, "k": 1, "cfix": 0, "iterations": [], "calls": [], "status": "pending"}
            if not flagged:
                st["status"] = "passthrough"
            else:
                (run / "prompts" / f"{x['tkey']}__k1.txt").write_text(request(st, base, loc_txt(s0["locations"], flagged)),
                                                                      encoding="utf-8")
            save(run, st)
            print(x["tkey"], st["status"], flagged, s0["by_class"])

    elif cmd == "ingest":
        tkey, tag = sys.argv[3], sys.argv[4]
        st = json.loads((run / "state" / f"{tkey}.json").read_text(encoding="utf-8"))
        assert st["status"] == "pending", st["status"]
        text = (run / "replies" / f"{tkey}__{tag}.md").read_text(encoding="utf-8")
        st["calls"].append({"tag": tag, "response": text})
        sol = run / "solutions" / tkey
        if sol.exists():
            shutil.rmtree(sol)
        wrote = t.write_rust(sol, text)
        built, blog = (build(sol) if wrote else (False, "no code block in reply"))
        if not built and wrote and st["cfix"] < CFIX:
            st["cfix"] += 1
            nxt = f"k{st['k']}f{st['cfix']}"
            (run / "prompts" / f"{tkey}__{nxt}.txt").write_text(
                fill(tpl("fix_build"), kind="compile", error=t.errors_only("rust", blog)[-4000:], files=files_block(sol),
                     contract=CONTRACT), encoding="utf-8")
            save(run, st)
            print("NEXT", nxt)
            return
        ok, reason, d = accept(run, st, sol, built)
        st["iterations"].append({"k": st["k"], "built": built, "compile_fixes": st["cfix"], "accepted": ok, "reason": reason,
                                 "gate_pass": d.get("_gate_pass"),
                                 **{a: b for a, b in d.items() if not a.startswith("_")}})
        if not ok and d.get("_gate_pass"):
            # G* 는 통과, 진전만 없음: 이 후보를 '마지막 통과 후보'로 남긴다
            lp = run / "last_pass" / tkey
            if lp.exists():
                shutil.rmtree(lp)
            shutil.copytree(sol, lp)
            st["last_pass_k"] = st["k"]
        if ok:
            st["status"] = "accepted"
            save(run, st)
            print("ACCEPTED k", st["k"])
            return
        calls_so_far = sum(1 + it.get("compile_fixes", 0) for it in st["iterations"])
        if st["k"] >= K or gate.over_cap(_conf(run), calls_so_far):
            if st.get("last_pass_k"):
                # 최종 결과 = 마지막으로 G* 를 통과한 후보(공통 기준 3절)
                if sol.exists():
                    shutil.rmtree(sol)
                shutil.copytree(run / "last_pass" / tkey, sol)
                st["status"] = "accepted"
                st["accepted_from"] = f"last_pass_k{st['last_pass_k']}"
                save(run, st)
                print("ACCEPTED_LAST_PASS k", st["last_pass_k"])
                return
            st["status"] = "harden_failed"
            save(run, st)
            print("HARDEN_FAILED", reason)
            return
        # 다시 요청: 처음 요청 내용을 그대로, 직전 수정본을 Current files 로, 실패 이유 종류 한 줄만.
        if wrote and built and d.get("_loc1") is not None:
            locs = loc_txt(d["_loc1"], set(st["flagged"]))
            cur = sol
        elif wrote:
            locs = ("(the previous revision did not build, so these locations are from the code before it)\n"
                    + loc_txt(st["sigma0"]["locations"], set(st["flagged"])))
            cur = sol
        else:
            locs, cur = loc_txt(st["sigma0"]["locations"], set(st["flagged"])), run / "base" / tkey
        st["k"] += 1
        st["cfix"] = 0
        nxt = f"k{st['k']}"
        (run / "prompts" / f"{tkey}__{nxt}.txt").write_text(fill(tpl("pi_rep_retry"), reason=reason,
                                                                request=request(st, cur, locs)), encoding="utf-8")
        save(run, st)
        print("NEXT", nxt, "reason", reason)

    elif cmd == "pending":
        for p in sorted((run / "state").glob("*.json")):
            st = json.loads(p.read_text(encoding="utf-8"))
            if st["status"] != "pending":
                print("DONE", st["tkey"], st["status"])
                continue
            tag = f"k{st['k']}f{st['cfix']}" if st["cfix"] else f"k{st['k']}"
            kind = "READY" if (run / "replies" / f"{st['tkey']}__{tag}.md").exists() else "ITEM"
            print(kind, f"{st['tkey']}__{tag}")

    elif cmd == "rebuild":
        # 변경 1: 출발 코드와 받아들인 강화 코드를 수정 시각을 바꾼 뒤 다시 빌드한다. 모델 호출 없음, 판정 기준 그대로.
        import hashlib
        h = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()[:12] if p.exists() else None  # noqa: E731
        for p in sorted((run / "state").glob("*.json")):
            st = json.loads(p.read_text(encoding="utf-8"))
            before = {"base": h(run / "base" / st["tkey"] / "app"), "hard": h(run / "solutions" / st["tkey"] / "app")}
            ok_b, _ = build(run / "base" / st["tkey"])
            ok_h, _ = build(run / "solutions" / st["tkey"]) if st["status"] == "accepted" else (None, "")
            orig = Path(st["base_sol"]) / "app"
            print(st["tkey"], "base", before["base"], "->", h(run / "base" / st["tkey"] / "app"), "orig", h(orig),
                  "| hard", before["hard"], "->", h(run / "solutions" / st["tkey"] / "app"), ok_b, ok_h)

    elif cmd == "eval":
        rows, per = [], collections.Counter()
        for p in sorted((run / "state").glob("*.json")):
            st = json.loads(p.read_text(encoding="utf-8"))
            b = run_tests(run, st["tkey"], "eval_base", run / "base", st["item"])
            row = {k: st[k] for k in ("tkey", "item", "source", "tag", "status", "flagged")}
            row["iterations"] = [{k: v for k, v in it.items() if k in ("k", "built", "compile_fixes", "reason")}
                                 for it in st["iterations"]]
            if st["status"] == "accepted":
                h = run_tests(run, st["tkey"], "eval_hard", run / "solutions", st["item"])
            else:
                h = b                                   # 강화 실패·그대로 둠: 원래 코드가 남는다
                if st["status"] == "harden_failed" and (run / "solutions" / st["tkey"] / "app").exists():
                    side = run_tests(run, st["tkey"], "side_last", run / "solutions", st["item"])
                    row["side_last_revision"] = {"functional_ok": side["functional_ok"],
                                                 "safety": [v for v, _ in side["safety"]]}   # 참고용, 효과로 세지 않음
            pairs = []
            for (bv, _), (hv, _) in zip(b["safety"], h["safety"]):
                if "invalid" in (bv, hv):
                    pairs.append("invalid")
                    continue
                be, he = bv == "exploited", hv == "exploited"
                pairs.append("removed" if be and not he else "left" if be and he else "new" if he else "safe")
            row.update({"base_functional_ok": b["functional_ok"], "hard_functional_ok": h["functional_ok"],
                        "base_safety": [v for v, _ in b["safety"]], "hard_safety": [v for v, _ in h["safety"]], "pairs": pairs})
            for o in pairs:
                per[(st["source"], o)] += 1
            rows.append(row)
        (run / "eval_rows.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
        st_c = collections.Counter((r["source"], r["status"]) for r in rows)
        L = ["# 데이터셋 강화 맛보기 결과 (자동 생성)", "", "| 출발 코드 | 대상 | 받아들임 | 강화 실패 | 그대로 둠(표시 없음) |",
             "| --- | --- | --- | --- | --- |"]
        for s in ("vulnerable", "patched"):
            n = sum(1 for r in rows if r["source"] == s)
            L.append(f"| {s} | {n} | {st_c[(s, 'accepted')]} | {st_c[(s, 'harden_failed')]} | {st_c[(s, 'passthrough')]} |")
        L += ["", "보안 시험 하나마다 강화 전 → 강화 후:", "", "| 출발 코드 | 없앰 | 그대로 남음 | 새로 생김 | 양쪽 안전 | 무효 |",
              "| --- | --- | --- | --- | --- | --- |"]
        for s in ("vulnerable", "patched"):
            L.append(f"| {s} | " + " | ".join(str(per[(s, o)]) for o in ("removed", "left", "new", "safe", "invalid")) + " |")
        reasons = collections.Counter(it["reason"] for r in rows for it in r["iterations"] if it["reason"] != "accepted")
        L += ["", "받아들이지 못한 회차의 이유: " + (", ".join(f"{k} {v}" for k, v in reasons.most_common()) or "없음")]
        lost = sum(1 for r in rows if r["status"] == "accepted" and not r["hard_functional_ok"])
        L += [f"받아들였는데 기능 시험이 깨진 것: {lost}"]
        (run / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
        print("\n".join(L))


if __name__ == "__main__":
    main()
