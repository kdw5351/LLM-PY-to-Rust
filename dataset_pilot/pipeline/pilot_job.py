"""시험 운행(본실험_재설계안 기준, 개발용 10개 항목). 사전계획: Downloads/시험운행_사전계획_2026-11-12.md
모델 호출은 파일 주고받기(하위 에이전트). 빌드는 번역마다 따로 쓰는 Docker 볼륨에서 한다(공유 폴더 재사용 버그 방지).

실험 A (옮기기, 주석 지운 출발 코드 export/programs_nc):
  prep-a   <run> <ids>                 : prompts/<key>__r0.txt  (key = item__source__cond)
  ingest-a <run> <key> <round>         : 빌드/확인 → 고치기 요청(최대 3) 또는 logs/<key>.json
  (평가는 eval_run.py <run> 을 그대로 쓴다)
실험 B 의 B0·B1·예산 대조(BUD). B4 는 harden_item_job.py(v2)로 돌리고, 그 실행의 조건 확인 입력을 받아들이기에 같이 쓴다:
  prep-b   <brun> <b4run> <arun>       : 대상(실험 A 에서 기능 통과한 Py→Rs 전부)마다 조건별 첫 요청
  ingest-b <brun> <cond> <tkey> <tag>  : 답 처리(tag = k<k>[f<f>])
  pending-b <brun>                      (WAIT = 이어 붙인 조건이 1단계를 기다림)
  init-chain <brun>                     : 1단계가 끝난 대상의 SPEC2 등 이어 붙인 조건을 시작
  eval-b   <brun>
RCI(자기 비판 반복, 비판 tag k1c) 와 SPEC2(B1 → B1) 는 2026-11-13 추가(완화조건_재설계_2026-11-13.md 3절).
BESTREP(기존 최선 반복, config best_cond·rep_call_cap; 2회차부터 tag r<n>k<k>...)은 2026-11-13 검토의견_반영_결정 1절로 추가.
이어 붙인 조건의 정의는 chain_of, 요청 종류는 stage2_request 한 곳(RUN_MAIN_FORMATS.md "4단계 새 조건 붙이는 곳").
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DS = HERE.parent
sys.path.insert(0, str(HERE))
import harden_item_job as hij  # noqa: E402
import harden_job as hj  # noqa: E402
import gate  # noqa: E402

t = hj.t
NC = t.EXPORT / "programs_nc"   # 내보내기 폴더는 translate.EXPORT 를 따른다(PYRS_EXPORT_ROOT, 2026-11-13)
K_B, CFIX = 3, 2
CONDS_B = ("B0", "B1", "BUD")
# B5 = B1 + 제안 방법의 구성 요소(검사 목록·조건 확인 신호·공통 규칙 7개), B5m = B5 에서 조건 확인 신호만 뺀 것.
# 설계: Downloads/B5_합친방법_설계_2026-11-12.md. 실행 폴더 config 의 "conds" 로 고른다(기본은 위 세 조건).
B5_CONDS = ("B5", "B5m")
PANIC_LINTS = {"panic"}
# RCI = 자기 비판 반복(Tony 외, TOSEM 2025). 요청문 원문 그대로(완화조건_재설계_2026-11-13.md 3절).
#   비판 1번(k1c, 답은 글) → 개선(k1). 거절되면 개선 요청을 pi_rep_retry 로 감싸 다시(k2, k3). 비판은 한 번만 하고 다시 쓴다.
#   비판 호출도 공통 상한·호출 수에 넣는다. 첫 개선 후보(k1 빌드 결과, 받아들이기 전)는 RCI/first_candidate 에 따로 둔다.
RCI_CRITIQUE = "Review the following answer and find security problems with it: "
RCI_IMPROVE = ("Based on the critique: ", ", improve the following answer: ")
# 이어 붙인 조건: 이름 -> (1단계 조건, 2단계 조건). 1단계는 같은 실행의 그 조건 최종 결과를 그대로 쓴다(다시 만들지 않음).
# 2단계 받아들이기는 다른 조건과 같은 기준(원래 번역 대비 σ0·A0·기능 시험). 나중에 COMB = ("B1", "EXEC") 를 더한다.
CHAINS = {"SPEC2": ("B1", "B1")}
# 되풀이 조건(2026-11-13 검토의견_반영_결정 1절 "기존 최선 반복", 4-나): 1단계 = 같은 실행의 conf["best_cond"] 최종 결과,
# 그 위에 같은 조건을 한 회차씩 다시(회차마다 직전 회차의 최종 프로그램에서 시작). 대상 하나의 전체 호출(1단계 + 모든 회차,
# 비판·컴파일 수정 포함)이 conf["rep_call_cap"] 에 닿거나 다음 회차가 들어갈 자리가 없으면 멈춘다. 받아들이기는 다른 조건과 같다
# (원래 번역 대비). 최종 = 마지막으로 받아들여진 프로그램(없으면 1단계 최종).
REPEAT_CHAINS = ("BESTREP",)
REPEATABLE = ("B0", "B1", "ORA", "RCI")     # 지금 프로그램을 고치는 조건만 되풀이할 수 있다(BUD 는 처음부터 다시 번역)
# 원 방식 그대로의 결과(실험설계서_4단계 4절): 받아들이기 전 첫 후보(k1 빌드 결과)를 <cond>/first_candidate 에 둔다.
# RCI 는 처음부터, B0·B1·ORA·이어 붙인 조건의 2단계는 2026-11-13(run_main.py) 추가. 요청문·받아들이기 판정은 바꾸지 않는다.
# BUD(다시 번역)는 고치는 조건이 아니라 첫 후보가 없다. 되풀이 조건은 1회차의 k1.
FIRST_CANDIDATE_CONDS = ("RCI", "B0", "B1", "ORA") + tuple(CHAINS) + REPEAT_CHAINS
# 요청 단계(phase) -> 태그 끝 글자. 신호 단계는 모델 호출이지만 고치기 상한(own_calls)에 넣지 않는다(signal_calls, RUN_MAIN_FORMATS.md).
PHASE_TAG = {"critique": "c", "signal": "s"}


def chain_of(conf, c):
    """### 이어 붙인 조건의 정의 (여기 한 곳) ###
    반환: None(이어 붙인 조건 아님) 또는 {stage1: 1단계 조건, stage2: 2단계 요청 종류(stage2_request 의 열쇠),
    cap: 대상 하나의 전체 호출 상한(None = 없음), repeat: 회차를 되풀이하는가}. 4단계 새 기법은 여기에 이름을 더한다."""
    if c in CHAINS:
        return {"stage1": CHAINS[c][0], "stage2": CHAINS[c][1], "cap": None, "repeat": False}
    if c == "BESTREP":
        b = (conf or {}).get("best_cond", "B1")
        assert b in REPEATABLE, b
        return {"stage1": b, "stage2": b, "cap": int(conf["rep_call_cap"]), "repeat": True}
    return None


def is_chain(c):
    return c in CHAINS or c in REPEAT_CHAINS


def stage2_request(run, st, cur):
    """### 2단계 요청 종류 -> 요청 만드는 함수 (여기 한 곳). EXEC 를 더할 때 이 사전에 넣는다. ###
    종류 = st["chain"]["stage2"](chain_of 가 정한다). B0·B1·ORA·RCI 는 그 조건 자신의 요청문 그대로."""
    builders = {
        "B1": lambda: request_b(run, "B1", st, cur),
        "B0": lambda: request_b(run, "B0", st, cur),
        "ORA": lambda: request_b(run, "ORA", st, cur),
        "RCI": lambda: rci_improve(st, cur),
        # "EXEC": lambda: request_exec(run, st, cur),   # COMB 용(아직 구현하지 않음)
    }
    return builders[st["chain"]["stage2"]]()


def kind_of(st):
    """요청·단계 처리에 쓰는 조건 종류: 이어 붙인 조건은 2단계 종류, 그 밖은 조건 이름."""
    return st["chain"]["stage2"] if "chain" in st else st["cond"]


def tag_pre(st):
    """되풀이 조건 2회차부터 태그 앞에 r<n> 을 붙인다(1회차와 다른 모든 조건은 빈 글자 = 예전 이름 그대로)."""
    n = st.get("round", 1)
    return f"r{n}" if n > 1 else ""


def own_calls(st):
    """이 조건(2단계 조건이면 지금 회차의 2단계만)이 쓴 고치기 호출 수: 시도 + 컴파일 수정 + RCI 비판. 고치기 상한에 쓴다."""
    return len(st["log"]) + sum(x.get("compile_fixes", 0) for x in st["log"]) + st.get("critique_calls", 0)


def stage2_calls(st):
    """2단계 전체 호출(되풀이 조건은 지난 회차 합 + 지금 회차, 신호 호출 포함)."""
    ch = st.get("chain") or {}
    return sum(r["calls"] for r in ch.get("rounds", [])) + own_calls(st) + st.get("signal_calls", 0)


def total_calls(st):
    return (stage2_calls(st) if "chain" in st else own_calls(st) + st.get("signal_calls", 0)) \
        + (st["chain"]["stage1_calls"] if "chain" in st else 0)


def budget_left(st):
    """대상 하나의 전체 호출 상한까지 남은 호출(상한이 없으면 무한)."""
    cap = (st.get("chain") or {}).get("cap")
    return float("inf") if cap is None else cap - total_calls(st)


def min_round_calls(kind):
    return 2 if kind == "RCI" else 1          # RCI 회차는 비판 + 개선 최소 2번


def rci_improve(st, cur):
    return (RCI_IMPROVE[0] + st["critique"] + RCI_IMPROVE[1] + hj.files_block(cur) + "\n\n" + hj.CONTRACT)


def start_round(run, c, st):
    """이어 붙인 조건의 (다음) 회차를 시작한다: accepted/<tkey>(직전 결과) 위에서 첫 요청을 쓴다."""
    cur = run / c / "accepted" / st["tkey"]
    st.update({"status": "running", "k": 1, "cfix": 0, "log": []})
    for k in ("phase", "critique", "critique_calls", "truncated"):
        st.pop(k, None)
    (run / c / "prompts").mkdir(parents=True, exist_ok=True)
    if st["chain"]["stage2"] == "RCI":           # RCI 종류: 비판 요청부터(prep-b 의 RCI 와 같은 글)
        st.update({"phase": "critique", "critique_calls": 0})
        (run / c / "prompts" / f"{st['tkey']}__{tag_pre(st)}k1c.txt").write_text(RCI_CRITIQUE + hj.files_block(cur),
                                                                                 encoding="utf-8")
    else:
        (run / c / "prompts" / f"{st['tkey']}__{tag_pre(st)}k1.txt").write_text(stage2_request(run, st, cur),
                                                                                encoding="utf-8")


def finish_round(run, c, st):
    """되풀이 조건: 끝난 회차를 기록하고, 들어갈 자리가 있으면 다음 회차를 시작한다. 아니면 최종 상태를 정한다."""
    ch = st["chain"]
    ch["rounds"].append({"round": st["round"], "status": ch["stage2_status"], "calls": own_calls(st) + st.get("signal_calls", 0),
                         "attempts": len(st["log"]), "compile_fixes": sum(x.get("compile_fixes", 0) for x in st["log"]),
                         "critique_calls": st.get("critique_calls", 0), "signal_calls": st.get("signal_calls", 0),
                         "truncated_by_cap": bool(st.get("truncated")),
                         "reasons": [x["reason"] for x in st["log"]]})
    st["log"], st["signal_calls"] = [], 0
    st.pop("critique_calls", None)
    if budget_left(st) >= min_round_calls(ch["stage2"]):
        st["round"] += 1
        start_round(run, c, st)
        return True
    any_acc = ch["stage1_status"] == "accepted" or any(r["status"] == "accepted" for r in ch["rounds"])
    st["status"] = "accepted" if any_acc else "harden_failed"
    ch["stop"] = "cap_reached" if budget_left(st) <= 0 else "next_round_does_not_fit"
    return False


def init_chains(run):
    """1단계가 끝난 대상의 이어 붙인 조건을 시작한다(상태 waiting -> running, 첫 2단계 요청)."""
    conf = jl(run / "config.json")
    for c in conds_of(conf):
        spec = chain_of(conf, c)
        if spec is None:
            continue
        for p in sorted((run / c / "state").glob("*.json")):
            st = jl(p)
            if st["status"] != "waiting":
                continue
            s1c = spec["stage1"]
            st1 = jl(run / s1c / "state" / f"{st['tkey']}.json")
            if st1["status"] in ("running", "waiting"):
                continue
            cur = run / c / "accepted" / st["tkey"]
            if cur.exists():
                shutil.rmtree(cur)
            shutil.copytree(run / s1c / "accepted" / st["tkey"], cur)   # 1단계 최종 프로그램(거절로 끝났으면 출발 코드)
            st["chain"] = {"stage1": s1c, "stage2": spec["stage2"], "stage1_status": st1["status"],
                           "stage1_calls": total_calls(st1), "stage2_calls": 0}
            st.update({"k": 1, "cfix": 0, "log": []})
            if spec["repeat"]:
                st["chain"].update({"cap": spec["cap"], "rounds": []})
                st["round"] = 1
                if budget_left(st) < min_round_calls(spec["stage2"]):   # 1회차도 들어가지 않는다: 1단계 결과 그대로
                    st["status"] = st1["status"]
                    st["chain"]["stop"] = "cap_reached" if budget_left(st) <= 0 else "next_round_does_not_fit"
                    js(p, st)
                    print("CHAIN_DONE", c, st["tkey"], "no round fits")
                    continue
            start_round(run, c, st)
            js(p, st)
            print("CHAIN_READY", c, st["tkey"], "stage1", st1["status"])


def conds_of(conf):
    return tuple(conf.get("conds", CONDS_B))
GENERIC = ("Review the program below for security defects and revise it so that they are fixed. Keep the input/output "
           "contract and all existing behavior for valid input unchanged. Change only what is needed.\n\n")


def build_iso(sol, key):
    """번역마다 따로 쓰는 빌드 볼륨."""
    t.TARGET_VOL = "dsp-pilot-" + hashlib.sha256(str(key).encode()).hexdigest()[:12]
    return hj.build(sol)


def sigma_iso(sol, key):
    t.TARGET_VOL = "dsp-pilot-" + hashlib.sha256(str(key).encode()).hexdigest()[:12]
    return hj.sigma(sol)


def jl(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def js(p, d):
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    Path(p).write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def main():
    cmd, run = sys.argv[1], Path(sys.argv[2])

    if cmd == "prep-a":
        # 선택 인자 4: 옮기기 요청문 버전(v1 기본, v2 = 전역 값 유지). 실행 폴더 config.json 에 기록한다.
        ver = sys.argv[4] if len(sys.argv) > 4 else "v1"
        for d in ("prompts", "replies", "solutions", "logs", "state"):
            (run / d).mkdir(parents=True, exist_ok=True)
        cp = run / "config.json"
        js(cp, {**(jl(cp) if cp.exists() else {}), "translate_prompt": ver})
        for item in Path(sys.argv[3]).read_text().split():
            for source in ("vulnerable", "patched"):
                src = (NC / item / f"{source}.py").read_text(encoding="utf-8")
                for cond in ("PyRs", "PyPy"):
                    key = f"{item}__{source}__{cond}"
                    (run / "prompts" / f"{key}__r0.txt").write_text(
                        t.prompt("rust" if cond == "PyRs" else "python", src, ver), encoding="utf-8")
                    print(key)

    elif cmd == "ingest-a":
        key, rnd = sys.argv[3], int(sys.argv[4])
        item, source, cond = key.split("__")
        lang = "rust" if cond == "PyRs" else "python"
        sol = run / "solutions" / key
        sp = run / "state" / f"{key}.json"
        st = jl(sp) if sp.exists() else {"item": item, "source": source, "cond": cond, "model": "claude-code-subagent(sonnet)",
                                         "calls": [], "regen": 0, "copied": False, "source_dir": "export/programs_nc"}
        text = (run / "replies" / f"{key}__r{rnd}.md").read_text(encoding="utf-8")
        st["calls"].append({"kind": "translate" if rnd == 0 else "fix", "round": rnd, "response": text})
        if rnd == 0 and sol.exists():
            shutil.rmtree(sol)
        wrote = t.write_rust(sol, text) if lang == "rust" else t.write_py(sol, text)
        if not wrote and not (sol.exists() and any(sol.iterdir())):
            built, blog = False, "no code block in reply"
        else:
            built, blog = build_iso(sol, key) if lang == "rust" else t.check_py(sol)
        if not built and rnd < 3:
            (run / "prompts" / f"{key}__r{rnd + 1}.txt").write_text(t.fix_prompt(lang, blog), encoding="utf-8")
            js(sp, st)
            print("FIX", rnd + 1)
            return
        st.update({"built": built, "fix_rounds": rnd, "build_log_tail": blog[-1500:]})
        if lang == "python" and built:
            src = (NC / item / f"{source}.py").read_text(encoding="utf-8")
            st["similarity"] = round(t.similarity(src, (sol / "main.py").read_text(encoding="utf-8")), 3)
            st["copied"] = st["similarity"] >= 0.90
        js(sp, st)
        js(run / "logs" / f"{key}.json", st)
        print("BUILT" if built else "FAILED", "fix_rounds", rnd, "similarity", st.get("similarity"))

    elif cmd == "prep-b":
        b4run, arun = Path(sys.argv[3]), Path(sys.argv[4])
        # 선택 인자 5: 조건 목록(쉼표). 선택 인자 6 이후 key=value 는 config 에 그대로 넣는다(예: gate=unified).
        conds = tuple(sys.argv[5].split(",")) if len(sys.argv) > 5 else CONDS_B
        extra = dict(a.split("=", 1) for a in sys.argv[6:])
        for k in ("call_cap", "rep_call_cap"):
            if k in extra:
                extra[k] = int(extra[k])
        js(run / "config.json", {"b4run": str(b4run), "arun": str(arun), "K": K_B, "compile_fix": CFIX,
                                 "conds": list(conds), **extra})
        for tg in hij.jload(b4run / "targets.json"):
            b4st = jl(b4run / "state" / f"{tg['tkey']}.json")      # B4 의 prep 이 잰 σ0·A0 를 같이 쓴다
            base = b4run / "base" / tg["tkey"]
            for c in conds:
                st = {**tg, "cond": c, "k": 1, "cfix": 0, "log": [], "status": "running",
                      "A0": b4st["A0"], "sigma0": b4st["sigma0"]}
                if c in B5_CONDS:
                    st["b4run"] = str(b4run)
                    st["unmet"] = unmet_initial(b4st) if c == "B5" else []
                    st["observed_cur"] = {str(n): b4st["observed"].get(str(n), "") for n in st["unmet"]}
                    st["locations_cur"] = [l for l in b4st["sigma0"].get("locations", []) if l["class"] in PANIC_LINTS]
                    st["accepted_once"] = False
                if is_chain(c):                      # 1단계가 끝나면 init-chain 이 시작한다
                    st["status"] = "waiting"
                    js(run / c / "state" / f"{tg['tkey']}.json", st)
                    continue
                cur = run / c / "accepted" / tg["tkey"]
                if cur.exists():
                    shutil.rmtree(cur)
                shutil.copytree(base, cur)
                (run / c / "prompts").mkdir(parents=True, exist_ok=True)
                if c == "RCI":                       # 비판 요청부터(답은 코드가 아닌 글)
                    st.update({"phase": "critique", "critique_calls": 0})
                    (run / c / "prompts" / f"{tg['tkey']}__k1c.txt").write_text(
                        RCI_CRITIQUE + hj.files_block(cur), encoding="utf-8")
                else:
                    (run / c / "prompts" / f"{tg['tkey']}__k1.txt").write_text(request_b(run, c, st, cur), encoding="utf-8")
                js(run / c / "state" / f"{tg['tkey']}.json", st)
            print(tg["tkey"])

    elif cmd == "init-chain":
        init_chains(run)

    elif cmd == "ingest-b":
        c, tkey, tag = sys.argv[3], sys.argv[4], sys.argv[5]
        conf = jl(run / "config.json")
        b4run = Path(conf["b4run"])
        sp = run / c / "state" / f"{tkey}.json"
        st = jl(sp)
        pre, kind = tag_pre(st), kind_of(st)
        assert st["status"] == "running" and tag.startswith(f"{pre}k{st['k']}"), (st["status"], tag)
        text = (run / c / "replies" / f"{tkey}__{tag}.md").read_text(encoding="utf-8")
        if kind == "RCI" and st.get("phase") == "critique":  # 비판 답(글)을 받아 개선 요청 k1 을 만든다
            assert tag == f"{pre}k1c", tag
            st.update({"critique": text.strip(), "critique_calls": 1, "phase": "improve"})
            (run / c / "prompts" / f"{tkey}__{pre}k1.txt").write_text(
                rci_improve(st, run / c / "accepted" / tkey), encoding="utf-8")
            js(sp, st)
            print("NEXT", f"{pre}k1", "critique_received")
            return
        cand = run / c / "cand" / tkey
        if cand.exists():
            shutil.rmtree(cand)
        wrote = t.write_rust(cand, text)
        built, blog = build_iso(cand, f"{c}/{tkey}") if wrote else (False, "no code block in reply")
        if not built and wrote and st["cfix"] < CFIX and budget_left(st) < 1:
            st["truncated"] = True                           # 전체 호출 상한(되풀이 조건): 컴파일 수정 자리가 없다
        if not built and wrote and st["cfix"] < CFIX and budget_left(st) >= 1:
            st["cfix"] += 1
            nxt = f"{pre}k{st['k']}f{st['cfix']}"
            (run / c / "prompts" / f"{tkey}__{nxt}.txt").write_text(
                hj.fill(hj.tpl("fix_build"), kind="compile", error=t.errors_only("rust", blog)[-4000:],
                        files=hj.files_block(cand), contract=hj.CONTRACT), encoding="utf-8")
            js(sp, st)
            print("NEXT", nxt)
            return
        if c in FIRST_CANDIDATE_CONDS and st["k"] == 1 and st.get("round", 1) == 1:   # 원 방식 그대로: 받아들이기 전 첫 후보
            fc = run / c / "first_candidate" / tkey
            if fc.exists():
                shutil.rmtree(fc)
            if built:
                shutil.copytree(cand, fc)
            st["first"] = {"built": built, "compile_fixes": st["cfix"]}
        reason = "accepted"
        if not built:
            reason = "build"
        else:
            root = run / c / "_root"
            if (root / tkey).exists():
                shutil.rmtree(root / tkey)
            shutil.copytree(cand, root / tkey)
            b4st = jl(b4run / "state" / f"{tkey}.json")
            outs = hij.measure(b4run, tkey, st["item"], f"{c}_{pre}k{st['k']}", root)
            okd, dd, acc = hij.signals(b4run, b4st, outs)
            s1 = sigma_iso(cand, f"{c}/{tkey}")
            s0 = st["sigma0"]
            if gate.enabled(conf):                         # 공통 기준 G* (공통받아들이기기준_2026-11-12.md)
                fo = hj.run_tests(run / c, tkey, f"gatefunc_{pre}k{st['k']}", root, st["item"])["functional_ok"] \
                    if gate.use_functional(conf) else None
                _, reason, _ = gate.check(True, s0, s1, st["A0"], acc, b4st.get("d0"), dd, func_ok=fo,
                                          rules=gate.rules(conf))
            else:                                          # 시험 운행 때의 기준(옛 실행 재현용)
                inc = [k for k in hj.SIGMA_CLASSES if s1["by_class"].get(k, 0) > s0["by_class"].get(k, 0)]
                if s1["unsafe_blocks"] > s0["unsafe_blocks"]:
                    inc.append("unsafe")
                new_load = [k for k, v in s1["codeload"].items() if v > s0["codeload"].get(k, 0)]
                new_deps = sorted(set(s1["deps"]) - set(s0["deps"]))
                if not set(st["A0"]) <= set(acc):
                    reason = "functional_regression"
                elif new_load or new_deps:
                    reason = "loader_changed"
                elif inc:
                    reason = "risk_points_increased"
        st["log"].append({"k": st["k"], "built": built, "compile_fixes": st["cfix"], "reason": reason})
        cur = run / c / "accepted" / tkey
        # 예산 대조(BUD)는 가장 비싼 방법과 같은 예산으로 다시 생성한다(사용자 결정): K = 공통 상한 C.
        # BUD 의 최종 결과 규칙(검토의견_반영_결정 1절): 받아들이기를 처음 통과한 다시 번역이 최종이고 거기서 멈춘다(아래
        # reason == "accepted" 갈래: accepted/ 에 복사, status accepted, 다음 요청 없음). 상한 안에 통과가 없으면 exhausted 갈래:
        # accepted/ 는 prep-b 가 넣은 출발 코드 그대로이고 status harden_failed(eval-b 는 출발 코드를 최종으로 쓴다).
        kc = gate.call_cap(conf) if (c == "BUD" and gate.call_cap(conf)) else K_B
        spent = own_calls(st)          # 기존 조건은 시도 + 컴파일 수정 그대로(RCI 만 비판 1번이 더해진다)
        exhausted = st["k"] >= kc or gate.over_cap(conf, spent)
        if not exhausted and reason != "accepted" and budget_left(st) < 1:   # 되풀이 조건: 전체 호출 상한에 닿아 회차를 끊는다
            exhausted, st["truncated"] = True, True
        remaining = []
        if reason == "accepted" and c == "B5":
            # B5: 받아들였어도 방법 자신의 조건 신호가 남으면(표시한 조건을 아직 못 지킴) 다시 시도 신호로 쓴다.
            remaining = [n for n in st["unmet"] if not dd.get(n)]
            st["observed_cur"] = {str(n): hij.observed_text(outs[n][1]) for n in remaining if n in outs}
        if c in B5_CONDS and reason == "accepted":
            st["locations_cur"] = [l for l in s1.get("locations", []) if l["class"] in PANIC_LINTS]
        if reason == "accepted" and (not remaining or exhausted):
            shutil.rmtree(cur)
            shutil.copytree(cand, cur)
            st["status"] = "accepted"
            if "chain" in st:
                st["chain"]["stage2_status"] = "accepted"
            print("ACCEPTED k", st["k"], ("(signal remains: %s)" % remaining) if remaining else "")
        elif reason == "accepted":                           # B5: 받아들인 코드에서 남은 조건으로 다시 시도
            shutil.rmtree(cur)
            shutil.copytree(cand, cur)
            st["accepted_once"], st["unmet"] = True, remaining
            st["k"] += 1
            st["cfix"] = 0
            req = ("Your previous revision was accepted, but the program still does not handle some input conditions "
                   "listed below. The files under \"Current files\" are that accepted version; start from them.\n\n"
                   + request_b(run, c, st, cur))
            (run / c / "prompts" / f"{tkey}__{pre}k{st['k']}.txt").write_text(req, encoding="utf-8")
            print("NEXT", f"{pre}k{st['k']}", "accepted_but_conditions_remain", remaining)
        elif exhausted:
            # 원래 코드를 둔다(상한 도달 포함). B5 가 앞서 받아들인 코드가 있으면 그것이 최종.
            st["status"] = "accepted" if st.get("accepted_once") else "harden_failed"
            if "chain" in st:          # 2단계가 못 받아들여지면 1단계 최종 프로그램(accepted/ 에 그대로 있음)과 상태를 따른다
                st["chain"]["stage2_status"] = st["status"]
                st["status"] = st["chain"]["stage1_status"]
            print("ACCEPTED(last accepted kept)" if st.get("accepted_once") else "HARDEN_FAILED", reason)
        else:
            st["k"] += 1
            st["cfix"] = 0
            req = request_b(run, c, st, cur if c != "BUD" else None)
            if c != "BUD":                                   # 예산 대조는 이유 없이 새로 만든다
                req = hj.fill(hj.tpl("pi_rep_retry"), reason=reason, request=req)
            (run / c / "prompts" / f"{tkey}__{pre}k{st['k']}.txt").write_text(req, encoding="utf-8")
            print("NEXT", f"{pre}k{st['k']}", reason)
        if "chain" in st:
            st["chain"]["stage2_calls"] = stage2_calls(st)
            if "rounds" in st["chain"] and st["status"] != "running":     # 되풀이 조건: 회차 끝
                nxt = finish_round(run, c, st)
                st["chain"]["stage2_calls"] = stage2_calls(st)
                print("ROUND", st["round"] if nxt else "done", st["status"])
        js(sp, st)

    elif cmd == "pending-b":
        for c in conds_of(jl(run / "config.json")):
            for p in sorted((run / c / "state").glob("*.json")):
                st = jl(p)
                if st["status"] == "waiting":                # 이어 붙인 조건: 1단계가 아직 안 끝남
                    print("WAIT", c, st["tkey"], chain_of(jl(run / "config.json"), c)["stage1"])
                    continue
                if st["status"] != "running":
                    print("DONE", c, st["tkey"], st["status"])
                    continue
                tag = tag_pre(st) + f"k{st['k']}" + (f"f{st['cfix']}" if st["cfix"] else "") \
                    + PHASE_TAG.get(st.get("phase"), "")
                has = (run / c / "replies" / f"{st['tkey']}__{tag}.md").exists()
                print("READY" if has else "ITEM", c, f"{st['tkey']}__{tag}")

    elif cmd == "eval-b":
        conf = jl(run / "config.json")
        b4run = Path(conf["b4run"])
        rows, first_rows = [], []
        for c in conds_of(conf):
            for p in sorted((run / c / "state").glob("*.json")):
                st = jl(p)
                b = hj.run_tests(run / c, st["tkey"], "eval_base", b4run / "base", st["item"])
                h = hj.run_tests(run / c, st["tkey"], "eval_hard", run / c / "accepted", st["item"]) \
                    if st["status"] == "accepted" else b
                row = pairs_row(c, st, b, h, calls=total_calls(st))
                if "chain" in st:
                    row.update({"calls_stage1": st["chain"]["stage1_calls"], "calls_stage2": stage2_calls(st),
                                "stage1_status": st["chain"]["stage1_status"],
                                "stage2_status": st["chain"].get("stage2_status")})
                    if "rounds" in st["chain"]:              # 되풀이 조건: 회차별 상태와 호출 나눔
                        row.update({"best_cond": st["chain"]["stage1"], "call_cap_total": st["chain"]["cap"],
                                    "rounds": st["chain"]["rounds"], "n_rounds": len(st["chain"]["rounds"]),
                                    "round_statuses": [r["status"] for r in st["chain"]["rounds"]],
                                    "calls_rounds": [r["calls"] for r in st["chain"]["rounds"]],
                                    "stop": st["chain"].get("stop")})
                if c in FIRST_CANDIDATE_CONDS and (c == "RCI" or "first" in st):   # 원 방식 그대로(받아들이기 기준 없이 첫 후보)
                    fs = st.get("first") or {"built": None}
                    if fs["built"]:
                        f = hj.run_tests(run / c, st["tkey"], "eval_first", run / c / "first_candidate", st["item"])
                        fr = pairs_row(c + "@first", st, b, f, calls=row["calls"])
                        row["first"] = {"built": True, "functional_ok": f["functional_ok"],
                                        **({"pairs": fr["pairs"]} if "pairs" in fr else {"blinded_kinds": fr["blinded_kinds"]})}
                        first_rows.append({**fr, "status": "first_built"})
                    else:
                        row["first"] = {"built": fs["built"]}        # False = 빌드 안 됨, None = k1 까지 못 감
                        first_rows.append({"cond": c + "@first", "tkey": st["tkey"], "source": st["source"],
                                           "status": "first_not_built", "calls": row["calls"],
                                           "base_functional_ok": b["functional_ok"], "hard_functional_ok": False,
                                           "pairs": []})
                rows.append(row)
        js(run / "eval_rows.json", rows)
        summ = summary(rows)
        if first_rows:
            summ.update(summary(first_rows))
            for k in {r["cond"] for r in first_rows}:
                summ[k]["first_built"] = sum(1 for r in first_rows if r["cond"] == k and r["status"] == "first_built")
        print(json.dumps(summ, ensure_ascii=False, indent=1))


def translate_version(run):
    """실험 B 의 예산 대조는 실험 A 와 같은 옮기기 요청문을 쓴다(실험 A 실행 폴더의 버전을 따른다)."""
    cp = Path(run) / "config.json"
    conf = jl(cp) if cp.exists() else {}
    if "translate_prompt" in conf:
        return conf["translate_prompt"]
    ap = Path(conf["arun"]) / "config.json" if conf.get("arun") else None
    return jl(ap).get("translate_prompt", "v1") if ap and ap.exists() else "v1"


def unmet_initial(b4st):
    """출발 코드가 지키지 못하는 stated 조건: 정상 입력은 정상(ok0)인데 위반 입력이 명세대로 끝나지 않음(d0=0)."""
    out = []
    for n in b4st.get("considered", []):
        line = hij.cond_line(b4st, n)
        if "[stated]" in line and b4st["ok0"].get(str(n)) and not b4st["d0"].get(str(n)):
            out.append(n)
    return out


def all_rules_text():
    """공통 규칙 𝒢 7개 전부(B5 는 점검으로 규칙을 고르지 않는다)."""
    import re as _re
    rules = {int(m.group(1)): m.group(2).strip()
             for m in _re.finditer(r"^RULE (\d+):\s*(.*)$", hj.tpl("rules"), _re.M)}
    return "\n".join(f"RULE {n}: {rules[n]}" for n in sorted(rules))


def b5_sections(run, st):
    b4st = jl(Path(st["b4run"]) / "state" / f"{st['tkey']}.json")
    stated = [l for l in b4st["checklist"] if "[stated]" in l]
    out = "# Input conditions from the specification\n\n" + ("\n".join(stated) or "(none)") + "\n\n"
    if st["cond"] == "B5":
        lines = [f"{hij.cond_line(b4st, n)}\n  {st['observed_cur'].get(str(n), '')}".rstrip() for n in st["unmet"]]
        out += ("# Conditions the current program does not handle\n\n" + ("\n".join(lines) or "(none detected)")
                + "\n\n")
    locs = "\n".join(f"{l['file']}:{l['line']} — {l['signal']}" for l in st.get("locations_cur", []))
    if locs:
        out += "# Risk locations (panic)\n\n" + locs + "\n\n"
    out += "# Security rules to apply\n\n" + all_rules_text() + "\n\n"
    return out


def spec_text_policy(item):
    """오라클 조건 전용: 명세에 security_policy(정답 설명)까지 넣는다. 주 결론에는 쓰지 않는다(참고선)."""
    td = json.loads((hj.EXPORT / "programs" / item / "meta.json").read_text(encoding="utf-8"))["task_description"]
    return "\n\n".join(f"{lab}:\n{td[k].strip()}" for k, lab in hij.SPEC_FIELDS_POLICY if (td.get(k) or "").strip())


def b4_checklist(run, st):
    """B2 전용: 명세에서 뽑은 검사 목록(stated 만). B4 실행이 뽑아 둔 것을 같이 쓴다."""
    b4st = jl(Path(st.get("b4run") or jl(run / "config.json")["b4run"]) / "state" / f"{st['tkey']}.json")
    return [l for l in b4st["checklist"] if "[stated]" in l]


def request_b(run, c, st, cur):
    if c == "RCI":   # 개선 요청(비판은 한 번 받은 것을 다시 쓴다)
        return rci_improve(st, cur)
    if is_chain(c):  # 2단계 요청(1단계 결과 위에서)
        return stage2_request(run, st, cur)
    if c == "BUD":   # 고치지 않고 처음부터 다시 옮긴다(같은 옮기기 요청)
        return t.prompt("rust", (NC / st["item"] / f"{st['source']}.py").read_text(encoding="utf-8"),
                        translate_version(run))
    body = GENERIC
    if c == "ORA":   # 오라클(참고선): B1 + security_policy. 명세에 정답 설명을 넣은 상한.
        body += "# Specification\n\n" + spec_text_policy(st["item"]) + "\n\n"
    elif c in ("B1",) + B5_CONDS:
        body += "# Specification\n\n" + hij.hj.spec_text(st["item"]) + "\n\n"
    if c == "B2":    # 검사 목록만(명세 원문·규칙 없음)
        body += "# Input conditions from the specification\n\n" + ("\n".join(b4_checklist(run, st)) or "(none)") + "\n\n"
    if c in B5_CONDS:
        body += b5_sections(run, st)
    return body + "# Current files\n\n" + hj.files_block(cur) + "\n\n" + hj.CONTRACT


def pairs_row(c, st, b, h, calls):
    pairs = []
    for (bv, _), (hv, _) in zip(b["safety"], h["safety"]):
        if "invalid" in (bv, hv):
            pairs.append("invalid")
            continue
        be, he = bv == "exploited", hv == "exploited"
        pairs.append("removed" if be and not he else "left" if be and he else "new" if he else "safe")
    row = {"cond": c, "tkey": st["tkey"], "source": st["source"], "status": st["status"], "calls": calls,
           "base_functional_ok": b["functional_ok"], "hard_functional_ok": h["functional_ok"], "pairs": pairs}
    if b.get("blinded_kinds") or h.get("blinded_kinds"):   # 가림(run_main.py): 보안 시험을 돌리지 않았으므로 칸을 두지 않는다
        row.pop("pairs")
        row["blinded_kinds"] = b.get("blinded_kinds") or h.get("blinded_kinds")
    return row


def summary(rows):
    out = {}
    for r in rows:
        s = out.setdefault(r["cond"], {"targets": 0, "accepted": 0, "func_broken": 0, "calls": 0,
                                       "removed": 0, "left": 0, "new": 0, "safe": 0, "removed_func_kept": 0,
                                       "left_func_kept": 0, "new_func_kept": 0})
        s["targets"] += 1
        s["accepted"] += r["status"] in ("accepted", "full", "partial")
        s["calls"] += r["calls"]
        broken = r["base_functional_ok"] and not r["hard_functional_ok"]
        s["func_broken"] += broken
        for o in r.get("pairs", []):
            if o in s:
                s[o] += 1
                if not broken and o in ("removed", "left", "new"):
                    s[o + "_func_kept"] += 1
    return out


if __name__ == "__main__":
    main()
