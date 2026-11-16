"""하위 에이전트(Claude Code)를 번역 모델로 쓰는 맛보기용. 결제 API를 쓰지 않는다.
translate.py 와 같은 지시문·같은 빌드·같은 고치기 규칙(최대 3번)을 쓰되, 모델 호출 대신 파일을 주고받는다.
  prep   <run> <ids file>          : prompts/<key>__r0.txt 를 만든다(출발 코드 + 지시문). 에이전트는 이 파일 하나만 읽는다.
  ingest <run> <key> <round>       : replies/<key>__r<round>.md 를 받아 빌드/확인한다.
                                     실패하고 round<3 이면 prompts/<key>__r<round+1>.txt(오류 출력)를 만들고 FIX 를 찍는다.
                                     끝나면 logs/<key>.json 을 translate.py 와 같은 형식으로 쓴다.
온도·시드는 정할 수 없으므로 본 실험 결과에 넣지 않는다. Py→Py 는 다시 만들기 대신 유사도만 기록한다.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import translate as t  # noqa: E402

t.TARGET_VOL = "dsp-cargo-target-agent"   # 로컬 시험 운행과 빌드 폴더를 나눈다

cmd, run = sys.argv[1], Path(sys.argv[2])
CONDS = ("PyRs", "PyPy")
SOURCES = ("vulnerable", "patched")


def split(key):
    item, source, cond = key.split("__")
    return item, source, cond


if cmd == "prep":
    (run / "prompts").mkdir(parents=True, exist_ok=True)
    (run / "replies").mkdir(parents=True, exist_ok=True)
    for item in Path(sys.argv[3]).read_text().split():
        for source in SOURCES:
            for cond in CONDS:
                src = (t.EXPORT / "programs" / item / f"{source}.py").read_text(encoding="utf-8")
                lang = "rust" if cond == "PyRs" else "python"
                key = f"{item}__{source}__{cond}"
                (run / "prompts" / f"{key}__r0.txt").write_text(t.prompt(lang, src), encoding="utf-8")
                print(key)

elif cmd == "ingest":
    key, rnd = sys.argv[3], int(sys.argv[4])
    item, source, cond = split(key)
    lang = "rust" if cond == "PyRs" else "python"
    sol = run / "solutions" / key
    state_p = run / "state" / f"{key}.json"
    state_p.parent.mkdir(parents=True, exist_ok=True)
    state = json.loads(state_p.read_text(encoding="utf-8")) if state_p.exists() else \
        {"item": item, "source": source, "cond": cond, "model": "claude-code-subagent(sonnet)", "calls": [], "regen": 0, "copied": False}
    text = (run / "replies" / f"{key}__r{rnd}.md").read_text(encoding="utf-8")
    state["calls"].append({"kind": "translate" if rnd == 0 else "fix", "round": rnd, "response": text})
    if rnd == 0 and sol.exists():
        import shutil
        shutil.rmtree(sol)
    wrote = t.write_rust(sol, text) if lang == "rust" else t.write_py(sol, text)
    if not wrote and not (sol.exists() and any(sol.iterdir())):
        built, blog = False, "no code block in reply"
    else:
        built, blog = t.build_rust(sol) if lang == "rust" else t.check_py(sol)
    if not built and rnd < 3:
        (run / "prompts" / f"{key}__r{rnd + 1}.txt").write_text(t.fix_prompt(lang, blog), encoding="utf-8")
        state_p.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
        print("FIX", rnd + 1)
        sys.exit(0)
    state.update({"built": built, "fix_rounds": rnd, "build_log_tail": blog[-1500:]})
    if lang == "python" and built:
        src = (t.EXPORT / "programs" / item / f"{source}.py").read_text(encoding="utf-8")
        sim = t.similarity(src, (sol / "main.py").read_text(encoding="utf-8"))
        state["similarity"] = round(sim, 3)
        state["copied"] = sim >= 0.90
    (run / "logs").mkdir(parents=True, exist_ok=True)
    (run / "logs" / f"{key}.json").write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
    print("BUILT" if built else "FAILED", "fix_rounds", rnd, "similarity", state.get("similarity"))
