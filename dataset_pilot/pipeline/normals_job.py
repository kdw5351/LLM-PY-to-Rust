"""정상 입력 묶음 (공통받아들이기기준_2026-11-12.md 9절). 받아들이기의 기능 확인을 강하게 한다.
명세(security_policy 제외)만 보고 받은 '평범하게 처리돼야 하는 입력'을 원본 Python 과 번역에 똑같이 넣어 출력을 비교한다.
데이터셋 시험은 쓰지 않는다. 실행은 Docker(네트워크 없음)에서만.

  prep   <run>   : 항목마다 요청 prompts/nm__<item>.txt
  ingest <run>   : replies/nm__<item>.md 를 읽어 원본 Python(취약·수정)에 돌리고 normals/<item>.json 에 저장
  base   <run>   : 대상마다 출발 번역이 원본과 같은 출력을 내는 입력 집합 N0 를 normals/_n0.json 에 저장
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DS = HERE.parent
sys.path.insert(0, str(HERE))
import harden_job as hj  # noqa: E402
import harden_item_job as hij  # noqa: E402
from judge import equal  # noqa: E402

EXPORT = DS / "export"
TPL = (HERE / "prompts_ds" / "pi_normals.md").read_text(encoding="utf-8")


def jl(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def items_of(run):
    return sorted({x["item"] for x in jl(run / "targets.json")})


def parse_reply(text):
    m = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.S)
    data = json.loads(m.group(1) if m else text)
    return [a for a in data if isinstance(a, dict)]


def load(run, item):
    p = run / "normals" / f"{item}.json"
    return jl(p) if p.exists() else None


def match_set(nm, source, outs):
    """원본(같은 출발 버전)이 정상으로 끝나고 번역 출력이 같은 입력 번호."""
    orig = nm["orig"][source]
    return sorted(i for i, (o, x) in enumerate(zip(orig, outs))
                  if o["st"] == "ok" and x["st"] == "ok" and equal(x["val"], o["val"]))


def measure(run, key, item, label, sol_root):
    """번역 하나(sol_root/<key>/app)에 정상 입력을 넣은 결과 목록. 정상 입력이 없으면 None."""
    nm = load(run, item)
    if not nm or not nm["inputs"]:
        return None, None
    res = hij.run_inputs(run, f"nm__{label}", sol_root, [(key, item, "rust", f"/s/{key}/app")], {item: nm["inputs"]})
    return nm, res[key]


def main():
    cmd, run = sys.argv[1], Path(sys.argv[2])
    (run / "prompts").mkdir(parents=True, exist_ok=True)
    (run / "normals").mkdir(parents=True, exist_ok=True)
    if cmd == "prep":
        for it in items_of(run):
            (run / "prompts" / f"nm__{it}.txt").write_text(hj.fill(TPL, spec=hj.spec_text(it)), encoding="utf-8")
            print("prompt", it)
    elif cmd == "ingest":
        for it in items_of(run):
            rp = run / "replies" / f"nm__{it}.md"
            if not rp.exists():
                print("MISSING", it)
                continue
            try:
                inputs = parse_reply(rp.read_text(encoding="utf-8"))
            except (ValueError, AttributeError) as e:
                print("PARSE_FAIL", it, e)
                continue
            rr = hij.run_inputs(run, f"nm_orig__{it}", EXPORT / "programs_nc",
                                [(f"{it}/{s}", it, "python", f"/s/{it}/{s}.py") for s in ("vulnerable", "patched")],
                                {it: inputs})
            nm = {"inputs": inputs, "orig": {s: rr[f"{it}/{s}"] for s in ("vulnerable", "patched")}}
            hij.jsave(run / "normals" / f"{it}.json", nm)
            okv = sum(o["st"] == "ok" for o in nm["orig"]["vulnerable"])
            okp = sum(o["st"] == "ok" for o in nm["orig"]["patched"])
            print(it, "inputs", len(inputs), "ok on vulnerable", okv, "ok on patched", okp)
    elif cmd == "base":
        n0 = {}
        for x in jl(run / "targets.json"):
            nm, outs = measure(run, x["tkey"], x["item"], f"base__{x['tkey']}", run / "base")
            n0[x["tkey"]] = match_set(nm, x["source"], outs) if nm else []
            print(x["tkey"], "N0", len(n0[x["tkey"]]), "of", len(nm["inputs"]) if nm else 0)
        hij.jsave(run / "normals" / "_n0.json", n0)


if __name__ == "__main__":
    main()
