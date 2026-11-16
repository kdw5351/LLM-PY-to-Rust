"""개발용 기록 다시 판정 (본실행_준비완료기준_2026-11-12.md A2·A3, 받아들이기 규칙 v2).

모델을 다시 부르지 않는다. 저장된 시도 응답(replies/<tkey>__k<k>[f<f>].md)을 순서대로 다시 빌드·시험해
규칙 v2로 판정하고, 처음 받아들여진 시도에서 멈춘다(그 앞 시도의 요청문은 v1과 같으므로 재구성이 정확하다).
v2는 v1보다 너그럽기만 하므로 받아들이는 시점이 늦어지지 않는다.

사용: python rejudge_v2.py <src_run> <dst_run>
  src_run: pilot_Bc_GF_2026-11-12 (B0·B1·BUD)
결과: <dst_run>/<cond>/state/<tkey>.json, <dst_run>/eval_rows.json, <dst_run>/summary.json
원래 실행 폴더는 읽기만 한다.
"""
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pilot_job as pj  # noqa: E402
import gate  # noqa: E402

hj, hij, t = pj.hj, pj.hij, pj.t
RULES = "v2"


def attempt_reply(src, c, tkey, k, cfix):
    """시도 k 의 마지막 응답(컴파일 수정이 있었으면 마지막 수정본)."""
    for f in range(cfix, -1, -1):
        tag = f"k{k}" + (f"f{f}" if f else "")
        p = src / c / "replies" / f"{tkey}__{tag}.md"
        if p.exists():
            return p.read_text(encoding="utf-8"), tag
    return None, None


def judge_attempt(src, dst, conf, c, st, k, text, tag):
    tkey = st["tkey"]
    cand = dst / c / "cand" / f"{tkey}__k{k}"
    if cand.exists():
        shutil.rmtree(cand)
    if not t.write_rust(cand, text):
        return "build", {}, None
    built, _ = pj.build_iso(cand, f"rj/{c}/{tkey}")
    if not built:
        return "build", {}, None
    root = dst / c / "_root"
    if (root / tkey).exists():
        shutil.rmtree(root / tkey)
    shutil.copytree(cand, root / tkey)
    b4run = Path(conf["b4run"])
    b4st = pj.jl(b4run / "state" / f"{tkey}.json")
    outs = hij.measure(b4run, tkey, st["item"], f"rj_{c}_k{k}", root)
    _, dd, acc = hij.signals(b4run, b4st, outs)
    s1 = pj.sigma_iso(cand, f"rj/{c}/{tkey}")
    fo = hj.run_tests(dst / c, tkey, f"rj_gatefunc_k{k}", root, st["item"])["functional_ok"]
    ok, reason, det = gate.check(True, st["sigma0"], s1, st["A0"], acc, b4st.get("d0"), dd, func_ok=fo, rules=RULES)
    return reason, det, cand


def main():
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    conf = pj.jl(src / "config.json")
    pj.js(dst / "config.json", {**conf, "gate_rules": RULES, "rejudged_from": str(src)})
    b4run = Path(conf["b4run"])
    rows = []
    only = set(sys.argv[3:])
    for c in pj.CONDS_B:
        for p in sorted((src / c / "state").glob("*.json")):
            st = pj.jl(p)
            tkey = st["tkey"]
            if only and tkey not in only:
                continue
            v1_log = st["log"]
            affected = any(e["reason"] in ("risk_points_increased", "loader_changed") for e in v1_log)
            new = {**st, "log": [], "rules": RULES, "v1_status": st["status"], "v1_log": v1_log}
            final = None
            if not affected:                          # v1 과 같은 결과(다시 만들 필요 없음)
                new["log"], new["status"] = v1_log, st["status"]
                new["rejudged"] = False
                if st["status"] == "accepted":
                    final = src / c / "accepted" / tkey
            else:
                new["rejudged"] = True
                new["status"] = "harden_failed"
                for e in v1_log:
                    k, cfix = e["k"], e.get("compile_fixes", 0)
                    if e["reason"] == "build":
                        new["log"].append({**e})
                        continue
                    text, tag = attempt_reply(src, c, tkey, k, cfix)
                    if text is None:
                        new["log"].append({"k": k, "reason": "missing_reply"})
                        continue
                    reason, det, cand = judge_attempt(src, dst, conf, c, st, k, text, tag)
                    new["log"].append({"k": k, "compile_fixes": cfix, "reason": reason, "v1_reason": e["reason"],
                                       "detail": det, "reply": tag})
                    print(c, tkey, f"k{k}", "v1:", e["reason"], "-> v2:", reason, flush=True)
                    if reason == "accepted":
                        new["status"], final = "accepted", cand
                        break
            pj.js(dst / c / "state" / f"{tkey}.json", new)
            b = hj.run_tests(dst / c, tkey, "eval_base", b4run / "base", st["item"])
            h = b
            if final is not None:
                acc_root = dst / c / "accepted"
                if (acc_root / tkey).exists():
                    shutil.rmtree(acc_root / tkey)
                shutil.copytree(final, acc_root / tkey)
                h = hj.run_tests(dst / c, tkey, "eval_hard", acc_root, st["item"])
            calls = len(new["log"]) + sum(x.get("compile_fixes", 0) for x in new["log"])
            rows.append(pj.pairs_row(c, new, b, h, calls=calls))
            pj.js(dst / "eval_rows.json", rows)
    summ = pj.summary(rows)
    pj.js(dst / "summary.json", summ)
    print(json.dumps(summ, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
