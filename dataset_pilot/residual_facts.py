"""Residual security-test facts for a B run (no model calls, no re-runs unless stored outputs are missing).

usage: python residual_facts.py <brun>      (from dataset_pilot/)
Writes <brun>/residual_facts.tsv and <brun>/residual_facts.json.
One record per (cond, tkey, security-test index) where
  source == vulnerable and label in {left, new}, or source == patched and label == new.
Only kinds and error NAMES are written/printed: never test args, returned values or error message text.

Sources:
  labels, status, calls, RCI first-candidate labels : <brun>/eval_rows.json
  gate reasons                                     : <brun>/<cond>/state/<tkey>.json  (log[].reason)
  final-program per-test outputs                   : <brun>/<cond>/_runs/<tkey>__eval_hard.runs.jsonl (status accepted)
                                                     <brun>/<cond>/_runs/<tkey>__eval_base.runs.jsonl (otherwise; = start code)
  test expectations                                : export/tests/<item>.json  (safety[i].expect: raises | value)
  CWE                                              : export/programs/<item>/meta.json  ("cwe")
  original Python vulnerable/patched outputs       : export/originals_runs.jsonl  (key "<item>/<source>")
Judging uses pipeline/judge.py (same as harden_job.run_tests), timing rule from usable/items.tsv as harden_job.TIM.
"""
import collections
import json
import re
import sys
from pathlib import Path

DS = Path(__file__).resolve().parent
sys.path.insert(0, str(DS / "pipeline"))
from judge import judge_record, parse  # noqa: E402

EXPORT = DS / "export"
TIM = None  # 시간 초과 인정 항목: main() 이 처음 쓸 때 usable/items.tsv 에서 읽는다(가져오기만으로는 자료 파일을 읽지 않음)


def tim():
    global TIM
    if TIM is None:
        TIM = set(l.split("\t")[1] for l in open(DS / "usable" / "items.tsv", encoding="utf-8") if "시간 초과 규칙으로 인정" in l)
    return TIM


NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:]{0,60}$")
FIELDS = ["cond", "tkey", "item", "cwe", "source", "test_index", "label", "status", "gate_reasons", "calls", "process",
          "expect_kind", "actual_kind", "actual_sub", "failure_mode", "orig_vul_kind", "orig_pat_kind", "first_label",
          "stage2_status"]


def jl(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def err_name(s):
    s = str(s)
    return s if NAME_RE.match(s) else "<non-name>"


def kind_of(run):
    """(kind, sub). kind: ok | error:<Name> | timeout | crash | unknown. sub refines crash: panic/signal/nonjson/oom."""
    if run is None:
        return "unknown", ""
    st, sub, _val = parse(run)
    if st == "ok":
        return "ok", ""
    if st == "error":
        return "error:" + err_name(sub), ""
    if sub == "timeout":
        return "timeout", ""
    err = run.get("stderr") or ""
    if "memory allocation" in err or "MemoryError" in err:
        return "crash", "oom"
    if sub == "panic":
        return "crash", "panic"
    rc = run.get("rc")
    if isinstance(rc, int) and rc < 0:
        return "crash", "signal"
    return "crash", "nonjson" if rc == 0 else "nonzero_exit"


def expect_kind(exp):
    if "raises" in exp:
        return "error:" + err_name(exp["raises"]) if exp["raises"] else "error"
    if "value" in exp:
        return "value"
    return "unknown"


def failure_mode(ek, ak, asub):
    if ak == "timeout" or (ak == "crash" and asub == "oom"):
        return "F4"
    if ak == "crash":
        return "F5"
    if ek.startswith("error") and ak == "ok":
        return "F1"
    if ek == "value" and ak == "ok":
        return "F2"
    if ek.startswith("error") and ak.startswith("error"):
        return "F3"
    return "F?"


def load_runs(p):
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8").splitlines()[0])


def main():
    run = Path(sys.argv[1])
    rows = jl(run / "eval_rows.json")
    orig = {}
    for line in open(EXPORT / "originals_runs.jsonl", encoding="utf-8"):
        if line.strip():
            r = json.loads(line)
            orig[r["key"]] = r
    recs, missing, mismatch = [], [], 0
    for row in rows:
        c, tkey, source = row["cond"], row["tkey"], row["source"]
        item = tkey.split("__")[1]
        want = {"left", "new"} if source == "vulnerable" else {"new"}
        idx = [i for i, lab in enumerate(row["pairs"]) if lab in want]
        st = jl(run / c / "state" / f"{tkey}.json")
        tests = jl(EXPORT / "tests" / f"{item}.json")
        # consistency check: re-judge stored outputs and compare with eval_rows labels
        tag = "eval_hard" if row["status"] == "accepted" else "eval_base"
        fin = load_runs(run / c / "_runs" / f"{tkey}__{tag}.runs.jsonl")
        base = load_runs(run / c / "_runs" / f"{tkey}__eval_base.runs.jsonl")
        if fin is None or base is None:
            missing.append((c, tkey))
        else:
            jb, jh = judge_record(base, tests, item in tim()), judge_record(fin, tests, item in tim())
            pairs = []
            for (bv, _), (hv, _) in zip(jb["safety"], jh["safety"]):
                if "invalid" in (bv, hv):
                    pairs.append("invalid")
                    continue
                be, he = bv == "exploited", hv == "exploited"
                pairs.append("removed" if be and not he else "left" if be and he else "new" if he else "safe")
            mismatch += pairs != row["pairs"]
        if not idx:
            continue
        meta = jl(EXPORT / "programs" / item / "meta.json")
        reasons = [x.get("reason", "?") for x in st.get("log", [])]
        first_pairs = (row.get("first") or {}).get("pairs") if c == "RCI" else None
        for i in idx:
            ek = expect_kind(tests["safety"][i]["expect"])
            fr = fin["runs"]["safety"][i] if fin and i < len(fin["runs"]["safety"]) else None
            ak, asub = kind_of(fr)
            ok_ = []
            for s in ("vulnerable", "patched"):
                o = orig.get(f"{item}/{s}")
                osf = o["runs"]["safety"] if o else []
                ok_.append(kind_of(osf[i])[0] if o and len(osf) == len(tests["safety"]) else "unknown")
            recs.append({
                "cond": c, "tkey": tkey, "item": item, "cwe": "CWE-" + str(meta.get("cwe", "?")), "source": source,
                "test_index": i, "label": row["pairs"][i], "status": row["status"], "gate_reasons": ">".join(reasons),
                "calls": row["calls"], "process": "P1" if row["status"] == "harden_failed" else "P2",
                "expect_kind": ek, "actual_kind": ak, "actual_sub": asub, "failure_mode": failure_mode(ek, ak, asub),
                "orig_vul_kind": ok_[0], "orig_pat_kind": ok_[1],
                "first_label": (first_pairs[i] if first_pairs and i < len(first_pairs) else
                                ("not_built" if c == "RCI" else "")),
                "stage2_status": (st.get("chain") or {}).get("stage2_status", ""),
            })
    (run / "residual_facts.json").write_text(json.dumps(recs, ensure_ascii=False, indent=1), encoding="utf-8")
    with open(run / "residual_facts.tsv", "w", encoding="utf-8", newline="") as fh:
        fh.write("\t".join(FIELDS) + "\n")
        for r in recs:
            fh.write("\t".join(str(r[k]) for k in FIELDS) + "\n")

    print(f"records {len(recs)}  rows {len(rows)}  stored-output missing {len(missing)}  label mismatches on re-judge {mismatch}")
    conds = list(dict.fromkeys(r["cond"] for r in rows))
    for c in conds:
        R = [r for r in recs if r["cond"] == c]
        tg = {}
        for r in R:
            tg.setdefault(r["tkey"], r)
        print(f"\n== {c}: targets with >=1 record {len(tg)}  (P1 {sum(v['process'] == 'P1' for v in tg.values())}, "
              f"P2 {sum(v['process'] == 'P2' for v in tg.values())}; vulnerable {sum(v['source'] == 'vulnerable' for v in tg.values())}, "
              f"patched {sum(v['source'] == 'patched' for v in tg.values())})  records {len(R)}")
        print("  records by label/source:", dict(collections.Counter((r["source"][:3], r["label"]) for r in R)))
        print("  records by failure_mode:", dict(sorted(collections.Counter(r["failure_mode"] for r in R).items())))
        print("  records by actual_kind:", dict(collections.Counter(r["actual_kind"] + (":" + r["actual_sub"] if r["actual_sub"] else "") for r in R)))
        print("  targets by CWE:", dict(sorted(collections.Counter(v["cwe"] for v in tg.values()).items())))
        p1 = [v for v in tg.values() if v["process"] == "P1"]
        print("  P1 targets by last gate reason:", dict(collections.Counter(v["gate_reasons"].split(">")[-1] for v in p1)))
        if c == "RCI":
            print("  RCI first_label of records:", dict(collections.Counter(r["first_label"] for r in R)))
        print("  unknown actual_kind:", sum(r["actual_kind"] == "unknown" for r in R),
              " orig unknown (vul/pat):", sum(r["orig_vul_kind"] == "unknown" for r in R), "/",
              sum(r["orig_pat_kind"] == "unknown" for r in R))
    B = [r for r in recs if r["cond"] == "B1"]
    if B:
        cnt = collections.Counter((cw, fm) for _tk, cw, fm in {(r["tkey"], r["cwe"], r["failure_mode"]) for r in B})
        fms = sorted({fm for _, fm in cnt})
        print("\n== B1 CWE x failure_mode (targets, once per distinct mode)")
        print("CWE\t" + "\t".join(fms))
        for cw in sorted({cw for cw, _ in cnt}):
            print(cw + "\t" + "\t".join(str(cnt[(cw, fm)]) for fm in fms))


if __name__ == "__main__":
    main()
