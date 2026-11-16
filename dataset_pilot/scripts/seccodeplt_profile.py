"""SecCodePLT 항목의 설계 적합성 프로파일(컨테이너 안에서만 실행).
항목마다: 기능/보안 시험 수, 인자와 기대값을 JSON으로 옮길 수 있는지, 코드 길이, 설명 필드.
usage: python -I seccodeplt_profile.py <items_dir> <ids_file> <out.jsonl>"""
import json, os, sys, base64
items_dir, ids_file, out = sys.argv[1:4]
def portable(v):
    if v is None or isinstance(v, (bool, int, float, str)): return True
    if isinstance(v, bytes): return True          # base64 표기로 옮길 수 있음
    if isinstance(v, (list, tuple)): return all(portable(x) for x in v)
    if isinstance(v, dict): return all(isinstance(k, str) and portable(x) for k, x in v.items())
    return False
with open(out, "w") as f:
    for iid in open(ids_file).read().split():
        it = json.load(open(os.path.join(items_dir, iid + ".json"), encoding="utf-8"))
        g = it["ground_truth"]; r = {"id": iid, "cwe": it["CWE_ID"]}
        try:
            ns = {}; exec(it["unittest"]["setup"] or "", ns); tns = dict(ns); exec(it["unittest"]["testcases"], tns)
            tc = tns["testcases"]
            for kind in ("capability", "safety"):
                cases = tc.get(kind, [])
                r[kind + "_n"] = len(cases)
                r[kind + "_args_portable"] = all(portable(k) for k, _ in cases)
                r[kind + "_exp_portable"] = all((isinstance(e, type) and issubclass(e, BaseException)) or portable(e) for _, e in cases)
                r[kind + "_exc_expected"] = sum(1 for _, e in cases if isinstance(e, type) and issubclass(e, BaseException))
            r["setup_nonempty"] = bool((it["unittest"]["setup"] or "").strip())
        except BaseException as e:
            r["error"] = type(e).__name__
        r["vuln_chars"] = len(g["code_before"] + g["vulnerable_code"] + g["code_after"])
        r["patch_chars"] = len(g["code_before"] + g["patched_code"] + g["code_after"])
        td = it["task_description"]
        if isinstance(td, str):
            try: td = json.loads(td)
            except Exception: td = {"description": td}
        r["desc_fields"] = sorted(td.keys()) if isinstance(td, dict) else []
        r["desc_chars"] = len(json.dumps(td, ensure_ascii=False))
        r["func"] = next((l.strip()[4:].split("(")[0] for l in g["code_before"].splitlines() if l.strip().startswith("def ")), None)
        r["install_requires"] = list(it.get("install_requires") or [])
        f.write(json.dumps(r) + "\n")
print("done")
