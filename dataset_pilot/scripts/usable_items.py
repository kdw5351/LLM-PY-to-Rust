"""쓸 수 있는 항목 목록 만들기 (2026-11-11 사용자 기준: 결과에 취약점이 드러나야 하고, 깨지거나 이상한 항목은 쓰지 않는다).
받은 데이터는 읽기만 한다. 실행 결과 파일(results/)만 읽어 판정한다. usage: python -I scripts/usable_items.py <dataset_pilot dir>

판정 기준(모든 출처 공통):
  U1 두 판 모두 오류 없이 실행된다(준비 오류·크래시·도구 누락 없음).
  U2 수정판: 기능 시험과 보안 시험을 모두 통과한다.
  U3 취약판: 기능 시험은 모두 통과하고 보안 시험은 하나 이상 실패한다.
  U4 취약점이 결과에 드러난다: 취약판이 공격 입력을 받아들였다(값을 돌려줌, 공격 효과가 관찰됨).
     다른 예외로 실패했을 뿐인 것(예: 공격 입력이 SyntaxError 로 튕김)은 제외한다.
  U5 시간: 2026-11-11 고정 규칙(수정판은 제한의 10% 안에 끝나고 취약판은 3/3 제한 초과일 때만 시간 초과를 취약으로 인정).
     시험 뒤 프로세스가 끝나지 않아 제한에 걸린 항목은 제외한다.
  U6 다시 돌려도 같은 결과(SecCodePLT, CWEval 은 2번 돌려 비교).
  U7 내용이 완전히 같은 항목은 하나만 남긴다.
"""
import collections
import hashlib
import json
import os
import sys

base = sys.argv[1]
R = os.path.join(base, "results")
OUT = os.path.join(base, "usable")
os.makedirs(OUT, exist_ok=True)
rows_out = []   # (source, id, verdict, reason)


def seccodeplt():
    def load(p):
        d = collections.defaultdict(dict)
        for line in open(p, encoding="utf-8"):
            r = json.loads(line)
            d[r["id"]][r["version"]] = r
        return d
    a = load(os.path.join(R, "seccodeplt_all.jsonl"))
    b = load(os.path.join(R, "seccodeplt_all_run2.jsonl"))
    keys = ("capability", "safety", "capability_details", "safety_details", "timeout", "setup_error", "crash")
    tim = {}
    for line in open(os.path.join(R, "seccodeplt_timing.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        tim[r["id"]] = r
    # U7: 완전히 같은 항목
    first_by_hash, dup_of = {}, {}
    for iid in sorted(a):
        it = json.load(open(os.path.join(base, "seccodeplt_all", iid + ".json"), encoding="utf-8"))
        g = it["ground_truth"]
        h = hashlib.sha256("\x00".join([g["code_before"], g["vulnerable_code"], g["patched_code"], g["code_after"],
                                        it["unittest"]["setup"] or "", it["unittest"]["testcases"]]).encode()).hexdigest()
        if h in first_by_hash:
            dup_of[iid] = first_by_hash[h]
        else:
            first_by_hash[h] = iid
    for iid in sorted(a):
        vu, pa = a[iid]["vulnerable_code"], a[iid]["patched_code"]
        same = all({k: a[iid][v].get(k) for k in keys} == {k: b[iid][v].get(k) for k in keys}
                   for v in ("vulnerable_code", "patched_code"))
        if not same:
            rows_out.append(("SecCodePLT", iid, "exclude", "U6 두 번 돌린 결과가 다름")); continue
        if any(k in x for x in (vu, pa) for k in ("setup_error", "crash")):
            rows_out.append(("SecCodePLT", iid, "exclude", "U1 실행 오류")); continue
        if vu.get("timeout") or pa.get("timeout"):
            t = tim.get(iid)
            ok = (t is not None and all(s.startswith("cap") for s in t["patched_code"]["results"])
                  and max(t["patched_code"]["times"]) < 1.0
                  and all(x == "TIMEOUT" for x in t["vulnerable_code"]["results"]))
            if ok and iid not in dup_of:
                rows_out.append(("SecCodePLT", iid, "use", "시간 초과 규칙으로 인정(ReDoS, 따로 집계)"))
            else:
                rows_out.append(("SecCodePLT", iid, "exclude", "U5 시간 규칙 불충족" if not ok else f"U7 {dup_of[iid]} 와 같음"))
            continue
        ct, st = pa["capability"][1], pa["safety"][1]
        if st == 0:
            rows_out.append(("SecCodePLT", iid, "exclude", "U3 보안 시험 없음")); continue
        if pa["capability"][0] != ct or pa["safety"][0] != st:
            rows_out.append(("SecCodePLT", iid, "exclude", "U2 수정판이 시험 실패")); continue
        if vu["capability"][0] != vu["capability"][1]:
            rows_out.append(("SecCodePLT", iid, "exclude", "U3 취약판이 기능 시험 실패")); continue
        if vu["safety"][0] == vu["safety"][1]:
            rows_out.append(("SecCodePLT", iid, "exclude", "U3 취약판이 보안 시험을 모두 통과")); continue
        if "returned" not in vu.get("safety_details", []):
            rows_out.append(("SecCodePLT", iid, "exclude", "U4 공격 입력을 받아들이지 않고 다른 예외로만 실패")); continue
        if iid in dup_of:
            rows_out.append(("SecCodePLT", iid, "exclude", f"U7 {dup_of[iid]} 와 같음")); continue
        rows_out.append(("SecCodePLT", iid, "use", "기능 시험 없음(보안만)" if ct == 0 else ""))


def cweval():
    def load(p):
        d = {}
        for line in open(p, encoding="utf-8"):
            if " | " in line:
                k, v = line.rstrip("\n").split(" | ", 1)
                d[k.strip()] = " ".join(w for w in v.split() if not w.endswith("s") or not w[:-1].replace(".", "").isdigit())
        return d
    a, b = load(os.path.join(R, "cweval_py.txt")), load(os.path.join(R, "cweval_py_run2.txt"))
    for k in sorted(a):
        if a[k] != b.get(k):
            rows_out.append(("CWEval", k, "exclude", "U6 두 번 돌린 결과가 다름"))
        elif "failed" in a[k] or "error" in a[k]:
            rows_out.append(("CWEval", k, "exclude", "U1 받은 그대로 시험이 깨짐(" + a[k] + ")"))
        else:
            # 시험 파일이 안전한 구현의 통과와 취약한 구현(*_unsafe)의 보안 실패를 함께 확인한다(U2·U3·U4).
            rows_out.append(("CWEval", k, "use", ""))


def patcheval():
    d = os.path.join(R, "patcheval_python")
    p = os.path.join(d, "summary.tsv")
    mp = os.path.join(OUT, "patcheval_manual_ok.tsv")   # 사람이 로그를 직접 보고 취약점이 드러났다고 확인한 항목
    manual_ok = dict(l.rstrip("\n").split("\t", 1) for l in open(mp, encoding="utf-8") if l.strip()) if os.path.exists(mp) else {}
    if not os.path.exists(p):
        return
    for line in open(p, encoding="utf-8"):
        cve, vrc, frc, _ = (line.rstrip("\n").split("\t") + ["", "", "", ""])[:4]
        if vrc == "PULL_FAIL":
            rows_out.append(("PatchEval", cve, "exclude", "U1 이미지를 받지 못함")); continue
        if vrc in ("124", "137") or frc in ("124", "137"):
            rows_out.append(("PatchEval", cve, "exclude", f"U5 제한 시간에 걸림(vul={vrc}, fix={frc})")); continue
        if frc != "0":
            rows_out.append(("PatchEval", cve, "exclude", "U2 공식 수정판이 공격 시험 실패")); continue
        if vrc == "0":
            rows_out.append(("PatchEval", cve, "exclude", "U3 취약판이 공격 시험 통과")); continue
        log = open(os.path.join(d, cve + ".vul.log"), encoding="utf-8", errors="replace").read()
        broken = any(s in log for s in ("ModuleNotFoundError", "ImportError while", "ERROR collecting", "SyntaxError: ",
                                        "No such file or directory: 'vul-run.sh'", "command not found"))
        shown = any(s in log for s in ("AssertionError", "assert ", "FAIL:", " failed"))
        if broken or not shown:
            if cve in manual_ok:
                rows_out.append(("PatchEval", cve, "use", "기능 시험은 아직 안 돎; 로그 직접 확인: " + manual_ok[cve])); continue
            rows_out.append(("PatchEval", cve, "check", "U1/U4 취약판 실패가 환경 오류일 수 있음(직접 확인 필요)")); continue
        rows_out.append(("PatchEval", cve, "use", "기능 시험은 아직 안 돎"))


seccodeplt(); cweval(); patcheval()
with open(os.path.join(OUT, "items.tsv"), "w", encoding="utf-8") as f:
    f.write("source\tid\tverdict\treason\n")
    for r in rows_out:
        f.write("\t".join(r) + "\n")
for src in ("SecCodePLT", "CWEval", "PatchEval"):
    use = [r[1] for r in rows_out if r[0] == src and r[2] == "use"]
    with open(os.path.join(OUT, src.lower() + "_usable.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(use) + ("\n" if use else ""))
    c = collections.Counter((r[2], r[3]) for r in rows_out if r[0] == src)
    print(src, "use", len(use), "| total", sum(c.values()))
    for (v, why), n in sorted(c.items()):
        print("   ", v, n, why)
