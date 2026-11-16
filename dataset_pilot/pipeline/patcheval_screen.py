"""PatchEval Python 항목을 '함수 하나를 Rust로 떼어 낼 수 있는가'로 거른다(정적 확인만, 실행 없음).

떼어 낼 수 있음(1차 후보)의 조건 — 측정 전에 고정:
  S1 고친 함수가 1개다(vul_func, fix_func 각 1개, 같은 파일).
  S2 함수가 파싱된다(조각을 들여쓰기 풀어 ast 로 읽힘).
  S3 메서드가 아니다(첫 인자가 self/cls 가 아님) — 객체 상태에 기대지 않음.
  S4 본문이 프레임워크 객체에 기대지 않는다: request/session/self/db/app/g/current_app/cursor/Response 같은 이름을 쓰지 않음.
  S5 길이가 60줄 이하다.
  S6 async·generator 가 아니다(yield/await 없음), 데코레이터가 없다(라우트 등).
출력: usable/patcheval_slice_screen.tsv (항목별 통과/걸린 조건, 크기, CWE). 코드 내용은 출력하지 않는다.
"""
import ast
import json
import sys
import textwrap
from pathlib import Path

DS = Path(__file__).resolve().parent.parent
FRAMEWORK = {"request", "session", "db", "app", "g", "current_app", "cursor", "Response", "flask", "django",
             "settings", "conn", "connection", "os", "subprocess", "open", "socket", "requests", "urllib"}
HARD = {"request", "session", "db", "app", "g", "current_app", "cursor", "Response", "settings", "conn", "connection"}


def analyze(snippet):
    src = textwrap.dedent(snippet)
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    fns = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if not fns:
        return None
    fn = fns[0]
    args = [a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs]
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)} | \
            {n.value.id for n in ast.walk(fn) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    return {"name": fn.name, "nargs": len(args), "method": bool(args) and args[0] in ("self", "cls"),
            "async": isinstance(fn, ast.AsyncFunctionDef) or any(isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)) for n in ast.walk(fn)),
            "decorated": bool(fn.decorator_list), "lines": (fn.end_lineno or 0) - fn.lineno + 1,
            "hard": sorted(names & HARD), "soft": sorted((names & FRAMEWORK) - HARD),
            "varargs": bool(fn.args.vararg or fn.args.kwarg)}


def main():
    usable = set((DS / "usable" / "patcheval_usable.txt").read_text().split())
    sizes = {}
    for l in (DS / "results" / "patcheval_python" / "summary.tsv").read_text().splitlines():
        p = l.split("\t")
        if len(p) >= 4 and p[3].isdigit():
            sizes[p[0]] = int(p[3])
    rows = []
    for x in json.loads((DS / "patcheval" / "patcheval_verified.json").read_text(encoding="utf-8")):
        cve = x["cve_id"]
        if cve not in usable:
            continue
        fails = []
        vf, ff = x.get("vul_func") or [], x.get("fix_func") or []
        if not (len(vf) == 1 and len(ff) == 1 and vf[0]["file_path"] == ff[0]["file_path"]):
            fails.append("S1")
        a = analyze(vf[0]["snippet"]) if vf else None
        b = analyze(ff[0]["snippet"]) if ff else None
        if a is None or b is None:
            fails.append("S2")
        else:
            if a["method"] or b["method"]:
                fails.append("S3")
            if a["hard"] or b["hard"]:
                fails.append("S4")
            if max(a["lines"], b["lines"]) > 60:
                fails.append("S5")
            if a["async"] or b["async"] or a["decorated"] or b["decorated"]:
                fails.append("S6")
        rows.append({"cve": cve, "cwe": ",".join(x.get("cwe_info") or {}), "repo": x.get("repo", "").rsplit("/", 2)[-1] if x.get("repo") else "",
                     "n_vul": len(vf), "n_fix": len(ff), "fails": fails, "a": a, "gb": round(sizes.get(cve, 0) / 1e9, 1)})
    out = DS / "usable" / "patcheval_slice_screen.tsv"
    with out.open("w", encoding="utf-8") as f:
        f.write("cve\tcwe\trepo\tn_vul\tn_fix\tpass\tfails\tfunc\tnargs\tlines\tsoft_deps\timage_gb\n")
        for r in sorted(rows, key=lambda r: (len(r["fails"]), r["gb"])):
            a = r["a"] or {}
            f.write("\t".join(map(str, [r["cve"], r["cwe"], r["repo"], r["n_vul"], r["n_fix"], int(not r["fails"]),
                                        ",".join(r["fails"]), a.get("name", ""), a.get("nargs", ""), a.get("lines", ""),
                                        ",".join(a.get("soft", [])), r["gb"]])) + "\n")
    import collections
    c = collections.Counter(x for r in rows for x in r["fails"])
    print("usable", len(rows), "pass all", sum(1 for r in rows if not r["fails"]))
    print("fail counts", dict(c))
    print("single-function items", sum(1 for r in rows if "S1" not in r["fails"]))
    print("written", out)


if __name__ == "__main__":
    main()
