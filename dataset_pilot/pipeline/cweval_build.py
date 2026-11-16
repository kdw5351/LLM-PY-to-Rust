"""CWEval Python 과제를 옮기기 실험 형식으로 바꾼다(코드를 실행하지 않고 ast로 읽기만 한다).

과제마다:
  vulnerable.py = 시험 파일의 첫 번째 취약 구현(<name>_unsafe 또는 <name>_unsafe_0)을 <name> 으로 이름만 바꾼 것 + 시험 파일의 import 문 + 입출력 약속
  patched.py    = 과제 파일(안전한 구현) + 입출력 약속
  meta.json     = 함수 이름, 인자 이름 순서, 반환 형식 표기(튜플 복원용), 시험 파일 이름
인자에 JSON으로 옮길 수 없는 형(sqlite3.Cursor 등)이 있는 과제는 건너뛰고 skipped.txt 에 적는다.
usage: python -I cweval_build.py <cweval/benchmark/core/py> <usable ids file> <out dir>
"""
import ast
import json
import os
import sys

src_dir, ids_file, out = sys.argv[1:4]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
MAIN = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_items.py"), encoding="utf-8").read()
MAIN = MAIN.split("MAIN = r'''", 1)[1].split("'''", 1)[0]
PORTABLE = {"str", "bytes", "int", "float", "bool", "dict", "list", "Dict", "List", "Tuple", "None", "Optional"}

skipped = []
os.makedirs(out, exist_ok=True)
for tid in open(ids_file).read().split():
    task_src = open(os.path.join(src_dir, tid + "_task.py"), encoding="utf-8").read()
    test_path = os.path.join(src_dir, tid + "_test.py")
    test_src = open(test_path, encoding="utf-8").read()
    tt = ast.parse(test_src)
    name = None
    for n in tt.body:
        if isinstance(n, ast.ImportFrom) and n.module == tid + "_task":
            name = n.names[0].name
    task_tree = ast.parse(task_src)
    fdef = next(n for n in task_tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    params = [a.arg for a in fdef.args.args]
    ann_words = set()
    for a in fdef.args.args:
        if a.annotation is not None:
            ann_words |= {w for w in ast.unparse(a.annotation).replace("[", " ").replace("]", " ").replace(",", " ").replace("|", " ").split()}
    if ann_words - PORTABLE:
        skipped.append(f"{tid}\t인자 형식을 JSON으로 옮길 수 없음: {sorted(ann_words - PORTABLE)}")
        continue
    ret = ast.unparse(fdef.returns) if fdef.returns is not None else ""
    unsafe = next((n for n in tt.body if isinstance(n, ast.FunctionDef) and n.name in (name + "_unsafe", name + "_unsafe_0")), None)
    if unsafe is None:
        skipped.append(f"{tid}\t취약 구현을 찾지 못함")
        continue
    imports = [ast.unparse(n) for n in tt.body if isinstance(n, (ast.Import, ast.ImportFrom))
               and not (isinstance(n, ast.ImportFrom) and n.module == tid + "_task")
               and not any(a.name == "pytest" for a in getattr(n, "names", []))]
    seg = ast.get_source_segment(test_src, unsafe)
    seg = seg.replace("def " + unsafe.name + "(", "def " + name + "(", 1)
    pdir = os.path.join(out, "programs", tid)
    os.makedirs(pdir, exist_ok=True)
    main = MAIN.replace("{FUNC}", name)
    open(os.path.join(pdir, "vulnerable.py"), "w", encoding="utf-8").write("\n".join(imports) + "\n\n\n" + seg + "\n" + main)
    open(os.path.join(pdir, "patched.py"), "w", encoding="utf-8").write(task_src.rstrip() + "\n" + main)
    json.dump({"id": tid, "func": name, "params": params, "returns": ret, "unsafe_variant": unsafe.name,
               "test_file": tid + "_test.py"}, open(os.path.join(pdir, "meta.json"), "w", encoding="utf-8"), indent=1)
open(os.path.join(out, "skipped.txt"), "w", encoding="utf-8").write("\n".join(skipped) + ("\n" if skipped else ""))
print("built", len(open(ids_file).read().split()) - len(skipped), "skipped", len(skipped))
