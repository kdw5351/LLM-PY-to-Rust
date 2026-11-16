"""출발 코드에서 주석과 설명문(docstring)을 지운다(2026-11-12 결정: 번역 모델에게 주석이 보안 힌트가 되지 않게).
코드를 실행하지 않는다. ast 로 읽고, 모듈·클래스·함수 본문 맨 앞의 문자열 식(설명문)을 빼고, ast.unparse 로 다시 쓴다
(주석은 ast 에 남지 않으므로 함께 사라진다). 본문이 설명문뿐이면 pass 를 넣는다. 이름·문자열 값·동작은 그대로 둔다.
usage: python -I strip_comments.py <programs_dir> <out_dir>
  <programs_dir>/<id>/{vulnerable,patched}.py  ->  <out_dir>/<id>/{vulnerable,patched}.py, <out_dir>/strip_report.tsv
"""
import ast
import io
import os
import sys
import tokenize


def count_comments(src):
    n = 0
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            n += 1
    return n


class Strip(ast.NodeTransformer):
    def __init__(self):
        self.docstrings = 0

    def _body(self, node):
        b = node.body
        if b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant) and isinstance(b[0].value.value, str):
            self.docstrings += 1
            b = b[1:] or [ast.Pass()]
            node.body = b
        return node

    def visit_Module(self, node):
        self.generic_visit(node)
        return self._body(node)

    def visit_ClassDef(self, node):
        self.generic_visit(node)
        return self._body(node)

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        return self._body(node)

    def visit_AsyncFunctionDef(self, node):
        self.generic_visit(node)
        return self._body(node)


def strip(src):
    tree = ast.parse(src)
    s = Strip()
    tree = s.visit(tree)
    ast.fix_missing_locations(tree)
    out = ast.unparse(tree) + "\n"
    ast.parse(out)                     # 다시 읽히는지 확인
    return out, count_comments(src), s.docstrings


def main():
    src_dir, out_dir = sys.argv[1:3]
    rows = []
    for item in sorted(os.listdir(src_dir)):
        d = os.path.join(src_dir, item)
        if not os.path.isdir(d):
            continue
        os.makedirs(os.path.join(out_dir, item), exist_ok=True)
        for ver in ("vulnerable", "patched"):
            p = os.path.join(d, ver + ".py")
            if not os.path.exists(p):
                continue
            src = open(p, encoding="utf-8").read()
            out, nc, nd = strip(src)
            open(os.path.join(out_dir, item, ver + ".py"), "w", encoding="utf-8").write(out)
            rows.append(f"{item}\t{ver}\t{nc}\t{nd}")
    with open(os.path.join(out_dir, "strip_report.tsv"), "w", encoding="utf-8") as f:
        f.write("item\tversion\tcomments_removed\tdocstrings_removed\n" + "\n".join(rows) + "\n")
    print("files", len(rows), "with comments", sum(1 for r in rows if r.split("\t")[2] != "0"),
          "with docstrings", sum(1 for r in rows if r.split("\t")[3] != "0"))


if __name__ == "__main__":
    main()
