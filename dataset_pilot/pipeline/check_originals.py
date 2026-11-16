"""원본(취약한 버전, 수정된 버전)이 입출력 약속과 우리 실행기에서도 데이터셋과 같은 결과를 내는지 확인한다.
통과한 항목만 옮기기 실험에 쓴다(실행 환경에 따라 기대값이 바뀌는 항목은 여기서 걸러진다).
usage: python -I check_originals.py <export_dir> <usable_items.tsv>"""
import json, sys, os, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from judge import judge_record
exp, items_tsv = sys.argv[1:3]
tim = set(l.split("\t")[1] for l in open(items_tsv, encoding="utf-8") if "시간 초과 규칙으로 인정" in l)
res = collections.defaultdict(dict)
for l in open(os.path.join(exp, "originals_runs.jsonl")):
    r = json.loads(l); t = json.load(open(os.path.join(exp, "tests", r["item"] + ".json")))
    j = judge_record(r, t, r["item"] in tim)
    w = r["key"].split("/")[1]
    res[r["item"]][w] = j
ok, bad = [], []
for i, d in sorted(res.items()):
    v, p = d.get("vulnerable"), d.get("patched")
    good = v and p and v["functional_ok"] and v["any_exploited"] and p["functional_ok"] and not p["any_exploited"] and not p["any_invalid"]
    (ok if good else bad).append(i)
open(os.path.join(exp, "reproduced_ids.txt"), "w").write("\n".join(ok) + "\n")
with open(os.path.join(exp, "not_reproduced.tsv"), "w", encoding="utf-8") as f:
    for i in bad:
        f.write(i + "\t" + json.dumps({w: {"cap": res[i][w]["capability"], "saf": res[i][w]["safety"]} for w in res[i]}) + "\n")
print("reproduced", len(ok), "not", len(bad))
