"""SecCodePLT 항목 전부를 두 판으로 실행한다(컨테이너 안). 판마다 별도 프로세스, 시간 제한 30초.
usage: python -I seccodeplt_batch.py <items_dir> <out.jsonl>
"""
import json
import os
import subprocess
import sys

items_dir, out_path = sys.argv[1], sys.argv[2]
files = sorted(f for f in os.listdir(items_dir) if f.endswith(".json"))
with open(out_path, "w", encoding="utf-8") as out:
    for i, f in enumerate(files):
        for which in ("vulnerable_code", "patched_code"):
            try:
                cp = subprocess.run([sys.executable, "-I", "/scripts/seccodeplt_item.py", os.path.join(items_dir, f), which],
                                    capture_output=True, text=True, timeout=30, cwd="/tmp")
                line = cp.stdout.strip().splitlines()[-1] if cp.stdout.strip() else json.dumps(
                    {"id": f[:-5], "version": which, "crash": cp.stderr[-300:]})
            except subprocess.TimeoutExpired:
                line = json.dumps({"id": f[:-5], "version": which, "timeout": True})
            out.write(line + "\n")
        if i % 100 == 0:
            print(i, flush=True)
print("DONE", len(files))
