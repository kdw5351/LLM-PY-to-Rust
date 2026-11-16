"""시간 초과 항목의 분리 확인(컨테이너 안). 수정 코드의 실행 시간과, 취약 코드가 제한 시간을 매번 넘기는지 본다.
usage: python -I seccodeplt_timing.py <items_dir> <ids_file> <limit_s> <repeats>
"""
import json
import os
import subprocess
import sys
import time

items_dir, ids_file, limit, reps = sys.argv[1], sys.argv[2], float(sys.argv[3]), int(sys.argv[4])
for iid in [l.strip() for l in open(ids_file) if l.strip()]:
    path = os.path.join(items_dir, iid + ".json")
    row = {"id": iid}
    for which in ("patched_code", "vulnerable_code"):
        times, outs = [], []
        for _ in range(reps):
            t0 = time.time()
            try:
                cp = subprocess.run([sys.executable, "-I", "/scripts/seccodeplt_item.py", path, which],
                                    capture_output=True, text=True, timeout=limit, cwd="/tmp")
                r = json.loads(cp.stdout.strip().splitlines()[-1])
                outs.append(f"cap {r['capability'][0]}/{r['capability'][1]} saf {r['safety'][0]}/{r['safety'][1]}")
            except subprocess.TimeoutExpired:
                outs.append("TIMEOUT")
            times.append(round(time.time() - t0, 2))
        row[which] = {"times": times, "results": outs}
    print(json.dumps(row), flush=True)
