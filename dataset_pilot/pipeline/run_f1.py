"""F1 예행 실행 드라이버 (본실행_준비완료기준 F1). 결제 0 — 로컬 모델만.

실험 B 조건(B0·B1·B2·B5·B5m·예산대조·오라클)은 지금까지 하위 에이전트가 요청문에 답했다.
본 실행은 모델이 답한다. 이 드라이버가 `pilot_job pending-b` 로 대기 중인 요청문을 찾아,
`model_client` 로 모델을 불러 답을 쓰고 `ingest-b` 로 받아들인다. 모두 끝날 때까지 돈다.

usage: python run_f1.py <Brun> [--model qwen2.5-coder:14b] [--max-rounds 400] [--dry N]
  --dry N: 모델을 부르지 않고(가짜 응답) 처음 N번만 돌려 배선만 확인한다(결제·GPU 없음).
파이프라인 전체(실험 A 생성, B4 검사목록·조건확인 준비)는 각 작업이 따로 돌린다. 이 드라이버는 B 조건 응답 단계다.
"""
import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import model_client as mc  # noqa: E402

SYSTEM = "You are an expert software engineer."
FAKE_RUST = "```toml\n[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n```\n```rust\nfn main(){}\n```\n"
FAKE_PY = "```python\nimport sys,json\nd=json.loads(sys.stdin.readline())\nprint(json.dumps({\"ok\": None}))\n```\n"


def _job(script, *args):
    return subprocess.run([sys.executable, "-X", "utf8", str(HERE / script), *map(str, args)],
                          capture_output=True, text=True, encoding="utf-8")


def answer(client, model, prompt_path, reply_path, transport, fake=FAKE_RUST):
    txt = Path(prompt_path).read_text(encoding="utf-8")
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": txt}]
    tp = (lambda *a: (fake, 10, 10)) if transport else None
    out, _ = client.call(model, msgs, temperature=0.0, seed=1, _transport=tp)
    Path(reply_path).parent.mkdir(parents=True, exist_ok=True)
    Path(reply_path).write_text(out, encoding="utf-8")


def fill_unanswered(client, model, pdir, pattern, transport, fake=FAKE_RUST):
    """pdir/<pattern>.txt 중 짝 .md 가 없는 것을 모두 답한다(ingest 없는 단계: ck·pr·where)."""
    n = 0
    for pf in sorted(Path(pdir).glob(pattern + ".txt")):
        rp = Path(pdir) / f"{pf.stem}.md"
        if not rp.exists():
            answer(client, model, pf, rp, transport, fake)
            n += 1
    return n


def pending(run):
    out = subprocess.run([sys.executable, "-X", "utf8", str(HERE / "pilot_job.py"), "pending-b", str(run)],
                         capture_output=True, text=True, encoding="utf-8")
    items = []
    for line in out.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == "ITEM":                 # ITEM <cond> <tkey>__<tag>
            cond, tk = parts[1], parts[2]
            tkey, tag = tk.rsplit("__", 1)
            items.append((cond, tkey, tag))
    return items


def ingest(run, cond, tkey, tag):
    subprocess.run([sys.executable, "-X", "utf8", str(HERE / "pilot_job.py"), "ingest-b", str(run), cond, tkey, tag],
                   check=True, encoding="utf-8")


def drive_bconds(run, client, model, transport, max_rounds, dry):
    """실험 B 조건(pilot_job): pending-b -> ITEM 답 -> ingest-b 루프."""
    done = 0
    for _ in range(max_rounds):
        todo = pending(run)
        if not todo:
            print("B-conds done,", done, "answers"); return done
        for cond, tkey, tag in todo:
            answer(client, model, run / cond / "prompts" / f"{tkey}__{tag}.txt",
                   run / cond / "replies" / f"{tkey}__{tag}.md", transport)
            ingest(run, cond, tkey, tag)
            done += 1
            if dry and done >= dry:
                print("DRY stop,", done, "answers"); return done
    return done


def drive_b3(run, client, model, transport, max_rounds, dry):
    """B3(harden_job): prep-ck -> ck 답 -> prep -> (pending ITEM 답 -> ingest) -> eval."""
    _job("harden_job.py", "prep-ck", run)
    fill_unanswered(client, model, run / "prompts", "ck__*", transport)
    _job("harden_job.py", "prep", run)
    done = 0
    for _ in range(max_rounds):
        out = _job("harden_job.py", "pending", run).stdout
        items = [l.split()[1] for l in out.splitlines() if l.startswith("ITEM")]
        if not items:
            break
        for tk in items:
            tkey, tag = tk.rsplit("__", 1)
            answer(client, model, run / "prompts" / f"{tk}.txt", run / "replies" / f"{tk}.md", transport)
            _job("harden_job.py", "ingest", run, tkey, tag)
            done += 1
            if dry and done >= dry:
                print("B3 DRY stop,", done, "answers"); return done
    _job("harden_job.py", "eval", run)
    print("B3 done,", done, "answers"); return done


def drive_b4(run, client, model, base_run, spec_policy, transport, max_rounds, dry):
    """B4(harden_item_job): init -> prep-probe -> pr 답 -> probe -> prep -> where 답 -> plan -> (pending ITEM 답 -> ingest) -> eval."""
    _job("harden_item_job.py", "init", run, base_run, spec_policy)
    _job("harden_item_job.py", "prep-probe", run)
    fill_unanswered(client, model, run / "prompts", "pr__*", transport, fake=FAKE_PY)
    _job("harden_item_job.py", "probe", run)
    _job("harden_item_job.py", "prep", run)
    done = 0
    for _ in range(max_rounds):
        out = _job("harden_item_job.py", "pending", run).stdout
        where = [l for l in out.splitlines() if l.startswith("WHERE")]
        items = [l.split()[1] for l in out.splitlines() if l.startswith("ITEM")]
        if where:                                   # 차선 질문: w 답 -> plan
            fill_unanswered(client, model, run / "prompts", "*__w*", transport)
            _job("harden_item_job.py", "plan", run)
            continue
        if not items:
            break
        for tk in items:
            tkey, tag = tk.rsplit("__", 1)
            answer(client, model, run / "prompts" / f"{tk}.txt", run / "replies" / f"{tk}.md", transport, fake=FAKE_RUST)
            _job("harden_item_job.py", "ingest", run, tkey, tag)
            done += 1
            if dry and done >= dry:
                print("B4 DRY stop,", done, "answers"); return done
    _job("harden_item_job.py", "eval", run)
    print("B4 done,", done, "answers"); return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--which", choices=["bconds", "b3", "b4"], default="bconds")
    ap.add_argument("--base-run", default=None, help="b4: B4 init 의 base_run")
    ap.add_argument("--spec-policy", default="0", help="b4: 0|1")
    ap.add_argument("--model", default="qwen2.5-coder:14b")
    ap.add_argument("--max-rounds", type=int, default=400)
    ap.add_argument("--dry", type=int, default=0)
    a = ap.parse_args()
    run = Path(a.run)
    client = mc.ModelClient(run / "_calls", cost_cap_usd=None)
    if a.which == "bconds":
        drive_bconds(run, client, a.model, a.dry, a.max_rounds, a.dry)
    elif a.which == "b3":
        drive_b3(run, client, a.model, a.dry, a.max_rounds, a.dry)
    else:
        drive_b4(run, client, a.model, a.base_run, a.spec_policy, a.dry, a.max_rounds, a.dry)
    print("total cost $%.4f" % client.total_cost())


if __name__ == "__main__":
    main()
