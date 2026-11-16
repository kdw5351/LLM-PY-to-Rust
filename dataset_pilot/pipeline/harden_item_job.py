"""항목별 강화+조건 확인 (제안서 7절 '강화 방법 보완', 제안서대조_및_강화보완안_2026-11-10.md 3부)을 데이터셋 항목에 맞춰 돌린다.
승인 요청 문서의 데이터셋 설계를 따른다: 점검 = 코드 신호(clippy) + 조건 확인 입력, 받아들이기의 기능 확인 = 조건 확인의 정상 입력에서
원본 Python 과 같은 출력, 데이터셋 시험은 평가에만 쓴다. 모델 호출은 파일 주고받기(하위 에이전트). 사전계획은 Downloads/ 에 따로 둔다.
모델이 만든 코드(번역·조건 확인 스크립트)는 Docker(네트워크 없음) 안에서만 돌린다.

  init        <run> <base_run> <spec_policy 0|1>  : 대상·출발 코드·검사 목록 준비 (spec_policy=1 이면 검사 목록 요청을 새로 만든다)
  ck-validity <run>                 : 검사 목록 답의 상태(none_claimed/parsed/unreadable)를 checklist_validity.json 에(15-2)
  prep-probe  <run>                 : 검사 목록 항목마다 조건 확인 입력 요청 prompts/pr__<item>__c<n>.txt
  probe       <run>                 : 조건 확인 스크립트를 돌려 입력 쌍을 얻고, 원본 Python 의 출력을 잰다
  prep        <run>                 : 대상마다 σ0, ok/d/u, 받아들이기 기준 집합 A0, 차선 질문 prompts/<tkey>__w<n>.txt
  plan        <run>                 : 차선 답을 읽고 항목 목록 F* 를 정해 첫 항목 요청을 쓴다
  ingest      <run> <tkey> <tag>    : 항목 수정 답 처리(tag = j<j>a<a>[f<f>])
  eval        <run>                 : 강화 전/후 데이터셋 보안 시험 비교 + 방법 지표
"""
import collections
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DS = HERE.parent
sys.path.insert(0, str(HERE))
import harden_job as hj  # noqa: E402  (build, sigma, rules_text, files_block, spec_text, fill, run_tests, CONTRACT)
from judge import equal, parse  # noqa: E402
import gate  # noqa: E402

t = hj.t
EXPORT = hj.EXPORT
PD = HERE / "prompts_ds"
K_ITEM, CFIX, MAX_ITEMS = 2, 2, 8          # 사전 고정 값
CLASS_ORDER = hj.SIGMA_CLASSES             # 종류 항목 순서(classes.py 의 순서)
SPEC_FIELDS_POLICY = hj.SPEC_FIELDS + [("security_policy", "Security policy")]


def P(name):
    return (PD / f"{name}.md").read_text(encoding="utf-8")


def jload(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def jsave(p, d):
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    Path(p).write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def spec_for(run, item):
    if not jload(run / "config.json")["spec_policy"]:
        return hj.spec_text(item)
    td = jload(EXPORT / "programs" / item / "meta.json")["task_description"]
    return "\n\n".join(f"{lab}:\n{td[k].strip()}" for k, lab in SPEC_FIELDS_POLICY if (td.get(k) or "").strip())


_CK_TAG = re.compile(r"^CHECK\s*(\d+)\s*[\[(]?\s*(stated|inferred)\s*[\])]?\s*:", re.I)


def norm_check_line(line):
    """검사 목록 한 줄의 표기를 'CHECK n [stated]:' 꼴로 맞춘다(2026-11-14: 로컬 Qwen 이 대괄호 없이 'CHECK 1 stated:' 로 답해
    명세에 적힌 조건이 0개로 세어졌다). 표기(stated/inferred)가 없는 줄은 그대로 둔다 = 이전처럼 stated 로 세지 않는다.
    이미 맞는 줄은 글자 하나 바뀌지 않는다."""
    m = _CK_TAG.match(line)
    if not m:
        return "CHECK" + line[5:] if line[:5].upper() == "CHECK" else line   # 2026-11-14(15-2): 'check' 도 CHECK 로
    return f"CHECK {m.group(1)} [{m.group(2).lower()}]:" + line[m.end():]


def _ck_lines(run, item):
    txt = (run / "replies" / f"ck__{item}.md").read_text(encoding="utf-8")
    return txt, [l.strip() for l in txt.replace("\r\n", "\n").split("\n")]


def checklist(run, item):
    """CHECK 로 시작하는 줄(2026-11-14 15-2: 대소문자 무시). 표기는 norm_check_line 으로 맞춘다."""
    return [norm_check_line(l) for l in _ck_lines(run, item)[1] if l[:5].upper() == "CHECK"]


def checklist_validity(run, item):
    """검토의견_반영_결정 15-2: 검사 목록 답의 상태. 조건처럼 보이는 줄 = CHECK 로 시작(대소문자 무시) 또는 '->' 가 든 줄,
    읽음 = 그 가운데 _CK_TAG 로 'CHECK n' 과 stated/inferred 표기를 읽을 수 있는 줄. 답의 내용은 싣지 않는다."""
    txt, lines = _ck_lines(run, item)
    like = [l for l in lines if l[:5].upper() == "CHECK" or "->" in l]
    tags = [m.group(2).lower() for m in (_CK_TAG.match(l) for l in like) if m]
    state = "none_claimed" if not like else ("parsed" if len(tags) == len(like) else "unreadable")
    return {"state": state, "condition_like": len(like), "readable": len(tags), "stated": tags.count("stated"),
            "inferred": tags.count("inferred"), "reply_chars": len(txt)}


def cfg(run):
    return jload(run / "config.json")


def is_v2(run):
    """v2 이상(v3 포함): 조건 확인 입력과 함께 minus_expect 를 받는다."""
    return (cfg(run).get("probe_version") or 1) >= 2


# v3 (2026-11-12 개발용 변경, F1_검출기_정확도 진단): 출발 Python 에서 '어긴 입력'이 조건과 무관하게 깨지면
# 그 확인 입력은 쓰지 않고 차선 질문으로 넘긴다. 출발 Python(옮기기 원본)은 방법이 원래 가진 정보다.
GENERIC_ERRORS = {"TypeError", "KeyError", "AttributeError", "IndexError", "NameError", "UnboundLocalError"}


def named_errors(spec):
    return set(re.findall(r"\b([A-Z]\w*(?:Error|Exception))\b", spec))


# v5 (조건확인_v5_설계_2026-11-12.md): 출발 Python 의 모듈 수준 값 대입문만 보여 준다(함수·클래스 본문은 빼고).
# 취약·수정 두 판의 모듈 수준 값은 데이터셋 814개 모두에서 같다(2026-11-12 확인) — 두 판의 차이를 흘리지 않는다.
NC_DIR = EXPORT / "programs_nc"
GLOBAL_ONE_MAX, GLOBAL_ALL_MAX = 1500, 4000


def module_data(item):
    import ast
    import warnings
    src = (NC_DIR / item / "vulnerable.py").read_text(encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tree = ast.parse(src)
    out, total = [], 0
    for n in tree.body:
        if not isinstance(n, (ast.Assign, ast.AnnAssign)):
            continue
        seg = ast.get_source_segment(src, n) or ""
        if len(seg) > GLOBAL_ONE_MAX:
            seg = seg[:GLOBAL_ONE_MAX] + "  # ... (truncated)"
        if total + len(seg) > GLOBAL_ALL_MAX:
            out.append("# ... (more module-level data omitted)")
            break
        out.append(seg)
        total += len(seg)
    return "```python\n" + "\n".join(out) + "\n```" if out else "(none)"


# v6 (B6_통합조건_설계_2026-11-13.md): 요청문은 v5(모듈 수준 값 포함), 거르기는 v3 의 v3_valid 를 그대로 쓴다.
V3_FILTER = (3, 6)          # signals 에서 v3_valid 거르기를 쓰는 버전
MODULE_DATA = (5, 6)        # prep-probe 에서 모듈 수준 값(globals)을 넣는 버전


def v3_valid(e, om0, named):
    """출발 Python 에서 어긴 입력의 끝맺음 om0 이 이 확인 입력을 쓸 만하게 하는가.
    조건을 안 지키는 출발 코드라면 정상으로 끝나야 하고, 지키는 출발 코드라면 명세가 요구한 대로 끝나야 한다.
    그 밖(명세에 없는 일반 오류, 값을 요구했는데 오류)은 입력이 잘못 만들어진 것으로 본다. 기대가 '명세에 없음'이면 판정 근거가 없다."""
    if not isinstance(e, dict) or e.get("unspecified") or not (e.get("error") or "value" in e):
        return False
    if om0["st"] != "error":
        return True                                     # 정상 끝(조건 안 지킴 또는 값 일치) 또는 시간 초과·비정상 종료
    sub = om0.get("sub") or ""
    if not e.get("error"):
        return False                                    # 값을 요구했는데 오류
    if sub in GENERIC_ERRORS and sub not in named:
        return False
    want = e["error"] if isinstance(e["error"], str) else None
    if want and want in named and sub != want:
        return False
    return True


def considered(run, item):
    """조건 항목으로 쓸 검사 목록 번호(1부터). v2(2026-11-12 개발용 변경): 명세에 적힌 조건([stated])만."""
    ck = checklist(run, item)
    if cfg(run).get("stated_only"):
        return [n for n, l in enumerate(ck, 1) if "[stated]" in l]
    return list(range(1, len(ck) + 1))


# ---- 끝난 방식 ----
def outcome(r):
    st, sub, val = parse(r)
    return {"st": st, "sub": sub, "val": val}


def expected_kind(line):
    """검사 목록 줄의 '->' 뒤 문장에서 어겼을 때의 끝맺음 e_i 를 기계적으로 정한다(사전 고정 규칙)."""
    rhs = line.split("->", 1)[-1]
    if re.search(r"\b[A-Z]\w*(Error|Exception)\b", rhs) or re.search(r"\b(raise|raises|reject|rejects|error)\b", rhs, re.I):
        return "error"
    if re.search(r"\breturns?\s+None\b", rhs):
        return "none"
    if re.search(r"\breturns?\s+False\b", rhs):
        return "false"
    return "unspecified"


def d_of(e, o_plus, o_minus):
    if o_plus["st"] != "ok":
        return None                                    # ok_i = 0
    if isinstance(e, dict):                            # v2: 조건 확인 입력과 함께 받은 minus_expect
        if e.get("error"):
            return o_minus["st"] == "error"
        if "value" in e:
            return o_minus["st"] == "ok" and equal(o_minus["val"], e["value"])
        e = "unspecified"
    if e == "error":
        return o_minus["st"] == "error"
    if e == "none":
        return o_minus["st"] == "ok" and o_minus["val"] is None
    if e == "false":
        return o_minus["st"] == "ok" and o_minus["val"] is False
    return o_minus["st"] != "abnormal" and not (o_minus["st"] == "ok" and equal(o_minus["val"], o_plus["val"]))


def observed_text(o):
    if o["st"] == "ok":
        return "When given an input that violates this condition, the program completed normally and returned a value."
    if o["st"] == "error":
        return "When given an input that violates this condition, the program reported an error that does not match what the specification requires."
    if o["sub"] == "timeout":
        return "When given an input that violates this condition, the program did not finish within the time limit."
    return "When given an input that violates this condition, the program crashed (panic or abnormal exit)."


# ---- 입력 쌍 실행 ----
def run_inputs(run, label, prog_root, jobs, item_inputs):
    """jobs: [(key, item, lang, path_in_container)], item_inputs: item -> [args...]. runner.py 를 컨테이너에서 돌린다."""
    td = run / "_probe_tests" / label
    td.mkdir(parents=True, exist_ok=True)
    for item, args in item_inputs.items():
        fx = jload(EXPORT / "tests" / f"{item}.json").get("fixtures") or {}
        jsave(td / f"{item}.json", {"capability": [{"args": a} for a in args], "safety": [], "fixtures": fx})
    jf = run / "_probe_tests" / f"{label}.jobs.jsonl"
    jf.write_text("".join(json.dumps({"key": k, "item": i, "lang": lg, "path": p}) + "\n" for k, i, lg, p in jobs), encoding="utf-8")
    out = f"{label}.runs.jsonl"
    r = subprocess.run(["docker", "run", "--rm", "--init", "--network", "none", "--memory", "2g",
                        "-v", f"{prog_root.resolve()}:/s:ro", "-v", f"{(run / '_probe_tests').resolve()}:/r",
                        "-v", f"{HERE}:/pipeline:ro", "pyrs-seccodeplt-runner", "python", "-I", "/pipeline/runner.py",
                        f"/r/{jf.name}", f"/r/{label}", f"/r/{out}", "10"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(r.stdout[-1500:] + r.stderr[-1500:])
    res = {}
    for l in (run / "_probe_tests" / out).read_text(encoding="utf-8").splitlines():
        rec = json.loads(l)
        res[rec["key"]] = [outcome(x) for x in rec["runs"]["capability"]]
    return res


def probe_list(run, item):
    pr = jload(run / "probes" / f"{item}.json")
    return [(int(n), v) for n, v in sorted(pr.items(), key=lambda kv: int(kv[0])) if v["status"] == "ok"]


def measure(run, tkey, item, label, sol_root):
    """프로그램 하나(sol_root/<tkey>/app)에 이 항목의 모든 입력 쌍을 넣어 n -> (o_plus, o_minus)."""
    pl = probe_list(run, item)
    args = []
    for _, v in pl:
        args += [v["plus"]["args"], v["minus"]["args"]]
    if not args:
        return {}
    res = run_inputs(run, f"{tkey}__{label}", sol_root, [(tkey, item, "rust", f"/s/{tkey}/app")], {item: args})[tkey]
    return {n: (res[2 * k], res[2 * k + 1]) for k, (n, _) in enumerate(pl)}


def signals(run, st, outs):
    """ok_n, d_n, A(받아들이기용 정상 입력 집합)."""
    orig = jload(run / "probes" / f"{st['item']}.orig.json")[st["source"]]
    ok, d, acc = {}, {}, []
    pv = st.get("probe_version") or 1
    v2 = pv >= 2
    named = named_errors(spec_for(run, st["item"])) if pv in V3_FILTER else set()
    for n, (op, om) in outs.items():
        e = st["expect"][str(n)]
        o0 = orig[str(n)]
        # v2: 정상 입력은 옮기기 출발 Python(같은 버전)에서도 정상으로 끝나야 쓸 수 있다(방법이 가진 정보만 씀)
        ok[n] = op["st"] == "ok" and (not v2 or o0["st"] == "ok")
        if pv in V3_FILTER and ok[n]:                    # v3 거르기(v4 도 v3 입력, v6 = v5 요청문 + v3 거르기). v5 는 거르지 않는다
            ok[n] = v3_valid(e, orig[f"{n}_minus"], named)
        d[n] = bool(d_of(e, op, om)) if ok[n] else False
        if o0["st"] == "ok" and op["st"] == "ok" and equal(op["val"], o0["val"]):
            acc.append(n)
    return ok, d, sorted(acc)


def cond_line(st, n):
    return st["checklist"][n - 1] if n - 1 < len(st["checklist"]) else ""


def request(st, item_spec, sol):
    kind, key = item_spec
    if kind == "cond":
        n = key
        obs = st["observed"].get(str(n)) or ("No usable input was available to test this condition, "
                                             "and the program does not appear to check it.")
        return hj.fill(P("pi_item_cond"), condition=cond_line(st, n), observed=obs, rules=hj.rules_text(set()),
                       files=hj.files_block(sol), contract=hj.CONTRACT)
    cls = key
    locs = "\n".join(f"{l['file']}:{l['line']} — {l['signal']} ({l['class']})" for l in st["cur_sigma"]["locations"]
                     if l["class"] == cls) or "(none from code signal)"
    return hj.fill(P("pi_item_class"), cls=cls, locations=locs, rules=hj.rules_text({cls}), files=hj.files_block(sol),
                   contract=hj.CONTRACT)


def write_item_prompt(run, st, retry=None):
    j, a = st["j"], st["a"]
    cur = run / "accepted" / st["tkey"]
    req = request(st, tuple(st["items"][j - 1]), cur)
    if retry:
        req = hj.fill(P("pi_item_retry"), reason=retry["reason"], where=retry.get("where", ""), same=retry.get("same", ""),
                      request=req)
    (run / "prompts" / f"{st['tkey']}__j{j}a{a}.txt").write_text(req, encoding="utf-8")
    return f"j{j}a{a}"


def _calls(st):
    return sum(1 + l.get("compile_fixes", 0) for l in st.get("log", []))


def advance(run, st):
    """다음 항목으로. 끝나면 상태를 정한다."""
    st["j"] += 1
    st["a"], st["cfix"] = 1, 0
    if not st["items"]:
        st["status"] = "passthrough"          # F* 가 비면 손대지 않는다
        return None
    if gate.over_cap(cfg(run), _calls(st)):   # 공통 호출 상한 C 에 도달: 더 안 보낸다(지금까지 받아들인 코드가 최종)
        n_acc = sum(1 for r in st["item_results"] if r["accepted"])
        st["status"] = "partial" if n_acc else "passthrough"
        return None
    if st["j"] > len(st["items"]):
        n_acc = sum(1 for r in st["item_results"] if r["accepted"])
        st["status"] = "full" if n_acc == len(st["items"]) else ("partial" if n_acc else "harden_failed")
        return None
    return write_item_prompt(run, st)


def main():
    cmd, run = sys.argv[1], Path(sys.argv[2])
    for d in ("prompts", "replies", "state", "probes", "accepted", "cand", "base"):
        (run / d).mkdir(parents=True, exist_ok=True)

    if cmd == "init":
        base_run, pol = Path(sys.argv[3]), sys.argv[4] == "1"
        v = int(sys.argv[5]) if len(sys.argv) > 5 else 1
        jsave(run / "config.json", {"spec_policy": pol, "base_run": str(base_run), "K_item": K_ITEM, "compile_fix": CFIX,
                                    "max_items": MAX_ITEMS, "probe_version": v, "stated_only": v >= 2})
        if (base_run / "targets.json").exists():
            tg = jload(base_run / "targets.json")
        else:
            tg = [jload(p) for p in sorted((base_run / "state").glob("*.json"))]
        jsave(run / "targets.json", [{k: s[k] for k in ("tkey", "tag", "item", "source", "base_sol")} for s in tg])
        for item in sorted({s["item"] for s in tg}):
            if not pol and (base_run / "replies" / f"ck__{item}.md").exists():
                shutil.copy2(base_run / "replies" / f"ck__{item}.md", run / "replies" / f"ck__{item}.md")   # 같은 요청문의 답
            else:
                (run / "prompts" / f"ck__{item}.txt").write_text(hj.fill(hj.tpl("pi_ext"), spec=spec_for(run, item)),
                                                                  encoding="utf-8")
        print("targets", len(tg))

    elif cmd == "ck-validity":                           # 15-2: 항목별 검사 목록 상태를 run/checklist_validity.json 에
        rec = {i: checklist_validity(run, i) for i in sorted({x["item"] for x in jload(run / "targets.json")})}
        jsave(run / "checklist_validity.json", rec)
        print("checklist states", dict(collections.Counter(r["state"] for r in rec.values())))

    elif cmd == "prep-probe":
        pv =cfg(run).get("probe_version") or 1
        tpl_name = {1: "pi_probe", 2: "pi_probe_v2", 3: "pi_probe_v3", 5: "pi_probe_v5", 6: "pi_probe_v5"}[pv]
        for item in sorted({x["item"] for x in jload(run / "targets.json")}):
            ck = checklist(run, item)
            extra = {"globals": module_data(item)} if pv in MODULE_DATA else {}
            for n in considered(run, item):
                (run / "prompts" / f"pr__{item}__c{n}.txt").write_text(
                    hj.fill(P(tpl_name), condition=ck[n - 1], spec=spec_for(run, item), **extra), encoding="utf-8")
            print(item, "considered", considered(run, item), "of", len(ck))

    elif cmd == "probe":
        items = sorted({x["item"] for x in jload(run / "targets.json")})
        if len(sys.argv) > 3:                             # 선택: 이 항목들만(이어 돌리기용). 없으면 전부(기존 동작)
            items = [i for i in items if i in set(sys.argv[3:])]
        for item in items:
            res = {}
            ck = checklist(run, item)
            for n in considered(run, item):
                line = ck[n - 1]
                rp = run / "replies" / f"pr__{item}__c{n}.md"
                v = {"condition": line, "status": "no_reply"}
                if rp.exists():
                    code = t.blocks(rp.read_text(encoding="utf-8"), "python")
                    if not code:
                        v["status"] = "no_code"
                    else:
                        w = run / "_probe_scripts" / f"{item}__c{n}"
                        w.mkdir(parents=True, exist_ok=True)
                        (w / "probe.py").write_text(code[0], encoding="utf-8")
                        c, log = t.docker(["--network", "none", "--memory", "512m", "-v", f"{w.resolve()}:/w:ro", t.PY_IMAGE,
                                           "sh", "-c", "cd /tmp && timeout 10 python -I -B /w/probe.py < /dev/null"], timeout=60)
                        lines = [l for l in log.splitlines() if l.strip().startswith("{")]
                        try:
                            obj = json.loads(lines[-1])
                            assert isinstance(obj["plus"]["args"], dict) and isinstance(obj["minus"]["args"], dict)
                            v.update({"status": "ok", "plus": obj["plus"], "minus": obj["minus"]})
                            if is_v2(run):
                                me = obj.get("minus_expect")
                                v["minus_expect"] = me if isinstance(me, dict) and (
                                    me.get("error") is True or (isinstance(me.get("error"), str) and me["error"])
                                    or "value" in me) else {"unspecified": True}
                        except Exception:  # noqa: BLE001
                            v.update({"status": "bad_output", "rc": c, "log_tail": log[-300:]})
                res[str(n)] = v
            jsave(run / "probes" / f"{item}.json", res)
            # 원본 Python(취약한 버전·수정된 버전)에 정상 입력과 어긴 입력을 넣는다
            pl = [(n, v) for n, v in sorted(res.items(), key=lambda kv: int(kv[0])) if v["status"] == "ok"]
            args = []
            for _, v in pl:
                args += [v["plus"]["args"], v["minus"]["args"]]
            orig = {"vulnerable": {}, "patched": {}}
            if args:
                rr = run_inputs(run, f"orig__{item}", EXPORT / "programs",
                                [(f"{item}/{s}", item, "python", f"/s/{item}/{s}.py") for s in ("vulnerable", "patched")],
                                {item: args})
                for s in ("vulnerable", "patched"):
                    for k, (n, _) in enumerate(pl):
                        orig[s][n] = rr[f"{item}/{s}"][2 * k]
                        orig[s][n + "_minus"] = rr[f"{item}/{s}"][2 * k + 1]
            jsave(run / "probes" / f"{item}.orig.json", orig)
            print(item, collections.Counter(v["status"] for v in res.values()))

    elif cmd == "prep":
        for x in jload(run / "targets.json"):
            if (run / "state" / f"{x['tkey']}.json").exists():
                continue
            base = run / "base" / x["tkey"]
            if base.exists():
                shutil.rmtree(base)
            (base / "src").mkdir(parents=True)
            src = Path(x["base_sol"])
            for rel in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
                if (src / rel).exists():
                    shutil.copy(src / rel, base / rel)
            ok_b, _ = hj.build(base)
            assert ok_b, x["tkey"]
            s0 = hj.sigma(base)
            ck = checklist(run, x["item"])
            cons = considered(run, x["item"])
            if is_v2(run):
                pr = jload(run / "probes" / f"{x['item']}.json")
                expect = {str(n): pr.get(str(n), {}).get("minus_expect", {"unspecified": True}) for n in cons}
            else:
                expect = {str(n): expected_kind(ck[n - 1]) for n in cons}
            st = {**x, "checklist": ck, "considered": cons, "expect": expect, "sigma0": s0,
                  "probe_version": cfg(run).get("probe_version", 1),
                  "cur_sigma": s0, "status": "need_where", "where": {}, "observed": {}}
            outs = measure(run, x["tkey"], x["item"], "base", run / "base")
            ok, d, acc = signals(run, st, outs)
            st.update({"ok0": ok, "d0": d, "A0": acc, "ok_cur": ok, "d_cur": d})
            for n, (op, om) in outs.items():
                if ok[n] and not d[n]:
                    st["observed"][str(n)] = observed_text(om)
            # 쓸 수 있는 쌍이 없는 조건(검사 목록에 있으나 입력 쌍이 없거나 ok=0): 차선 질문
            need = [n for n in cons if not ok.get(n, False)]
            for n in need:
                (run / "prompts" / f"{x['tkey']}__w{n}.txt").write_text(
                    hj.fill(P("pi_where"), condition=ck[n - 1], files=hj.files_block(base)), encoding="utf-8")
            st["where_needed"] = need
            if not need:
                st["status"] = "ready"
            acc_dir = run / "accepted" / x["tkey"]
            if acc_dir.exists():
                shutil.rmtree(acc_dir)
            shutil.copytree(base, acc_dir)
            jsave(run / "state" / f"{x['tkey']}.json", st)
            print(x["tkey"], "conds", len(ck), "ok", sum(ok.values()), "d", sum(d.values()), "A0", len(acc), "where", need)

    elif cmd == "plan":
        for p in sorted((run / "state").glob("*.json")):
            st = jload(p)
            if st["status"] not in ("need_where", "ready"):
                continue
            for n in st["where_needed"]:
                rp = run / "replies" / f"{st['tkey']}__w{n}.md"
                if not rp.exists():
                    break
                first = rp.read_text(encoding="utf-8").strip().splitlines()[0].strip().upper() if rp.read_text(encoding="utf-8").strip() else ""
                st["where"][str(n)] = "NO" if first.startswith("NO") else "YES" if first.startswith("YES") else "UNCLEAR"
            else:
                conds = [n for n in st.get("considered", range(1, len(st["checklist"]) + 1))
                         if (st["ok0"].get(str(n), st["ok0"].get(n)) and not st["d0"].get(str(n), st["d0"].get(n)))
                         or st["where"].get(str(n)) == "NO"]
                classes = [k for k in CLASS_ORDER if st["sigma0"]["by_class"].get(k, 0) > 0]
                items = ([["cond", n] for n in conds] + [["class", k] for k in classes])[:MAX_ITEMS]
                st.update({"items": items, "items_uncapped": len(conds) + len(classes), "j": 0, "item_results": [],
                           "status": "running"})
                tag = advance(run, st)
                jsave(p, st)
                print(st["tkey"], "items", items, "->", tag or st["status"])
                continue
            jsave(p, st)
            print(st["tkey"], "waiting where", st["where"])

    elif cmd == "ingest":
        tkey, tag = sys.argv[3], sys.argv[4]
        p = run / "state" / f"{tkey}.json"
        st = jload(p)
        assert st["status"] == "running" and tag.startswith(f"j{st['j']}a{st['a']}"), (st["status"], st.get("j"), tag)
        text = (run / "replies" / f"{tkey}__{tag}.md").read_text(encoding="utf-8")
        cand = run / "cand" / tkey
        if cand.exists():
            shutil.rmtree(cand)
        wrote = t.write_rust(cand, text)
        built, blog = hj.build(cand) if wrote else (False, "no code block in reply")
        if not built and wrote and st["cfix"] < CFIX:
            st["cfix"] += 1
            nxt = f"j{st['j']}a{st['a']}f{st['cfix']}"
            (run / "prompts" / f"{tkey}__{nxt}.txt").write_text(
                hj.fill(hj.tpl("fix_build"), kind="compile", error=t.errors_only("rust", blog)[-4000:],
                        files=hj.files_block(cand), contract=hj.CONTRACT), encoding="utf-8")
            jsave(p, st)
            print("NEXT", nxt)
            return
        kind, key = st["items"][st["j"] - 1]
        cur = run / "accepted" / tkey
        same = wrote and all((cand / r).exists() and (cur / r).exists() and
                             (cand / r).read_text(encoding="utf-8").rstrip() == (cur / r).read_text(encoding="utf-8").rstrip()
                             for r in ("Cargo.toml", "src/main.rs"))
        reason, where, det = "accepted", "", {}
        unified, gate_pass = gate.enabled(cfg(run)), False
        if not built:
            reason = "build"
        else:
            # cand 를 measure 하려면 /s/<tkey>/app 구조가 필요하다
            croot = run / "_cand_root"
            if (croot / tkey).exists():
                shutil.rmtree(croot / tkey)
            shutil.copytree(cand, croot / tkey)
            outs = measure(run, tkey, st["item"], f"j{st['j']}a{st['a']}", croot)
            ok, d, acc = signals(run, st, outs)
            s1 = hj.sigma(cand)
            okc = {int(k): v for k, v in st["ok_cur"].items()}
            dc = {int(k): v for k, v in st["d_cur"].items()}
            s_a = st["cur_sigma"]
            det = {"ok": ok, "d": d, "A": acc, "sigma": s1["by_class"]}
            inc = [k for k in hj.SIGMA_CLASSES if s1["by_class"].get(k, 0) > s_a["by_class"].get(k, 0)]
            if s1["unsafe_blocks"] > s_a["unsafe_blocks"]:
                inc.append("unsafe")
            new_load = [k for k, v in s1["codeload"].items() if v > st["sigma0"]["codeload"].get(k, 0)]
            new_deps = sorted(set(s1["deps"]) - set(st["sigma0"]["deps"]))
            if unified:
                # 공통 기준 G*: 출발 코드 대비. 통과하면 코드는 남기고, '진전'은 다시 시도 신호로만 본다.
                fo = hj.run_tests(run, tkey, f"gatefunc_j{st['j']}a{st['a']}", croot, st["item"])["functional_ok"] \
                    if gate.use_functional(cfg(run)) else None
                g_ok, g_reason, _ = gate.check(True, st["sigma0"], s1, st["A0"], acc, st["d0"], d, func_ok=fo,
                                               rules=gate.rules(cfg(run)))
                gate_pass = g_ok
                if not g_ok:
                    reason = g_reason
                elif kind == "cond" and st["ok0"].get(str(key), st["ok0"].get(key)) and not d.get(key):
                    reason = "condition_not_handled"
                elif kind == "class" and s1["by_class"].get(key, 0) >= s_a["by_class"].get(key, 0):
                    reason = "risk_points_not_reduced"
            elif not set(st["A0"]) <= set(acc):
                reason = "functional_regression"
            elif new_load or new_deps:
                reason = "loader_changed"
            elif inc:
                reason = "risk_points_increased"
                locs = [l for l in s1["locations"] if l["class"] in inc]
                where = "Locations: " + "; ".join(f"{l['file']}:{l['line']} {l['signal']}" for l in locs[:10]) + "\n"
            elif any(okc.get(n) and not ok.get(n) for n in okc) or any(dc.get(n) and not d.get(n) for n in dc):
                reason = "condition_regression"
            elif kind == "cond" and st["ok0"].get(str(key), st["ok0"].get(key)) and not d.get(key):
                reason = "condition_not_handled"
            elif kind == "class" and s1["by_class"].get(key, 0) >= s_a["by_class"].get(key, 0):
                reason = "risk_points_not_reduced"
                locs = [l for l in s1["locations"] if l["class"] == key]
                where = "Locations: " + "; ".join(f"{l['file']}:{l['line']} {l['signal']}" for l in locs[:10]) + "\n"
        rec = {"item": [kind, key], "attempt": st["a"], "built": built, "compile_fixes": st["cfix"], "reason": reason,
               "same_as_input": bool(same), "gate_pass": bool(gate_pass), **det}
        st.setdefault("log", []).append(rec)
        if unified and gate_pass and reason != "accepted":
            # G* 는 통과했지만 진전이 없음: 코드는 남긴다(최종 결과 = 마지막으로 G* 를 통과한 후보)
            shutil.rmtree(cur)
            shutil.copytree(cand, cur)
            st["ok_cur"], st["d_cur"], st["cur_sigma"] = det["ok"], det["d"], hj.sigma(cur)
        if reason == "accepted":
            shutil.rmtree(cur)
            shutil.copytree(cand, cur)
            st["ok_cur"], st["d_cur"], st["cur_sigma"] = det["ok"], det["d"], hj.sigma(cur)
            for n, (op, om) in outs.items():
                if ok[n] and not d[n]:
                    st["observed"][str(n)] = observed_text(om)
            no_check = kind == "cond" and not st["ok0"].get(str(key), st["ok0"].get(key))
            st["item_results"].append({"item": [kind, key], "accepted": True, "attempts": st["a"], "without_check": no_check})
            nxt = advance(run, st)
        elif st["a"] < K_ITEM and not gate.over_cap(cfg(run), _calls(st)):
            st["a"] += 1
            st["cfix"] = 0
            nxt = write_item_prompt(run, st, {"reason": reason, "where": where,
                                              "same": "Your previous reply returned the same code as the input.\n" if same else ""})
        else:
            st["item_results"].append({"item": [kind, key], "accepted": False, "attempts": st["a"], "last_reason": reason})
            nxt = advance(run, st)
        jsave(p, st)
        print(reason.upper(), "->", nxt or st["status"])

    elif cmd == "pending":
        # 진행 중인 대상마다 지금 답을 기다리는 요청 파일 이름(답이 없는 것만)
        for p in sorted((run / "state").glob("*.json")):
            st = jload(p)
            if st["status"] == "need_where":
                miss = [f"{st['tkey']}__w{n}" for n in st["where_needed"] if not (run / "replies" / f"{st['tkey']}__w{n}.md").exists()]
                print("WHERE", st["tkey"], " ".join(miss))
            elif st["status"] == "running":
                tag = f"j{st['j']}a{st['a']}" + (f"f{st['cfix']}" if st["cfix"] else "")
                if not (run / "replies" / f"{st['tkey']}__{tag}.md").exists():
                    print("ITEM", f"{st['tkey']}__{tag}")
                else:
                    print("READY", f"{st['tkey']}__{tag}")
            else:
                print("DONE", st["tkey"], st["status"])

    elif cmd == "eval":
        rows, per = [], collections.Counter()
        for p in sorted((run / "state").glob("*.json")):
            st = jload(p)
            b = hj.run_tests(run, st["tkey"], "eval_base", run / "base", st["item"])
            changed = any(r["accepted"] for r in st.get("item_results", [])) or \
                any(l.get("gate_pass") for l in st.get("log", []))   # G*: 진전 없이 통과한 코드도 남는다
            h = hj.run_tests(run, st["tkey"], "eval_hard", run / "accepted", st["item"]) if changed else b
            pairs = []
            for (bv, _), (hv, _) in zip(b["safety"], h["safety"]):
                if "invalid" in (bv, hv):
                    pairs.append("invalid")
                    continue
                be, he = bv == "exploited", hv == "exploited"
                pairs.append("removed" if be and not he else "left" if be and he else "new" if he else "safe")
            for o in pairs:
                per[(st["source"], o)] += 1
            res = st.get("item_results", [])
            rows.append({"tkey": st["tkey"], "source": st["source"], "status": st["status"], "items": st.get("items"),
                         "items_uncapped": st.get("items_uncapped"), "item_results": res,
                         "n_cond_items": sum(1 for r in res if r["item"][0] == "cond"),
                         "n_cond_acc": sum(1 for r in res if r["item"][0] == "cond" and r["accepted"]),
                         "n_class_items": sum(1 for r in res if r["item"][0] == "class"),
                         "n_class_acc": sum(1 for r in res if r["item"][0] == "class" and r["accepted"]),
                         "probe_usable": sum(1 for v in st["ok0"].values() if v), "conds": len(st["checklist"]),
                         "base_functional_ok": b["functional_ok"], "hard_functional_ok": h["functional_ok"],
                         "base_safety": [v for v, _ in b["safety"]], "hard_safety": [v for v, _ in h["safety"]],
                         "pairs": pairs})
        jsave(run / "eval_rows.json", rows)
        # 조건 확인 입력 정확도: 수정된 원본 Python(참조 구현)에서 정상 입력은 정상, 어긴 입력은 e_i (보고만, 방법에 되돌리지 않음)
        acc_n = acc_d = 0
        for item in sorted({r["tkey"].split("__")[1] for r in rows}):
            pr = jload(run / "probes" / f"{item}.json")
            org = jload(run / "probes" / f"{item}.orig.json")["patched"]
            ck = checklist(run, item)
            for n, v in pr.items():
                if v["status"] != "ok":
                    continue
                acc_d += 1
                e = v.get("minus_expect", {"unspecified": True}) if is_v2(run) else expected_kind(ck[int(n) - 1])
                if d_of(e, org[n], org[n + "_minus"]):
                    acc_n += 1
        st_c = collections.Counter((r["source"], r["status"]) for r in rows)
        L = ["# 항목별 강화+조건 확인 결과 (자동 생성)", "",
             "| 출발 코드 | 대상 | 완전 강화 | 부분 강화 | 강화 실패 |", "| --- | --- | --- | --- | --- |"]
        for s in ("vulnerable", "patched"):
            n = sum(1 for r in rows if r["source"] == s)
            L.append(f"| {s} | {n} | {st_c[(s, 'full')]} | {st_c[(s, 'partial')]} | {st_c[(s, 'harden_failed')]} |")
        L += ["", "보안 시험 하나마다 강화 전 → 강화 후:", "", "| 출발 코드 | 없앰 | 그대로 남음 | 새로 생김 | 양쪽 안전 | 무효 |",
              "| --- | --- | --- | --- | --- | --- |"]
        for s in ("vulnerable", "patched"):
            L.append(f"| {s} | " + " | ".join(str(per[(s, o)]) for o in ("removed", "left", "new", "safe", "invalid")) + " |")
        L += ["", f"조건 항목: 표시 {sum(r['n_cond_items'] for r in rows)}, 받아들임 {sum(r['n_cond_acc'] for r in rows)}",
              f"종류 항목: 표시 {sum(r['n_class_items'] for r in rows)}, 받아들임 {sum(r['n_class_acc'] for r in rows)}",
              f"조건 확인 입력을 쓸 수 있던 조건(출발 코드 기준): {sum(r['probe_usable'] for r in rows)} / {sum(r['conds'] for r in rows)}",
              f"조건 확인 입력 정확도(수정된 원본 Python 기준, 쌍 단위): {acc_n} / {acc_d}",
              f"강화 뒤 데이터셋 기능 시험이 깨진 것: {sum(1 for r in rows if r['base_functional_ok'] and not r['hard_functional_ok'])}"]
        (run / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
        print("\n".join(L))


if __name__ == "__main__":
    main()
