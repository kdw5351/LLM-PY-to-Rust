"""조건 검사를 '검출기'로 쓸 때의 정확도(개발용). 모델 호출 0, 실행 0 — 저장된 판정만 대조.

검출기 양성(이 번역이 명세의 보안 조건을 빠뜨렸다):
  --rule v2 (기본): 고려한 조건 중 하나라도 (ok0 이고 d0 거짓) 또는 (ok0 거짓이고 where == NO)
  --rule v4 (조건확인_v4_설계_2026-11-12.md): (ok0 이고 d0 거짓)만 '예'. ok0 거짓 조건은 where 가 YES 면 지킴,
            NO 이거나 답이 없으면 '보류'. 번역본: 예 > 보류 > 아니오 순.
정답: 그 번역이 데이터셋 보안 시험에 하나라도 뚫렸는가(pairs 에 left/new).
판별력 진단: 원본 Python(취약/수정)에 같은 판정을 적용한 결과(원인 설명용, 판정에 쓰지 않음).
출력: 개수만. 시험 내용·입력은 출력하지 않는다.

usage: python detector_acc.py [--rule v2|v4] <B4run> <Arun> [<B4run> <Arun> ...]
"""
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harden_item_job import d_of  # noqa: E402  같은 판정 함수를 원본에 적용


def truth_map(arun):
    rows = json.loads((Path(arun) / "eval_rows.json").read_text(encoding="utf-8"))
    out = {}
    for r in rows:
        if r["cond"] != "PyRs":
            continue
        out[(r["item"], r["source"])] = any(p in ("left", "new") for p in r["pairs"])
    return out


def verdict(st, rule="v2"):
    """반환: ('yes'|'hold'|'no', 근거 목록)."""
    pos, hold, how = False, False, []
    for c in map(str, st["considered"]):
        if st["ok0"].get(c):
            if not st["d0"].get(c, True):
                pos = True; how.append(f"{c}:probe")
            continue
        w = str(st["where"].get(c, "")).strip().upper()
        if rule == "v4":
            if not w.startswith("YES"):
                hold = True; how.append(f"{c}:hold")
        elif w.startswith("NO"):
            pos = True; how.append(f"{c}:where")
    return ("yes" if pos else "hold" if hold else "no"), how


def discriminates(b4run, item, st):
    """원본 Python 에 같은 판정을 적용: (취약 원본 d, 수정 원본 d). 이상적 = FT."""
    f = Path(b4run) / "probes" / f"{item}.orig.json"
    if not f.exists():
        return None
    d = json.loads(f.read_text(encoding="utf-8"))
    out = {}
    for c in map(str, st["considered"]):
        e = st["expect"].get(c)
        r = []
        for s in ("vulnerable", "patched"):
            o = d.get(s, {})
            if c in o and f"{c}_minus" in o and e is not None:
                v = d_of(e, o[c], o[f"{c}_minus"])
                r.append("-" if v is None else ("T" if v else "F"))
            else:
                r.append("?")
        out[c] = "".join(r)
    return out


CELL = {("yes", True): "TP", ("yes", False): "FP", ("no", True): "FN", ("no", False): "TN",
        ("hold", True): "HOLD+", ("hold", False): "HOLD-"}


def pair_kind(vv, vp):
    """취약 번역본 판정 vv, 수정 번역본 판정 vp (둘 다 뚫림=취약, 안 뚫림=수정일 때)."""
    if "hold" in (vv, vp):
        return "한쪽이상보류"
    return {("yes", "no"): "둘다맞음", ("yes", "yes"): "둘다예", ("no", "no"): "둘다아니오",
            ("no", "yes"): "뒤바뀜"}[(vv, vp)]


def main(argv):
    rule = "v2"
    if argv and argv[0] == "--rule":
        rule, argv = argv[1], argv[2:]
    tot = collections.Counter()
    pairs = collections.Counter()
    for b4run, arun in zip(argv[0::2], argv[1::2]):
        truth = truth_map(arun)
        print(f"== {b4run}  (정답: {arun}, 규칙 {rule})")
        by_item = collections.defaultdict(dict)
        for sf in sorted((Path(b4run) / "state").glob("*.json")):
            st = json.loads(sf.read_text(encoding="utf-8"))
            key = (st["item"], st["source"])
            if key not in truth:
                print("  skip(no truth)", *key); continue
            v, how = verdict(st, rule)
            t = truth[key]
            cell = CELL[(v, t)]
            tot[cell] += 1
            by_item[st["item"]][st["source"]] = (v, t)
            disc = discriminates(b4run, st["item"], st)
            print(f"  {st['item']} {st['source'][:4]}  판정={v}{how}  뚫림={'예' if t else '아니오'}  -> {cell}  원본판별={disc}")
        for item, d in by_item.items():
            if set(d) == {"vulnerable", "patched"} and d["vulnerable"][1] and not d["patched"][1]:
                pairs[pair_kind(d["vulnerable"][0], d["patched"][0])] += 1
    tp, fp, fn, tn = tot["TP"], tot["FP"], tot["FN"], tot["TN"]
    hp, hn = tot["HOLD+"], tot["HOLD-"]
    print("\n합계", dict(tot))
    print(f"번역본: 맞게 잡음 {tp}, 오경보 {fp}, 놓침 {fn}, 맞게 거름 {tn}, 보류 {hp + hn}"
          f" (뚫린 {tp + fn + hp}개 중 보류 {hp}, 안 뚫린 {fp + tn + hn}개 중 보류 {hn})")
    print(f"판정한 {tp + fp + fn + tn}개 중 맞음 {tp + tn}")
    print("짝(취약 뚫림·수정 안전인 항목):", dict(pairs))


if __name__ == "__main__":
    main(sys.argv[1:])
