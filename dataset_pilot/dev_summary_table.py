"""개발용 Haiku 69항목 결과를 저장된 결과 파일에서 다시 세어 표로 만든다(모델 호출 없음, 실행 없음).

읽는 것: hk6_A/eval_rows.json(번역), tf69_A/eval_rows.json(보이는 시험 되먹임 뒤 번역),
        hk6_B(B1, B5 이름으로 저장된 통합 조건), hk7_B(B1, RCI, SPEC2), hk8_B(ORA), export/programs/<item>/meta.json(CWE)
쓰는 것: <out>/조건별_결과표.md, <out>/항목별_결과표.csv, <out>/_항목번호_열쇠.json(항목 id 대응. 밖으로 내보내지 않는다)
항목 id 는 표에 쓰지 않고 D01~D69 번호로 바꾼다. 시험 입력과 답 내용은 읽지도 쓰지도 않는다.

usage (dataset_pilot 폴더에서): python -X utf8 dev_summary_table.py <out 폴더>
"""
import collections
import csv
import json
import sys
from pathlib import Path

HOME = Path(__file__).resolve().parent
C = collections.Counter


def J(p):
    return json.loads((HOME / p).read_text(encoding="utf-8"))


def item_of(r):
    return r["tkey"].split("__")[1]


def reasons(run, cond, tkey):
    st = J(f"{run}/{cond}/state/{tkey}.json")
    return "/".join(sorted({h.get("reason") for h in st["log"] if isinstance(h, dict) and h.get("reason")}))


def main(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    A = J("hk6_A/eval_rows.json")
    T = J("tf69_A/eval_rows.json")
    items = sorted({r["item"] for r in A})
    assert len(items) == 69
    label = {it: f"D{n:02d}" for n, it in enumerate(items, 1)}
    cwe = {it: "CWE-" + str(J(f"export/programs/{it}/meta.json").get("cwe", "?")) for it in items}
    a = {(r["item"], r["source"]): r for r in A if r["cond"] == "PyRs"}
    t = {(r["item"], r["source"]): r for r in T if r["cond"] == "PyRs"}
    vul64 = {it for it in items if a[(it, "vulnerable")]["functional_ok"]}
    pat66 = {it for it in items if a[(it, "patched")]["functional_ok"]}
    vul54 = {it for it in vul64 if "left" in a[(it, "vulnerable")]["pairs"]}
    vul10 = vul64 - vul54

    conds = [("명세 자기 수정", "hk7_B", "B1"), ("명세 자기 수정 두 번", "hk7_B", "SPEC2"),
             ("자기 비판 반복(받아들이기 기준 거침)", "hk7_B", "RCI"),
             ("통합 조건 B6(확인 입력 신호, 뺀 조건)", "hk6_B", "B5"),
             ("정책 제공 참고 조건", "hk8_B", "ORA")]
    rows = {}
    for name, run, c in conds:
        rs = [r for r in J(f"{run}/eval_rows.json") if r["cond"] == c]
        v = {item_of(r): r for r in rs if r["source"] == "vulnerable"}
        p = {item_of(r): r for r in rs if r["source"] == "patched"}
        assert set(v) == vul64 and set(p) == pat66, (run, c)
        rows[name] = (run, c, v, p)
    # 원 방식 그대로(받아들이기 기준 없음)의 첫 결과물: RCI 행의 first
    _run, _c, rv, rp = rows["자기 비판 반복(받아들이기 기준 거침)"]
    first = lambda r: r["first"].get("pairs", [])

    def agg(v, p, pairs=lambda r: r["pairs"], gated=True):
        still = {it for it, r in v.items() if "left" in pairs(r)}
        revived = {it for it, r in v.items() if "new" in pairs(r)}
        d = collections.OrderedDict()
        d["대상(취약판 번역 + 수정판 번역)"] = f"{len(v) + len(p)} ({len(v)} + {len(p)})"
        if gated:
            acc = sum(r["status"] == "accepted" for r in list(v.values()) + list(p.values()))
            d["받아들여짐 / 출발 코드로 돌아감"] = f"{acc} / {len(v) + len(p) - acc}"
            d["최종 코드의 기능 시험 통과"] = str(sum(bool(r["hard_functional_ok"]) for r in list(v.values()) + list(p.values())))
        else:
            ok = sum(bool(r["first"]["functional_ok"]) for r in list(v.values()) + list(p.values()))
            d["받아들여짐 / 출발 코드로 돌아감"] = "기준 없음"
            d["최종 코드의 기능 시험 통과"] = f"{ok} (깨짐 {len(v) + len(p) - ok})"
        d["없앤 보안 시험(남아 있던 108개 중)"] = str(sum(pairs(r).count("removed") for r in v.values()))
        d["처음 취약했던 54개 중 여전히 취약"] = str(len(still & vul54))
        d["사라졌던 10개 중 다시 취약해진 번역"] = str(len((still | revived) & vul10))
        d["수정판 번역(66개)에서 새로 생김: 번역 / 시험"] = \
            f"{sum(1 for r in p.values() if 'new' in pairs(r))} / {sum(pairs(r).count('new') for r in p.values())}"
        d["호출 수"] = str(sum(r["calls"] for r in list(v.values()) + list(p.values()))) if gated else "(위 행과 같은 실행)"
        return d, still

    table, stills = [], {}
    for name, (run, c, v, p) in rows.items():
        d, still = agg(v, p)
        table.append((name, d))
        stills[name] = still
        if c == "RCI":
            d2, still2 = agg(v, p, pairs=first, gated=False)
            table.append(("자기 비판 반복(원 방식 그대로, 기준 없음)", d2))
            stills["RCI@first"] = still2

    L = []
    w = L.append
    w("# 개발용 Haiku 69항목: 조건별 결과표 (저장된 결과 파일에서 다시 셈)")
    w("")
    w("만든 방법: `dataset_pilot/dev_summary_table.py`. 모델을 다시 부르지 않았고 아무것도 다시 실행하지 않았다. 숫자는 모두 개수다.")
    w("")
    w("## 1. 번역 단계 (Python→Rust, 모델 Claude Haiku, 항목마다 번역 1개)")
    w("")
    w("| | 취약판 번역 | 수정판 번역 |")
    w("| --- | --- | --- |")
    for k, f in (("번역 수", lambda s: sum(1 for it in items)),
                 ("빌드됨", lambda s: sum(a[(it, s)]["built"] for it in items)),
                 ("첫 시도에 빌드됨", lambda s: sum(a[(it, s)]["fix_rounds"] == 0 for it in items)),
                 ("기능 시험 모두 통과", lambda s: sum(bool(a[(it, s)]["functional_ok"]) for it in items)),
                 ("기능 시험 실패(빌드는 됨)", lambda s: sum(not a[(it, s)]["functional_ok"] for it in items))):
        w(f"| {k} | {f('vulnerable')} | {f('patched')} |")
    tv = C(x for it in vul64 for x in a[(it, "vulnerable")]["pairs"])
    tp = C(x for it in pat66 for x in a[(it, "patched")]["pairs"])
    w(f"| 기능 통과한 번역의 보안 시험 수 | {sum(tv.values())} | {sum(tp.values())} |")
    w(f"| 그중 남음 / 없어짐 / 원래 양쪽 안전 | {tv['left']} / {tv['gone']} / {tv['safe']} | 해당 없음 |")
    w(f"| 그중 새로 생김 | 해당 없음 | {tp['new']} |")
    w(f"| 취약한 번역(보안 시험이 하나라도 뚫림) | {len(vul54)} | {sum(1 for it in pat66 if 'new' in a[(it, 'patched')]['pairs'])} |")
    w(f"| 취약점이 모두 사라진 번역 | {len(vul10)} | 해당 없음 |")
    w("")
    w(f"- 취약판과 수정판 번역이 둘 다 기능 시험을 통과한 항목: {len(vul64 & pat66)}개.")
    w(f"- 보이는 시험 되먹임을 붙인 번역 절차(`tf69_A`)로 같은 번역을 이어 돌린 뒤: 기능 통과 취약판 "
      f"{sum(bool(t[(it, 'vulnerable')]['functional_ok']) for it in items)}, 수정판 "
      f"{sum(bool(t[(it, 'patched')]['functional_ok']) for it in items)}. 보안 시험 결과는 바뀌지 않았다.")
    w("- Python→Python 재작성 대조는 이 69항목에서는 돌리지 않았다(번역 수 0).")
    w("")
    w("## 2. 완화 조건 (대상 = 기능 통과한 번역 130개 = 취약판 64 + 수정판 66, 모든 조건이 같은 130개)")
    w("")
    heads = list(table[0][1].keys())
    w("| 조건 | " + " | ".join(heads) + " |")
    w("| --- |" + " --- |" * len(heads))
    for name, d in table:
        w(f"| {name} | " + " | ".join(d[h] for h in heads) + " |")
    w("")
    b1, sp2, ora = stills["명세 자기 수정"], stills["명세 자기 수정 두 번"], stills["정책 제공 참고 조건"]
    w(f"- 명세 자기 수정 뒤 남은 번역과 두 번 뒤 남은 번역은 같은 집합인가: {'예' if b1 == sp2 else '아니오'} ({len(b1)}개).")
    w(f"- 정책 제공 참고 조건 뒤 남은 {len(ora)}개 중 명세 자기 수정 뒤에도 남았던 것 {len(ora & b1)}개, "
      f"명세 자기 수정은 고쳤는데 정책 제공 조건은 못 고친 것 {len(ora - b1)}개. "
      f"명세 자기 수정 뒤 남은 {len(b1)}개 중 정책 제공 조건에서 고쳐진 것 {len(b1 - ora)}개.")
    w("- 같은 실행을 두 번 센 곳: 명세 자기 수정의 결과는 `hk6_B`와 `hk7_B`에 같은 값으로 들어 있다(다시 만들지 않고 가져옴).")
    w("- 출발 코드로 돌아간 이유(조건, 출발 판, 거절 이유 묶음 → 번역 수):")
    for name, (run, c, v, p) in rows.items():
        cnt = C()
        for src, m in (("취약판", v), ("수정판", p)):
            for it, r in m.items():
                if r["status"] != "accepted":
                    cnt[(src, reasons(run, c, r["tkey"]))] += 1
        w(f"  - {name}: " + (", ".join(f"{s} {rs} {n}" for (s, rs), n in sorted(cnt.items())) or "없음"))
    w("")
    w("## 3. 약점 종류별 (취약판 번역, 번역 수)")
    w("")
    w("| CWE | 항목 | 기능 통과 | 번역 뒤 취약 | 명세 자기 수정 뒤 취약 | 자기 비판 반복 뒤 취약 | 정책 제공 조건 뒤 취약 |")
    w("| --- | --- | --- | --- | --- | --- | --- |")
    rci = stills["자기 비판 반복(받아들이기 기준 거침)"]
    for cw in sorted(set(cwe.values()), key=lambda s: int(s.split("-")[1])):
        its = [it for it in items if cwe[it] == cw]
        w(f"| {cw} | {len(its)} | {sum(it in vul64 for it in its)} | {sum(it in vul54 for it in its)} | "
          f"{sum(it in b1 for it in its)} | {sum(it in rci and it in vul54 for it in its)} | {sum(it in ora for it in its)} |")
    w(f"| 합계 | {len(items)} | {len(vul64)} | {len(vul54)} | {len(b1)} | {len(rci & vul54)} | {len(ora)} |")
    w("")
    (out / "조건별_결과표.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    with open(out / "항목별_결과표.csv", "w", encoding="utf-8-sig", newline="") as fh:
        wr = csv.writer(fh)
        hdr = ["항목번호", "CWE", "취약판_기능통과", "취약판_보안시험수", "취약판_남음", "취약판_없어짐", "수정판_기능통과", "수정판_새로생김"]
        for name, (run, c, v, p) in rows.items():
            hdr += [f"{c}_취약판_상태", f"{c}_취약판_남음", f"{c}_취약판_다시생김", f"{c}_수정판_상태", f"{c}_수정판_새로생김"]
        hdr += ["RCI첫결과물_취약판_기능통과", "RCI첫결과물_취약판_남음", "RCI첫결과물_수정판_기능통과", "RCI첫결과물_수정판_새로생김"]
        wr.writerow(hdr)
        for it in items:
            av, ap = a[(it, "vulnerable")], a[(it, "patched")]
            row = [label[it], cwe[it], int(bool(av["functional_ok"])), len(av["pairs"]) if av["functional_ok"] else "",
                   av["pairs"].count("left") if av["functional_ok"] else "", av["pairs"].count("gone") if av["functional_ok"] else "",
                   int(bool(ap["functional_ok"])), ap["pairs"].count("new") if ap["functional_ok"] else ""]
            for name, (run, c, v, p) in rows.items():
                rv_, rp_ = v.get(it), p.get(it)
                row += [rv_["status"] if rv_ else "", rv_["pairs"].count("left") if rv_ else "", rv_["pairs"].count("new") if rv_ else "",
                        rp_["status"] if rp_ else "", rp_["pairs"].count("new") if rp_ else ""]
            fv, fp = rv.get(it), rp.get(it)
            row += [int(bool(fv["first"]["functional_ok"])) if fv else "", first(fv).count("left") if fv else "",
                    int(bool(fp["first"]["functional_ok"])) if fp else "", first(fp).count("new") if fp else ""]
            wr.writerow(row)
    (out / "_항목번호_열쇠.json").write_text(json.dumps(label, ensure_ascii=False, indent=1), encoding="utf-8")
    print("items", len(items), "vul64", len(vul64), "pat66", len(pat66), "vul54", len(vul54))
    print("wrote", out)


if __name__ == "__main__":
    main(sys.argv[1])
