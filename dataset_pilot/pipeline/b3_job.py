"""실험 B 조건 B3 = 제안서 방법(규칙+검사 목록+점검, 하네스 H-both).

이 데이터셋에서의 점검(triage):
- 점검용 공격(A^g)이 없으므로 제안서 7절 규칙대로 코드 신호만 쓴다(G^d 없음).
- 임계값 τ_k = 1(config tau_default). 그래서 표시 집합 F_s = {σ_k ≥ 1} = {σ_k > 0}.
- 이는 H-all(점검 없음)의 표시 집합과 같다. 즉 이 데이터셋에서는 B3 의 점검이 아무것도 걸러내지 못한다.
- H7-e(점검이 비용을 줄이는가)는 이 데이터셋만으로는 시험할 수 없다(τ>1 이나 점검용 공격이 있어야 함).
- 그래도 B3 의 '고치기' 내용(규칙+검사 목록, pi_rep)은 B0·B1·B4 가 쓰지 않은 제안서 고유 요청이라, 돌릴 값이 있다.

구현: harden_job(H-all) 의 절차를 그대로 쓰되 대상만 시험 운행의 PyRs 20개로 돌린다.
받아들이기·예산(K=3, 컴파일 수정 2)은 harden_job 그대로. 결과 맞추기 없음(요청문·규칙·받아들이기 안 바꿈).

  prep-ck <run> / prep <run> / ingest <run> <tkey> <tag> / eval <run>  (harden_job 과 동일)
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import harden_job as hj  # noqa: E402

DS = HERE.parent
hj.BASES = {"b3": DS / "pilot_A_2026-11-12"}        # 시험 운행 PyRs(기능 통과) 20개
hj.t.TARGET_VOL = "dsp-cargo-target-b3"

if __name__ == "__main__":
    hj.main()
