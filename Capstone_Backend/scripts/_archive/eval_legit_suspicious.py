# -*- coding: utf-8 -*-
"""
eval_legit_suspicious.py  —  🗄️ เก็บเข้ากรุแล้ว รันไม่ได้ตั้งแต่ 2026-08-26
==========================================================================
สคริปต์นี้วัดสูตร risk score ของฝั่งเรา (WEIGHT_AI = 0.35) ซึ่ง "ลบทิ้งแล้ว" —
มติ 2026-08-26 ยกความเป็นเจ้าของสูตรให้ทีม .92 (risk_scoring/risk_config.py)
risk_score.py ตอนนี้เหลือแค่ประตู fast path ไม่มี compute_final_score() อีกแล้ว

จะ import แล้ว AttributeError แน่นอน — เก็บไว้เป็นหลักฐานว่าเคยวัดอะไรไว้เท่านั้น
ถ้าอยากวัด FP ของสูตรที่ใช้จริง ต้องไปวัดที่ฝั่ง .92
โค้ดสูตรเดิม: git show 9ca80c2:Capstone_Backend/risk_score.py
==========================================================================
วัด false-positive กับอีเมล "legit-but-suspicious" โดยใช้ฟังก์ชันจริงจาก risk_score.py
- LEGIT cases  : อีเมลจริงที่ดูน่าสงสัย -> ควรได้ Allow/Warning (ถ้าได้ Quarantine/Block = FP)
- THREAT cases : อันตรายจริง (control) -> ควรได้ Quarantine/Block (ถ้าได้ Allow/Warning = FN)
รันซ้ำได้หลังแก้ risk_score.py เพื่อเทียบ before/after
"""
import sys
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parents[1]))
import risk_score as R

# แต่ละ case: (name, kind, features)  kind = "legit" | "threat"
# features: ai, link, abuse, header, dmarc("pass"/"fail"), reply_mismatch, malware
CASES = [
    # ---------- LEGIT-BUT-SUSPICIOUS (ควร Allow/Warning) ----------
    ("Newsletter (From!=Reply-To)",        "legit",  dict(ai=15, link=10, abuse=0,  header=30, dmarc="pass", reply=True,  mal=False)),
    ("Password reset (มีลิงก์)",            "legit",  dict(ai=35, link=10, abuse=0,  header=0,  dmarc="pass", reply=False, mal=False)),
    ("Shipping/tracking notification",      "legit",  dict(ai=20, link=15, abuse=0,  header=0,  dmarc="pass", reply=False, mal=False)),
    ("Forwarded email (DMARC fail)",        "legit",  dict(ai=10, link=0,  abuse=0,  header=0,  dmarc="fail", reply=False, mal=False)),
    ("Real bank alert (โทนเร่งด่วน)",       "legit",  dict(ai=55, link=10, abuse=0,  header=0,  dmarc="pass", reply=False, mal=False)),
    ("SaaS noreply notification",           "legit",  dict(ai=20, link=10, abuse=0,  header=30, dmarc="pass", reply=True,  mal=False)),
    ("Marketing promo (urgency+link)",      "legit",  dict(ai=45, link=20, abuse=0,  header=30, dmarc="pass", reply=True,  mal=False)),
    ("Mailing list (dmarc fail+reply)",     "legit",  dict(ai=15, link=5,  abuse=0,  header=30, dmarc="fail", reply=True,  mal=False)),
    ("Meeting invite (no subject)",         "legit",  dict(ai=10, link=0,  abuse=0,  header=10, dmarc="pass", reply=False, mal=False)),
    ("HR/payroll legit (พูดถึงเงิน)",       "legit",  dict(ai=40, link=0,  abuse=0,  header=0,  dmarc="pass", reply=False, mal=False)),
    # ---------- REAL THREATS (control, ควร Quarantine/Block) ----------
    ("Classic phishing",                    "threat", dict(ai=95, link=80, abuse=0,  header=30, dmarc="fail", reply=True,  mal=False)),
    ("Malware attachment",                  "threat", dict(ai=40, link=0,  abuse=0,  header=0,  dmarc="pass", reply=False, mal=True)),
    ("VT-confirmed malicious link",         "threat", dict(ai=60, link=100,abuse=0,  header=0,  dmarc="pass", reply=False, mal=False)),
    ("BEC wire fraud",                      "threat", dict(ai=70, link=0,  abuse=0,  header=30, dmarc="fail", reply=True,  mal=False)),
    ("Phishing from bad IP",                "threat", dict(ai=85, link=60, abuse=95, dmarc_pen=15, header=30, dmarc="fail", reply=True, mal=False)),
    ("Spoofed sender (high abuse IP)",      "threat", dict(ai=60, link=40, abuse=90, header=30, dmarc="fail", reply=True,  mal=False)),
]


def level_of(f):
    pen = f.get("dmarc_pen", 15 if f["dmarc"] == "fail" else 0)
    score = R.compute_final_score(
        raw_ai_score=f["ai"], raw_link_score=f["link"], abuseipdb_score=f["abuse"],
        header_anomaly_score=f["header"], dmarc_status=f["dmarc"], dmarc_penalty=pen,
        reply_to_mismatch=f["reply"], has_malware=f["mal"])
    level, _ = R.risk_level_from_score(score)
    # strip emoji/color word -> plain
    plain = level.split()[-1] if level else level
    return score, plain


def main():
    print(f"{'Case':<34}{'kind':<8}{'score':>7}  {'level':<12}{'verdict'}")
    print("-" * 78)
    fp = fn = n_legit = n_threat = 0
    for name, kind, f in CASES:
        score, lvl = level_of(f)
        bad = lvl in ("Quarantine", "Block")
        if kind == "legit":
            n_legit += 1
            is_fp = bad
            fp += is_fp
            verdict = "FALSE POSITIVE" if is_fp else "ok"
        else:
            n_threat += 1
            is_fn = not bad
            fn += is_fn
            verdict = "MISS (FN)" if is_fn else "ok"
        mark = "X" if verdict.startswith(("FALSE", "MISS")) else " "
        print(f"{name:<34}{kind:<8}{score:>7.1f}  {lvl:<12}[{mark}] {verdict}")
    print("-" * 78)
    print(f"LEGIT-but-suspicious : {fp}/{n_legit} โดน Quarantine/Block  = FP rate {fp/n_legit*100:.0f}%")
    print(f"THREAT detection     : {n_threat-fn}/{n_threat} จับได้        = detection {(n_threat-fn)/n_threat*100:.0f}%")


if __name__ == "__main__":
    main()
