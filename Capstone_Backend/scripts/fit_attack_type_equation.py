# -*- coding: utf-8 -*-
"""fit สมการแยกประเภทการโจมตีจาก label ที่คนติดไว้

รันเมื่อผู้ตรวจกรอก type_label_worksheet.xlsx เสร็จแล้ว:
    venv/Scripts/python.exe scripts/fit_attack_type_equation.py

ได้อะไร: logistic regression หนึ่งสมการต่อหนึ่งประเภท

    logit(ประเภท) = b0 + b1*x1 + b2*x2 + ...
    P(ประเภท)     = 1 / (1 + e^(-logit))

ทำไมเลือก logistic regression ไม่ใช่ XGBoost:
  รายงาน "ค่าสัมประสิทธิ์" กับ "odds ratio" ต่อหลักฐานได้ตรง ๆ
  เช่น "ถ้ามี spoof_own_org โอกาสเป็น BEC เพิ่มขึ้น N เท่า"
  ซึ่งเป็นคำตอบที่ป้องกันได้ในเชิงวิชาการ · XGBoost 800 ต้นตอบแบบนี้ไม่ได้

=====================================================================
กติกาการรายงานผล — ห้ามละเมิด
=====================================================================
  fit    ด้วย ชุด A + ชุด B  (B เอียงโดยตั้งใจ ช่วยให้มีตัวอย่างต่อคลาสพอ)
  รายงาน ด้วย ชุด A เท่านั้น (สุ่มล้วน = สะท้อนของจริง)

ถ้ารายงานด้วย B ด้วย ตัวเลขจะสวยเกินจริง เพราะ B ถูกคัดมาให้ง่ายต่อการแยก
"""
import os
import sys
import math

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.chdir(HERE)
import email_preprocess as ep  # noqa: E402

DIR = os.path.join(HERE, "datasets", "pmg_dataset_for_students", "06_type_labels")
LABEL_COL = "ประเภทที่ผู้ตรวจตัดสิน"
MIN_PER_CLASS = 25          # ต่ำกว่านี้ค่าสัมประสิทธิ์ไม่มีความหมาย

# ต้องตรงกับ FIT_FEATURES ใน build_type_label_worksheet.py
# ⚠️ ไม่มี link_text_mismatch และ attachment_risk เพราะชุดข้อมูลนี้คำนวณไม่ได้
#    ใส่เข้ามา = train/serving skew (ตอนเทรนเป็น 0 เสมอ ตอนใช้จริงมีค่า)
FEATURES = [
    "spoof_display_name", "spoof_homoglyph", "spoof_lookalike", "spoof_brand",
    "spoof_brand_related", "spoof_own_org", "spoof_freemail_corp",
    "link_count", "unique_link_domains", "link_domain_ratio", "external_link_ratio",
    "has_unsubscribe", "link_login_lure", "no_links",
    "asks_credential", "has_urgency", "sender_is_free_mailer",
]
# ตัวแปรที่เป็นจำนวน ต้อง scale ไม่งั้น coefficient เทียบกันไม่ได้
COUNTS = {"link_count", "unique_link_domains", "link_domain_ratio", "external_link_ratio"}

TYPE_MAP = {
    "Phishing (ล่อไปกรอกข้อมูล/รหัสผ่าน)": "Phishing",
    "BEC (ปลอมเป็นคน ขอให้โอนเงิน/ทำอะไร)": "Business Email Compromise (BEC)",
    "Spam (โฆษณา ส่งกระจาย)": "Spam (High-Risk Source)",
    "Malware (มีไฟล์แนบอันตราย)": "Malware Attachment",
    "ไม่ใช่การโจมตี": "Normal",
}


def load_labels() -> pd.DataFrame:
    xl = os.path.join(DIR, "type_label_worksheet.xlsx")
    frames = []
    if os.path.exists(xl):
        for sheet in pd.read_excel(xl, sheet_name=None).items():
            name, d = sheet
            d["_sheet"] = "A" if name.startswith("A") else "B"
            frames.append(d)
    else:
        for f, tag in (("sheetA_random_200.csv", "A"), ("sheetB_enriched_200.csv", "B")):
            p = os.path.join(DIR, f)
            if os.path.exists(p):
                d = pd.read_csv(p)
                d["_sheet"] = tag
                frames.append(d)
    if not frames:
        sys.exit(f"ไม่พบไฟล์ label ใน {DIR} — รัน build_type_label_worksheet.py ก่อน")
    lab = pd.concat(frames, ignore_index=True)
    if LABEL_COL not in lab.columns:
        sys.exit(f"ไม่มีคอลัมน์ '{LABEL_COL}' — ผู้ตรวจยังไม่ได้กรอก")
    lab = lab[["MailID", LABEL_COL, "_sheet"]].dropna(subset=[LABEL_COL])
    lab = lab[lab[LABEL_COL].astype(str).str.strip() != ""]
    lab["y"] = lab[LABEL_COL].map(TYPE_MAP)
    unknown = lab[lab["y"].isna()][LABEL_COL].unique()
    if len(unknown):
        print(f"  ⚠️ ข้ามคำตอบที่ไม่รู้จัก: {list(unknown)[:5]}")
    return lab.dropna(subset=["y"])


def main():
    lab = load_labels()
    feat = pd.read_csv(os.path.join(DIR, "_features_DO_NOT_SHOW_REVIEWER.csv"))
    df = lab.merge(feat.drop(columns=["_sheet"], errors="ignore"), on="MailID", how="inner")
    print(f"label ที่กรอกแล้ว {len(lab)} · จับคู่ feature ได้ {len(df)}")
    print("\nจำนวนตัวอย่างต่อประเภท")
    counts = df["y"].value_counts()
    print(counts.to_string())

    usable = [c for c in counts.index if counts[c] >= MIN_PER_CLASS]
    skipped = [c for c in counts.index if counts[c] < MIN_PER_CLASS]
    if skipped:
        print(f"\n  ⚠️ ข้ามประเภทที่ตัวอย่างน้อยกว่า {MIN_PER_CLASS}: {skipped}")
        print("     ค่าสัมประสิทธิ์จากตัวอย่างน้อยเกินไปไม่มีความหมาย ให้ติดป้ายเพิ่ม")
    if not usable:
        sys.exit("ยังไม่มีประเภทไหนมีตัวอย่างพอ — ติดป้ายเพิ่มก่อน")

    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import classification_report
    except ImportError:
        sys.exit("ต้องมี scikit-learn: venv/Scripts/python.exe -m pip install scikit-learn")

    X = df[FEATURES].astype(float).copy()
    for c in COUNTS:                       # log1p ให้ค่าที่เป็นจำนวนไม่ครอบงำ coefficient
        X[c] = np.log1p(X[c])
    mu, sd = X.mean(), X.std().replace(0, 1)
    Xs = (X - mu) / sd

    print("\n" + "=" * 78)
    print("สมการต่อประเภท — logistic regression (one-vs-rest)")
    print("=" * 78)
    hand = ep.ATTACK_TYPE_WEIGHTS
    for t in usable:
        y = (df["y"] == t).astype(int)
        if y.sum() < MIN_PER_CLASS or (1 - y).sum() < 5:
            continue
        m = LogisticRegression(max_iter=2000, class_weight="balanced").fit(Xs, y)
        coef = pd.Series(m.coef_[0], index=FEATURES).sort_values(key=abs, ascending=False)
        print(f"\n■ {t}   (n={int(y.sum())} จาก {len(y)})")
        print(f"   b0 = {m.intercept_[0]:+.3f}")
        print(f"   {'ตัวแปร':<24}{'b':>9}{'odds ratio':>13}   น้ำหนักที่ตั้งเอง")
        print("   " + "-" * 68)
        for k, v in coef.head(8).items():
            orr = math.exp(v)
            hw = hand.get(t, {}).get(k)
            mark = "" if hw is None else f"{hw:+d}"
            flag = ""
            if hw is not None and ((hw > 0) != (v > 0)):
                flag = "  ⚠️ คนละทิศกับที่ตั้งไว้"
            print(f"   {k:<24}{v:>+9.3f}{orr:>13.2f}   {mark:>6}{flag}")

    # ---- รายงานความแม่น: ชุด A เท่านั้น ----
    print("\n" + "=" * 78)
    print("ความแม่นของกฎที่ใช้อยู่ตอนนี้ — วัดบนชุด A (สุ่มล้วน) เท่านั้น")
    print("=" * 78)
    a = df[df["_sheet"] == "A"]
    if a.empty:
        print("  ยังไม่มี label จากชุด A")
        return
    pred = [ep.classify_attack_type(r)["attack_type"]
            for r in a[list(ep.ATTACK_EVIDENCE)].to_dict("records")]
    print(f"  n = {len(a)}")
    print(classification_report(a["y"], pred, zero_division=0))
    print("  ⚠️ ห้ามเอาชุด B มารวมในตัวเลขนี้ — B ถูกคัดมาให้แยกง่าย ตัวเลขจะสวยเกินจริง")


if __name__ == "__main__":
    main()
