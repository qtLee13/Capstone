# -*- coding: utf-8 -*-
"""สร้างชุดให้คนติดป้าย "ประเภทการโจมตี" เพื่อเอาไป fit สมการแทนน้ำหนักที่ตั้งเอง

ทำไมต้องมี: ตอนนี้ ATTACK_TYPE_WEIGHTS ตั้งจากนิยาม + อัตราการติดที่วัดได้
  ตอบอาจารย์ได้ว่า "ตั้งจากนิยามแล้ววัดย้อนกลับ" แต่ตอบไม่ได้ว่า "ทำไมถึงเป็นเลขนี้"
  พอมี label จากคน จะ fit logistic regression ได้ -> ได้ค่าสัมประสิทธิ์ที่มาจากข้อมูลจริง

=====================================================================
การออกแบบการสุ่ม — สำคัญกว่าตัวเลขที่ได้
=====================================================================
แบ่งเป็น 2 ชุด เพราะมันตอบคนละคำถาม:

  ชุด A (สุ่มล้วน 200 ฉบับ)
    -> ใช้ตอบว่า "ประเภทไหนพบบ่อยแค่ไหนจริง ๆ" และ "โมเดลแม่นแค่ไหน"
    -> ห้ามเรียงลำดับใหม่ ห้ามคัดเลือก ไม่งั้นตัวเลขที่ได้จะไม่ใช่ของจริง

  ชุด B (คัดให้ครบประเภท 200 ฉบับ)
    -> ใช้ตอบว่า "หน้าตาของแต่ละประเภทเป็นยังไง" เพราะบางประเภทหายากมาก
       ถ้าสุ่มล้วนอาจได้ BEC แค่ 2-3 ฉบับ ซึ่งไม่พอ fit อะไรเลย
    -> ⚠️ ชุดนี้ "เอียงโดยตั้งใจ" ห้ามเอาไปคิดอัตราส่วนหรือความแม่นยำเด็ดขาด

  fit สมการ: ใช้ A + B (ยิ่งมีตัวอย่างต่อคลาสเยอะยิ่งดี)
  รายงานผล : ใช้ A อย่างเดียวเท่านั้น

⚠️ ห้าม pre-fill ช่องคำตอบด้วยผลของโมเดลเราเอง — จะกลายเป็นวนประเมินตัวเอง
   คำตอบของโมเดลเก็บแยกไว้ในไฟล์ _ai_... ที่ห้ามให้ผู้ตรวจเห็น

=====================================================================
ข้อจำกัดของชุดข้อมูลที่ต้องรู้ก่อนใช้ผล
=====================================================================
1. ชุดบริษัทเป็น spam ทั้งหมด (6,939 ฉบับ ไม่มี ham เลย)
   -> ป้าย "ไม่ใช่การโจมตี" ที่ผู้ตรวจให้ = เมลที่ถูกกักผิด ไม่ใช่กลุ่มตัวอย่างเมลปกติ
   -> สมการที่ fit ได้จะไม่รู้จักเมลปกติดีพอ ต้องขอ ham ที่มีเนื้อความเพิ่ม

2. ชุดนี้ไม่มีข้อมูลไฟล์แนบเลย -> เรียนรู้คลาส Malware ไม่ได้
   (ไม่เป็นไรนัก เพราะ Malware ตัดสินจาก attachment_risk ตามนิยามอยู่แล้ว)

3. 🔴 มีแต่ body_text (ข้อความล้วน) ไม่มี HTML ต้นฉบับ
   -> link_text_mismatch คำนวณไม่ได้ (ต้องอ่าน href จาก <a>)
   -> ห้ามใส่ตัวแปรนี้ตอน fit ไม่งั้นจะเป็น train/serving skew:
      ตอนเทรนเห็นเป็น 0 เสมอ แต่ตอนใช้งานจริงมีค่า -> สัมประสิทธิ์จะเพี้ยน
      (กับดักเดิมของโปรเจกต์ ดู STAGE2_FEATURES เรื่อง dmarc_fail)
"""
import os
import sys
import random

import re

import pandas as pd

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.chdir(HERE)
import email_preprocess as ep  # noqa: E402

OUT = os.path.join(HERE, "datasets", "pmg_dataset_for_students", "06_type_labels")
SRC = "datasets/data set form enterp/"
SEED = 20260826

# อักขระควบคุมที่ Excel เขียนไม่ได้ (ยกเว้น tab/newline/CR)
# สร้างด้วย chr() แทนการเขียน escape ในสตริง — กันตัวอักขระจริงหลุดลงไฟล์ต้นฉบับ
_ILLEGAL_CHARS = "".join(chr(c) for c in list(range(0, 9)) + [11, 12] + list(range(14, 32)))
_ILLEGAL_RE = re.compile("[" + re.escape(_ILLEGAL_CHARS) + "]")

TYPES = [
    "Phishing (ล่อไปกรอกข้อมูล/รหัสผ่าน)",
    "BEC (ปลอมเป็นคน ขอให้โอนเงิน/ทำอะไร)",
    "Spam (โฆษณา ส่งกระจาย)",
    "Malware (มีไฟล์แนบอันตราย)",
    "ไม่ใช่การโจมตี",
    "บอกไม่ได้",
]

# ตัวแปรที่คำนวณได้จากชุดนี้จริง ๆ (ไม่มี HTML -> ไม่มี link_text_mismatch)
FIT_FEATURES = [
    "spoof_display_name", "spoof_homoglyph", "spoof_lookalike", "spoof_brand",
    "spoof_brand_related", "spoof_own_org", "spoof_freemail_corp",
    "link_count", "unique_link_domains", "link_domain_ratio", "external_link_ratio",
    "has_unsubscribe", "link_login_lure", "no_links",
    "asks_credential", "has_urgency", "sender_is_free_mailer",
]


def load() -> pd.DataFrame:
    a = pd.read_csv(SRC + "Training Spam dataset_voutlook/training_ready_dataset.csv", low_memory=False)
    b = pd.read_csv(SRC + "Training Spam dataset_SMM/smm_training_ready_dataset.csv", low_memory=False)
    a["_src"], b["_src"] = "voutlook", "SMM"
    return pd.concat([a, b], ignore_index=True)


def evidence_of(row) -> dict:
    """ใช้ตัวสกัดหลักฐานตัวเดียวกับตอน serve — ห้ามคำนวณเองซ้ำ"""
    display = str(row.get("sender_display_name") or "")
    dom = str(row.get("sender_domain") or "")
    spoof = ep.detect_sender_spoofing(display, dom, str(row.get("receiver_domain") or ""))
    body = str(row.get("body_text") or "")
    return ep.attack_evidence(
        spoof_reasons=spoof["reasons"], body_text=body, sender_domain=dom,
        reply_to_mismatch=False,            # ชุดนี้ไม่มี Reply-To
        attachment_risk=False,              # ชุดนี้ไม่มีข้อมูลไฟล์แนบ
        subject=str(row.get("subject") or ""),
    )


def main():
    os.makedirs(OUT, exist_ok=True)
    df = load()
    rng = random.Random(SEED)

    ev = pd.DataFrame([evidence_of(r) for _, r in df.iterrows()], index=df.index)
    guess = [ep.classify_attack_type(e)["attack_type"] for e in ev.to_dict("records")]
    df["_guess"] = guess

    # ---- ชุด A: สุ่มล้วน ห้ามเรียงใหม่ ----
    idx_a = rng.sample(list(df.index), 200)
    sheet_a = df.loc[idx_a]

    # ---- ชุด B: คัดให้ครบประเภท (เอาที่ไม่ซ้ำกับ A) ----
    left = df.drop(index=idx_a)
    parts, per = [], 50
    for t in ("Phishing", "Business Email Compromise (BEC)", "Spam (High-Risk Source)", "Normal"):
        pool = left[left["_guess"] == t]
        take = min(per, len(pool))
        if take:
            parts.append(pool.sample(take, random_state=SEED))
    sheet_b = pd.concat(parts) if parts else left.head(0)

    def sheet(d, verdict_col):
        out = pd.DataFrame({
            "ลำดับ": range(1, len(d) + 1),
            "MailID": d["MailID"].values,
            verdict_col: "",                                  # ← ช่องที่ผู้ตรวจกรอก (ว่างเสมอ)
            "ผู้ส่ง": d["sender_domain"].values,
            "ชื่อที่แสดง": d["sender_display_name"].values,
            "เมลฟรี": d["sender_is_free_mailer"].values,
            "จำนวนลิงก์": d["link_count"].values,
            "โดเมนลิงก์ไม่ซ้ำ": d["unique_link_domains"].values,
            "หัวเรื่อง": d["subject"].astype(str).str.slice(0, 120).values,
            "เนื้อหา (800 ตัวแรก)": d["body_text"].astype(str).str.slice(0, 800).values,
        })
        return out

    a_out = sheet(sheet_a, "ประเภทที่ผู้ตรวจตัดสิน")
    b_out = sheet(sheet_b, "ประเภทที่ผู้ตรวจตัดสิน")
    a_out.to_csv(os.path.join(OUT, "sheetA_random_200.csv"), index=False, encoding="utf-8-sig")
    b_out.to_csv(os.path.join(OUT, "sheetB_enriched_200.csv"), index=False, encoding="utf-8-sig")

    # ---- ไฟล์ feature + คำตอบของโมเดล: ห้ามให้ผู้ตรวจเห็น ----
    hid = pd.concat([
        ev.loc[sheet_a.index].assign(MailID=sheet_a["MailID"].values, _sheet="A", _guess=sheet_a["_guess"].values),
        ev.loc[sheet_b.index].assign(MailID=sheet_b["MailID"].values, _sheet="B", _guess=sheet_b["_guess"].values),
    ])
    hid.to_csv(os.path.join(OUT, "_features_DO_NOT_SHOW_REVIEWER.csv"), index=False, encoding="utf-8-sig")

    # ---- Excel พร้อม dropdown ----
    try:
        from openpyxl import Workbook
        from openpyxl.worksheet.datavalidation import DataValidation
        from openpyxl.utils.dataframe import dataframe_to_rows
        wb = Workbook(); wb.remove(wb.active)
        for name, d in (("A_สุ่มล้วน", a_out), ("B_คัดให้ครบประเภท", b_out)):
            ws = wb.create_sheet(name)
            for r in dataframe_to_rows(d, index=False, header=True):
                # เนื้อเมลจริงมีอักขระควบคุมติดมาด้วย openpyxl โยน IllegalCharacterError
                # openpyxl โยน IllegalCharacterError -> ล้างก่อนเขียน ไม่งั้นไฟล์ไม่ออกเลย
                ws.append([_ILLEGAL_RE.sub(" ", v) if isinstance(v, str) else v for v in r])
            dv = DataValidation(type="list", formula1='"' + ",".join(TYPES) + '"', allow_blank=True)
            ws.add_data_validation(dv)
            dv.add(f"C2:C{len(d) + 1}")
            ws.column_dimensions["C"].width = 34
            ws.column_dimensions["I"].width = 46
            ws.column_dimensions["J"].width = 90
            ws.freeze_panes = "D2"
        wb.save(os.path.join(OUT, "type_label_worksheet.xlsx"))
        xlsx = "type_label_worksheet.xlsx"
    except Exception as e:                                    # openpyxl ไม่มีก็ยังได้ CSV
        xlsx = f"(ข้าม Excel: {e})"

    print(f"เขียนที่ {OUT}")
    print(f"  sheetA_random_200.csv     {len(a_out)} แถว  (สุ่มล้วน — ใช้รายงานผล)")
    print(f"  sheetB_enriched_200.csv   {len(b_out)} แถว  (คัดให้ครบประเภท — ห้ามใช้คิดอัตราส่วน)")
    print(f"  _features_DO_NOT_SHOW_REVIEWER.csv  {len(hid)} แถว")
    print(f"  {xlsx}")
    print(f"\nชุด B ประกอบด้วย (ตามที่ heuristic เดา ไม่ใช่คำตอบ):")
    print(sheet_b["_guess"].value_counts().to_string())
    print(f"\nตัวแปรที่จะใช้ fit ({len(FIT_FEATURES)} ตัว) — ตัด link_text_mismatch ออกเพราะชุดนี้ไม่มี HTML")


if __name__ == "__main__":
    main()
