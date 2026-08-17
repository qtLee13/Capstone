# [ต้องแก้] ลด False-Positive อีเมล "legit-but-suspicious" ใน compute_final_score

**ถึง:** เจ้าของเครื่อง Storage/Risk Server (.92)
**จาก:** AI Server (10.22.1.94)
**สรุป:** ปรับตรรกะ `compute_final_score` — เดิมอีเมลปกติที่มีสัญญาณอ่อนตัวเดียว (Reply-To ไม่ตรง / DMARC fail) โดน Quarantine ผิด แก้แล้ววัดได้ **FP 50% → 0% โดยยังจับ threat 100%**

> โค้ดอ้างอิงที่แก้เสร็จแล้วอยู่ที่ `risk_score.py` บนเครื่อง AI — ก็อปตรรกะไปใช้บน .92 ได้เลย

---

## ปัญหา (วัดจากชุดทดสอบ 16 เคส)
อีเมล legit จริงมักมี Reply-To ต่างจาก From (newsletter, no-reply, mailing list) หรือ DMARC fail
(email forwarding) — ของเดิม `elif reply_to_mismatch or dmarc=="fail" or abuse>80: floor=65`
ดันเป็น **65 = Quarantine ทันที** จากสัญญาณอ่อนตัวเดียว → **50% ของ legit-but-suspicious โดนกักผิด**

## สิ่งที่เปลี่ยน

### 1) ค่าคงที่ (เพิ่ม/แก้)
```python
SUSPICIOUS_FLOOR     = 45    # เดิม 65  -> สัญญาณอ่อน>=2 ดันแค่ Warning
QUARANTINE_FLOOR     = 60    # ใหม่: อันตรายน่าจะจริง -> Quarantine
SUSPICIOUS_AI        = 50    # ใหม่: ai เกินนี้ = BERT มองว่าคุกคาม
AUTH_TRUST_ABUSE_MAX = 25    # ใหม่: IP สะอาด
AUTH_TRUST_AI_MAX    = 40    # ใหม่: ai ต่ำ = ไม่ใช่ phishing
# ABUSEIPDB_HIGH_THRESHOLD = 80 (เท่าเดิม)
```

### 2) ตรรกะ floor ใน compute_final_score (แทนบล็อก if/elif เดิม)
```python
if raw_link_score == 100 or has_malware:
    final_score = 100
else:
    # (②) auth trust: DMARC ผ่าน + IP สะอาด + AI ต่ำ = เชื่อได้ ไม่ดันขึ้น Quarantine
    authenticated = (dmarc_status == "pass"
                     and abuseipdb_score < AUTH_TRUST_ABUSE_MAX
                     and raw_ai_score < AUTH_TRUST_AI_MAX)
    if authenticated:
        final_score = min(final_score, LEVEL_WARNING - 1)      # อย่างมากแค่ก่อน Warning
    else:
        # (①) ต้องมีสัญญาณยืนยัน — อ่อนตัวเดียวไม่พอ
        strong_signal = abuseipdb_score > ABUSEIPDB_HIGH_THRESHOLD
        weak_signals  = int(bool(reply_to_mismatch)) + int(dmarc_status == "fail")
        if strong_signal or (raw_ai_score >= SUSPICIOUS_AI and weak_signals >= 1):
            final_score = max(final_score, QUARANTINE_FLOOR)   # BEC/phishing/IP แข็ง -> Quarantine
        elif weak_signals >= 2:
            final_score = max(final_score, SUSPICIOUS_FLOOR)   # (③) ai ต่ำ+อ่อน2 -> แค่ Warning
```

**หลักการ:** ใช้ `raw_ai_score` เป็นตัวแยก **BEC (ai สูง+สัญญาณ → Quarantine)** ออกจาก
**mailing list (ai ต่ำ+สัญญาณเท่ากัน → แค่ Warning)** — ทั้งคู่มี 2 สัญญาณอ่อนเท่ากันแต่ผลต่างกัน

## ผลที่วัดได้ (สคริปต์ `eval_legit_suspicious.py` บนเครื่อง AI)
| | ก่อน | หลัง |
|---|---|---|
| legit-but-suspicious โดน Quarantine/Block | 5/10 (50%) | **0/10 (0%)** |
| threat จับได้ (phishing/malware/BEC/spoof) | 6/6 (100%) | **6/6 (100%)** |

ตัวอย่างที่เปลี่ยน: Newsletter/SaaS/Forwarded/Marketing → Allow-Warning · Mailing list → Warning
· **BEC wire fraud ยัง Quarantine (60)** · phishing/malware ยัง Block เหมือนเดิม

## ไม่ต้องแก้
- weight, LEVEL_BLOCK/QUARANTINE/WARNING, risk_level_from_score — เท่าเดิม
- คอลัมน์ DB / payload keys — ไม่เกี่ยว (คนละเรื่องกับ NOTE_for_92.md abuseipdb rename)

## deploy
แก้ที่ไฟล์คำนวณคะแนนฝั่ง .92 แล้วรีสตาร์ท service — ควรทดสอบด้วยชุด legit-but-suspicious ซ้ำหลังแก้
