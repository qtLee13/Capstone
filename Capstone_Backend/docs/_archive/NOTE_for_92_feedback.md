# [ขอเพิ่ม] เก็บ email_hash ใน EmailLog เพื่อปิด feedback loop (dataset จริง)

**ถึง:** เจ้าของเครื่อง Storage/Risk Server (.92)
**จาก:** AI Server (10.22.1.94)
**สรุป:** AI server เพิ่ม `email_hash` ใน `raw_signals` แล้ว — ขอ `.92` **เก็บ email_hash ลง EmailLog** เพื่อให้ analyst feedback join กลับไปหา feature+text ที่ AI server capture ไว้ → ได้ dataset retrain จากอีเมลจริง

---

## ภาพรวม feedback loop
```
main.py (/analyze)  ──raw_signals(มี email_hash + 6 features + subject + body)──►  Gateway ─► .92
     │                                                                                    │
     └─(DATASET_CAPTURE=1)─► logs/dataset_capture.jsonl (feature+text ครบ, key=hash)      │
                                                                                          ▼
                                                              EmailLog (score + is_phishing + attack_type)
                                                                     ▲  analyst กด /feedback แก้ label
                                                                     │
   export_feedback_dataset.py  ◄── corrections CSV (hash, attack_type, is_phishing) จาก EmailLog
     │
     └─► datasets/feedback/feedback_stage1.csv (text,label) + feedback_stage2.csv (6feat,label)
             → append เข้าชุดเทรน แล้ว retrain
```

## สิ่งที่ `.92` ต้องทำ (เล็กน้อย)
1. **เพิ่มคอลัมน์ `email_hash` (String, index)** ใน EmailLog แล้วเก็บค่าจาก `raw_signals["email_hash"]`
2. (มีอยู่แล้ว) analyst แก้ label ผ่าน `/feedback` → `is_phishing`; ถ้าให้แก้ `attack_type` ได้ด้วยจะดีมาก
3. **export corrections** เป็น CSV ให้ AI server เป็นระยะ:
   ```sql
   SELECT email_hash AS hash, attack_type, is_phishing
   FROM email_logs
   WHERE email_hash IS NOT NULL;   -- (จะกรองเฉพาะที่ analyst ยืนยัน/แก้แล้วก็ได้)
   ```
   → ไฟล์นี้ป้อนให้ `export_feedback_dataset.py --corrections corr.csv`

## ฝั่ง AI server (ทำแล้ว)
- `raw_signals["email_hash"]` = SHA-256 ของ text ที่ sanitize แล้ว (key เดียวกับ L1 cache)
- `DATASET_CAPTURE=1` (env) → เขียน `logs/dataset_capture.jsonl` (⚠️ มีเนื้อหาอีเมลจริง = PII, ปิด default, ป้องกันไฟล์)
- `scripts/export_feedback_dataset.py` แปลง JSONL(+corrections) → training CSV

## หมายเหตุสำคัญ (คุณภาพ dataset)
- ถ้า **ไม่มี corrections** → label = โมเดลทายเอง (weak label) → **ห้าม retrain ตรงๆ** เพราะจะ reinforce ความผิดพลาด
- ควรใช้ `--only-corrected` เอาเฉพาะที่ analyst ยืนยัน → dataset คุณภาพสูง สำหรับ retrain จริง
