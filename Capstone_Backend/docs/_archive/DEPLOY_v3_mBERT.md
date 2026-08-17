# Deploy Runbook — mBERT v3 (P7 ภาษาไทย) + fixes ค้าง

> ใช้ตอน VM กลับมา online · ต้องขึ้น **ทั้งชุดพร้อมกัน** ไม่งั้น ai_score skew
> ปลายทาง: `ford@AI-Server-VM2` (Remote-SSH 192.168.56.101) → `/home/ford/ai_project`
> เตรียมไว้ 2026-07-17 (ยัง scp ไม่ได้เพราะ VM ไม่ได้รัน)

---

## 0. เช็คก่อนว่า VM ต่อได้
```bash
ssh ford@AI-Server-VM2 "echo ok && ls /home/ford/ai_project"
```

## 1. scp ไฟล์ (รันจาก c:/Users/acer/Documents/CapStoneG10/Capstone_Backend)

```bash
DEST=ford@AI-Server-VM2:/home/ford/ai_project

# Stage 1 mBERT (โฟลเดอร์ 682MB — นานสุด)
scp -r phishing_bert_model_v3            $DEST/

# Stage 2 (retrain ด้วย mBERT ai_score — ต้องคู่ v3 เสมอ)
scp xgboost_type_classifier.json         $DEST/
scp label_encoder.pkl                    $DEST/

# โค้ด serve
scp main.py                              $DEST/
scp email_preprocess.py                  $DEST/     # ⚠️ ไฟล์ใหม่ ถ้าลืม = ImportError ตอน start
scp risk_score.py                        $DEST/
scp model_metrics.json                   $DEST/     # ⚠️ ไฟล์ใหม่ ป้อน GET /model/info (ลืม = metrics เป็น null)
scp scripts/export_feedback_dataset.py   $DEST/scripts/
```

## 2. ❌ ห้ามทำ
- **ห้าม** `scp .env` (มี secret/API key — ค่าบน VM ถูกตั้งไว้แล้ว)
- **ห้าม** ขึ้น `phishing_bert_model_v3` แต่ลืม `xgboost_type_classifier.json`+`label_encoder.pkl` ใหม่
  → ai_score จาก mBERT จะไม่ match XGB เก่า = train/serving skew (ปัญหาที่เพิ่งแก้)

## 3. Restart service บน VM
```bash
ssh ford@AI-Server-VM2
cd /home/ford/ai_project
# ยืนยันไฟล์มาครบ
ls -d phishing_bert_model_v3 && ls email_preprocess.py xgboost_type_classifier.json label_encoder.pkl
# restart (ปรับตามที่ตั้งไว้จริง — systemd หรือ uvicorn โดยตรง)
sudo systemctl restart ai_project    # หรือ: pkill -f uvicorn; uvicorn main:app --host 0.0.0.0 --port 8000
```

## 4. Smoke test หลัง deploy
```bash
# health
curl -s http://10.22.1.94:8000/health
# ยิงอีเมลไทย -> ควรได้ raw_signals + attack_type (ต้องมี X-Security-Token)
curl -s -X POST http://10.22.1.94:8000/analyze \
  -H "X-Security-Token: $API_SECRET_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text":"Subject: บัญชีถูกระงับ\n\nกรุณายืนยันตัวตนที่ลิงก์ภายใน 24 ชม.","recipient":"test@corp.com"}'
```
คาดหวัง: `raw_ai_score` สูง (~100) สำหรับ phishing ไทย · ก่อนหน้านี้ (bert-uncased) จะได้คะแนนมั่วเพราะอ่านไทยไม่ออก

## 5. Rollback (ถ้าพัง)
```bash
# บน VM: ชี้กลับ v2 + XGB เก่า
# main.py: MODEL_PATH = "phishing_bert_model_v2"
# กู้ XGB เก่า (ชื่อ backup ฝั่ง local: xgboost_type_classifier_prev_20260717_151705.json)
```

---
## ไฟล์อ้างอิง
- ผล P7 เต็ม: `Cap Stone AI/capstone-email-security/results/P7_THAI_RESULTS.md`
- backup Stage2 เก่า (ฝั่ง local): `datasets/stage2/_prev_v2bert_20260717_151650/`, `xgboost_type_classifier_prev_*.json`
