# ตอบทีม Dashboard (10.22.1.181) — เรื่อง endpoint "Retrain model"

**จาก:** ทีม AI Server (10.22.1.94)
**วันที่:** 2026-07-20

ขอบคุณที่ถามมาก่อนเปิดปุ่มจริงครับ — **ดีมากที่ยังไม่เปิด** เพราะมี 3 เรื่องที่ต้องตกลงกันก่อน ไม่งั้นปุ่มจะพังหรือทำให้โมเดลแย่ลง

---

## ⚠️ สรุปสถานะตรงๆ ก่อน (สำคัญที่สุด อ่านส่วนนี้ก่อน)

### 1. ตอนนี้ยังไม่มี endpoint `/model/*` เลยสักตัว
ที่ .94 มีอยู่ตอนนี้: `/health`, `/analyze`, `/dashboard`, `/logs`, `/feedback` — **ทั้ง 5 ข้อที่ขอมาต้องสร้างใหม่ทั้งหมด**

### 2. "Retrain" ไม่ใช่ปุ่มเดียว — ระบบมี 2 stage ที่คนละโลกกันสิ้นเชิง

| | Stage 1 (BERT คัดกรอง phishing) | Stage 2 (XGBoost แยกชนิดภัย) |
|---|---|---|
| เวลาเทรน | **45–60 นาที บน GPU (RTX 3070)** | **0.25 วินาที** |
| ต้องใช้ GPU | **ใช่** | ไม่ต้อง |
| เทรนบน VM .94 ได้ไหม | ❌ **ไม่ได้** — VM ไม่มี GPU บน CPU จะกินเวลา **หลายชั่วโมงถึงเป็นวัน** และ RAM อาจไม่พอ | ✅ ได้สบาย |
| เหมาะเป็นปุ่มใน UI ไหม | ❌ ไม่เหมาะ | ✅ เหมาะมาก |

**ข้อเสนอ:** ปุ่ม "Retrain model" ใน UI ควรหมายถึง **Stage 2 เท่านั้น** ส่วน Stage 1 (BERT) เป็นงาน offline ที่ทำบนเครื่อง GPU แล้ว deploy ขึ้นมาเป็นรอบๆ (ทำไปแล้ว 3 เวอร์ชัน: v1 → v2 → v3=mBERT รองรับไทย)

> ถ้า UI จำเป็นต้องมีปุ่มเดียว แนะนำให้เขียนป้ายว่า **"Retrain attack-type classifier"** จะได้ไม่เข้าใจผิดว่ากดแล้วเทรน BERT ใหม่ทั้งตัว

### 3. ข้อมูล labeled สำหรับ retrain **ยังไม่พร้อม** — DB เก็บ feature ไม่ครบ
โมเดล Stage 2 ใช้ **6 features** แต่ตาราง `email_logs` เก็บมาแค่ 2:

| feature ที่โมเดลต้องใช้ | มีใน DB ไหม |
|---|---|
| `ai_score` | ✅ มี |
| `link_risk` | ✅ มี |
| `abuseipdb_score` | ❌ **ไม่มี** |
| `dmarc_fail` | ❌ **ไม่มี** |
| `reply_to_mismatch` | ❌ **ไม่มี** |
| `attachment_risk` | ❌ **ไม่มี** |
| เนื้อความอีเมล (สำหรับ Stage 1) | ❌ **ไม่มี** |

→ **ถ้าดึงจาก DB ตอนนี้ retrain ไม่ได้** ต้องแก้อย่างใดอย่างหนึ่งก่อน (ดูข้อ 4)

---

## ตอบทีละข้อ

### 1️⃣ Endpoint สั่ง retrain
เห็นด้วยกับ async ครับ เสนอสัญญาแบบนี้:

```
POST /model/retrain          Header: X-Security-Token
body (ทุก field optional):
{
  "stage": 2,                  // ตอนนี้รองรับแค่ 2 (Stage 1 ต้องทำ offline บน GPU)
  "date_from": "2026-06-01",   // ช่วงข้อมูลที่ใช้เทรน
  "date_to":   "2026-07-20",
  "min_samples": 50,           // กันเทรนด้วยข้อมูลน้อยเกินจนโมเดลแย่ลง
  "dry_run": false             // true = เทรนแล้ววัดผล แต่ยังไม่สลับใช้จริง
}

202 Accepted → {"job_id":"rt_20260720_143000","stage":2,"state":"queued","started_at":"..."}
409 Conflict → {"detail":"retrain already running","job_id":"..."}   // ตามที่ขอมาครับ
400 Bad Request → ข้อมูล labeled ไม่ถึง min_samples
```

**เรื่อง hyperparameter:** เสนอให้ **fully automatic** ครับ — ไม่เปิดให้ปรับจาก UI เพราะถ้า SOC ปรับ `max_depth`/`learning_rate` เองโดยไม่มี validation set ที่ดี มีโอกาสทำโมเดลแย่ลงมากกว่าดีขึ้น ให้ปรับได้แค่ **ช่วงวันที่** กับ **dry_run** พอ

**⭐ ขอแนะนำเพิ่ม: `dry_run` สำคัญมาก** — ให้ UI เทรนดูผลก่อน แล้วโชว์ "โมเดลใหม่ F1 = X vs ปัจจุบัน = Y" ให้ SOC กด **ยืนยัน** ค่อยสลับจริง ปลอดภัยกว่าเทรนแล้วสลับทันทีเยอะ

### 2️⃣ Endpoint เช็คสถานะ
```
GET /model/retrain/status?job_id=rt_20260720_143000
→ {
  "job_id":"...", "stage":2,
  "state":"running|succeeded|failed|awaiting_confirm",
  "progress": 0-100,
  "started_at":"...", "finished_at":null,
  "message":"training on 1,204 labeled samples",
  "metrics_new":     {"weighted_f1":0.71,"macro_f1":0.68},   // เมื่อเสร็จ
  "metrics_current": {"weighted_f1":0.69,"macro_f1":0.66},   // ของที่ใช้อยู่ ไว้เทียบ
  "error": null
}
```

**เวลาเทรนปกติ:** Stage 2 = **ไม่ถึง 1 วินาที** (ข้อมูล ~1,000 แถว) รวม overhead ดึงข้อมูล+ประเมินผลแล้ว **คาดว่า 5–20 วินาที**
→ **poll ทุก 2 วินาที พอครับ** ไม่ต้องถี่กว่านั้น และให้ timeout ที่ ~2 นาที (ถ้าเกินแปลว่ามีอะไรผิดปกติ)

### 3️⃣ Endpoint ดูข้อมูลโมเดลปัจจุบัน
```
GET /model/info
→ {
  "stage1": {"name":"phishing_bert_model_v3","type":"bert-base-multilingual-cased",
             "deployed_at":"2026-07-17","languages":["en","th"],
             "metrics":{...}},
  "stage2": {"name":"xgboost_type_classifier","type":"XGBoost",
             "trained_at":"2026-07-17T15:17:05","n_train":952,
             "classes":["BEC","Malware Attachment","Phishing","Spam (High-Risk Source)"],
             "metrics":{...}}
}
```

**📌 ตัวเลขจริงล่าสุด — เอาไปแทน mock data ได้เลยตอนนี้ ไม่ต้องรอ endpoint:**

**Stage 1 — mBERT v3** (deploy 2026-07-17)
| ชุดทดสอบ | Accuracy | Precision | Recall | **FP rate** |
|---|---|---|---|---|
| English (held-out 3,000) | **99.80%** | 0.9987 | 0.9975 | **0.14%** |
| ไทย (held-out 800) | **93.63%** | 0.937 | 0.935 | **6.25%** |

*ก่อนหน้านี้ (v2 อังกฤษล้วน) ภาษาไทยได้ acc 74.9% และ FP rate 47.75% — อ่านไทยไม่ออก*
*ความเร็ว ~11–12 ms/อีเมล*

**Stage 2 — XGBoost** (retrain 2026-07-17, 952 ตัวอย่างจริง)
| Metric | ค่า |
|---|---|
| Accuracy (holdout 191) | **71.2%** |
| Macro-F1 | **0.66** |
| Weighted-F1 (5-fold CV) | **0.689 ± 0.028** |
| F1 รายคลาส | Spam 0.80 · Malware 0.75 · Phishing 0.62 · **BEC 0.48** |
| ความเร็ว | 0.5 ms/อีเมล |

> ⚠️ ขอความกรุณาอย่าโชว์ตัวเลข Stage 2 แบบปัดสวย — โดยเฉพาะ **BEC 0.48 ยังอ่อน** และ **Malware วัดจากตัวอย่างแค่ 26 ฉบับ** ถ้า UI โชว์ว่า "แม่นยำ 71%" เฉยๆ อาจทำให้ SOC เชื่อใจเกินจริง

### 4️⃣ ข้อมูลที่ใช้ retrain มาจากไหน — **ข้อนี้ต้องคุยกันมากที่สุด**

**ตอบตรงๆ: ตอนนี้ .94 ยังไม่ได้ดึง labeled data จาก DB อัตโนมัติ และดึงไปก็ retrain ไม่ได้** เพราะ DB ขาด 4 ใน 6 features (ตารางด้านบน)

ฝั่ง .94 มีกลไกเก็บข้อมูลอยู่แล้ว: เปิด env `DATASET_CAPTURE=1` แล้วทุกอีเมลที่วิเคราะห์จะถูกบันทึกลง JSONL **พร้อม features ครบ 6 ตัว + เนื้อความ + `email_hash`** และมีสคริปต์ `scripts/export_feedback_dataset.py` ที่เอา JSONL มา join กับ label ที่ analyst แก้ แล้ว export เป็นชุดเทรน

**ฟีเจอร์ "flag false negative" ของทีม Dashboard ต่อกับของเราได้ 2 ทาง — เลือกทางใดทางหนึ่ง:**

**ทาง A (แนะนำ — เร็วสุด ไม่ต้องแก้ DB):**
ให้ Dashboard ส่ง flag มาที่ .94 พร้อม **`email_hash`** ที่เราส่งไปใน `raw_signals` ตอน `/analyze`
```
POST /model/feedback-label
{ "email_hash":"a1b2c3...", "true_label":"Phishing", "is_phishing":true, "analyst":"user@corp" }
```
เรา join กลับกับ features ที่เก็บไว้เองด้วย hash → ได้ข้อมูลเทรนครบทันที
**สิ่งที่ต้องขอจากฝั่ง Dashboard:** เก็บ `email_hash` ไว้ในระบบ/DB ด้วย (ตอนนี้ Gateway ได้รับค่านี้ไปแล้วทุกฉบับ ต้องเช็คว่าถูกบันทึกต่อไหม)

**ทาง B: เพิ่มคอลัมน์ใน DB `email_logs`** — `abuseipdb_score`, `dmarc_fail`, `reply_to_mismatch`, `attachment_risk`, `email_hash` แล้วให้ฝั่งที่เขียน DB (Gateway/mail server) เขียนค่าเหล่านี้ลงไป จากนั้น .94 ดึงจาก DB ตรงๆ ได้
**ข้อดี:** สะอาดระยะยาว **ข้อเสีย:** ต้องแก้ 3 ฝั่ง (DB schema + Gateway + .94)

> **⚠️ เตือนเรื่องปริมาณข้อมูล:** ตอนนี้โมเดลเทรนจาก 952 ตัวอย่าง ถ้า SOC flag มา 10–20 ฉบับแล้วกด retrain **โมเดลแทบไม่เปลี่ยน หรืออาจแย่ลง** เพราะข้อมูลใหม่น้อยเกินและอาจเอียง (SOC flag เฉพาะเคสที่หลุด = ไม่ใช่ตัวแทนอีเมลทั้งหมด)
> **ขอเสนอ:** ปุ่ม retrain ควร **disable จนกว่าจะมี label ใหม่ ≥ 50 ฉบับ** และ UI โชว์ว่า "มี label ใหม่ 12/50 — ยังเทรนไม่ได้" จะช่วย set ความคาดหวังของ SOC ด้วย

### 5️⃣ Rollback
**ทำได้ครับ** — ระบบเก็บ backup ทุกครั้งที่เทรนอยู่แล้ว (ตอนนี้มี `xgboost_type_classifier_prev_20260717_151705.json` + `label_encoder_prev_*.pkl` และ BERT เก็บเป็นโฟลเดอร์แยกเวอร์ชัน v1/v2/v3)

เสนอ:
```
GET /model/history
→ [{"version":"xgb_20260717_151705","trained_at":"...","n_train":952,
    "metrics":{"weighted_f1":0.689},"active":true},
   {"version":"xgb_20260716_142700","trained_at":"...","n_train":919,
    "metrics":{"weighted_f1":0.663},"active":false}]

POST /model/activate   {"version":"xgb_20260716_142700"}
→ 200 {"active":"xgb_20260716_142700","previous":"xgb_20260717_151705"}
```
สลับกลับใช้เวลาไม่ถึงวินาที (แค่โหลดไฟล์ใหม่)

**แต่ทางที่ดีกว่า rollback คือกันไม่ให้พลาดตั้งแต่แรก** → ใช้ `dry_run` ตามข้อ 1 ให้ SOC เห็นตัวเลขก่อนยืนยัน จะได้ไม่ต้อง rollback บ่อย

---

## 🔧 สิ่งที่ทีม .94 ต้องทำ (ประเมินงาน)

| งาน | สถานะ |
|---|---|
| `/model/info` | ง่าย — ตัวเลขมีครบแล้ว ทำได้ก่อนเลย |
| `/model/history` + `/model/activate` | ง่าย — backup มีอยู่แล้ว |
| `/model/retrain` + `/status` (Stage 2) | ปานกลาง — ต้องทำ job runner + สถานะ |
| `/model/feedback-label` + ต่อข้อมูลจริง | **ต้องตกลงทาง A/B กับทีม Dashboard + Gateway ก่อน** |

## ❓ ขอคำตอบกลับ 3 ข้อ
1. **ปุ่ม retrain = Stage 2 อย่างเดียว** ตกลงไหม (Stage 1 ทำ offline บน GPU)
2. **เลือกทาง A หรือ B** สำหรับข้อมูล labeled — และถ้าเลือก A ฝั่ง Dashboard/Gateway เก็บ `email_hash` ไว้อยู่แล้วหรือยัง
3. รับได้ไหมกับ **เกณฑ์ขั้นต่ำ 50 label** ถึงจะกด retrain ได้ (กันโมเดลแย่ลง)

ตอบ 3 ข้อนี้แล้วเราเริ่มทำ endpoint ได้ทันทีครับ — `/model/info` เอาไปใช้แทน mock data ได้ก่อนเลยไม่ต้องรอ
