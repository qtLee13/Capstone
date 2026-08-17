# ตอบทีม Dashboard (รอบ 2) — `/model/info` เขียนเสร็จแล้ว + เรื่อง connection refused

**จาก:** ทีม AI Server (10.22.1.94) · **วันที่:** 2026-07-20

ขอบคุณที่ยืนยันทั้ง 3 ข้อครับ สรุปที่ตกลงกัน: **retrain = Stage 2 เท่านั้น · ใช้ Path A (email_hash) · ขั้นต่ำ 50 label**

---

## 1. เรื่อง `.94:8000/health` ต่อไม่ติด — **แก้แล้ว service ขึ้นแล้ว** ✅

สาเหตุคือ **service ไม่ได้รันอยู่จริงตอนนั้น** (VM ปิด) ไม่ใช่ firewall หรือ port
`ping` ผ่านเพราะ ZeroTier ทำงาน แต่ไม่มี process ฟัง port 8000 → connection refused
(ถ้าเป็น firewall จะได้ timeout แทน — ใช้แยกอาการได้)

**ตอนนี้ service รันแล้ว ทดสอบได้เลย** · port **8000** เหมือนเดิม ไม่เปลี่ยน

---

## 2. `GET /model/info` — **deploy ขึ้น production แล้ว พร้อมใช้** ✅

ยืนยันจากการยิงจริง: `200` เมื่อใส่ token ถูก, `403` เมื่อ token ผิด, โมเดลโหลดครบทั้ง 2 stage
เอาไปแทน mock data ใน `AiModelPage.jsx` / `ItDashboard.jsx` ได้ทันที

```bash
curl -H "X-Security-Token: <API_SECRET_KEY>" http://10.22.1.94:8000/model/info
```

### Request
```
GET http://10.22.1.94:8000/model/info
Header: X-Security-Token: <API_SECRET_KEY เดียวกับที่ใช้กับ /dashboard, /logs>
```

### HTTP status ที่ต้อง handle
| กรณี | status |
|---|---|
| สำเร็จ | `200` |
| **ไม่ใส่ header** `X-Security-Token` | **`401`** |
| ใส่ token ผิด | `403` |

> หมายเหตุ: ไม่ใส่ header ได้ 401 (ไม่ใช่ 403) — เป็นพฤติกรรมเดียวกับ `/dashboard` และ `/logs` ที่ใช้อยู่แล้ว

### Response ตัวอย่างจริง (ตัดมาบางส่วน)
```jsonc
{
  "stage1": {
    "name": "phishing_bert_model_v3",
    "type": "bert-base-multilingual-cased (mBERT)",
    "task": "phishing vs legitimate",
    "deployed_at": "2026-07-17",
    "languages": ["en", "th"],
    "previous_version": "phishing_bert_model_v2 (bert-base-uncased, English only)",
    "evaluations": {
      "english": { "dataset":"held-out English 3,000 (excluded from v3 training)",
                   "n_test":3000, "accuracy":0.998, "precision":0.9987, "recall":0.9975,
                   "f1":0.9981, "fp_rate":0.0014, "inference_ms":12.07 },
      "thai":    { "dataset":"held-out Thai 800 (400 legit / 400 phishing, machine-translated NLLB-200)",
                   "n_test":800,  "accuracy":0.9363, "precision":0.9373, "recall":0.935,
                   "f1":0.9362, "fp_rate":0.0625, "inference_ms":10.83 }
    },
    "improvement_note": "ก่อนหน้านี้ (v2) ภาษาไทย accuracy 0.7488 fp_rate 0.4775 — อ่านไทยไม่ออก",
    "caveats": [ "...ชุดทดสอบไทยเป็นข้อความแปลด้วยเครื่อง...", "..." ],
    "model_path": "phishing_bert_model_v3",
    "loaded": true,
    "file_updated_at": "2026-07-17T08:10:01Z"
  },
  "stage2": {
    "name": "xgboost_type_classifier",
    "type": "XGBoost",
    "trained_at": "2026-07-17",
    "n_train_total": 952,
    "classes": ["Business Email Compromise (BEC)","Malware Attachment","Phishing","Spam (High-Risk Source)"],
    "features": ["ai_score","link_risk","abuseipdb_score","dmarc_fail","reply_to_mismatch","attachment_risk"],
    "evaluations": {
      "holdout": { "n_train":761, "n_test":191, "accuracy":0.712, "macro_f1":0.663,
                   "per_class_f1": { "Spam (High-Risk Source)":0.80, "Malware Attachment":0.75,
                                     "Phishing":0.62, "Business Email Compromise (BEC)":0.48 } },
      "cross_validation": { "weighted_f1":0.6891, "weighted_f1_std":0.028, "macro_f1":0.6566 }
    },
    "inference_ms": 0.52,
    "class_support": { "Spam (High-Risk Source)":500, "Phishing":300,
                       "Business Email Compromise (BEC)":126, "Malware Attachment":26 },
    "caveats": [ "BEC F1 = 0.48 ยังอ่อนที่สุด...", "Malware มีตัวอย่างเทรนแค่ 26 ฉบับ...", "..." ],
    "loaded": true,
    "file_updated_at": "2026-07-17T08:17:05Z"
  },
  "server_time": "2026-07-20T...Z",
  "retrain_supported": { "stage1": false, "stage2": false, "note": "..." }
}
```

### จุดที่อยากให้ UI ใช้ประโยชน์
- **`caveats[]`** — เป็น array ข้อความไทย ใส่ไว้ให้เอาไปแสดงเป็นหมายเหตุ/tooltip ใต้ตัวเลขได้เลย ตรงกับที่ตกลงกันว่าจะไม่โชว์ตัวเลขแบบปัดสวย
- **`class_support`** — จำนวนตัวอย่างที่เทรนต่อคลาส เอาไปโชว์คู่กับ F1 ได้ จะเห็นชัดว่าทำไม Malware (26 ฉบับ) ถึงต้องอ่านด้วยความระวัง
- **`loaded`** — ถ้าเป็น `false` แปลว่าโมเดลโหลดไม่สำเร็จบน server → UI ควรขึ้นเตือน ไม่ใช่โชว์ metric เฉยๆ
- **`retrain_supported`** — ตอนนี้ `stage2: false` เพราะ endpoint retrain ยังไม่ deploy · เมื่อพร้อมจะเปลี่ยนเป็น `true` **ให้ UI ใช้ค่านี้เปิด/ปิดปุ่ม retrain แทนการ hardcode** จะได้ไม่ต้องแก้โค้ดฝั่งคุณตอนเราเปิดใช้
- **`file_updated_at`** — เวลาไฟล์โมเดลจริงบนดิสก์ ใช้ยืนยันว่า server กำลังรันโมเดลตัวไหน (เผื่อ deploy แล้วลืม restart)

> ตัวเลข metric ทั้งหมดอ่านจากไฟล์ `model_metrics.json` บน server ไม่ได้ hardcode ในโค้ด → ตอน retrain/deploy โมเดลใหม่ ตัวเลขจะอัปเดตเอง ฝั่ง Dashboard ไม่ต้องแก้อะไร

---

## 2.5 ⚠️ แจ้งบั๊กที่เพิ่งแก้ — ถ้าเคยทดสอบ `/analyze` ด้วยอีเมลภาษาไทย ผลก่อนหน้านี้ใช้ไม่ได้

ระหว่างทดสอบ end-to-end เจอบั๊กในตัว parse อีเมลของ `/analyze`:
เนื้อความ **ภาษาไทย (และภาษาอื่นที่ไม่ใช่ ASCII)** ถูกแปลงเป็นข้อความหนี `สว...` ก่อนถึงโมเดล
→ โมเดลไม่เคยเห็นภาษาไทยจริงเลย → **อีเมลไทยปกติถูกตีเป็นภัย**

| อีเมลทดสอบ | ก่อนแก้ | หลังแก้ (ยืนยันบน production แล้ว) |
|---|---|---|
| ไทย — นัดประชุมทีม (ปกติ) | `ai_score 98.81` → Phishing ❌ | **`ai_score 0.12` → Normal** ✅ |
| ไทย — แจ้งบัญชีถูกระงับ (phishing) | 99.91 | 99.32 → BEC ✅ |
| อังกฤษ — phishing | 100.0 | 100.0 → Spam ✅ |

**แก้แล้วและ deploy ขึ้น production เรียบร้อย** (สาเหตุ: parse อีเมลจาก string แทน bytes — ตอนนี้เปลี่ยนเป็น bytes แล้ว)

**สิ่งที่ทีม Dashboard ควรทำ:**
- ถ้าเคยเก็บผลทดสอบอีเมลไทยไว้ก่อนหน้านี้ → **ทิ้งแล้วทดสอบใหม่**
- ตัวเลขภาษาไทยใน `/model/info` (accuracy 0.9363) เป็นค่าระดับโมเดล — **ตอนนี้ production ส่งผลตรงกับค่านี้แล้วจริง** (ก่อนแก้ไม่ตรง)

---

## 3. ขั้นตอนถัดไป

| งาน | ผู้รับผิดชอบ | สถานะ |
|---|---|---|
| `/model/info` | .94 | ✅ **deploy แล้ว ใช้งานได้ทันที** |
| เพิ่มคอลัมน์ `email_hash` ใน `email_logs` + ประสาน Gateway | Dashboard | ⏳ กำลังทำ |
| `/model/feedback-label` (รับ flag ตาม Path A) | .94 | ⏸️ รอ `email_hash` พร้อมฝั่ง Dashboard |
| `/model/retrain` + `/status` (Stage 2) | .94 | ⏸️ รอข้อมูล label ครบ 50 |
| `/model/history` + `/model/activate` (rollback) | .94 | 💤 ทำได้เลยเมื่อต้องการ — backup มีอยู่แล้ว บอกได้ถ้าจะเริ่มออกแบบปุ่ม rollback |

**หมายเหตุเรื่อง `email_hash`:** ค่านี้ .94 ส่งไปใน `raw_signals` ของ `/analyze` ทุกฉบับอยู่แล้ว (field ชื่อ `email_hash`) — ฝั่ง Gateway แค่ต้องบันทึกต่อลง DB ไม่ต้องคำนวณเอง
มันคือ SHA-256 ของเนื้อความอีเมลที่ normalize แล้ว → **อีเมลฉบับเดียวกันจะได้ค่าเดิมเสมอ** ใช้ join ข้ามระบบได้ปลอดภัย

ขอบคุณที่ทำงานละเอียดครับ 🙏
