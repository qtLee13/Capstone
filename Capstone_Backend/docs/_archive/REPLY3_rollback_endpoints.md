# ตอบทีม Dashboard (รอบ 3) — `/model/history` + `/model/activate` (rollback) เสร็จแล้ว

**จาก:** ทีม AI Server (10.22.1.94) · **วันที่:** 2026-07-20

รับทราบความคืบหน้า Path A ครับ (คอลัมน์ `email_hash` + proxy พร้อมแล้ว รอ Gateway เขียนค่า)
ระหว่างรอ ทำ **rollback endpoints ให้เสร็จแล้ว** ตามที่ขอ — ทดสอบครบทุกเส้นทางแล้ว รอ deploy

---

## ⚠️ อ่านก่อน: rollback ของระบบนี้ไม่ใช่แค่ "สลับไฟล์"

โมเดล Stage 2 **ผูกกับ Stage 1** เพราะ feature ตัวแรกของมันคือ `ai_score` ที่ออกมาจาก BERT
→ ถ้าเอาโมเดล Stage 2 ที่เทรนคู่กับ BERT ตัวเก่า มาใช้กับ BERT ตัวปัจจุบัน **feature จะเพี้ยน (train/serving skew)** ผลลัพธ์จะมั่วโดยไม่มี error ใดๆ ให้เห็น

เราจึงใส่ **ตัวกันไว้ใน API**: ถ้าเวอร์ชันที่จะสลับไปไม่ตรงกับ Stage 1 ที่ใช้อยู่ → **ตอบ `409` ไม่ยอมสลับ** เว้นแต่ส่ง `force: true`

### 🔴 สถานะจริงตอนนี้ (สำคัญกับการออกแบบ UI)
ตอนนี้มี Stage 2 อยู่ **2 เวอร์ชัน** และ **ตัวเก่าใช้ rollback แบบปลอดภัยไม่ได้**:

| เวอร์ชัน | เทรนเมื่อ | คู่กับ Stage 1 | สลับได้ไหม |
|---|---|---|---|
| `xgb_20260717_151705` | 2026-07-17 | `phishing_bert_model_v3` (mBERT) | ✅ ใช้งานอยู่ |
| `xgb_20260716_142700` | 2026-07-16 | `phishing_bert_model_v2` (อังกฤษล้วน) | ⚠️ ต้อง `force` เท่านั้น |

→ **แปลว่าตอนนี้ปุ่ม rollback จะยังไม่มีปลายทางที่ปลอดภัยให้กด** จนกว่าจะมีการ retrain Stage 2 รอบใหม่ (ซึ่งจะเทรนคู่กับ mBERT v3 → ย้อนกลับได้อย่างปลอดภัย)
UI ควรรองรับสภาพนี้ เช่น disable ปุ่มพร้อมข้อความ *"ยังไม่มีเวอร์ชันก่อนหน้าที่เข้ากันได้"*

---

## 1. `GET /model/history`

```
GET http://10.22.1.94:8000/model/history
Header: X-Security-Token: <API_SECRET_KEY>
```

```jsonc
{
  "stage1_active": "phishing_bert_model_v3",
  "stage2_active": "xgb_20260717_151705",
  "versions": [
    {
      "version": "xgb_20260717_151705",
      "active": true,
      "trained_at": "2026-07-17T15:17:05",
      "trained_with_stage1": "phishing_bert_model_v3",
      "n_train": 952,
      "note": "retrain ด้วย ai_score จาก mBERT v3 (รองรับไทย) — ตัวที่ใช้งานอยู่",
      "metrics": { "accuracy":0.712, "macro_f1":0.663, "weighted_f1_cv":0.6891,
                   "per_class_f1": { "Spam (High-Risk Source)":0.8, "Malware Attachment":0.75,
                                     "Phishing":0.62, "Business Email Compromise (BEC)":0.48 } },
      "files_available": true,
      "compatible_with_active_stage1": true,
      "activatable": false,          // false เพราะเป็นตัวที่ใช้อยู่แล้ว
      "warning": null
    },
    {
      "version": "xgb_20260716_142700",
      "active": false,
      "trained_at": "2026-07-16T14:27:00",
      "trained_with_stage1": "phishing_bert_model_v2",
      "n_train": 919,
      "metrics": null,
      "metrics_note": "ไม่ระบุตัวเลข เพราะวัดบน feature ที่ ai_score มาจาก BERT คนละตัว เทียบตรงๆ ไม่ได้",
      "files_available": true,
      "compatible_with_active_stage1": false,
      "activatable": true,
      "warning": "โมเดลนี้เทรนคู่กับ Stage 1 'phishing_bert_model_v2' แต่ตอนนี้ระบบใช้ 'phishing_bert_model_v3' — ai_score จะไม่ตรงกับตอนเทรน (train/serving skew) ต้องส่ง force=true ถึงจะสลับได้"
    }
  ]
}
```
เรียงจากใหม่ → เก่า

**ฟิลด์ที่อยากให้ UI ใช้:**
| ฟิลด์ | ใช้ทำอะไร |
|---|---|
| `activatable` | เปิด/ปิดปุ่ม "ย้อนกลับ" ของแต่ละแถว |
| `compatible_with_active_stage1` | `false` → แสดงไอคอนเตือนสีส้ม ไม่ใช่ปุ่มปกติ |
| `warning` | ข้อความไทยพร้อมใช้ ใส่ใน tooltip / dialog ยืนยันได้เลย |
| `metrics` = `null` | อย่าโชว์ช่องว่าง ให้แสดง `metrics_note` แทน |
| `files_available` | `false` = ไฟล์หายจากดิสก์ ต้องเทาไว้ |

---

## 2. `POST /model/activate`

```
POST http://10.22.1.94:8000/model/activate
Header: X-Security-Token: <API_SECRET_KEY>
Body:   { "version": "xgb_20260716_142700", "force": false }
```

### สำเร็จ `200`
```json
{
  "status": "activated",
  "active": "xgb_20260716_142700",
  "previous": "xgb_20260717_151705",
  "classes": ["Business Email Compromise (BEC)","Malware Attachment","Phishing","Spam (High-Risk Source)"],
  "cache_cleared": 143,
  "forced": true,
  "warning": "สลับแบบ force ทั้งที่ไม่ตรงกับ Stage 1 ..."
}
```

### status ทั้งหมดที่ต้อง handle
| status | ความหมาย | UI ควรทำ |
|---|---|---|
| `200` `status: activated` | สลับสำเร็จ | refresh หน้า + โชว์ toast |
| `200` `status: unchanged` | เวอร์ชันนี้ใช้อยู่แล้ว | ไม่ต้องทำอะไร |
| **`409`** `error: stage1_mismatch` | ไม่เข้ากับ Stage 1 ปัจจุบัน | **เปิด dialog ยืนยัน** แล้วยิงซ้ำด้วย `force: true` |
| `409` (ข้อความไฟล์หาย) | ไฟล์โมเดลหายจากดิสก์ | แจ้ง error ติดต่อทีม .94 |
| `404` | ไม่มีเวอร์ชันนี้ | แจ้ง error |
| `500` | สลับล้มเหลว (โมเดลเดิมยังทำงานอยู่) | แจ้ง error |

body ของ `409 stage1_mismatch`:
```json
{ "detail": { "error":"stage1_mismatch",
              "message":"เวอร์ชันนี้เทรนคู่กับ Stage 1 '...' แต่ระบบใช้ '...' อยู่ — ...",
              "requires":"force=true" } }
```
→ เอา `detail.message` ไปแสดงใน dialog ได้ตรงๆ

**ข้อเสนอเรื่อง UX:** dialog ยืนยันควรเขียนชัดว่า *"โมเดลนี้ไม่ได้เทรนคู่กับตัวคัดกรองปัจจุบัน ผลการจำแนกประเภทภัยอาจผิดพลาด"* ไม่ใช่แค่ "ยืนยันหรือไม่" — เพราะผลเสียมองไม่เห็นทันที (ไม่มี error ระบบ แต่จำแนกผิด)

---

## 3. รายละเอียดที่ควรรู้

- **เร็วมาก** — สลับเสร็จไม่ถึง 1 วินาที (แค่โหลดไฟล์ 1.3 MB) ไม่ต้องทำ polling
- **ล้าง cache อัตโนมัติ** — ระบบมี L1 cache เก็บผลวิเคราะห์ ถ้าไม่ล้างจะคืนคำตอบที่คิดด้วยโมเดลเก่า → เราล้างให้ทุกครั้งที่สลับ (`cache_cleared` บอกจำนวนที่ล้าง) **ผลมีทันทีกับอีเมลฉบับถัดไป**
- **ปลอดภัยต่อ request ที่กำลังวิ่ง** — มี lock กันสลับกลางคัน
- **`/model/info` อัปเดตตาม** — หลังสลับ ตัวเลข metric ที่ `/model/info` จะเปลี่ยนเป็นของเวอร์ชันใหม่ทันที (มีฟิลด์ `stage2.active_version` บอกกำกับ) ไม่ต้องกลัวโชว์เลขผิดรุ่น
- **rollback ได้เฉพาะ Stage 2** — Stage 1 (BERT) ไม่เปิดให้สลับผ่าน API โดยตั้งใจ เพราะการเปลี่ยน Stage 1 ต้องเปลี่ยน Stage 2 คู่กันเสมอ ถ้าต้องย้อน Stage 1 จริงๆ ให้แจ้งทีม .94 ทำเป็น deploy คู่

---

## 4. สถานะงานรวม

| งาน | สถานะ |
|---|---|
| `GET /model/info` | ✅ deploy แล้ว ใช้งานได้ |
| `GET /model/history` | ✅ เขียนเสร็จ + เทสต์แล้ว · ⏳ รอ deploy |
| `POST /model/activate` | ✅ เขียนเสร็จ + เทสต์แล้ว · ⏳ รอ deploy |
| `POST /model/feedback-label` | ⏸️ รอ Gateway เขียน `email_hash` ลง DB |
| `POST /model/retrain` + status | ⏸️ รอมี label ครบ 50 |

จะแจ้งอีกครั้งเมื่อ deploy `/model/history` + `/model/activate` ขึ้น production เรียบร้อยครับ
