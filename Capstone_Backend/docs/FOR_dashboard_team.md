# ถึงทีม Dashboard — ตรวจ branch `dashboard` แล้ว + endpoint ที่รออยู่ทำเสร็จแล้ว

**จาก:** ทีม AI Server (.94) · **อัปเดต:** 2026-08-09
*(ฉบับก่อนหน้ารีวิว prototype เก่าบน `main` — ไฟล์นี้เขียนใหม่ทั้งหมดจากโค้ดจริงบน branch `dashboard`)*

---

## 0. ขอโทษเรื่องรีวิวผิดตัวครับ 🙏

ไม่ใช่ความผิดฝั่งคุณเลย — ตอนนั้นบน `main` มีแต่ prototype เก่า เราเลยรีวิวตัวนั้น
ตรวจ branch `dashboard` (`f4c67db`) แล้ว **ยืนยันว่าแก้ครบตามที่แจ้งจริงทุกข้อ** และทำเกินที่ขอไปเยอะ (role-based admin/it/soc, มี backend proxy ของตัวเอง, audit log)

**สิ่งที่ประทับใจเป็นพิเศษ:** เอา token ไว้ฝั่ง backend ไม่ให้หลุดลง browser bundle — ถูกต้องมาก 👏

---

## 1. 🎉 endpoint ที่คุณรออยู่ — **ทำเสร็จแล้ว**

ในโค้ดคุณเขียน comment ไว้ว่า:
```python
# .94 ยังไม่ deploy endpoint นี้ (รอฝั่งเรา) — เตรียม proxy ไว้ล่วงหน้า จะ 502 จนกว่าเขาจะเปิดใช้
resp = requests.post(f"{AI_API_BASE}/model/feedback-label", ...)
```

**ทำให้แล้วครับ ตรงตาม payload ที่คุณส่งมาเป๊ะ** — ไม่ต้องแก้โค้ดฝั่งคุณเลย

### Request (ตรงกับที่คุณส่งอยู่แล้ว)
```jsonc
POST http://10.22.1.94:8000/model/feedback-label
X-Security-Token: <token>

{
  "email_hash":  "9a4e3030...",              // จาก /logs
  "true_label":  "Phishing",                 // 1 ใน 5 ค่าด้านล่าง
  "is_phishing": true,
  "analyst":     "soc@corp.com"              // ที่คุณใส่ current_user["email"] มา ✅
}
```

### Response
```jsonc
{
  "status": "recorded",
  "email_hash": "9a4e3030...",
  "true_label": "Phishing",
  "db_row_updated": true,        // อัปเดตแถวใน email_logs ให้แล้ว -> refresh แล้วเห็นค่าใหม่ทันที
  "labels_total": 12,            // จำนวนครั้งที่กด (รวมแก้ซ้ำ)
  "labels_unique": 9,            // ← จำนวนอีเมลที่ไม่ซ้ำ = ตัวที่นับเข้าเกณฑ์
  "labels_required": 50,
  "ready_to_retrain": false
}
```

### ⚠️ ค่า `true_label` ที่รับได้ — มีแค่ 5 ค่านี้ (ตัวพิมพ์ต้องตรงเป๊ะ)
```
"Phishing"
"Spam (High-Risk Source)"
"Business Email Compromise (BEC)"
"Malware Attachment"
"Normal"                          ← analyst บอกว่าจริงๆ ไม่ใช่ภัย
```
ส่งค่าอื่นมาจะได้ **400** พร้อมรายการที่ถูกต้อง (เช่น ส่ง `"phishing"` ตัวเล็กก็ไม่ผ่าน)
เราตั้งใจให้เข้มงวด เพราะ label ที่พิมพ์ผิดจะปนเข้าชุดเทรนแล้ว**ไม่มีใครรู้ตัว**

> 💡 แนะนำให้ UI ใช้ **dropdown** ไม่ใช่ช่องพิมพ์ · ดึงรายการสดจาก `/model/feedback-stats` (ด้านล่าง) จะไม่มีทางหลุด

### 🆕 แถมให้: `GET /model/feedback-stats`
```jsonc
{ "labels_total": 12, "labels_unique": 9, "labels_required": 50,
  "ready_to_retrain": false,
  "valid_labels": ["Phishing", "Spam (High-Risk Source)", ..., "Normal"] }
```
**เอาไปทำ progress bar ได้เลย** — *"เก็บ label แล้ว 9/50 ฉบับ"* ให้ analyst เห็นว่าอีกเท่าไหร่จะเทรนใหม่ได้ (เป็นแรงจูงใจให้กด feedback ด้วย)

### พฤติกรรมที่ควรรู้
| กรณี | ผลลัพธ์ |
|---|---|
| กด label ซ้ำ hash เดิม (analyst เปลี่ยนใจ) | ✅ รับ · เก็บเป็นบรรทัดใหม่ (audit trail) · `labels_unique` **ไม่เพิ่ม** · ตอนเทรนใช้บรรทัดล่าสุด |
| hash ที่ยังไม่มีใน DB | ✅ รับ · `db_row_updated: false` แต่ label ถูกเก็บแล้ว |
| DB ล่ม | ✅ label ยังถูกเก็บ (ไม่หาย) · แค่ `db_row_updated: false` |
| เขียนไฟล์ไม่ได้ | ❌ **500** — จะไม่ตอบ 200 หลอกๆ ทั้งที่ไม่ได้บันทึก |

> **flag หลายฉบับพร้อมกัน** (แคมเปญเดียวส่งหลาย user) ที่คุณทำไว้ — ใช้ได้เลย ยิงทีละ hash วนไป · rate limit 120/นาที

---

## 2. ✅ `/ai/dashboard` — คุณลบออกแล้ว เรียบร้อย

เราทักไปว่า `/ai/dashboard` ชี้ไป .94 ทั้งที่เจ้าของข้อมูลคือ .92 — **คุณลบทิ้งเลยเพราะเป็น dead code ไม่มีใครเรียก** ยิ่งดีครับ 👍

เจ้าภาพข้อมูลตอนนี้ชัดเจนแล้ว:
| ข้อมูล | ดึงจาก |
|---|---|
| อีเมล/สถิติ/quarantine/rules | **.92** (เจ้าของ DB) |
| เรื่องโมเดล — `/model/info`, `/model/history`, `/model/activate`, `/model/feedback-label`, `/model/feedback-stats` | **.94** |

---

## 3. ✅ ยืนยันสิ่งที่คุณแก้ (ตรวจจาก branch `dashboard`) — ตรงตามที่แจ้งทุกข้อ

| ข้อ | สถานะที่ตรวจพบ |
|---|---|
| 1.1 legend วนจาก `attackTypes[]` ไม่ hardcode | ✅ ไม่มี `Spear Phishing` แล้ว |
| 1.2 ไม่พึ่งนับ array ฝั่ง client | ✅ backend คำนวณ stats ให้ |
| 1.3 ใช้ `risk_level`/`decision` จาก backend | ✅ ไม่เดาซ้ำฝั่ง UI |
| 1.4 กราฟ volume ไม่มี proportion ปลอม | ✅ *(stacked เต็มรูปแบบรอ `volumeByType` จาก .92 — สเปกส่งให้เขาแล้ว)* |
| 3.2 หน้า AI Model | ✅ ดึง `/model/info` + `/model/history` + `/model/activate` ครบ · แสดง metric แยก EN/TH + `caveats` + `class_support` |
| 3.3 Quarantine + release | ✅ *(ตัด recall ออกตามที่ทีมตัดสินใจ — โอเคครับ ถ้าจะเอากลับ endpoint ยังอยู่)* |
| 3.4 ปุ่ม Feedback label | ✅ ทำเผื่อทั้งเดี่ยวและหลายฉบับ — **ตอนนี้ปลายทางพร้อมแล้ว** |

---

## 4. ✅ **deploy เสร็จแล้ว — ทั้ง 2 endpoint live บน .94**

ทดสอบจริงบนเครื่อง .94 แล้ว ผ่านทั้ง 3 เคส:

```bash
# 1) label ถูกต้อง
{"status":"recorded","email_hash":"test123abcdef","true_label":"Phishing",
 "db_row_updated":false,"labels_total":1,"labels_unique":1,
 "labels_required":50,"ready_to_retrain":false}

# 2) label ปลอม -> 400 พร้อมรายการที่ถูกต้อง
{"detail":{"error":"invalid_label","message":"true_label 'Spear Phishing' ไม่ใช่คลาสที่โมเดลรู้จัก",
 "valid_labels":["Business Email Compromise (BEC)","Malware Attachment","Phishing",
                 "Spam (High-Risk Source)","Normal"]}}

# 3) stats
{"labels_total":1,"labels_unique":1,"labels_required":50,"ready_to_retrain":false,
 "valid_labels":[...5 ค่า...]}
```

**เทส end-to-end ได้เลยครับ** 🎉

---

## 5. 🔴 ถ้ายังได้ 502 อยู่ — สาเหตุน่าจะไม่ใช่ "ยังไม่ deploy"

**เพราะโค้ด proxy ฝั่งคุณแปลง error ทุกชนิดเป็น 502 หมด:**

```python
resp.raise_for_status()                       # 400/403/404 ก็ throw ตรงนี้
except requests.RequestException:
    raise HTTPException(502, "AI server unavailable")   # ← กลายเป็น 502 หมด
```

`requests.HTTPError` เป็นลูกของ `RequestException` → **403 (token ผิด) และ 400 (label ผิด) ก็ขึ้นว่า "AI server unavailable" เหมือนกัน** ทั้งที่เซิร์ฟเวอร์ตอบปกติ

### ไล่หาสาเหตุตามลำดับ (ยิงจากเครื่องที่รัน dashboard backend)

```bash
# ① .94 ตอบไหม (ไม่ต้องใช้ token)
curl -s http://10.22.1.94:8000/health
#   ไม่ตอบ  -> ปัญหาเครือข่าย/ZeroTier หรือ uvicorn ไม่ได้รัน
#   ตอบ ok  -> ไปข้อ ②

# ② endpoint มีจริงไหม (ไม่ใส่ token — ควรได้ 403 ไม่ใช่ 404)
curl -s -o /dev/null -w "%{http_code}\n" http://10.22.1.94:8000/model/feedback-stats
#   403 -> endpoint มีแล้ว ✅ ปัญหาอยู่ที่ token (ข้อ ③)
#   404 -> ยังไม่ deploy จริง (แจ้งเรา)

# ③ token ตรงไหม
curl -s http://10.22.1.94:8000/model/feedback-stats -H "X-Security-Token: $AI_API_TOKEN"
#   ได้ JSON -> ใช้ได้แล้ว
#   403     -> AI_API_TOKEN ฝั่งคุณไม่ตรงกับ .env บน .94
```

**เดาว่าน่าจะเป็นข้อ ③** — ใน `config.py` ค่า default คือ `AI_API_TOKEN = os.environ.get("AI_API_TOKEN", "")` (ว่าง) ถ้าไม่ได้ตั้ง env จริง จะส่ง token ว่างไป → **403 → คุณเห็นเป็น 502**

### 💡 ขอแนะนำให้แก้ error handling ด้วย

ตอนนี้ **analyst จะไม่มีวันรู้ว่าตัวเองส่ง label ผิด** — เพราะ 400 `invalid_label` ที่เราตั้งใจส่งรายการที่ถูกต้องกลับไป ถูกกลืนเป็น "AI server unavailable"

คุณทำถูกแล้วใน `/ai/model-activate` (เช็ค `resp.status_code == 409` แล้วส่ง detail เดิมต่อ) — เสนอให้ใช้แพตเทิร์นเดียวกัน:

```python
try:
    resp = requests.post(f"{AI_API_BASE}/model/feedback-label", ...)
except requests.RequestException:
    raise HTTPException(502, "AI server unavailable")     # เชื่อมต่อไม่ได้จริงๆ เท่านั้น

if resp.status_code == 400:      # label ไม่ถูกต้อง -> ให้ analyst เห็นรายการที่ถูก
    raise HTTPException(400, resp.json().get("detail", resp.text))
if resp.status_code == 403:      # token ผิด -> แยกออกจาก "เซิร์ฟเวอร์ล่ม"
    raise HTTPException(502, "AI token invalid — ตรวจ AI_API_TOKEN")
resp.raise_for_status()
```

> เป็นบทเรียนเดียวกับที่โปรเจกต์นี้เจอมาหลายรอบ: **error ที่ถูกกลืน อันตรายกว่า error ที่ดังชัด** — 502 บอกแค่ "พัง" แต่ไม่บอกว่าพังตรงไหน

---

## 6. หลังจากนี้

| ทีม | ค้างอะไร |
|---|---|
| **AI (.94)** | เหลือ `POST /model/retrain` ตัวเดียว — จะทำตอน `labels_unique` ใกล้ 50 |
| **Dashboard** | ไม่มีงานค้าง · แนะนำแก้ error handling (ข้อ 5) เพื่อให้ analyst เห็น error จริง |
| **Storage (.92)** | ✅ ทำครบแล้ว — เก็บ `reasons` ลง DB แล้ว **หน้า detail ดึงมาแสดงได้เลย** ว่าทำไมถึงโดนบล็อก |
| **Gateway** | ไม่มี |

> 💡 **`reasons` พร้อมใช้แล้ว** — ทีม .92 เพิ่มคอลัมน์นี้ให้แล้ว `/logs` จะมีมาด้วย
> เอาไปแสดงในหน้า detail ได้เลย เช่น *"SPF failed · Reply-To domain mismatch"* จะมีประโยชน์กับ analyst มากกว่าตัวเลขคะแนนเฉยๆ

ขอบคุณที่ทำมาเยอะขนาดนี้ครับ 🙏 เจอตรงไหนอีกบอกได้เลย
