# ถึงทีม Dashboard — ข้อมูลจริงที่ระบบมี และควรแสดงยังไง

**จาก:** ทีม AI Server (.94) · **วันที่:** 2026-08-09
**ที่มา:** ทีม Dashboard แจ้งว่า *"ตอนนี้ข้อมูลบน UI เป็นความคิดของคนเดียว อาจไม่ตรงกับข้อมูลจริงที่ทำออกมา"* — ถูกต้องครับ เราไล่โค้ดจริงใน repo ทั้ง 3 ฝั่งแล้ว เจอทั้งจุดที่ **แสดงผิด** และ **ข้อมูลดีๆ ที่มีอยู่แล้วแต่ยังไม่ได้แสดง**

> ทุกข้อในเอกสารนี้อ้างอิงโค้ดใน repo ตรงๆ ไม่ใช่ความเห็น

---

## 0. สรุปสั้นที่สุด

| | |
|---|---|
| 🔴 **แสดงผิด/ข้อมูลปลอม** | 6 จุด — ต้องแก้ก่อน (มี 2 จุดที่ทำให้ตัวเลขบนจอ**ไม่ตรงกับความจริง**) |
| 🟢 **มีข้อมูลแล้ว ยังไม่แสดง** | 7 อย่าง — แก้แค่ฝั่ง UI ไม่ต้องแตะ backend |
| 🟡 **AI ผลิตแล้วแต่ตกหล่นกลางทาง** | 7 field — ต้องแก้ `/assess` + DB ก่อน |

---

## 1. 🔴 จุดที่แสดงผิด — ต้องแก้ก่อนอย่างอื่น

### 1.1 ประเภทการโจมตีในหน้าจอ **ไม่ตรงกับที่โมเดลทำนายจริง**

`App.jsx` legend เขียนไว้ 4 ชนิด: `Phishing` · `BEC` · **`Spear Phishing`** · `Malware`

**แต่โมเดล Stage 2 ของเราทำนายได้แค่ 4 คลาสนี้เท่านั้น:**

| คลาสจริงที่โมเดลคืนมา | สัดส่วนในชุดเทรน |
|---|---|
| `Spam (High-Risk Source)` | 500 / 952 — **เจอบ่อยที่สุด** |
| `Phishing` | 300 / 952 |
| `Business Email Compromise (BEC)` | 126 / 952 |
| `Malware Attachment` | 26 / 952 |

→ **`Spear Phishing` ไม่มีอยู่จริงในระบบ** ไม่มีทางขึ้นเลยสักครั้ง (ค้างจาก mock เดิม)
→ **`Spam (High-Risk Source)` ซึ่งเจอบ่อยที่สุด กลับไม่มีใน legend**

ต้องแก้ **2 ที่ให้ตรงกัน:**
- `dashboard/src/App.jsx` — legend 4 อัน (บรรทัด ~326-343)
- `storage-risk-server/storage_server.py` — `color_map` (บรรทัด ~285) ก็มี `"Spear Phishing"` ค้างอยู่เหมือนกัน

> เพิ่มเติม: ค่า `attack_type` ที่ AI คืนได้จริงมี 5 แบบ — 4 คลาสข้างบน **+ `"Normal"`** (อีเมลที่ผ่าน fast path ไม่เข้า Stage 2)

### 1.2 กราฟ Volume — สัดส่วนสีในแท่งเป็นของปลอม

`MiniBarChart` คำนวณสัดส่วนสีจาก **ยอดรวมทั้งช่วงเวลา** แล้วเอาไปคูณกับ**ทุกแท่ง**เท่ากันหมด:

```js
const typeProportions = attackTypes.map(t => t.count / getTotalByType(attackTypes))
// ↑ ค่าเดียว ใช้กับทุกวัน
const segmentHeight = (data.phishing[i] / max) * 64 * typeProportions[typeIdx]
```

**ผลคือทุกแท่งมีสัดส่วนสีเหมือนกันเป๊ะทุกวัน** ซึ่งไม่ใช่ข้อมูลจริง — วันที่โดน Malware ล้วนกับวันที่โดน Spam ล้วนจะหน้าตาเหมือนกัน

**เลือกทางใดทางหนึ่ง:**
- **(ก) ง่ายและซื่อสัตย์:** ทำเป็นแท่ง 2 สี `total` vs `phishing` (backend ส่ง 2 ชุดนี้มาให้แล้ว) — เลิกแบ่งตามชนิด
- **(ข) ถูกต้องเต็มรูปแบบ:** ให้ backend เพิ่ม breakdown ต่อวัน (ดูข้อ 4.1) แล้วค่อยทำ stacked จริง

### 1.3 🔴 หน้า Email Logs ดึงข้อมูลมาแค่ **10 แถว**

```python
# storage_server.py
def get_email_logs(risk_level: str = "", limit: int = 10, ...)   # ← default 10
```
```js
// EmailLogs.jsx
const res = await fetch(`${API_BASE}/logs`)    // ← ไม่ส่ง limit เลย
```

→ ได้มา 10 แถว แล้ว UI เอา 10 แถวนั้นมา **แบ่งหน้า (pagination)** ทำให้ดูเหมือนมีข้อมูลเยอะแต่จริงๆ มีแค่ 10
→ **และทำให้ auto-refresh พังเงียบ:** `App.jsx` ตรวจอีเมลใหม่ด้วยการนับ `data.length` — พอมีเมลเกิน 10 ฉบับ ค่าจะค้างที่ 10 ตลอดไป **ไม่ refresh อีกเลย**

**แก้:** `fetch(`${API_BASE}/logs?limit=200`)` (เพดาน backend คือ 200) · ส่วนตัวนับอีเมลใหม่ควรใช้ `stats.emailsToday` จาก `/dashboard` แทนการนับ array

### 1.4 🔴 UI คำนวณสถานะเอง ทั้งที่ DB เก็บ "สิ่งที่เกิดขึ้นจริง" ไว้แล้ว

UI ใช้ `getScorePolicy(score)` เดาสถานะจากคะแนน แต่ DB มีคอลัมน์ **`risk_level`** ที่บันทึกไว้ว่าอีเมลฉบับนั้น**ถูกจัดการยังไงจริงๆ** (`allow` / `warning` / `quarantine` / `block`)

**ปัญหาที่ตามมา — ขอบเขตไม่ตรงกัน:**

| คะแนน | engine จริง (`risk_engine.py`) | UI (`getScorePolicy`) |
|---|---|---|
| **80 พอดี** | `>= 80` → **Block** | `> 80` → **Quarantine** ❌ |
| **60 พอดี** | `>= 60` → **Quarantine** | `> 60` → **Warning** ❌ |

→ อีเมลที่**ถูกบล็อกจริง** อาจโชว์บนจอว่า "Quarantine"
→ และถ้ามี security override ในอนาคต การเดาจากคะแนนจะยิ่งเพี้ยน

**แก้:** ใช้ `email.risk_level` ตรงๆ (มาใน `/logs` อยู่แล้ว) เลิกคำนวณเอง

### 1.5 กราฟโดนัทใช้เกณฑ์คนละชุดกับ badge สถานะ

- `riskDist` (โดนัท): `< 40` / `40–70` / `>= 70`
- badge สถานะ: `30` / `60` / `80`

**หน้าเดียวกันมี 2 มาตรฐาน** ทำให้อ่านแล้วงง — ควรใช้ **30 / 60 / 80** ให้ตรงกับ action จริงทั้งหน้า (ต้องแก้ `riskDist` ฝั่ง `storage_server.py` ด้วย)

### 1.6 ตัวเลขที่เป็น placeholder แต่แสดงเหมือนของจริง

| ที่แสดง | ความจริง |
|---|---|
| `+0% vs yesterday` | `emailsChange` backend hardcode `0` เสมอ — ไม่เคยคำนวณ |
| ช่อง `dept` ของ Most targeted users | backend ใส่ `"N/A"` ตายตัว (ไม่มีข้อมูลแผนก) |
| `API_BASE = 'http://127.0.0.1:8000'` | hardcode localhost → เปิดจากเครื่องอื่นใช้ไม่ได้ ควรใช้ env var |

**แก้:** เอาออก หรือทำให้คำนวณจริง — อย่าแสดงตัวเลขที่ไม่มีความหมาย

---

## 2. 🟢 มีข้อมูลอยู่แล้ว แค่ยังไม่ได้แสดง (แก้ UI อย่างเดียว)

`/logs` คืน **ทุกคอลัมน์ของ `email_logs`** อยู่แล้ว — ที่ยังไม่ได้ใช้:

| field | คืออะไร | ควรแสดงยังไง |
|---|---|---|
| **`risk_level`** | ผลจริงที่เกิดกับเมล | badge สถานะ (แทนการคำนวณเอง — ข้อ 1.4) |
| **`email_hash`** | ID ประจำอีเมล | ใส่ในหน้า detail + **ปุ่ม "แจ้งว่าตัดสินผิด"** (ดูข้อ 5) |
| `is_phishing` | ธงว่าเป็นภัย | ใช้ filter |
| `domain_risk` / `header_anomaly` | มีใน modal แล้ว ✅ | — |

**และ endpoint ที่ backend เปิดไว้แล้วแต่ UI ไม่เคยเรียก:**

| endpoint | ทำอะไรได้ | คุ้มค่าทำเป็นหน้า |
|---|---|---|
| `GET /logs?risk_level=quarantine` | กรองฝั่ง server | ⭐ ใช้กับ filter ที่มีอยู่ (ตอนนี้กรองใน 10 แถวที่โหลดมา) |
| `GET /mailbox/{folder}` | ดูกล่อง inbox / quarantine จริง | ⭐⭐⭐ |
| `POST /mailbox/quarantine/{file}/release` | **ปล่อยเมลที่กักผิดออกไป** | ⭐⭐⭐ งานที่ IT ต้องทำบ่อยที่สุด |
| `POST /mailbox/inbox/{file}/recall` | **ดึงเมลกลับ** ถ้าปล่อยผิด | ⭐⭐⭐ |
| `GET/POST/DELETE /rules` · `/rules/preview` | จัดการกฎ + ดูผลก่อนใช้จริง | ⭐⭐ |
| `GET /welcomelist` | รายชื่อผู้ส่งที่ไว้ใจ | ⭐⭐ |
| `GET /gateway/status` · `/gateway/quarantine` | สถานะ PMG | ⭐ |
| **AI: `GET /model/info`** | **ข้อมูลโมเดล + metric จริง** | ⭐⭐⭐ (ดูข้อ 3) |

> ⚠️ endpoint พวกนี้ **ต้องใส่ `X-Security-Token`** ต่างจาก `/dashboard` กับ `/logs` ที่เปิดโล่ง

---

## 3. 🟢 หน้าที่ยังไม่มีเลย แต่ AI เตรียมข้อมูลไว้ให้แล้ว — **หน้าโมเดล**

`GET /model/info` บน AI server (.94:8000) ทำขึ้น**เพื่อ Dashboard โดยเฉพาะ** ตั้งแต่ 2026-07-16 แต่ตอนนี้ **UI ยังไม่มีหน้านี้เลย** — ข้อมูลที่พร้อมใช้:

```jsonc
{
  "stage1": {
    "name": "phishing_bert_model_v3",
    "type": "bert-base-multilingual-cased (mBERT)",
    "languages": ["en", "th"],
    "evaluations": {
      "english": { "accuracy": 0.998, "f1": 0.9981, "n_test": 3000, "inference_ms": 12.07 },
      "thai":    { "accuracy": 0.9363, "f1": 0.9362, "n_test": 800,  "inference_ms": 10.83 }
    },
    "caveats": ["ชุดทดสอบไทยเป็นข้อความแปลด้วยเครื่อง ..."]
  },
  "stage2": {
    "type": "XGBoost", "active_version": "xgb_20260722_171012",
    "classes": [...4 คลาส...],
    "features": ["ai_score","link_risk","abuseipdb_score","reply_to_mismatch","attachment_risk"],
    "evaluations": { "holdout": {...}, "cross_validation": {...} },
    "class_support": { "Spam (High-Risk Source)": 500, "Phishing": 300, "BEC": 126, "Malware Attachment": 26 },
    "caveats": ["BEC F1 = 0.52 ยังอ่อนที่สุด ...", "Malware มีตัวอย่างจริงแค่ 26 ฉบับ ..."]
  }
}
```

**เสนอให้ทำหน้า "AI Model" แสดง:**
- ชื่อ/เวอร์ชันโมเดลที่ใช้อยู่ + เวลาที่ deploy
- ตาราง metric **แยกอังกฤษ/ไทย** (จุดขายของโปรเจกต์ — รองรับไทยจริง)
- ความเร็ว inference
- **`caveats` — ต้องแสดงด้วย** เป็นข้อจำกัดที่เรารู้ตัว การโชว์ตัวเลขสวยๆ โดยไม่บอกข้อจำกัดจะทำให้เข้าใจผิด
- `class_support` ให้เห็นว่าคลาสไหนข้อมูลน้อย (Malware 26 → ตัวเลขไม่นิ่ง)

> มี `GET /model/history` + `POST /model/activate` ด้วย — ทำหน้าสลับ/ย้อนเวอร์ชันโมเดลได้ (มีตัวกันสลับผิด schema ในตัว)

---

## 4. 🟡 ข้อมูลที่ AI ผลิตแล้ว แต่ **ตกหล่นระหว่างทาง** — ต้องแก้ backend ก่อน

AI ส่ง `raw_signals` **22 field** → Gateway forward ครบ → **แต่ `/assess` รับแค่ 16** ที่เหลือ pydantic ทิ้งเงียบๆ

| field ที่หายไป | คืออะไร | ทำไมน่าเสียดาย |
|---|---|---|
| **`message_id`** | Message-ID ของเมล | key สำหรับ dedup กัน re-ingest (คุยกันไว้แล้ว) — **`AssessRequest` ยังไม่มี field นี้ → ตกหล่นทันที** |
| **`link_confidence`** | `confirmed` / `suspicious` / `low` / `none` | แยก "VirusTotal ฟันธงว่าอันตราย" ออกจาก "แค่รูปแบบ URL น่าสงสัย" — คนละน้ำหนักกันมาก |
| **`abuseipdb_measured`** | วัด IP ได้จริงไหม | ⚠️ ถ้า `false` แล้ว `abuseipdb_score = 0` **ไม่ได้แปลว่า IP สะอาด** แต่แปลว่า *ตรวจไม่ได้* — ถ้าโชว์ 0 เฉยๆ คนอ่านจะเข้าใจผิด |
| **`has_malware`** | มีไฟล์แนบอันตราย | ธงตรงๆ ที่ควรโชว์เป็นไอคอน |
| **`auth_source`** | SPF/DKIM/DMARC มาจากไหน (`pmg`/`header`/`checkdmarc`) | บอกความน่าเชื่อถือ — ค่าจาก PMG เชื่อได้กว่า header ที่ปลอมได้ |
| `sender_email` | อีเมลผู้ส่งเต็ม | ตอนนี้ตารางโชว์แค่ `sender_domain` |

**และค่าที่ risk engine คำนวณแล้ว ส่งกลับใน response แล้ว แต่ไม่ได้เก็บลง DB:**

| field | ทำไมสำคัญ |
|---|---|
| 🔥 **`reasons`** | **สำคัญที่สุดในเอกสารนี้** — เป็นคำอธิบายว่า *"ทำไมอีเมลฉบับนี้ถึงได้คะแนนนี้"* เช่น `"SPF failed"`, `"Reply-To domain mismatch"` · engine สร้างครบแล้ว ส่งกลับใน `/assess` แล้ว **แต่ไม่มีใครเก็บ** → หน้า detail เลยบอกได้แค่ตัวเลข ไม่บอกเหตุผล |
| `attachment_risk` | 1 ใน 6 องค์ประกอบคะแนน — modal โชว์แค่ 4 |
| `language_risk` | องค์ประกอบที่ 6 (ภาษาเชิง social engineering) |

### 4.1 สิ่งที่ต้องขอจากทีม storage (.92)

```python
# 1. AssessRequest — เพิ่ม field ที่ AI ส่งมาแล้ว
message_id: str = ""
link_confidence: str = "none"
abuseipdb_measured: bool = False
has_malware: bool = False

# 2. ตาราง email_logs — เพิ่มคอลัมน์
reasons          # JSON/Text  ← สำคัญที่สุด
attachment_risk  # Float
language_risk    # Float
message_id       # String
link_confidence  # String
abuseipdb_measured # Boolean
has_malware      # Boolean

# 3. /dashboard — เพิ่ม breakdown ต่อวัน (ถ้าจะทำ stacked chart จริง ข้อ 1.2)
"volumeByType": { "labels": [...], "series": [{ "type": "Phishing", "counts": [...] }, ...] }
```

---

## 5. 🔁 เรื่องที่ Dashboard เป็นกุญแจสำคัญ — **feedback loop**

ระบบเตรียมไว้ให้เรียนรู้จากงานจริงแล้ว แต่**ติดอยู่ที่ปุ่มเดียวบน Dashboard**

```
เมลจริง → วิเคราะห์ → เก็บ feature + email_hash
                          ▼
     ⛔ เจ้าหน้าที่กดแก้ป้ายกำกับผ่าน Dashboard   ← ยังไม่มีปุ่มนี้
                          ▼
              ครบ 50 ป้าย → เทรน Stage 2 ใหม่
```

**สิ่งที่ขอ:** ในหน้า detail ของแต่ละอีเมล เพิ่มปุ่มประมาณ *"ผลนี้ไม่ถูกต้อง"* แล้วให้เลือกประเภทที่ถูก (4 คลาส หรือ Normal) → ส่ง `email_hash` + label ที่ถูกต้องกลับมา

`email_hash` **มีอยู่ใน `/logs` แล้ว** — ขาดแค่ UI กับ endpoint รับ label (ฝั่ง AI เตรียมไว้แล้ว รอ integration)

> นี่คือทางเดียวที่โมเดลจะเก่งขึ้นจากข้อมูลจริงขององค์กร โดยเฉพาะ **อีเมลไทยของเจ้าของภาษา** ที่ตอนนี้เรายังไม่มี (ข้อมูลเทรนไทยเป็นข้อความแปลด้วยเครื่อง)

---

## 6. 📋 สรุปเป็นลำดับงาน

### ทีม Dashboard (แก้ UI อย่างเดียว — ทำได้เลย)
1. 🔴 แก้ legend ประเภทภัย → ใช้ 4 คลาสจริง (เอา `Spear Phishing` ออก · ใส่ `Spam (High-Risk Source)`)
2. 🔴 `/logs?limit=200` + เลิกนับ array เพื่อ detect เมลใหม่
3. 🔴 ใช้ `risk_level` จาก DB แทนการคำนวณสถานะเอง
4. 🔴 แก้กราฟ volume (ทางเลือก ก — total vs phishing) หรือรอ backend ทำข้อ 4.1
5. 🟡 เอา `+0% vs yesterday` กับ `dept` ออก · เปลี่ยน `API_BASE` เป็น env var
6. 🟢 ทำหน้า **AI Model** จาก `/model/info` (พร้อมใช้ทันที)
7. 🟢 ทำหน้า **Quarantine** จาก `/mailbox/*` + ปุ่ม release/recall
8. 🟢 เพิ่มปุ่ม **feedback label** ในหน้า detail

### ทีม Storage (.92)
1. 🔴 เอา `"Spear Phishing"` ออกจาก `color_map` · ปรับ `riskDist` เป็น 30/60/80
2. 🟡 เพิ่ม field ที่ตกหล่นใน `AssessRequest` (ข้อ 4.1) — โดยเฉพาะ **`message_id`**
3. 🔥 **เก็บ `reasons` ลง DB** แล้วส่งออกมาใน `/logs`
4. 🟡 เพิ่ม `attachment_risk` / `language_risk` ลง DB (คำนวณอยู่แล้ว)

### ทีม AI (.94)
- ✅ `/model/info`, `/model/history`, `/model/activate` — พร้อมแล้ว
- ✅ `raw_signals` ครบ 22 field รวม `message_id` — พร้อมแล้ว
- ⏸️ endpoint รับ feedback label — ทำได้ทันทีที่ Dashboard พร้อมส่ง

---

## 7. หลักการที่ขอให้ยึด

1. **อย่าแสดงตัวเลขที่ไม่มีที่มาจริง** — placeholder ที่ดูเหมือนข้อมูลจริงอันตรายกว่าไม่แสดงเลย
2. **แสดงสิ่งที่เกิดขึ้นจริง ไม่ใช่สิ่งที่คำนวณใหม่** — `risk_level` คือความจริง ส่วนการเดาจากคะแนนคือการทายซ้ำ
3. **"วัดไม่ได้" ≠ "ปลอดภัย"** — `abuseipdb = 0` ตอนที่วัดไม่ได้ ต้องแสดงเป็น "ไม่ทราบ" ไม่ใช่ "สะอาด"
4. **คะแนนต้องมาพร้อมเหตุผล** — `reasons` ทำให้ผู้ใช้ตัดสินใจได้ว่าจะเชื่อระบบหรือไม่

มีตรงไหนอยากให้อธิบายเพิ่ม หรืออยากได้ตัวอย่าง response จริงของ endpoint ไหน บอกได้เลยครับ 🙏
