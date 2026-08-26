# AI Server — Integration Guide (เครื่องที่ 2)

เอกสารสำหรับเพื่อนในทีมที่ต้องเชื่อมต่อกับ **AI Server (ฟอร์ด)**

> ⚠️ **ย้ายเครื่องแล้ว (2026-08)** — `10.22.1.94` (ZeroTier) **ปิดแล้ว** ยิงไปไม่มีอะไรตอบ

- **IP ปัจจุบัน:** `10.99.199.73` (LAN ของเครื่อง `ai-train`)
- **Port:** `8000`
- **Base URL:** `http://10.99.199.73:8000`
- **จากนอกวง:** port 8000 ไม่ได้ forward ออกอินเทอร์เน็ต — ระหว่างพัฒนาใช้ SSH tunnel
  ```
  ssh -p 2223 -L 8000:10.99.199.73:8000 admin@119.46.226.124
  ```
- **Auth:** ทุก endpoint (ยกเว้น `/health`, `/docs`) ต้องส่ง HTTP header:
  ```
  X-Security-Token: <API_SECRET_KEY ที่ตกลงกัน>
  ```
- **API docs (ลองยิงเล่นได้):** `http://10.99.199.73:8000/docs`

---

## สำหรับเครื่องที่ 1 (Gateway) → ยิงอีเมลเข้ามาวิเคราะห์

**`POST /analyze`**

Request:
```http
POST http://10.99.199.73:8000/analyze
X-Security-Token: <API_KEY>
Content-Type: application/json

{
  "text": "<raw email content ทั้งฉบับ รวม header From/Subject/Received>",
  "recipient": "user@corp.com"
}
```

- `text` = เนื้อหาอีเมลดิบทั้งฉบับ (raw `.eml` format) — ระบบ parse header เอง **จำเป็น**
- `recipient` = อีเมลผู้รับ (ไม่ส่งก็ได้ default = `unknown@corp.com`)
- จำกัด rate: **30 requests/นาที** ต่อ IP

> ⚠️ **เปลี่ยน contract แล้ว** — เดิม `/analyze` ตอบ `summary.final_risk_score` + `risk_level`
> **ตอนนี้ไม่ตอบแล้ว** เพราะสูตรคิดคะแนนความเสี่ยงย้ายไปเป็นของ **ทีม .92** (`risk_config.py`)
> ฝั่ง AI ส่งแค่ "สัญญาณดิบ" ให้ ใครถ่วงน้ำหนักเท่าไหร่เป็นเรื่องของฝั่ง scoring
> (มีสูตรที่เดียว ไม่งั้นอีเมลฉบับเดียวกันได้คนละคะแนน)

Response (ทุกกรณี — ทั้งเสี่ยงและปลอดภัย):
```json
{
  "raw_signals": {
    "email_hash": "...", "message_id": "...",
    "sender_domain": "...", "sender_email": "...", "recipient": "...",
    "spf_result": "fail", "dkim_result": "pass", "dmarc_result": "fail",
    "auth_source": {"spf": "pmg", "dkim": "header", "dmarc": "pmg", "sender_ip": "pmg"},
    "reply_to_mismatch": true,
    "sender_spoofing": true, "spoofing_score": 65, "spoofing_reasons": ["brand_mismatch:paypal!=evil.top"],
    "attack_evidence": { ... 20 ตัวแปร ดูหัวข้อข้างล่าง ... },
    "attack_type_v2": {"attack_type": "Phishing", "score": 220, "confidence": "สูง", "reasons": [...]},
    "attachment_type": ".pdf", "has_malware": false,
    "raw_ai_score": 99.47,
    "raw_link_score": 10, "link_confidence": "suspicious",
    "abuseipdb_score": 0, "abuseipdb_measured": false,
    "subject": "...", "body_text": "...",
    "attack_type": "Business Email Compromise (BEC)"
  }
}
```

**อีเมลที่ปลอดภัยชัดเจน (fast path)** — `raw_ai_score < 30`, ไม่มีไฟล์แนบอันตราย, ไม่มี URL ใน body
จะข้าม external check (VirusTotal / IPQS / DMARC) เพื่อความเร็ว โครงสร้างที่ตอบกลับ**เหมือนเดิมทุกฟิลด์** แต่:

| ฟิลด์ | ค่าตอน fast path | อ่านยังไง |
|---|---|---|
| `raw_link_score` | `0` | ไม่ได้ตรวจ ไม่ใช่ "ตรวจแล้วสะอาด" |
| `abuseipdb_score` | `0` | เช็คคู่กับ `abuseipdb_measured` เสมอ |
| `abuseipdb_measured` | `false` | **`false` = ไม่ได้วัด** อย่าตีความว่า IP สะอาด |
| `auth_source.sender_ip` | `"not_checked"` | |
| `attack_type` | `"Normal"` | มาจากการข้าม Stage 2 ไม่ใช่ผลของโมเดล |

---

## เกณฑ์ตัดสิน (risk_level) อยู่ที่ไหน

**ไม่ได้อยู่ที่ AI server** — ทีม .92 เป็นเจ้าของสูตรและเกณฑ์ ตั้งแต่ 2026-08-26

```
AI (ที่นี่)          .92 (risk_scoring/)        Gateway / Mail server
สัญญาณดิบ     →     คิดคะแนน + ระดับ      →     forward / quarantine / block
```

ถ้าอยากได้คะแนนรวม ให้เรียกฝั่ง .92 อย่าคำนวณเองซ้ำ


---

---

## 🆕 `attack_evidence` — ตัวแปรหลักฐานสำหรับแยกประเภทการโจมตี

> เพิ่ม 2026-08-26 · **additive อย่างเดียว** — `attack_type` เดิมยังส่งเหมือนเดิม ของที่ใช้อยู่ไม่พัง
> มีทั้งใน `POST /analyze` (ใน `raw_signals`) และ `POST /parse`

**ทำไมถึงเพิ่ม:** `attack_type` จาก XGBoost อธิบายที่มาไม่ได้ — วัดแล้วพบว่า 73% ของจุดตัดสินใจ
ในโมเดลคือคำถาม `ai_score > 99.99x ?` ซึ่งเป็นเศษทศนิยมของ softmax ไม่ใช่สัญญาณความปลอดภัย
(ดู `docs/stage1_ham_fp_eval.json`) · ตัวแปรข้างล่างคือ **หลักฐานดิบ** ที่ตรงกับนิยามของการโจมตีแต่ละแบบ
เอาไปตั้งน้ำหนักเองได้ทันที และอธิบายให้คนอื่นเข้าใจได้ว่าทำไมถึงตัดสินแบบนั้น

```json
"attack_evidence": {
  "spoof_display_name": 0, "spoof_homoglyph": 0, "spoof_lookalike": 0,
  "spoof_brand": 1, "spoof_brand_related": 0, "spoof_own_org": 0, "spoof_freemail_corp": 0,
  "link_count": 6, "unique_link_domains": 2, "link_domain_ratio": 3.0,
  "external_link_ratio": 1.0, "has_unsubscribe": 1, "no_links": 0,
  "reply_to_mismatch": 1, "attachment_risk": 0, "has_urgency": 1, "sender_is_free_mailer": 0
}
```

| ตัวแปร | ค่า | ความหมาย |
|---|---|---|
| `spoof_display_name` | 0/1 | display name เป็นอีเมลคนละโดเมนกับผู้ส่งจริง |
| `spoof_homoglyph` | 0/1 | โดเมนใช้อักษรหลอกตา / punycode |
| `spoof_lookalike` | 0/1 | โดเมนคล้ายแบรนด์จริง (ต่างตัวอักษรเดียว ความยาวเท่ากัน) |
| `spoof_brand` | 0/1 | อ้างแบรนด์ในชื่อ แต่โดเมนไม่เกี่ยวกับแบรนด์นั้น |
| `spoof_brand_related` | 0/1 | อ้างแบรนด์ และชื่อแบรนด์อยู่ในโดเมนด้วย (มักเป็นพาร์ตเนอร์จริง — น้ำหนักควรต่ำ) |
| `spoof_own_org` | 0/1 | 🔴 อ้างเป็นองค์กรของผู้รับ แต่ส่งจากข้างนอก — BEC ที่อันตรายที่สุด |
| `spoof_freemail_corp` | 0/1 | อ้างเป็นบริษัท/หน่วยงาน แต่ส่งจากเมลฟรี |
| `link_count` | จำนวน | ลิงก์ทั้งหมดในเนื้อเมล |
| `unique_link_domains` | จำนวน | โดเมนไม่ซ้ำของลิงก์ |
| `link_domain_ratio` | ทศนิยม | `link_count ÷ unique_link_domains` — **นิยามเดียวกับ data_dictionary ของบริษัท** สูง = ยัดลิงก์ซ้ำโดเมนเพื่อหลบฟิลเตอร์ |
| `external_link_ratio` | 0–1 | สัดส่วนลิงก์ที่ไม่ได้อยู่โดเมนผู้ส่ง |
| `has_unsubscribe` | 0/1 | มีข้อความ/ลิงก์ยกเลิกรับข่าว (อังกฤษ+ไทย) = ลักษณะเมลกระจาย |
| `link_login_lure` | 0/1 | 🔑 URL ชี้ไปหน้า login/verify/account — หัวใจของนิยาม "ฟิชชิ่ง" (ดูเฉพาะ path ไม่ดูชื่อโดเมน) |
| `no_links` | 0/1 | ไม่มีลิงก์เลย — **สัญญาณสำคัญของ BEC** (BEC ขอให้ทำอะไร ไม่ได้ล่อไปหน้าเว็บ) |
| `reply_to_mismatch` | 0/1 | Reply-To คนละโดเมนกับ From |
| `attachment_risk` | 0/1 | มีไฟล์แนบนามสกุลอันตราย |
| `has_urgency` | 0/1 | คำเร่งด่วน — **ตรวจทั้งอังกฤษและไทย** (ของบริษัทตรวจอังกฤษอย่างเดียว) |
| `sender_is_free_mailer` | 0/1 | ผู้ส่งใช้เมลฟรี (gmail/hotmail/…) |

**หลักฐานแมปกับประเภทการโจมตีอย่างไร** (ตามนิยาม ไม่ใช่ตามที่โมเดลเดา):

| ประเภท | หลักฐานที่ควรติด |
|---|---|
| **Malware** | `attachment_risk` |
| **BEC** | `spoof_display_name` / `spoof_own_org` / `spoof_freemail_corp` + `no_links` + `reply_to_mismatch` |
| **Phishing** | `spoof_brand` / `spoof_lookalike` / `spoof_homoglyph` + มีลิงก์ |
| **Spam** | `link_domain_ratio` สูง + `has_unsubscribe` |

### `attack_type_v2` — ประเภทการโจมตีที่ชี้ที่มาของคะแนนได้

> เพิ่ม 2026-08-26 · **`attack_type` เดิมยังส่งเหมือนเดิม** — ใช้คู่กันได้ ยังไม่ต้องเปลี่ยนอะไร

```json
"attack_type_v2": {
  "attack_type": "Business Email Compromise (BEC)",
  "score": 125,
  "confidence": "สูง",
  "reasons": ["spoof_own_org(+45)", "spoof_display_name(+40)",
              "reply_to_mismatch(+15)", "no_links(+15)", "has_urgency(+10)"],
  "scores": {"Business Email Compromise (BEC)": 125, "Phishing": 10,
             "Spam (High-Risk Source)": 0, "Malware Attachment": 0}
}
```

**สูตร:** `คะแนนของประเภท = ผลรวมน้ำหนักของหลักฐานที่ติด` แล้วเลือกประเภทที่คะแนนสูงสุด

| เงื่อนไข | ผลลัพธ์ |
|---|---|
| คะแนนสูงสุด ≥ 35 | ตอบประเภทนั้น |
| คะแนนสูงสุด < 35 และ `ai_score` ≥ 50 | `Unknown Threat` — เสี่ยงจริงแต่หลักฐานไม่พอบอกชนิด |
| คะแนนสูงสุด < 35 และ `ai_score` ต่ำ | `Normal` |

`confidence` = **สูง** เมื่อคะแนน ≥ 60 **และ** ทิ้งห่างอันดับสอง ≥ 30 · **กลาง** เมื่อ ≥ 40 และห่าง ≥ 15 · นอกนั้น **ต่ำ**

> ต้องผ่านทั้งสองเงื่อนไข — คะแนน 30 ที่ประเภทอื่นได้ 0 ไม่ใช่ความมั่นใจสูง มันคือหลักฐานน้อยที่ไม่มีคู่แข่ง

**ผลวัด** (ไม่ใช้ `ai_score` เลย):

| ชุดข้อมูล | Phishing | Spam | BEC | Normal |
|---|---|---|---|---|
| phishing_pot ฟิชชิ่งจริง (8,612) | 11.1% | 27.9% | 1.0% | 60.0% |
| SpamAssassin spam (1,896) | 0.9% | 18.5% | 0.8% | 79.7% |
| easy_ham เมลปกติ (1,200) | 0.3% | 1.8% | 0.0% | **97.9%** |

⚠️ **ข้อจำกัดที่ต้องรู้:** ฟิชชิ่งจริง **60% ยังระบุประเภทไม่ได้** เพราะรายชื่อแบรนด์มีแค่ราว 50 ชื่อ
และยังไม่ได้ตรวจ "ข้อความลิงก์ไม่ตรงกับ href" · ตัวเลขข้างบนวัดจาก "ทั้งกองเป็นประเภทเดียว"
ไม่ใช่ label รายฉบับ จึงบอกได้แค่ทิศทาง ไม่ใช่ความแม่นยำต่อฉบับ

### 🚫 ห้ามเอา `attack_type_v2.score` ไปบวกเข้า risk score

`risk_engine` แบ่ง 6 องค์ประกอบให้ตรวจคนละเรื่อง (AI / Link / Attachment / Domain / Language / Header)
รวมกันได้ 100 — ที่ปรึกษาย้ำว่าห้ามนับซ้ำ

`attack_type_v2` เป็น **คนละแกน**: บอกว่า "เป็นการโจมตีชนิดไหน" ไม่ได้บอกว่า "เสี่ยงแค่ไหน"
โดยเฉพาะ `has_urgency` ที่ทับกับ component `Language` ของ risk_engine โดยตรง

> แบ่งงานกันแบบนี้: **AI server บอกชนิด · risk_engine บอกความเสี่ยงและ action**

### ⚠️ ข้อควรรู้เรื่องการนับลิงก์

นับจากข้อความที่ **ถอดรหัสแล้ว** (text/plain + HTML ต้นฉบับ) ไม่ใช่จากอีเมลดิบ

วัดบน phishing_pot 600 ฉบับ (2026-08-26): อ่านจากอีเมลดิบทำให้ **24.2% หาลิงก์ไม่เจอเลย**
เพราะเนื้อเมลถูกเข้ารหัส base64 · พอถอดรหัสก่อนเหลือ 12.5%

> `raw_link_score` (คนละตัวกับ `link_count`) ยังอ่านจากอีเมลดิบอยู่ = ยังตาบอดกับเมลที่เข้ารหัส
> เป็นงานที่ต้องแก้ต่อ แต่แยกออกมาเพราะการแก้จะเปลี่ยนคะแนนที่ทีมอื่นใช้อยู่

## สำหรับเครื่องที่ 3 (Dashboard) → ดึงสถิติ

มี 2 ทางเลือก:

### ทางเลือก A (แนะนำ): เรียก API `/dashboard`
**`GET /dashboard?period=7days`** (period = `today` | `7days` | `30days`)

```http
GET http://10.99.199.73:8000/dashboard?period=7days
X-Security-Token: <API_KEY>
```

ได้สถิติพร้อมใช้:
```json
{
  "stats": {
    "emailsToday": 1000, "phishingDetected": 50, "phishingRate": 5.0,
    "allowed": 950, "warning": 0, "quarantined": 30, "blocked": 20,
    "blockRate": 100.0, "avgRiskScore": 12.3
  },
  "volume":   {"labels": [...], "total": [...], "phishing": [...]},
  "riskDist": [...], "domains": [...], "users": [...], "types": [...]
}
```
> หมายเหตุ: `period=today` ต้องใช้ PostgreSQL (ใช้ `date_trunc`) — บน SQLite จะ error

### ทางเลือก B: query PostgreSQL ตรงๆ
ทุก record อยู่ในตาราง **`email_logs`** บนเครื่องที่ 4 (PostgreSQL) — schema ด้านล่าง

---

## Database Schema — ตาราง `email_logs`

| column | type | คำอธิบาย |
|--------|------|----------|
| `id` | Integer (PK) | running number |
| `timestamp` | DateTime (UTC) | เวลาที่วิเคราะห์ |
| `sender_domain` | String | โดเมนผู้ส่ง |
| `recipient` | String | อีเมลผู้รับ |
| `subject` | String | หัวข้ออีเมล |
| `final_score` | Float | คะแนนรวม 0–100 |
| `ai_score` | Float | คะแนนจาก BERT |
| `link_risk` | Float | ความเสี่ยงจากลิงก์ |
| `domain_risk` | Float | คะแนน AbuseIPDB |
| `header_anomaly` | Float | ความผิดปกติของ header |
| `risk_level` | String | `allow` / `warning` / `quarantine` / `block` |
| `is_phishing` | Boolean | true = อันตราย (score ≥ 30) |
| `attack_type` | String | `Normal`, `BEC`, `Spear Phishing`, `Malware Attachment`, ... |

> อีเมลทุกฉบับถูกบันทึก (ทั้ง safe และ phishing) → Dashboard นับยอดรวมได้ครบ

---

## Endpoint อื่นๆ

| Method | Path | ใช้ทำอะไร |
|--------|------|-----------|
| GET  | `/health` | เช็คว่า server + model พร้อม (ไม่ต้อง auth) |
| GET  | `/logs?page=1&limit=20` | ดู log ดิบแบบแบ่งหน้า |
| POST | `/feedback` | แก้ผลว่า log นี้เป็น phishing จริงไหม `{"log_id": 1, "is_actually_phishing": true}` |
