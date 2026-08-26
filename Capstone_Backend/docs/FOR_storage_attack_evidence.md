# ถึงทีม Storage / Mail Server (.92) — `attack_evidence` พร้อมใช้แล้ว

> 2026-08-26 · จาก AI server (`10.99.199.73:8000`) · **additive ล้วน ของเดิมไม่พัง**

พอดีเห็นว่าย้าย `risk_scoring/` มาไว้ที่ `/opt/risk-mailserver` บนเครื่องเดียวกับเราแล้ว
เลยรีบแจ้งก่อนที่จะเขียนตัวคำนวณลิงก์/การปลอมตัวซ้ำอีกชุด

---

## สิ่งที่เพิ่มให้

`POST /analyze` → `raw_signals` และ `POST /parse` มีสองฟิลด์ใหม่

### 1. `attack_evidence` — ตัวแปรหลักฐาน 20 ตัว

```json
"attack_evidence": {
  "spoof_display_name": 0, "spoof_homoglyph": 0, "spoof_lookalike": 1,
  "spoof_brand": 1, "spoof_brand_related": 0, "spoof_own_org": 0, "spoof_freemail_corp": 0,
  "link_count": 1, "unique_link_domains": 1, "link_domain_ratio": 1.0,
  "external_link_ratio": 1.0, "has_unsubscribe": 0, "link_login_lure": 1,
  "link_text_mismatch": 1, "no_links": 0,
  "reply_to_mismatch": 0, "attachment_risk": 0,
  "asks_credential": 1, "has_urgency": 1, "sender_is_free_mailer": 0
}
```

ที่น่าจะใช้ได้ทันทีฝั่งพี่:

| ตัวแปร | ใช้แทนอะไร |
|---|---|
| `link_count`, `unique_link_domains`, `link_domain_ratio` | **นิยามเดียวกับ `data_dictionary` ของบริษัทเป๊ะ** (`link_count ÷ unique_link_domains`) |
| `spoof_*` 7 ตัว | แตกจาก `spoofing_reasons` ให้เป็น 0/1 รายตัว ไม่ต้อง parse string เอง |
| `link_text_mismatch` | ข้อความลิงก์อ้างโดเมนหนึ่ง แต่ `href` พาไปอีกโดเมน |
| `link_login_lure` | URL ชี้ไปหน้า login/verify (ดูเฉพาะ path ไม่ดูชื่อโดเมน) |

### 2. `attack_type_v2` — ประเภทที่ชี้ที่มาของคะแนนได้

```json
"attack_type_v2": {
  "attack_type": "Phishing", "score": 220, "confidence": "สูง",
  "reasons": ["spoof_lookalike(+45)", "link_text_mismatch(+45)", "spoof_brand(+40)",
              "link_login_lure(+40)", "asks_credential(+35)", "has_links(+10)", "has_urgency(+5)"],
  "scores": {"Phishing": 220, "Business Email Compromise (BEC)": 25, "Spam (High-Risk Source)": 0, "Malware Attachment": 0}
}
```

`attack_type` เดิม (จาก XGBoost) **ยังส่งเหมือนเดิม** ใช้คู่กันได้ ยังไม่ต้องเปลี่ยนอะไร

---

## 🚫 ข้อเดียวที่ขอให้ระวัง — อย่าเอา `attack_type_v2.score` ไปบวกเข้า risk score

`risk_engine` แบ่ง 6 องค์ประกอบให้ตรวจคนละเรื่องรวมกัน 100 และที่ปรึกษาเขียนกำกับไว้ว่า
*"ห้ามซ้ำกัน ไม่งั้นเมลฉบับเดียวจะโดนหักคะแนนสองเด้งจากสาเหตุเดียว"* — เห็นด้วยเต็มที่

`attack_type_v2` เป็น **คนละแกน**: บอกว่า *เป็นการโจมตีชนิดไหน* ไม่ได้บอกว่า *เสี่ยงแค่ไหน*

โดยเฉพาะ `has_urgency` กับ `asks_credential` ของเรา **ทับกับ component `Language`** ของพี่โดยตรง
(กลุ่ม `urgency` และ `credential_request`) ถ้าเอาไปบวกจะเป็นการนับซ้ำทันที

> เสนอให้แบ่งแบบนี้: **AI server บอกชนิด · risk_engine บอกความเสี่ยงและ action**

---

## 3 จุดที่ขอแก้ในเอกสาร SCORING_CALCULATION

ไล่เทียบกับโค้ดจริงแล้ว **ตัวเลขลิงก์ นามสกุลไฟล์ timeout ตรงหมดทุกตัว** รวมถึงการเทียบ 14/17/8 นามสกุล

### 🔴 1. `impersonates_recipient_org` — "0%" คือ *วัดไม่ได้* ไม่ใช่ *ความแม่น 0%*

เอกสารเขียนว่าความแม่น 0% แล้วสรุปว่า "ไม่ถึงเกณฑ์" จึงไม่ให้คะแนน

แต่ตรวจ CEAS_08 แล้ว โดเมนผู้รับกระจุกที่โดเมนสังเคราะห์ของงานแข่ง:

| โดเมนผู้รับ | จำนวน | สัดส่วน |
|---|---:|---:|
| `gvc.ceas-challenge.cc` | 23,816 | **61.7%** |
| `opensuse.org` | 1,955 | 5.1% |
| `python.org` | 1,795 | 4.7% |

สัญญาณนี้ต้องเทียบ *ชื่อองค์กรของผู้รับ* กับผู้ส่ง — เมื่อผู้รับ 61.7% ไม่ใช่องค์กรจริง
**สัญญาณนี้ไม่มีโอกาสติดเลยบนชุดนั้น** ตัวเลข 0 จึงไม่ได้แปลว่ามันแม่นแค่ 0%

เป็นเคสเดียวกับที่ฝั่งพี่แยก `abuseipdb_measured` ออกจากค่า 0 ไว้แล้ว — ตรรกะเดียวกันเป๊ะ

**ที่อยากให้ทบทวน:** นี่คือสัญญาณของ BEC ที่ปลอมเป็นคนในองค์กรเอง ซึ่งพี่เองเป็นคนชี้ไว้เมื่อ 17 ส.ค.
ว่าอันตรายที่สุด ตอนนี้มันถูกปิดอยู่เพราะตัวเลขที่ไม่เคยวัดได้จริง

ถ้าอยากวัดจริง ต้องใช้ชุดที่ผู้รับเป็นโดเมนองค์กรจริง — ชุด 6,939 ฉบับของบริษัทเข้าเกณฑ์

### 🟡 2. น้ำหนัก spoofing เป็นชุดเก่า

| เอกสาร | ของจริงตอนนี้ |
|---|---|
| `brand_mismatch` 45 | **50** |
| *(ไม่มี)* | `brand_related_domain` **20** |
| *(ไม่มี)* | `freemail_corporate_claim` **20** |

ตาราง precision ก็เป็นเลข *ก่อน* แยก `brand_mismatch` เป็นสองระดับ
หลังแยกแล้ว precision ขึ้นจาก **30% → 66.7%** (อยู่ใน `REPLY2_to_storage_spoofing_threshold.md`)

มีผลจริง: เอกสารให้ `brand_mismatch` แค่ 2 คะแนนเพราะเชื่อว่าแม่น 30%

### 🟡 3. คลาส Stage 2

เอกสารเขียน `Phishing / BEC / Spam / Other` — ของจริงไม่มี `Other`
คลาสที่สี่คือ **`Malware Attachment`**

---

## ข้อสังเกตเรื่องสูตรซ้ำสองชุด

ฝั่งเรายังมี `risk_score.py` ที่มี `WEIGHT_AI = 0.35` อยู่ ขัดกับ `AI_WEIGHT = 0.20` ของพี่

ตอนนี้เป็นตัวคิดคะแนนสองชุดในระบบเดียว ควรตกลงว่าใครเป็นเจ้าของ แล้วลบอีกชุดทิ้ง
ผมเสนอว่าให้เป็นของฝั่งพี่ (เพราะละเอียดกว่าและมีเอกสารกำกับ) แล้วเราลบของเราออก

---

รายละเอียดทุกตัวแปรอยู่ใน [`INTEGRATION.md`](INTEGRATION.md) · ผลวัดอยู่ใน [`attack_type_v2_eval.json`](attack_type_v2_eval.json)
