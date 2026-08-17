# ถึงทีม Storage / Mail Server (.92) — payload ตัวอย่างจริง + ข้อสังเกตเรื่อง scoring

**จาก:** ทีม AI Server (.94) · **อัปเดต:** 2026-08-09
*(งาน 4 ข้อที่ขอไว้ก่อนหน้า — คุณทำครบแล้ว ขอบคุณมากครับ 🙏 ไฟล์นี้เขียนใหม่เป็นของที่คุณขอ)*

---

## 1. 📦 payload ตัวอย่างจริง — `docs/sample_payloads_analyze.json`

**ไม่ใช่ตัวอย่างที่เขียนมือ** — รันผ่าน BERT + XGBoost + ตัวแกะอีเมลตัวเดียวกับ production เป๊ะ
ค่า `raw_ai_score` / `attack_type` / `link_confidence` เป็นผลลัพธ์จริงจากโมเดลที่ deploy อยู่บน .94

มี 6 เคส เลือกให้ครอบคลุมสิ่งที่คุณต้องเทส:

| เคส | ai | link | confidence | abuse | measured | malware | attack_type |
|---|---:|---:|---|---:|---|---|---|
| **A** ปกติ EN (fast path) | 0.00 | 0 | `none` | 0 | **false** | false | `Normal` |
| **B** ⭐ ฟิชชิ่ง + TLD เสี่ยง | 100.00 | 70 | `suspicious` | 0 | **false** | false | `Spam (High-Risk Source)` |
| **C** ⭐ เมลเดียวกับ B แต่ VT ยืนยัน + วัด IP ได้ | 100.00 | 100 | `confirmed` | 97 | **true** | false | `Phishing` |
| **D** ไฟล์แนบ `.pdf.exe` | 0.02 | 0 | `none` | 0 | true | **true** | `Malware Attachment` |
| **E** 🇹🇭 ไทยปกติ | 0.32 | 0 | `none` | 0 | **false** | false | `Normal` |
| **F** 🇹🇭 ฟิชชิ่งไทย | 99.99 | 70 | `suspicious` | 0 | **false** | false | `Phishing` |

### 🎯 เคส B กับ C คือของขวัญสำหรับคุณโดยเฉพาะ

**เป็นอีเมลฉบับเดียวกันเป๊ะ** ต่างกันแค่ 2 สัญญาณที่คุณกำลังจะ wire เข้า engine:

```
B:  link_confidence = "suspicious"   abuseipdb_measured = false   abuseipdb_score = 0
C:  link_confidence = "confirmed"    abuseipdb_measured = true    abuseipdb_score = 97
```

**ใช้ทดสอบได้ตรงๆ ว่า engine ใหม่แยกสองเคสนี้ออกไหม** — ถ้าให้คะแนนเท่ากันแปลว่ายังไม่ได้ใช้ field ใหม่

> เคส A / E / F มี `abuseipdb_measured: false` ให้เทสด้วย (fast path กับ external check ที่ไม่มี key ไม่ยิง API)

### วิธีใช้
```bash
# ดึงเฉพาะ raw_signals ของเคส B ไปยิงเข้า /assess
python3 -c "
import json,sys
d=json.load(open('sample_payloads_analyze.json',encoding='utf-8'))
k=[x for x in d if x.startswith('B.')][0]
print(json.dumps(d[k]['raw_signals'],ensure_ascii=False))" > b.json

curl -s -X POST http://127.0.0.1:8000/assess \
  -H "X-Security-Token: <token>" -H "Content-Type: application/json" \
  -d @b.json | python3 -m json.tool
```

> ⚠️ **เคส E / F มีภาษาไทยจริงใน `subject` + `body_text`** (ตรวจแล้วไม่เพี้ยน) — ใช้เทสว่าฝั่งคุณเก็บลง DB แล้วอ่านออกไหม เคยมีบั๊กแนวนี้ตอนแกะอีเมล

---

## 2. ⭐ เรื่องที่คุณตั้งข้อสังเกตเอง — `abuseipdb_measured` กับ auth-trust

> *"โดยเฉพาะ `abuseipdb_measured=false` ที่ควรกันไม่ให้ auth-trust เข้าใจผิดว่า IP สะอาด"*

**คุณจับประเด็นได้ถูกที่สุดแล้วครับ** และมันสำคัญกว่าที่คิด — ขอเสริมข้อมูลให้ตัดสินใจ

ใน `risk_config.py` ของคุณมี:
```python
AUTH_TRUST_ABUSE_MAX = 25      # IP สะอาดกว่านี้ = น่าเชื่อถือ
```

**ปัญหา:** ตอนนี้ `abuseipdb_score = 0` มาจาก 2 สถานการณ์ที่ตรงข้ามกันสุดขั้ว

| ที่มาของเลข 0 | ความหมายจริง | `abuseipdb_measured` |
|---|---|---|
| ตรวจแล้ว AbuseIPDB บอกว่าสะอาด | ✅ ปลอดภัยจริง | `true` |
| **ไม่ได้ตรวจ** (fast path / ไม่มี API key / API ล่ม / ไม่มี public IP) | ⚠️ **ไม่รู้อะไรเลย** | `false` |

→ ทั้งคู่ผ่านเงื่อนไข `0 <= 25` เหมือนกัน = **อีเมลที่ไม่เคยถูกตรวจ IP เลย ได้ auth-trust เท่ากับ IP ที่ยืนยันแล้วว่าสะอาด**

**เสนอ (แก้บรรทัดเดียว):**
```python
# เดิม
if abuseipdb_score <= AUTH_TRUST_ABUSE_MAX and ai_score <= AUTH_TRUST_AI_MAX:
    # ให้ auth trust

# เสนอ — "วัดไม่ได้" ต้องไม่นับเป็นหลักฐานว่าปลอดภัย
if abuseipdb_measured and abuseipdb_score <= AUTH_TRUST_ABUSE_MAX and ai_score <= AUTH_TRUST_AI_MAX:
```

> **หลักการ:** *ไม่มีข้อมูล ≠ ข้อมูลที่ดี* · การไม่รู้ไม่ควรถูกนับเป็นคะแนนบวก
> นี่เป็นบั๊กประเภทเดียวกับที่ฝั่งเราเจอใน P2 (ค่า `dmarc_fail = 0` ที่จริงแปลว่า "DNS lookup ล้ม" ไม่ใช่ "DMARC ผ่าน") — ตอนนั้นเราตัด feature นั้นทิ้งไปเลย

**⚠️ ระวังตอนแก้:** เคส A/E/F ในไฟล์ตัวอย่างคือ **อีเมลปกติที่ `measured=false`** ถ้าแก้แล้วเผลอทำให้ "วัดไม่ได้" = เพิ่มความเสี่ยง อีเมลปกติจะโดนคะแนนสูงขึ้นยกแผง → **ที่ถูกคือ "ไม่ให้โบนัส" ไม่ใช่ "เพิ่มโทษ"** ลองยิง 6 เคสนี้ก่อน/หลังแก้แล้วเทียบคะแนนดูครับ

---

## 3. 💡 `link_confidence` — ข้อเสนอการใช้งาน

| ค่า | คะแนน | มาจากไหน | แนะนำให้ใช้ยังไง |
|---|---|---|---|
| `confirmed` | 100 | **VirusTotal ฟันธงว่าอันตราย** | ✅ override / block เดี่ยวๆ ได้ |
| `suspicious` | 70–99 | เดาจากรูปแบบ URL (TLD เสี่ยง / ใช้ IP แทนโดเมน) | ⚠️ **บวกคะแนน อย่า override เดี่ยว** — ต้องมีสัญญาณอื่นร่วม |
| `low` | 10 | มีลิงก์ แต่ไม่มีอะไรน่าสงสัย | ปกติ |
| `none` | 0 | ไม่มีลิงก์ | ปกติ |

```python
conf = payload.get("link_confidence", "suspicious")   # default เผื่อ response รุ่นเก่า
if conf == "confirmed":
    final_score = max(final_score, 85)     # ยืนยันแล้ว
elif conf == "suspicious":
    final_score += 20                      # สงสัย — ให้สัญญาณอื่นถ่วงได้
```

> 💡 **หมายเหตุ:** ถ้ายังไม่ได้ตั้ง VirusTotal API key บน .94 **จะไม่มีอีเมลไหนได้ `confirmed` เลย** (เคส C ในไฟล์ตัวอย่างเราจำลอง VT hit ให้) — ออกแบบ scoring ให้ทำงานได้ดีแม้ไม่มี `confirmed` ด้วยครับ

---

## 4. ✅ ยืนยันงานที่คุณทำ + เรื่อง message_id

| งาน | สถานะ |
|---|---|
| ลบ `Spear Phishing` ออกจาก `color_map` | ✅ |
| `riskDist` เป็น 30/60/80 | ✅ ตรงกับ `_classify()` แล้ว |
| เก็บ `reasons` + `attachment_risk` + `language_risk` ลง DB | ✅ 🔥 **ข้อนี้มีค่าที่สุด** — Dashboard จะบอกได้แล้วว่า *ทำไม*ถึงโดนบล็อก |
| เพิ่ม field ที่ตกหล่นใน `AssessRequest` | ✅ |
| `message_id` + safe-dedup | ✅ มีในโค้ดแล้ว รอ push |

**เรื่อง `message_id` ที่เราทักไป — ขอโทษด้วยครับ** เราดูจาก repo แล้วไม่เห็นเลยเข้าใจว่ายังไม่ได้ทำ ที่จริงคุณทำไว้แล้วแค่ยังไม่ได้ push · เดี๋ยว push แล้วเราจะเช็คให้อีกรอบว่า field ตรงกันทั้งสองฝั่ง

> ทุก payload ในไฟล์ตัวอย่างมี `message_id` จริงครบ (เคสไทยก็มี) เอาไปเทส dedup ได้เลย
> **เทส dedup แนะนำ:** ยิงเคส B ซ้ำ 2 ครั้ง → ครั้งที่สองควรถูกข้าม · แล้วลองแก้แค่ `message_id` ให้ต่าง → ต้องไม่ถูกข้าม (เพราะ hash เดียวกันแต่คนละฉบับ)

---

## 5. สถานะฝั่งเรา

| | |
|---|---|
| `raw_signals` 22 field (รวม `message_id`, `link_confidence`, `abuseipdb_measured`) | ✅ live บน .94 |
| `POST /parse` · `/model/info` · `/model/history` · `/model/activate` | ✅ live |
| `POST /model/feedback-label` + `GET /model/feedback-stats` *(ใหม่ — Dashboard รออยู่)* | ✅ เขียน+เทสแล้ว ⏳ กำลัง deploy |

อยากได้เคสเพิ่ม (เช่น BEC ที่ไม่มีลิงก์เลย, อีเมลที่ auth ผ่านหมดแต่ AI สูง) บอกได้ครับ เดี๋ยวรันเพิ่มให้ 🙏
