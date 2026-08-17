# ตอบทีม Storage (.92) — `sender_spoofing` ทำเสร็จแล้ว

**จาก:** ทีม AI Server (.94) · **วันที่:** 2026-08-17 · **สถานะ:** ✅ เขียน + วัดผลแล้ว ⏳ รอ deploy

> ⚠️ **มีรอบ 2 แล้ว** — ทีม .92 ตอบกลับมา และมีการปรับ **เกณฑ์ 45 → 50**, แยก `brand_mismatch` เป็น 2 ระดับ,
> เพิ่มแบรนด์ไทย และเพิ่ม `PROTECTED_DOMAINS` · **ตัวเลขล่าสุดอยู่ที่ [REPLY2_to_storage_spoofing_threshold.md](REPLY2_to_storage_spoofing_threshold.md)**
> เอกสารนี้เก็บไว้เป็นบริบทของรอบแรก (ตัวเลขในนี้เป็นของเกณฑ์ 45)

> ต่อจาก [REPLY_to_storage_4questions.md](REPLY_to_storage_4questions.md) ข้อ 4 —
> ที่แจ้งไปว่า `sender_spoofing` เป็น `False` ตายตัว ทำให้กฎ **+4** ของคุณเป็น dead code
> **ตอนนี้คำนวณจริงแล้ว** และเลือกแบบ (ก) ให้เลย คือส่งทั้ง `bool` + `score` + `เหตุผล` มาให้ตั้งน้ำหนักเอง

---

## 1. คุณจะได้ field อะไรเพิ่ม

`raw_signals` (จาก `/analyze`) และ `/parse` เพิ่ม **3 field** — ของเดิมไม่มีอะไรเปลี่ยน:

```jsonc
{
  "sender_spoofing": true,        // เดิมเป็น false ตายตัว — ตอนนี้คำนวณจริง (contract เดิม ไม่ต้องแก้โค้ด)
  "spoofing_score": 100,          // 🆕 0–100
  "spoofing_reasons": [           // 🆕 รหัสสัญญาณ + รายละเอียด
    "lookalike_domain:paypa1.com~paypal.com",
    "brand_mismatch:paypal!=paypa1.com"
  ]
}
```

`/parse` ได้เพิ่มอีก 1 field: `sender_display_name` (ชื่อที่ผู้ส่งตั้งไว้ เช่น `"PayPal Service"`)

**`sender_spoofing` = `spoofing_score >= 45`** — ถ้าอยากได้เกณฑ์อื่น ใช้ `spoofing_score` ตัดเองได้เลย

---

## 2. ตรวจอะไรบ้าง (6 สัญญาณ)

| รหัส | น้ำหนัก | จับอะไร | ตัวอย่างจริง |
|---|---:|---|---|
| `display_name_other_email` | 60 | ชื่อผู้ส่งเป็นอีเมล**คนละโดเมน**กับที่ส่งจริง | `"billing@scb.co.th" <attacker@evil.top>` |
| `homoglyph_domain` | 60 | โดเมนมีอักษรที่ไม่ใช่ ASCII / punycode | `xn--80ak6aa92e.com` |
| `lookalike_domain` | 55 | โดเมนเลียนแบรนด์ | `paypa1.com` · `pay-pal.com` · `rnicrosoft.com` · `netflir.com` |
| `brand_mismatch` | 45 | ชื่ออ้างแบรนด์ แต่โดเมนไม่ใช่ของแบรนด์ | `"Microsoft Account Team" <alert@xq12367.com>` |
| `impersonates_recipient_org` | 30 | อ้างชื่อองค์กร**ผู้รับ** แต่ส่งจากข้างนอก | `"DocuSign via sammitr.com" <...@workslidesda.online>` |
| `freemail_corporate_claim` | 20 | อ้างเป็นบริษัท/แผนก แต่ส่งจาก Gmail | `"First Abu Dhabi Bank" <...@gmail.com>` |

น้ำหนักบวกกัน (เพดาน 100) · **2 ตัวล่างตั้งใจให้ต่ำกว่าเกณฑ์ = ไม่ยิงเดี่ยว ๆ** ต้องมีสัญญาณอื่นประกอบ

> ⚠️ **ไม่ได้ตรวจ SPF/DKIM ซ้ำ** — อันนั้น PMG ทำแล้วและแม่นกว่า (`spf_result`/`dkim_result` ใน `raw_signals`)
> ตัวนี้ตรวจเฉพาะ **"การแอบอ้างตัวตนที่ตาคนมองเห็น"** ซึ่งเป็นคนละเรื่องกับ auth ผ่านหรือไม่ผ่าน

---

## 3. 📊 วัดผลจริงแล้ว — ตัวเลขทั้งหมด

### 3.1 บนอีเมลปกติ 17,312 ฉบับ (CEAS_08 มี label จริง)

```
false positive = 9 / 17,312 = 0.052%
```

**นี่คือตัวเลขที่สำคัญที่สุดสำหรับคุณ** — กฎ +4 จะไปโดนอีเมลปกติแค่ 1 ใน 2,000 ฉบับ

### 3.2 บนอีเมลจริงของบริษัท 6,939 ฉบับ (ชุดที่เพิ่งได้มา)

| | ผล |
|---|---|
| ติดธง | 258 (3.7%) |
| **ผู้ส่งเป็นองค์กรไทยจริง** (`.co.th`/`.or.th`/`.go.th`/`.ac.th`) ที่ติดธง | **0 จาก 287** ✅ |

ข้อล่างสำคัญมาก — **ไม่ไปโดนอีเมลธุรกิจไทยเลยสักฉบับ** ซึ่งเป็นกลุ่มที่เสียหายที่สุดถ้าโดนกักผิด

ตัวอย่างที่ติด (จากของจริง ไม่ได้แต่งขึ้น):
```
[ 45] "Microsoft account team"  | xq12367.com            brand_mismatch
[ 45] "DHL | Express"           | bkmlaundromat.com      brand_mismatch
[ 45] "DocuSign"                | candydns.top           brand_mismatch
[ 55] "Liberty Mutual Insurance"| net17.netflir.com      lookalike (netflix)
[ 75] "DocuSign via sammitr.com"| workslidesda.online    brand_mismatch + อ้างองค์กรผู้รับ
```

### 3.3 🔴 ความแม่นรายสัญญาณ — เอาไปตั้งน้ำหนักเองได้

วัดบน CEAS_08 (ปกติ 17,312 · ฟิชชิ่ง 21,842):

| สัญญาณ | ติดในเมลปกติ | ติดในฟิชชิ่ง | ความแม่น |
|---|---:|---:|---:|
| `homoglyph_domain` | 0 | 1 | **100%** |
| `display_name_other_email` | 1 | 7 | **87.5%** |
| `lookalike_domain` | 1 | 2 | 66.7% |
| `brand_mismatch` | 7 | 3 | **30%** ⚠️ |
| `impersonates_recipient_org` | 10 | 0 | **0%** 🔴 |
| **รวม** | **9** | **12** | 57.1% |

**คำแนะนำจากตัวเลขนี้:**
- ✅ `homoglyph_domain` / `display_name_other_email` — เชื่อได้สูง จะให้น้ำหนักมากกว่า +4 ก็สมเหตุสมผล
- ⚠️ `brand_mismatch` — แม่นแค่ 30% บนชุดนี้ เพราะไปโดน newsletter ที่มีชื่อแบรนด์ (`Google Alert <…@googlealert.com>`)
- 🔴 **`impersonates_recipient_org` อย่าให้น้ำหนักเดี่ยว ๆ** — วัดได้ 0% ในชุดนี้ ตอนนี้ตั้งไว้ 30 (ต่ำกว่าเกณฑ์) จึงไม่เคยยิงเดี่ยว

> ⚠️ **ข้อจำกัดที่ต้องบอกตามตรง:** CEAS_08 เป็นเมลปี 2008 ซึ่งฟิชชิ่งยุคนั้นยัง**ไม่ค่อยใช้วิธีปลอมชื่อแบรนด์**
> ตัวเลข "จับฟิชชิ่งได้ 12 ฉบับ" จึงต่ำ **ไม่ได้แปลว่าตัวตรวจอ่อน** — มันแปลว่าชุดทดสอบไม่มีการโจมตีแบบนี้เยอะ
> บนอีเมลบริษัทยุคปัจจุบันติด 3.7% และดูรายฉบับแล้วถูกต้อง
> **ตัวนี้เป็นสัญญาณ "เจาะจงเทคนิค" ไม่ใช่ตัวจับฟิชชิ่งทั่วไป** — ใช้เป็นตัวบวกคะแนนตามที่คุณออกแบบไว้ถูกแล้ว

---

## 4. 🐛 เจอบั๊กในข้อมูลของบริษัทระหว่างทำ (แจ้งไว้เผื่อกระทบฝั่งคุณ)

ชุดข้อมูลบริษัทมี `receiver_domain` ที่ **ติดเครื่องหมาย `>` มาด้วย 1,475 จาก 6,939 แถว** (21%):

```
'sammitr.com'   ✅
'sammitr.com>'  ❌ ตัวแกะ header ลืมตัดวงเล็บปิด
```

รอบแรกที่ผมรัน ทำให้ `sammitr.com` กับ `sammitr.com>` กลายเป็น **คนละโดเมน** → ติดธงปลอมยกกอง

**แก้แล้วในฝั่งเรา** — `registrable_domain()` ล้างอักขระขยะก่อนเทียบเสมอ
**ถ้าฝั่งคุณแกะโดเมนจาก header เอง ลองเช็คด้วยครับ** ว่าโดน `>` ติดมาหรือเปล่า

---

## 5. ✅ กระทบของเดิมไหม — ไม่กระทบ

| ตรวจ | ผล |
|---|---|
| `sender_spoofing` เป็น feature ของโมเดลไหม | **ไม่ใช่** — ดู `STAGE2_FEATURES` (มี 5 ตัว ไม่มีตัวนี้) |
| ต้องเทรนโมเดลใหม่ไหม | **ไม่ต้อง** |
| `ai_score` / `attack_type` เปลี่ยนไหม | **ไม่เปลี่ยน** |
| contract เดิมพังไหม | **ไม่พัง** — `sender_spoofing` ยังเป็น bool ชื่อเดิม ที่เพิ่มมาเป็น field ใหม่ล้วน |

**ฝั่งคุณไม่ต้องแก้อะไรเลยก็ได้** — กฎ +4 เดิมจะเริ่มทำงานเองทันทีที่เรา deploy
จะแก้ก็ต่อเมื่ออยากใช้ `spoofing_score` / `spoofing_reasons` ตั้งน้ำหนักละเอียดขึ้น

---

## 6. ทดสอบเองได้

```bash
curl -s -X POST http://<AI>:8000/parse \
  -H "X-API-Key: $TOKEN" -H "Content-Type: application/json" \
  -d '{"text":"From: \"PayPal Service\" <service@paypa1.com>\r\nTo: staff@corp.co.th\r\nSubject: verify\r\nReceived: from x ([203.0.113.9])\r\n\r\nhi\r\n","recipient":"staff@corp.co.th"}' \
  | python3 -m json.tool
```

ควรได้:
```json
{
  "sender_display_name": "PayPal Service",
  "sender_spoofing": true,
  "spoofing_score": 100,
  "spoofing_reasons": ["lookalike_domain:paypa1.com~paypal.com", "brand_mismatch:paypal!=paypa1.com"]
}
```

---

## 7. ❓ อยากขอความเห็น 2 ข้อ

1. **รายชื่อแบรนด์** — ตอนนี้ใส่ไว้ ~40 แบรนด์ (Microsoft/Google/DHL/FedEx/DocuSign + ธนาคารไทย SCB/กสิกร/กรุงไทย/กรุงศรี + สรรพากร/ไปรษณีย์ไทย)
   **ในองค์กรจริงมีแบรนด์ไหนที่ถูกปลอมบ่อยแต่ยังไม่อยู่ในรายการไหมครับ** — เพิ่มได้ทันที ไม่ต้องเทรนใหม่
2. **เกณฑ์ 45** เหมาะไหม — ถ้าอยากให้ `brand_mismatch` (แม่น 30%) ไม่ยิงเดี่ยว ปรับเกณฑ์เป็น 50 ได้
   บอกมาได้เลยครับ เปลี่ยนบรรทัดเดียว

---

## 📋 สรุป

| | |
|---|---|
| กฎ +4 ของคุณ | ✅ **ใช้งานได้จริงแล้ว** (เดิมเป็น dead code) |
| false positive บนอีเมลปกติ | **0.052%** (9/17,312) |
| องค์กรไทยจริงที่โดนผิด | **0 จาก 287** |
| ต้องแก้โค้ดฝั่งคุณไหม | **ไม่ต้อง** (จะใช้ field ใหม่ค่อยแก้) |
| ต้องเทรนโมเดลใหม่ไหม | **ไม่ต้อง** |

ขอบคุณที่ถามคำถามข้อ 4 ครับ 🙏 — ถ้าไม่มีใครถามว่า *"คำนวณจากอะไร"* ก็คงไม่มีใครรู้ว่ามันไม่เคยทำงานเลย

> 📎 ตัวเลขดิบทั้งหมด: [sender_spoofing_eval.json](sender_spoofing_eval.json)
