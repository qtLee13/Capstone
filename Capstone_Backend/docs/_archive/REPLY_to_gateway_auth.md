# ตอบทีม Gateway (PMG) — เรื่องใช้ผล SPF/DKIM/DMARC ที่ PMG ส่งมา

**จาก:** ทีม AI Server (10.22.1.94) · **วันที่:** 2026-07-20

คุณคิดถูกครับ และเป็นข้อสังเกตที่ดีมาก — **ยืนยันว่า field ที่ PMG ส่งมาไม่ถูกอ่านเลยจริง** เพราะตัวรับ request (pydantic model) ไม่มี field พวกนั้น เลยถูกทิ้งเงียบๆ ตั้งแต่ก่อนถึง logic · **แก้แล้ว + ทดสอบแล้ว รอ deploy**

---

## 1. ตอบคำถามหลัก: ยึดค่าไหนเป็นหลัก → **ยึด PMG เป็นหลัก**

เห็นด้วยเต็มที่กับเหตุผลของคุณ — PMG เช็คที่ **connection-level IP จริงตอนรับเมล** ส่วน AI อ่านจาก `Received` header ที่ **upstream ปลอมได้** → PMG น่าเชื่อถือกว่าชัดเจน

**ลำดับความน่าเชื่อที่ตั้งไว้ (ต่อ field แยกกัน):**
```
PMG payload  >  Authentication-Results header  >  checkdmarc (เฉพาะ dmarc)
```
- ถ้า PMG ส่ง field นั้นมา → ใช้ค่า PMG ทันที (ไม่เช็คซ้ำ)
- ถ้า PMG ไม่ส่ง field นั้น → fallback ไปอ่าน header (backward-compatible กับ caller เดิม)

**ไม่ได้ทำแบบ "เทียบสองค่าแล้วเลือก"** เพราะ PMG น่าเชื่อกว่าอยู่แล้ว — แต่ **ถ้าสองค่าขัดกัน เราจะ log warning ไว้** (เช่น PMG spf=fail แต่ header เขียน spf=pass = อาจโดนยิง header ปลอม) มีประโยชน์ตอนสืบสวน

---

## 2. Field ที่รับ (ตรงกับที่ PMG ส่งมาเป๊ะ)

รับใน body ของ `POST /analyze` (optional ทุกตัว — ไม่ส่งก็ได้ ระบบ fallback เอง):

| field | ชนิด | ค่าที่รับได้ |
|---|---|---|
| `spf_result` | string | `pass` \| `fail` \| `softfail` \| `neutral` \| `none` \| `error` |
| `dkim_valid` | bool | `true` \| `false` \| `null` |
| `dmarc_result` | string | `pass` \| `fail` \| `none` |

ตัวอย่าง request:
```json
{
  "text": "<raw email>",
  "recipient": "user@corp.com",
  "spf_result": "fail",
  "dkim_valid": false,
  "dmarc_result": "fail"
}
```

---

## 3. สิ่งที่กลับไปใน `raw_signals` (response)

เราแปลง `dkim_valid` (bool) → `dkim_result` (string) ให้ contract เดิมที่ .92/scoring ใช้อยู่ **ไม่ต้องแก้**:
- `dkim_valid: true`  → `"dkim_result": "pass"`
- `dkim_valid: false` → `"dkim_result": "fail"`
- `dkim_valid: null`/ไม่ส่ง → fallback header หรือ `"none"`

เพิ่ม field ใหม่ **`auth_source`** ให้เห็นว่าแต่ละค่ามาจากไหน (โปร่งใส/ดีบั๊ก):
```json
{
  "raw_signals": {
    "spf_result": "fail",
    "dkim_result": "fail",
    "dmarc_result": "fail",
    "auth_source": { "spf": "pmg", "dkim": "pmg", "dmarc": "pmg" },
    ...
  }
}
```
`auth_source` แต่ละตัวเป็นได้: `"pmg"` | `"header"` | `"checkdmarc"` | `"none"`

---

## 4. ⚠️ 2 เรื่องที่ต้องบอกตามตรง

### 4.1 feature `dmarc_fail` ของโมเดล Stage 2 — ยัง**ไม่**เปลี่ยนมาใช้ค่า PMG (ตั้งใจ)
โมเดล Stage 2 (แยกชนิดภัย) มี feature ชื่อ `dmarc_fail` ซึ่ง **ยังคำนวณจาก `checkdmarc` เหมือนเดิม** ไม่ใช่จากค่า PMG
เหตุผล: โมเดลถูกเทรนด้วย `dmarc_fail` ที่มาจาก checkdmarc ถ้าสลับ source ตอน serve โดยไม่ retrain = train/serving skew
(หมายเหตุ: feature นี้เราวัดแล้วว่า **แทบไม่มีผลต่อการทำนาย** — importance ≈ 0 เพราะอีเมลภัยเกือบทุกฉบับ dmarc fail หมด)

**แปลว่า:** ค่า PMG ที่ส่งมา ใช้กับ **สัญญาณ scoring** (ที่ Gateway/.92 เอาไปคิดคะแนนสุดท้าย) เต็มที่ · แต่ยังไม่แตะ **feature ของโมเดล** จนกว่าจะ retrain รอบหน้า

### 4.2 checkdmarc ยังถูกเรียกอยู่ (ตอนผ่าน Stage 2) — เป็น "การเช็คซ้ำ" ที่คุณพูดถึงบางส่วน
ตอนนี้ AI ยังเรียก `checkdmarc` (DNS) อยู่ เพราะมันเลี้ยง feature ในข้อ 4.1 **ไม่ใช่เพื่อเช็ค auth ซ้ำกับ PMG**
ถ้าอยากตัดทิ้งเพื่อลด latency ทำได้ในอนาคต — แต่ต้อง retrain Stage 2 ให้ feature มาจาก PMG แทน จะได้ไม่ skew (งานรอบหน้า)

---

## 5. อีก 1 field ที่อยากขอเพิ่มจาก PMG (ถ้ามี)

ตอนนี้ AI หา sender IP จาก `Received` header เพื่อเอาไปเช็ค AbuseIPDB (reputation) — ซึ่งคุณพูดถูกว่า **header ปลอมได้**
ถ้า PMG ส่ง **connection-level IP จริง** มาด้วย (เช่น field `sender_ip`) เราจะเอาไปเช็ค AbuseIPDB ได้แม่นกว่าที่อ่านจาก header เยอะ — สนใจส่งเพิ่มไหมครับ? (optional เหมือนกัน ไม่ส่งก็ fallback header เหมือนเดิม)

---

## 6. สถานะ
- ✅ แก้โค้ด + ทดสอบครบ 5 สถานการณ์ (PMG อย่างเดียว / มี header / ขัดกัน / ไม่ส่งอะไร / dkim bool→string)
- ✅ แก้บั๊ก cache ที่เจอระหว่างทาง: เดิม cache key ใช้แค่เนื้อความ → body เดียวกันแต่ auth ต่าง (phishing template ส่งหลายโดเมน) จะได้ auth เก่าจาก cache · ตอนนี้ key รวม auth แล้ว
- ⏳ รอ deploy `main.py` ขึ้น production (จะแจ้งเมื่อขึ้นแล้ว)

**backward-compatible 100%** — caller เดิมที่ยังไม่ส่ง field auth ใหม่ ยังทำงานเหมือนเดิมทุกอย่าง (fallback ไปอ่าน header)
