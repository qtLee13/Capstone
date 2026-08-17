# ตอบทีม Gateway — เคส False Positive ของ `link_risk` (Yahoo Groups)

**จาก:** ทีม AI Server (10.22.1.94) · **วันที่:** 2026-07-22 · **สถานะ:** ✅ แก้แล้ว + deploy ขึ้น production แล้ว (2026-08-04)

---

## สรุปสั้น

รายงานของคุณ **ถูกต้อง** และทำให้เราเจอ **ต้นตอที่ลึกกว่านั้น — บั๊กอยู่ฝั่งเรา**

ปัญหาไม่ได้อยู่แค่ที่ threshold 70 ถูกปฏิบัติเหมือน 100 (ซึ่งก็จริงและควรแก้) แต่คือ **อีเมลฉบับนั้นไม่ควรได้ 70 ตั้งแต่แรก** — เป็น false positive ที่เกิดจากโค้ดฝั่ง AI ของเราเอง

| | |
|---|---|
| 🐛 ต้นตอ | ฝั่ง AI — การเทียบ TLD ใช้ substring matching |
| ✅ แก้แล้ว | `us.click.yahoo.com` เดิม **70** → ตอนนี้ **10** |
| 🆕 เพิ่มให้ | `link_confidence` แยก `suspicious` / `confirmed` ตามที่คุณเสนอ |
| 🔴 เจอเพิ่ม | **`sender_ip` ที่ PMG ส่งมา ถูกทิ้งเงียบๆ** (ดูข้อ 4) |

---

## 1. ต้นตอจริง: เทียบ TLD แบบ substring

โค้ดเดิมฝั่งเรา:

```python
if any(tld in url.lower() for tld in ['.xyz', '.top', '.click', '.tk']):
    risk += 60      # 10 + 60 = 70
```

`in` แปลว่า **"มีคำนี้อยู่ที่ไหนก็ได้ใน URL"** ไม่ใช่ "ลงท้ายด้วย TLD นี้" ผลคือ:

| URL | เดิม | ทำไมถึงโดน |
|---|---|---|
| `us.click.yahoo.com/...` | 🔴 70 | `.click` เป็น **subdomain** ไม่ใช่ TLD ← เคสของคุณ |
| `www.topgear.com/news` | 🔴 70 | มี `.top` อยู่ใน `topgear` |
| `erp.clicksuite.com.br/...` | 🔴 70 | มี `.click` อยู่ใน `clicksuite` |
| `cdn.tkmaxx.com/img.png` | 🔴 70 | มี `.tk` อยู่ใน `tkmaxx` |

### วัดขนาดปัญหาบนข้อมูลจริง

สแกน corpus 8,612 ฉบับ (28,537 URL):

```
URL ที่ "ติดกฎ" ด้วยการเทียบแบบเดิม : 158
  ├─ TLD เสี่ยงจริง                : 118  (74.7%)
  └─ 🔴 FALSE POSITIVE             :  40  (25.3%)
```

**1 ใน 4 ของทุกครั้งที่กฎนี้ยิง เป็นการยิงผิด**

และในคลัง SpamAssassin ทั้งหมด มีอีเมล 5 ฉบับที่ได้ 70 จากกฎนี้ — **เป็น false positive ทั้ง 5 ฉบับ**:
`top-lenders.com` · `click.top-special-offers.com` · `clickXchange.com` · `topsitez.us` · `toplinequotes.com`
(ทุกอันเป็น `.com`/`.us` ธรรมดา)

### แก้แล้ว

ตอนนี้แกะ hostname ออกมาก่อน แล้วเทียบเฉพาะ **ท้าย hostname** เท่านั้น:

```python
def has_risky_tld(url):
    return url_host(url).endswith(RISKY_TLDS)   # เทียบที่ TLD จริง
```

**ผลทดสอบกับเคสของคุณ:**
```
Yahoo Groups sponsor (us.click.yahoo.com)   70 -> 10   ✅
www.topgear.com                             70 -> 10   ✅
verify-account.top (ฟิชชิ่งจริง)             70 -> 70   ✅ ยังจับได้
45.83.12.9 (ใช้ IP แทนโดเมน)                90 -> 90   ✅ ยังจับได้
```

---

## 2. `link_confidence` — ทำตามข้อเสนอของคุณ

เห็นด้วยเต็มที่ว่าต้องแยก "รู้แน่ชัด" ออกจาก "ไม่แน่ใจ" (ตรรกะเดียวกับ `abuseipdb_measured`)
เพิ่ม field ใหม่ใน `raw_signals` แล้ว **ฝั่งคุณไม่ต้องเดาจากตัวเลขอีก**:

```jsonc
{
  "raw_signals": {
    "raw_link_score":  70,             // เหมือนเดิม ไม่เปลี่ยน contract
    "link_confidence": "suspicious",   // 🆕
    ...
  }
}
```

| `link_confidence` | คะแนน | มาจากอะไร | ควรใช้ยังไง |
|---|---|---|---|
| `"confirmed"` | 100 | **VirusTotal ยืนยันว่าเป็นมัลแวร์** | ✅ ใช้ hard override ได้เลย |
| `"suspicious"` | 70–99 | เดาจากรูปแบบ URL (TLD เสี่ยง / ใช้ IP แทนโดเมน) | ⚠️ **ต้องรวมกับสัญญาณอื่นก่อนตัดสิน** |
| `"low"` | 10 | มีลิงก์ แต่ไม่มีอะไรน่าสงสัย | ปกติ |
| `"none"` | 0 | ไม่มีลิงก์ | ปกติ |

### 👉 ที่อยากขอให้แก้ใน `risk_engine.py`

ข้อเสนอของคุณถูกต้องแล้วครับ ขอเสนอให้ใช้ `link_confidence` แทนการเทียบตัวเลขเอง:

```python
conf = raw.get("link_confidence", "suspicious")   # default เผื่อ response รุ่นเก่า

if conf == "confirmed":
    final_score = max(final_score, 85)      # ยืนยันแล้ว — override ได้
elif conf == "suspicious":
    final_score += 20                       # สงสัย — บวกคะแนน ไม่ override
    # ให้ ai_score/auth/reputation มีสิทธิ์ถ่วงกลับได้
```

**ทำไมถึงสำคัญ:** ในเคสของคุณ BERT ให้ `ai_score = 0.26` ซึ่งแปลว่า *"มั่นใจ 99.7% ว่าไม่ใช่ฟิชชิ่ง"* แต่ hard override ทำให้เสียงนั้นไม่ถูกนับเลย · ระบบ 2 ชั้นจะมีประโยชน์ก็ต่อเมื่อสัญญาณได้ถ่วงน้ำหนักกัน ไม่ใช่ให้สัญญาณเดียวชี้ขาด

> 💡 **หมายเหตุสำคัญ:** ปัจจุบันระดับ `"confirmed"` จะเกิดขึ้นก็ต่อเมื่อ VirusTotal รู้จัก URL นั้นและฟันธงว่าอันตราย
> ถ้าไม่ได้ตั้ง VT API key ไว้ **จะไม่มีอีเมลไหนได้ `confirmed` เลย** — ควรออกแบบ scoring ให้ทำงานได้ดีแม้ไม่มี confirmed

---

## 3. เคสของคุณหลังแก้ (ทดสอบจริง)

```
อีเมล: Stewart.Smith@ee.ed.ac.uk + ลิงก์ us.click.yahoo.com/...

  raw_ai_score    = 0.67      (BERT ยืนยันว่าปกติ)
  raw_link_score  = 10.0      ← เดิม 70
  link_confidence = "low"     ← ไม่เข้าเงื่อนไข override อีกต่อไป
```

→ ต่อให้ `risk_engine.py` ยังไม่แก้ อีเมลแบบนี้ก็จะไม่โดน override 85 แล้ว **แต่ยังแนะนำให้แก้อยู่ดี** เพราะ `suspicious` จริงๆ ก็ไม่ควร override เดี่ยวๆ

---

## 4. 🔴 เรื่องด่วน: `sender_ip` ที่ PMG ส่งมา ถูกทิ้งไปทั้งหมด

คุณบอกว่า *"PMG ส่ง sender_ip เข้า /analyze ทุกครั้งอยู่แล้ว"* — เราตรวจแล้ว **field นั้นไม่เคยถูกอ่านเลยครับ**

สาเหตุเดียวกับเคส SPF/DKIM รอบก่อน: ตัวรับ request (pydantic model) ไม่มี field ชื่อนี้ → **ถูกทิ้งเงียบๆ ตั้งแต่ก่อนถึง logic** ไม่มี error ให้เห็น

**แก้แล้ว** — ตอนนี้:
- ถ้า PMG ส่ง `sender_ip` มา → ใช้ตัวนั้นเช็ค AbuseIPDB (ปลอมไม่ได้)
- ถ้าไม่ส่ง → fallback อ่าน `Received` header เหมือนเดิม
- ถ้าสองค่าขัดกัน → **log warning** ไว้ (อาจเป็นสัญญาณว่า header ถูกปลอม)
- `raw_signals.auth_source.sender_ip` บอกว่าใช้ค่าจากไหน: `pmg` / `header` / `none` / `not_checked`

**ผลทดสอบ — ต่างกันจริงและต่างกันเยอะ:**
```
ไม่ส่ง sender_ip    -> ip_source=header  abuseipdb=97   ← IP จาก header
PMG ส่ง 45.83.12.9  -> ip_source=pmg     abuseipdb=0    ← IP จริงจาก connection
```

> ระหว่างทางยังเจอบั๊ก **L1 cache** ด้วย: cache key ไม่ได้รวม `sender_ip` ทำให้อีเมลเนื้อหาเดียวกันจาก IP คนละตัวได้คำตอบเก่า (ฟิชชิ่งชุดเดียวกันยิงจากหลาย IP จะได้ reputation ผิด) — แก้แล้วเช่นกัน

---

## 5. สิ่งที่เปลี่ยนทั้งหมด

| รายการ | กระทบ API ไหม |
|---|---|
| 🐛 แก้การเทียบ TLD (substring → ท้าย hostname) | ไม่ — แค่ค่า `raw_link_score` แม่นขึ้น |
| 🆕 `link_confidence` ใน `raw_signals` | เพิ่มอย่างเดียว backward-compatible |
| 🆕 รับ `sender_ip` ใน request (optional) | เพิ่มอย่างเดียว ไม่ส่งก็ทำงานเหมือนเดิม |
| 🆕 `auth_source.sender_ip` ใน `raw_signals` | เพิ่มอย่างเดียว |
| 🔧 cache key รวม `sender_ip` | ภายใน ไม่กระทบ |
| 🔧 เทรน Stage 2 ใหม่ | ไม่ — จำนวน/ชื่อ field เท่าเดิม |

**เรื่องเทรนใหม่:** เพราะ `link_risk` เป็น feature ของโมเดล Stage 2 พอแก้สูตรแล้วต้องเทรนใหม่ ไม่งั้นค่าตอนใช้งานจะไม่ตรงกับตอนเทรน
ตรวจแล้วกระทบชุดเทรนแค่ **1 จาก 952 แถว** (0.1%) ผลลัพธ์แทบไม่ขยับ (weighted-F1 0.6891 → 0.6903) แต่เทรนใหม่เพื่อให้สองฝั่งตรงกันเป๊ะ

---

## 6. 🙏 ขอบคุณจริงๆ

รายงานนี้มีค่ามากครับ เพราะเป็นบั๊กที่ **มองไม่เห็นจากฝั่งเราเลย** — ตัวเลข 70 ดูสมเหตุสมผลในล็อก ไม่มี error ไม่มีอะไรผิดปกติ ต้องมีคนเห็นอีเมลจริงที่โดนบล็อกผิดถึงจะจับได้

การที่คุณยิง ham corpus ผ่าน pipeline เต็มเป็นวิธีทดสอบที่ถูกต้องมาก — **ถ้าเจอเคสอื่นอีก ส่งมาได้เลยครับ** โดยเฉพาะเคสที่ `ai_score` ต่ำแต่ final score สูง เพราะนั่นคือสัญญาณว่ามีบางอย่าง override เสียงของโมเดลอยู่

รบกวนส่ง log/raw response ของเคสอื่นที่เจอด้วยได้เลยครับ ยินดีตรวจให้ทุกเคส
