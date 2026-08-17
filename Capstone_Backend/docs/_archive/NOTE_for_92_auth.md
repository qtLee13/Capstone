# [อัปเดต] สัญญาณ SPF/DKIM/DMARC ใน raw_signals เป็น "ผลจริงต่อฉบับ" แล้ว (P4)

**ถึง:** เจ้าของเครื่อง Storage/Risk Server (.92)
**จาก:** AI Server (10.22.1.94)
**สรุป:** AI server อ่าน `Authentication-Results` header (ที่ Proxmox ใส่มา) แล้วส่งผล **SPF/DKIM/DMARC จริงต่อฉบับ** ใน `raw_signals` — เดิม `spf_result`/`dkim_result` hardcode `"none"` และ `dmarc_result` มาจาก `checkdmarc` (เช็คแค่ว่าโดเมน "มี DMARC record ไหม" ไม่ใช่ "ฉบับนี้ผ่านไหม")

---

## ทำไมสำคัญ (แก้ช่องโหว่ auth-trust)
เดิม `compute_final_score` มี auth-trust override: `authenticated = (dmarc_status == "pass" ...)`
- เมล **spoof จาก paypal.com** → `checkdmarc` เห็นว่า paypal *มี* DMARC record → คืน `"pass"` → **auth-trust หลงเชื่อ ลดคะแนน!** (ช่องโหว่)
- ตอนนี้ `dmarc_result` มาจาก `Authentication-Results: dmarc=fail` จริง → **ไม่ถูก trust** (ถูกต้อง)

## สิ่งที่เปลี่ยนใน raw_signals (ฝั่ง AI ทำแล้ว)
| field | เดิม | ตอนนี้ |
|---|---|---|
| `spf_result` | `"none"` เสมอ | `pass/fail/softfail/none/temperror...` (จริง) |
| `dkim_result` | `"none"` เสมอ | `pass/fail/none...` (จริง) |
| `dmarc_result` | checkdmarc (record มีไหม) | **ผล DMARC จริงต่อฉบับ** (fallback checkdmarc ถ้าไม่มี header) |

## สิ่งที่ `.92` ควรทำ (ไม่บังคับ แต่แนะนำ)
1. **ไม่ต้องแก้ก็ได้** — `dmarc_status == "pass"` ยังทำงานถูก (ค่าใหม่ยังมี "pass"/"fail")
2. **แนะนำ:** ใช้ `spf_result`/`dkim_result` ที่ตอนนี้เป็นค่าจริงแล้ว มาเสริมการให้คะแนน เช่น
   - spf=fail หรือ dkim=fail → เพิ่มสัญญาณ spoofing
   - เข้มขึ้นได้: auth-trust ควรต้อง `spf==pass และ dkim==pass และ dmarc==pass` (แทนที่จะดูแค่ dmarc)

## หมายเหตุ (สำคัญ — กัน misuse)
- ผล auth เหล่านี้ **ใช้สำหรับ scoring เท่านั้น** ไม่ได้เอาไปเป็น feature ของโมเดล Stage 2
  (เพราะ spam corpus ตอนเทรนไม่มี Authentication-Results → ถ้าเอาเป็น feature จะเกิด cross-source artifact)
- `dmarc_fail` ที่เป็น **feature** ของโมเดล ยังมาจาก checkdmarc เหมือนเดิม (uniform train/serve)
