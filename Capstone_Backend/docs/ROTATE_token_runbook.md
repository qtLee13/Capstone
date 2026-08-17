# Runbook: หมุน API token แบบ Zero-Downtime

**จาก:** ทีม AI Server (.94) · **วันที่:** 2026-07-25
**ถึง:** Gateway (.66), Dashboard (.181), mail server (.92) — ทุกทีมที่ส่ง `X-Security-Token` เข้า AI

---

## ทำไมต้องหมุน

token ปัจจุบัน (ค่า `cap_super_...` ที่ตั้งไว้ตั้งแต่แรก) **ถูก commit ไว้ใน repo** (`docs/ASSESS_API_SPEC.md`) และถูก paste ในเทอร์มินัลหลายที่ → ถือว่า "รั่ว" ต้องเปลี่ยนเป็นค่าสุ่มใหม่ที่ไม่เคยขึ้น git

## ข่าวดี: ไม่ต้องนัดเวลาปิดพร้อมกัน

AI รองรับ **2 token พร้อมกันชั่วคราว** แล้ว (deploy รอบล่าสุด) — ระหว่าง grace period จะรับทั้ง token เก่าและใหม่ **แต่ละทีมย้ายเมื่อไหร่ก็ได้ ไม่มี downtime** ไม่ต้องนัดวินาทีเดียวกัน

---

## ลำดับการหมุน (ใครทำอะไร)

### 🟦 Phase 1 — AI เปิด grace (ทีม AI ทำ)
1. สร้าง token ใหม่บน VM (อย่า paste ในแชท/commit):
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```
2. แก้ `~/ai_project/.env` บน VM:
   ```
   API_SECRET_KEY=<token ใหม่ที่เพิ่งสร้าง>
   API_SECRET_KEY_OLD=<ค่า API_SECRET_KEY เดิมที่อยู่ใน .env ตอนนี้>
   ```
3. restart uvicorn
4. เช็ค log ตอน start ต้องเห็น: `⏳ โหมดหมุน token: ยังรับ API_SECRET_KEY_OLD อยู่ชั่วคราว`

➡️ **ตอนนี้ AI รับทั้ง 2 token** — ทุกทีมยังทำงานได้ด้วย token เก่า ไม่มีใครล่ม

### 🟩 Phase 2 — แต่ละทีมย้ายมา token ใหม่ (Gateway/Dashboard/.92 ทำ — เมื่อไหร่ก็ได้)
- ทีม AI จะส่ง **token ใหม่ให้ทาง private** (ไม่ลง repo/chat กลาง)
- แต่ละทีมแก้ config ฝั่งตัวเอง (`X-Security-Token`) เป็นค่าใหม่ แล้ว restart service ตัวเอง
- ไม่ต้องรอทีมอื่น ไม่ต้องนัดเวลา — ย้ายเสร็จทีละทีมได้เลย

### 🟥 Phase 3 — ปิด token เก่า (ทีม AI ทำ เมื่อทุกคนย้ายครบ)
- ทีม AI ดู log: ทุกครั้งที่ยังมีใครใช้ token เก่าจะมี
  `⚠️ มี request ใช้ token เก่า (API_SECRET_KEY_OLD) — ทีมนี้ยังไม่ย้ายมา token ใหม่`
- **พอ log นี้เงียบสนิท (เช่น 24 ชม. ไม่มีเลย) = ทุกทีมย้ายครบแล้ว**
- ลบบรรทัด `API_SECRET_KEY_OLD` ออกจาก `.env` → restart → **token เก่าตายทันที**
- ลบ token เก่าออกจาก `docs/ASSESS_API_SPEC.md` (เปลี่ยนเป็น `<token>` placeholder)

---

## ตรวจสอบระหว่างทาง

```bash
# ยังมีใครใช้ token เก่าอยู่ไหม (ดูก่อนตัดใน Phase 3)
grep "ใช้ token เก่า" ~/ai_project/uvicorn.log | tail
```

## ตอบ Gateway โดยตรง

> ไม่ต้องนัดเวลาปิดพร้อมกันครับ — AI รับ 2 token พร้อมกันได้แล้ว (grace mode)
> พอเราเปิด Phase 1 + ส่ง token ใหม่ให้ คุณแก้ config ฝั่ง Gateway **เมื่อไหร่ก็ได้** ไม่มี downtime
> ของเก่ายังใช้ได้จนกว่าเราจะยืนยันว่าทุกทีมย้ายครบแล้วค่อยตัด

---

## หมายเหตุความปลอดภัย
- token ใหม่ **ห้าม**ขึ้น git / chat กลาง — ส่งผ่านช่องทางส่วนตัวเท่านั้น
- `.env` ไม่ commit อยู่แล้ว (มีใน `.gitignore`) · `.env.example` ใส่แค่ชื่อ key ไม่ใส่ค่า
