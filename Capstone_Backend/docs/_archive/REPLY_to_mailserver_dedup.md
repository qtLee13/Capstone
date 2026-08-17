# ตอบทีม mail server (.92) — เรื่อง dedup ด้วย email_hash + `/parse` เพิ่ม email_hash ให้แล้ว

**จาก:** ทีม AI Server (.94) · **วันที่:** 2026-07-25 · **สถานะ:** ✅ ตกลง /parse เป็นตัวแกะมาตรฐาน · เพิ่ม `email_hash` ใน /parse

---

## 1. ✅ ตกลงตามนั้น

- ใช้ `/parse` ของ AI เป็นตัวแกะมาตรฐาน ฝั่งคุณไม่ทำ parser ซ้ำ — เยี่ยม ตรงตามที่ควรเป็น
- เรื่องหา IP: เห็นด้วยที่คุณเริ่มดึงจาก access log `/mailbox/quarantine` ได้เลยไม่ต้องรอเรา — พอ .94 กลับมา เราจะเอา `/analyze` log มา cross-check ยืนยัน (`journalctl -u ... | grep INCOMING` เตรียมไว้แล้ว)
- ต้นตอ = re-ingest เมลที่ประมวลผลแล้ว → แก้ที่ "หยุด re-ingest" ตรงกัน

---

## 2. 💡 idea dedup ด้วย email_hash — ดีมาก แต่มี 1 กับดักต้องกันก่อน

ไอเดียใช้ `email_hash` กัน re-ingest ดีมากครับ **แต่ขอเตือนกับดักที่โปรเจกต์นี้เจอมาหลายรอบ:**

### กับดัก: อย่าคำนวณ hash เอง ไม่งั้น key ไม่ตรงกับของเรา

`email_hash` ของเราไม่ใช่ sha256 ของ .eml ตรงๆ — มัน normalize ก่อน (ตัด zero-width/control, NFKD→ASCII, ยุบ whitespace, lowercase) แล้วค่อย hash
**ถ้าฝั่งคุณเขียนสูตร hash เองเพื่อ dedup มันจะตรงกับ hash ที่อยู่ใน `email_logs` ก็ต่อเมื่อสูตร normalize เป๊ะตัวเดียวกันเท่านั้น** — เพี้ยนนิดเดียว (เช่น ไม่ lowercase / ไม่ยุบ whitespace) key จะไม่ตรง แล้ว dedup จะเงียบๆ ไม่ทำงาน โดยไม่มี error (บั๊กสายเดียวกับ train/serving skew ที่เราเจอมา 4 รอบ)

### 🆕 ทางแก้: `/parse` คืน `email_hash` ให้แล้ว

เพิ่ม field `email_hash` ใน response ของ `/parse` แล้ว — **เป็น canonical hash ตัวเดียวกับที่ `/analyze` ใส่ลง `raw_signals.email_hash` เป๊ะ** (ใช้ฟังก์ชันเดียวกัน)

```jsonc
POST /parse  { "text": "<raw .eml>" }
->
{
  "email_hash": "7ef4867c...",   // 🆕 เอาไป dedup ได้เลย ตรงกับที่อยู่ใน email_logs แน่นอน
  "sender": ..., "subject": ..., "spf": ..., ...
}
```

**flow ที่แนะนำ** (dedup ก่อน assess):
```
รับเมลจะ (re-)ingest
  → POST /parse (ถูก ไม่โหลด BERT) → ได้ email_hash
  → hash นี้เคยมีใน email_logs แล้ว?  ── ใช่ → ข้าม ไม่ต้อง /analyze ซ้ำ
                                      └─ ไม่ → POST /analyze ตามปกติ
```
แบบนี้ hash ที่ใช้ dedup = hash ที่โมเดลใช้จริง 100% ไม่มีทางเพี้ยน

---

## 3. ⚠️ ข้อจำกัดที่ต้องรู้ก่อนใช้ hash "ข้าม" การ assess

hash ของเรา **ตัดตัวอักษร non-ASCII (ไทย/CJK) ทิ้งก่อน hash** — เดิมออกแบบไว้กัน spoof ด้วย zero-width/homoglyph แต่มีผลข้างเคียง:

> **อีเมลไทย 2 ฉบับที่เนื้อต่างกัน แต่ header ASCII (From/Subject ที่เป็นอังกฤษ) เหมือนกัน → ได้ email_hash ตรงกัน**
> ทดสอบจริง: body "ประชุมพรุ่งนี้" กับ "โอนเงินด่วนตอนนี้" ที่ header เดียวกัน → hash เดียวกันเป๊ะ

**แปลว่า:**
- ✅ ใช้ dedup **"เมลฉบับเดิมถูก re-ingest ซ้ำ"** — ปลอดภัย (ฉบับเดิม = hash เดิมเสมอ ตรงเป้าหมายคุณพอดี)
- ⚠️ **อย่าใช้ hash เดี่ยวๆ ตัดสิน "ข้ามการ assess ถาวร"** สำหรับเมลที่เนื้อเป็นไทย/CJK เพราะคนละฉบับอาจ hash ชนกัน
  → ถ้าจะใช้ "ข้าม assess" แนะนำ **จับคู่กับ `Message-ID`** ด้วย (hash ตรง **และ** Message-ID ตรง = ฉบับเดียวกันแน่)

> หมายเหตุฝั่งเรา: นี่เป็นข้อจำกัดของ hash ปัจจุบัน (กระทบ L1 cache กับ join key ด้วย) — เราจดไว้เป็นงานที่ควรปรับ (hash แบบเก็บ non-ASCII) แต่ **ยังไม่เปลี่ยนตอนนี้** เพราะ email_logs ฝั่งคุณเก็บ hash สูตรเดิมไว้แล้ว เปลี่ยนพร้อมกันค่อยคุยกันอีกที

---

## 4. สรุปงาน

| งาน | ใคร | สถานะ |
|---|---|---|
| `/parse` เป็นตัวแกะมาตรฐาน | AI (.94) | ✅ ตกลง |
| `email_hash` ใน /parse (canonical dedup key) | AI (.94) | ✅ เพิ่มแล้ว รอ deploy |
| dedup กัน re-ingest ด้วย email_hash (+Message-ID ถ้าจะข้าม assess) | mail server (.92) | 👍 ทำได้เลย |
| ดึง source IP จาก /mailbox log | mail server (.92) | ⏳ กำลังทำ |
| cross-check ด้วย /analyze log | AI (.94) | ⏳ รอ VM ออนไลน์ |
| หยุด re-ingest เมลที่ประมวลผลแล้ว | ทีมต้นตอ (กำลังหา) | ⏳ |

ขอบคุณเรื่อง email_hash ใน log ครับ — ช่วยให้ dedup เป็นไปได้จริง แค่อยากกันไม่ให้ไปคำนวณ hash เองแล้วเพี้ยน เลยเปิดให้ดึงจาก `/parse` ตรงๆ เลย 🙏
