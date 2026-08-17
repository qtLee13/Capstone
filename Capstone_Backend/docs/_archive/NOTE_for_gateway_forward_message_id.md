# โน้ตถึงทีม Gateway (.66) — ช่วย forward `message_id` ต่อเข้า `/assess`

**จาก:** ทีม AI Server (.94) · **วันที่:** 2026-07-25 · **ต้องการ:** เพิ่ม 1 field ตอน forward ไป `/assess`

---

## สรุปสั้น

ทีม mail server (.92) ทำ **safe-dedup** กัน re-ingest เสร็จแล้ว (เงื่อนไข: `email_hash` **และ** `message_id` ตรงทั้งคู่ถึงจะข้าม — ไม่ใช้ hash เดี่ยวเพราะ hash ชนกันได้กับเมลไทย)

เพื่อให้ dedup ทำงาน `/assess` ต้องได้รับ `message_id` — **AI ใส่ให้ใน `raw_signals` แล้ว** แต่ AI ตอบกลับมาที่ Gateway ไม่ได้ยิงเข้า `/assess` เอง → **ต้องให้ Gateway ส่งต่อ field นี้ไปด้วย**

---

## flow

```
AI /analyze ──(raw_signals มี message_id แล้ว ✅)──> Gateway (.66) ──forward──> /assess (.92)
                                                          └── ตรงนี้ต้องพา message_id ไปด้วย
```

## สิ่งที่ AI ใส่ให้แล้ว (live บน .94)

`raw_signals` ตอนนี้มี field `message_id` เพิ่มเข้ามา (เทสแล้ว):
```jsonc
{
  "raw_signals": {
    "email_hash":  "7d4e2d05...",
    "message_id":  "<real42@evil.xyz>",   // 🆕 แกะจาก Message-ID header ของเมล ("" ถ้าไม่มี)
    "sender_domain": "...",
    ...
  }
}
```

## 👉 ที่อยากขอ

ตอนที่ Gateway forward ผลเข้า `/assess` ของ `.92` **ขอให้พา `message_id` (และ `email_hash` ถ้ายังไม่ได้ส่ง) ติดไปด้วย** — ถ้าตอนนี้ forward แค่บาง field ของ raw_signals ให้เพิ่ม 2 ตัวนี้เข้าไป

- ทั้งคู่เป็น string ล้วน ไม่มี logic เพิ่ม
- backward-compatible: ถ้ายังไม่ส่ง `.92` ก็แค่ไม่ dedup (ไม่พังอะไร)

## เช็คได้

ยิง `/analyze` ดู raw_signals ที่ AI ตอบ (มี message_id ครบ):
```bash
curl -s -X POST http://10.22.1.94:8000/analyze -H "X-Security-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"text":"From: a@x.com\nMessage-ID: <abc@x.com>\nSubject: hi\n\nbody"}' | python3 -m json.tool
```

ขอบคุณครับ 🙏 พอ Gateway พา `message_id` ไปถึง `/assess` แล้ว dedup กัน re-ingest ของ `.92` จะทำงานครบวง
