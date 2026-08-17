# [ต้องแก้] เปลี่ยน contract ของ /analyze — AI ตอบ raw_signals กลับ Gateway ตรงๆ

**ถึง:** เจ้าของ Gateway (ZeroTier 10.22.1.66)
**จาก:** AI Server (10.22.1.94)
**สรุป:** AI Server **เลิกยิง `/assess` ไป .92 เองแล้ว** — เปลี่ยนมาตอบ **raw signals** กลับ Gateway ใน response ของ `/analyze` แทน · จากนั้น **Gateway + mail server จัดการ downstream กันเอง** (คิด risk score, เขียน DB, ตัดสิน deliver/quarantine) — จะทำเองหรือส่งต่อ risk service (.92) ก็แล้วแต่ฝั่ง Gateway

---

## เปลี่ยน flow

**เดิม:**
```
Gateway --/analyze--> AI Server --/assess--> .92 (คิดคะแนน+เขียน DB)
                                   <--summary--
Gateway <--summary-- AI Server
```

**ใหม่:**
```
Gateway --/analyze--> AI Server  (ตรวจ BERT/XGBoost/threat-intel)
Gateway <--raw_signals-- AI Server      ← AI จบหน้าที่ตรงนี้
Gateway + mail server  → คิด risk score + เขียน DB + ตัดสิน deliver/quarantine กันเอง
                         (ถ้ายังใช้ risk service .92 ก็ POST raw_signals ต่อได้ key ตรงกันหมด)
```

## response ใหม่ของ `POST /analyze` (สิ่งที่ Gateway จะได้รับ)
เดิมได้ `{"summary": {...}}` — **ตอนนี้ได้:**
```json
{
  "raw_signals": {
    "sender_domain": "...", "sender_email": "...", "recipient": "...",
    "spf_result": "none", "dkim_result": "none", "dmarc_result": "pass|fail|none",
    "reply_to_mismatch": true, "sender_spoofing": false,
    "attachment_type": [".pdf"], 
    "raw_ai_score": 0-100, "raw_link_score": 0-100, "abuseipdb_score": 0-100,
    "subject": "...", "body_text": "...", "attack_type": "Phishing|Spam|BEC|Malware|Normal"
  }
}
```

## สิ่งที่ Gateway + mail server ต้องทำต่อ (จุดสำคัญ)
รับ `raw_signals` แล้วเอาไปคิด risk score + เขียน DB + ตัดสิน deliver/quarantine เอง
**ถ้ายังใช้ risk service (.92)** ก็ POST `raw_signals` ทั้งก้อนต่อได้เลย (key ตรงกับที่ /assess รับอยู่แล้ว):

```
POST http://10.22.1.92:8000/assess   (ถ้ายังใช้ .92 — ไม่บังคับ)
Header: X-Security-Token: <API_SECRET_KEY เดียวกับที่ใช้อยู่>
Body:   <raw_signals ทั้งก้อน>
timeout: ~8s
```
.92 จะตอบ `{"summary": {final_risk_score, risk_level, action_color, attack_type}, "details": {...}}`
→ เอา `summary.risk_level` ไปตัดสิน deliver/quarantine/block

## เคสพิเศษ (ต้อง handle)
- ถ้า response มี `"status": "timeout_fallback"` → คือ AI กำลังประมวลผล request ซ้ำอยู่ยังไม่เสร็จ → Gateway ควร retry สั้นๆ หรือ deliver แบบ Warning ไว้ก่อน
- ถ้า risk service ล่ม → Gateway/mail server ควร fallback เป็น Warning เอง (เดิม AI ทำ fallback ให้ ตอนนี้ย้ายมาเป็นหน้าที่ฝั่ง Gateway)

## ⚠️ สำคัญเรื่อง DB / Dashboard
เดิม AI เป็นคนสั่งเขียน DB — **ตอนนี้ AI ไม่เขียน DB แล้ว** ถ้า Gateway/mail server ไม่เขียน log ลง DB เอง dashboard/logs จะว่าง ดังนั้นฝั่ง Gateway **ต้อง** เขียน log ทุก request

## ลำดับ deploy
1. **AI Server (.94)**: deploy `main.py` ใหม่ (ตอบ raw_signals) — ทำแล้ว
2. **Gateway (.66) + mail server**: แก้รับ `raw_signals` แล้วคิด risk + เขียน DB + ตัดสิน deliver เอง (ตาม note นี้) · ถ้ายังใช้ .92 ดู `NOTE_for_92.md` (key `abuseipdb_score`) + `NOTE_for_92_scoring.md`

> ถ้า deploy AI ก่อนแต่ Gateway ยังรอ `summary` อยู่ → Gateway จะ error/ได้ค่าว่าง จนกว่าจะแก้ให้รับ `raw_signals`

## หมายเหตุ
- AI ไม่ต้องรู้ IP ของ Gateway (.66) — ตอบกลับ connection เดิม (synchronous HTTP response)
- path เก่า (AI push /assess ไป .92 เอง) ถูก **ลบออกจาก main.py แล้ว** (`call_assess`/`ASSESS_URL` ไม่มีในโค้ดอีกต่อไป) — ไม่มี rollback ในโค้ด ถ้าจะกลับ flow เก่าต้องเขียนใหม่
