# [ต้องแก้] เปลี่ยนชื่อ field `ipqs_score` → `abuseipdb_score` (payload /assess)

**ถึง:** เจ้าของเครื่อง Storage/Risk Server (.92)
**จาก:** AI Server (10.22.1.94)
**สรุป:** เปลี่ยนชื่อ field เดียวใน payload ที่ AI Server ยิงเข้า `POST /assess` — รบกวนแก้ฝั่งรับด้วย

---

## สิ่งที่เปลี่ยน (แค่ชื่อ ค่าเหมือนเดิมทุกอย่าง)

| เดิม | ใหม่ |
|------|------|
| `"ipqs_score": <0–100>` | `"abuseipdb_score": <0–100>` |

- ความหมายเท่าเดิม = คะแนน **IP reputation** (สูง = อันตราย)
- ที่มา = **AbuseIPDB** (เดิมตั้งชื่อผิดเป็น ipqs แต่ source เป็น AbuseIPDB อยู่แล้ว)
- ช่วงค่า / ชนิดข้อมูลเหมือนเดิม (float 0–100)

## จุดที่ต้องแก้ฝั่ง .92

1. **จุดรับ payload `/assess`** — ที่อ่าน `payload["ipqs_score"]` / `.get("ipqs_score")` / field ใน Pydantic model → เปลี่ยนเป็น `abuseipdb_score`
2. **สูตรคิดคะแนน** — ถ้ามี `compute_final_score(...)` หรือ weight ที่ใช้ param ชื่อ `ipqs_score` → เปลี่ยนเป็น `abuseipdb_score`
3. **เขียน DB** — คอลัมน์ `domain_risk` (ตาราง `email_logs`) **ชื่อเดิมไม่ต้องแก้** แค่ให้ค่ามาจาก field ใหม่
4. **response `/assess`** — ถ้ามี echo field นี้กลับใน `details` → เปลี่ยนชื่อเป็น `abuseipdb_score` (Gateway/Dashboard จะได้ตรงกัน)

## ไม่ต้องแก้ / ไม่เปลี่ยน

- field อื่นทั้งหมด: `raw_ai_score`, `raw_link_score`, `dmarc_result`, `reply_to_mismatch`, `attachment_type`, `attack_type`, `sender_domain`, `subject`, `body_text` ฯลฯ
- endpoint, auth, ช่วงค่า, เกณฑ์ risk_level — เหมือนเดิมหมด

## สำคัญ: deploy พร้อมกัน

AI Server ส่ง key ใหม่ `abuseipdb_score` แล้ว → ถ้า .92 ยังอ่าน `ipqs_score` อยู่ field นี้จะกลายเป็น **null/0** จนกว่าจะแก้

> FYI: ฝั่ง AI ใส่ `ABUSEIPDB_API_KEY` ใน .env แล้ว และทดสอบผ่าน (Tor exit IP → abuseScore=100) — ค่านี้ทำงานจริง ส่งค่าจริงเข้า `/assess` แล้ว
