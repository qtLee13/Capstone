# API Spec สำหรับทีม Dashboard (เครื่อง 4)

ดึงข้อมูลทั้งหมดจาก Storage/Mail Server:

```
Base URL: http://10.22.1.92:8000
Header (ทุก endpoint ยกเว้น /dashboard): X-Security-Token: cap_super_secret_key_2026
CORS: เปิด allow ทุก origin แล้ว - fetch จาก React ได้ตรงๆ
```

---

## 1. สถิติหน้าแรก

### `GET /dashboard?period=today|7days|30days`
ไม่ต้องใช้ token — คืนสถิติสำเร็จรูปทั้งหน้า:
```json
{
  "stats": {"emailsToday": 10, "phishingDetected": 4, "phishingRate": 40.0,
            "allowed": 5, "warning": 1, "quarantined": 3, "blocked": 1,
            "blockRate": 100.0, "avgRiskScore": 46.2},
  "volume":   {"labels": ["Jul 09", ...], "total": [...], "phishing": [...]},
  "riskDist": [{"label": "Low (0–40)", "count": 12, "color": "#22c55e"}, ...],
  "domains":  [{"name": "evil.xyz", "count": 3}, ...],
  "users":    [{"email": "user@corp.com", "dept": "N/A", "hits": 5}, ...],
  "types":    [{"label": "Phishing", "count": 4, "color": "#3b82f6"}, ...]
}
```

## 2. Log ผลวิเคราะห์ (ตาราง email_logs)

### `GET /logs?risk_level=&limit=10`
- `risk_level` (ไม่บังคับ): `allow` | `warning` | `quarantine` | `block`
- **เมลที่ยังไม่ถูกส่งเข้ากล่องผู้ใช้ = `quarantine` (ตัวเมลค้างอยู่ที่นี่) กับ `block` (ถูกทิ้งที่ Gateway เหลือแต่ log)**
- `limit` สูงสุด 200
```json
{"status": "success", "count": 5, "data": [
  {"id": 42, "timestamp": "...", "sender_domain": "paypal.com", "recipient": "user@corp.com",
   "subject": "Account Review Required", "final_score": 72.5, "ai_score": 18.4,
   "link_risk": 20.0, "domain_risk": 12.5, "header_anomaly": 6.0,
   "risk_level": "quarantine", "is_phishing": true, "attack_type": "Phishing"}]}
```

## 3. เมลจริงในห้องกักกัน (สำหรับหน้า admin ตรวจสอบ)

### `GET /mailbox/quarantine` — รายการไฟล์เมลที่ถูกกัก
`?user=alice` กรองตามผู้รับได้ → `{"count": 4, "messages": ["user_2026...eml", ...]}`

### `GET /mailbox/quarantine/{filename}` — เปิดอ่านฉบับเต็ม
→ `{"raw_email": "From: ...\n..."}` (ชื่อไฟล์บอกผู้รับ+เวลา: `user_20260715T101415.eml`)

### `GET /mailbox/inbox` / `GET /mailbox/inbox/{filename}` — ฝั่ง inbox แบบเดียวกัน

## 4. ปุ่มคำสั่งของ admin

### `POST /mailbox/quarantine/{filename}/release?log_id={id}`
admin ตรวจแล้วว่าเป็น false positive → ย้ายเมลเข้า inbox + โผล่ใน IMAP ของ user ทันที
- `log_id` (ไม่บังคับ): ถ้าส่งมา แถวใน email_logs จะถูกแก้เป็น allow/is_phishing=false ให้สถิติตรง
```json
{"status": "released", "filename": "...", "moved_to": "inbox", "log_updated": true}
```

## 5. Rule Base (admin flag เมลไม่ดี)

### `POST /rules` — สร้างกฎบล็อก
```json
// แบบ A: flag จาก log ที่ admin เปิดดู (ระบบดึงโดเมนผู้ส่ง/หัวข้อจาก log ให้เอง)
{"log_id": 42, "rule_type": "sender"}          // หรือ "subject"
// แบบ B: พิมพ์เอง
{"rule_type": "body", "pattern": "crypto giveaway", "note": "สแกมแจกเหรียญ"}
```
- `rule_type`: `sender` (จับที่อยู่/โดเมนผู้ส่ง) | `subject` (จับคำในหัวข้อ) | `body` (จับคำในเนื้อหา)
- ผล: เมลใหม่ทุกฉบับที่เข้าเงื่อนไขจะถูกกักกันอัตโนมัติทันที (ด่านตรวจรอบสองก่อนเข้ากล่องผู้ใช้)

### `GET /rules` — รายการกฎทั้งหมด (Gateway ก็ดึงตัวนี้ไป block ที่ด่านแรก)
### `DELETE /rules/{id}` — ถอนกฎ

---

## หมายเหตุการเชื่อมต่อ
- เครื่อง Dashboard ต้องอยู่วง ZeroTier เดียวกัน (ping 10.22.1.92 ต้องผ่าน)
- frontend เดิมในโปรเจกต์ (capstone-dashboard) ตั้ง `API_BASE = 'http://127.0.0.1:8000'` ใน `src/App.jsx` และ `src/EmailLogs.jsx` — ถ้ารันบนเครื่อง 4 ต้องแก้เป็น `http://10.22.1.92:8000`
- endpoint ที่ต้องแนบ token: ทุกตัวยกเว้น `GET /dashboard` และ `GET /logs`
