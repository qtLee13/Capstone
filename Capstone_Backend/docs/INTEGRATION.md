# AI Server — Integration Guide (เครื่องที่ 2)

เอกสารสำหรับเพื่อนในทีมที่ต้องเชื่อมต่อกับ **AI Server (ฟอร์ด)**

- **ZeroTier IP:** `10.22.1.94`
- **Port:** `8000`
- **Base URL:** `http://10.22.1.94:8000`
- **Auth:** ทุก endpoint (ยกเว้น `/health`, `/docs`) ต้องส่ง HTTP header:
  ```
  X-Security-Token: <API_SECRET_KEY ที่ตกลงกัน>
  ```
- **API docs (ลองยิงเล่นได้):** `http://10.22.1.94:8000/docs`

---

## สำหรับเครื่องที่ 1 (Gateway) → ยิงอีเมลเข้ามาวิเคราะห์

**`POST /analyze`**

Request:
```http
POST http://10.22.1.94:8000/analyze
X-Security-Token: <API_KEY>
Content-Type: application/json

{
  "text": "<raw email content ทั้งฉบับ รวม header From/Subject/Received>",
  "recipient": "user@corp.com"
}
```

- `text` = เนื้อหาอีเมลดิบทั้งฉบับ (raw `.eml` format) — ระบบ parse header เอง **จำเป็น**
- `recipient` = อีเมลผู้รับ (ไม่ส่งก็ได้ default = `unknown@corp.com`)
- จำกัด rate: **30 requests/นาที** ต่อ IP

Response (อีเมลเสี่ยง):
```json
{
  "summary": {
    "final_risk_score": 65.31,
    "risk_level": "🟠 Quarantine",
    "action_color": "#dd6b20",
    "attack_type": "Business Email Compromise (BEC)"
  },
  "details": {
    "ai_score": 99.47, "link_risk": 10, "header_anomaly": 30,
    "abuseipdb_score": 0, "dmarc_status": "fail", "detected_links": [...]
  }
}
```

Response (อีเมลปลอดภัย — เข้า fast path):
```json
{
  "summary": {"final_risk_score": 0.12, "risk_level": "🟢 Allow", "action_color": "#2f855a", "attack_type": "Normal"},
  "details": {"message": "Safe"}
}
```

**เกณฑ์ risk_level จาก final_risk_score:**
| score | level | ความหมาย |
|-------|-------|----------|
| 0–29  | 🟢 Allow      | ปล่อยผ่าน |
| 30–59 | 🟡 Warning    | เตือน |
| 60–79 | 🟠 Quarantine | กักไว้ |
| 80–100| 🔴 Block      | บล็อก |

> Gateway เอา `risk_level` / `final_risk_score` ไปตัดสินใจว่าจะ forward อีเมลเข้า Mailpit (เครื่อง 4) หรือบล็อก

---

## สำหรับเครื่องที่ 3 (Dashboard) → ดึงสถิติ

มี 2 ทางเลือก:

### ทางเลือก A (แนะนำ): เรียก API `/dashboard`
**`GET /dashboard?period=7days`** (period = `today` | `7days` | `30days`)

```http
GET http://10.22.1.94:8000/dashboard?period=7days
X-Security-Token: <API_KEY>
```

ได้สถิติพร้อมใช้:
```json
{
  "stats": {
    "emailsToday": 1000, "phishingDetected": 50, "phishingRate": 5.0,
    "allowed": 950, "warning": 0, "quarantined": 30, "blocked": 20,
    "blockRate": 100.0, "avgRiskScore": 12.3
  },
  "volume":   {"labels": [...], "total": [...], "phishing": [...]},
  "riskDist": [...], "domains": [...], "users": [...], "types": [...]
}
```
> หมายเหตุ: `period=today` ต้องใช้ PostgreSQL (ใช้ `date_trunc`) — บน SQLite จะ error

### ทางเลือก B: query PostgreSQL ตรงๆ
ทุก record อยู่ในตาราง **`email_logs`** บนเครื่องที่ 4 (PostgreSQL) — schema ด้านล่าง

---

## Database Schema — ตาราง `email_logs`

| column | type | คำอธิบาย |
|--------|------|----------|
| `id` | Integer (PK) | running number |
| `timestamp` | DateTime (UTC) | เวลาที่วิเคราะห์ |
| `sender_domain` | String | โดเมนผู้ส่ง |
| `recipient` | String | อีเมลผู้รับ |
| `subject` | String | หัวข้ออีเมล |
| `final_score` | Float | คะแนนรวม 0–100 |
| `ai_score` | Float | คะแนนจาก BERT |
| `link_risk` | Float | ความเสี่ยงจากลิงก์ |
| `domain_risk` | Float | คะแนน AbuseIPDB |
| `header_anomaly` | Float | ความผิดปกติของ header |
| `risk_level` | String | `allow` / `warning` / `quarantine` / `block` |
| `is_phishing` | Boolean | true = อันตราย (score ≥ 30) |
| `attack_type` | String | `Normal`, `BEC`, `Spear Phishing`, `Malware Attachment`, ... |

> อีเมลทุกฉบับถูกบันทึก (ทั้ง safe และ phishing) → Dashboard นับยอดรวมได้ครบ

---

## Endpoint อื่นๆ

| Method | Path | ใช้ทำอะไร |
|--------|------|-----------|
| GET  | `/health` | เช็คว่า server + model พร้อม (ไม่ต้อง auth) |
| GET  | `/logs?page=1&limit=20` | ดู log ดิบแบบแบ่งหน้า |
| POST | `/feedback` | แก้ผลว่า log นี้เป็น phishing จริงไหม `{"log_id": 1, "is_actually_phishing": true}` |
