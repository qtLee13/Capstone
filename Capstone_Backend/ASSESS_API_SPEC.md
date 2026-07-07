# เปลี่ยนให้ AI server (เครื่องเพื่อน) เรียก Storage/Risk Server (เครื่องนี้) แทนการคำนวณ risk score + เขียน DB เอง

## Endpoint ที่ต้องเรียก
```
POST http://10.22.1.92:8000/assess
Header: X-Security-Token: cap_super_secret_key_2026
Content-Type: application/json
```

## สิ่งที่เพื่อนต้องทำฝั่ง AI server
1. ยังทำ email parsing + BERT (stage1) + XGBoost (stage2 attack_type) + link/IPQS/DMARC checks เหมือนเดิม
2. เอาโค้ดส่วน risk scoring (คำนวณ final_score/action) และการเขียน DB ออก
3. ส่ง raw signal ที่ได้มาที่ `/assess` แทน แล้วใช้ response ที่ได้กลับมาเป็นคำตอบสุดท้ายให้ Gateway

## Request Body (JSON)
```json
{
  "sender_domain": "string",
  "sender_email": "string",
  "recipient": "string",

  "spf_result": "pass | fail | none",
  "dkim_result": "pass | fail | none",
  "dmarc_result": "pass | fail | none",

  "reply_to_mismatch": true,
  "sender_spoofing": false,
  "attachment_type": [".exe", ".zip"],

  "raw_ai_score": 0,
  "raw_link_score": 0,
  "ipqs_score": 0,

  "subject": "string",
  "body_text": "string",

  "attack_type": "Phishing | Business Email Compromise (BEC) | Spam (High-Risk Source) | Malware Attachment | Spear Phishing | Normal"
}
```
field จำเป็นจริงๆ คือ `sender_domain`, `recipient`, `raw_ai_score`, `raw_link_score` — ที่เหลือมี default ให้หมด (false / 0 / "none" / "")

## Response ที่จะได้กลับ (JSON)
```json
{
  "summary": {
    "final_risk_score": 65.0,
    "risk_level": "🟠 High / Quarantine",
    "action_color": "#dd6b20",
    "attack_type": "Business Email Compromise (BEC)"
  },
  "details": {
    "ai_score": 18.4, "link_risk": 2.0, "domain_risk": 5.0,
    "header_anomaly": 6.0, "attachment_risk": 0.0, "language_risk": 3.0,
    "reasons": ["AI model classified this email as highly suspicious"]
  }
}
```

เกณฑ์ action มาจาก final_risk_score:
- `< 30`   → allow
- `30-59`  → warning
- `60-79`  → quarantine
- `>= 80`  → block

## ทดสอบด้วย curl
```bash
curl -X POST http://10.22.1.92:8000/assess \
  -H "X-Security-Token: cap_super_secret_key_2026" \
  -H "Content-Type: application/json" \
  -d '{"sender_domain":"test.com","recipient":"a@corp.com","raw_ai_score":80,"raw_link_score":10,"subject":"test","body_text":"urgent verify now"}'
```
