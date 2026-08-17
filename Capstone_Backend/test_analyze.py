"""
Test script สำหรับยิงอีเมลตัวอย่างเข้า /analyze
รันบน VM:  python test_analyze.py
หรือจากเครื่องอื่น:  แก้ BASE_URL เป็น http://10.22.1.94:8000
"""
import requests

# ---------- ตั้งค่า ----------
BASE_URL = "http://localhost:8000"
API_KEY  = "cap_super_secret_key_2026"   # ต้องตรงกับ API_SECRET_KEY ใน .env
HEADERS  = {"X-Security-Token": API_KEY}

# ---------- อีเมลตัวอย่าง ----------
PHISHING_EMAIL = """From: PayPal Security <service@paypa1-secure.com>
Reply-To: collect-info@malicious-domain.ru
Subject: Urgent: Your account has been suspended!
Received: from unknown (10.0.0.1)

Dear Customer,

We detected unusual activity on your account. Your account has been
temporarily suspended. You must verify your identity immediately or
your account will be permanently closed.

Click here to restore access: http://paypa1-secure.com/verify-login

Please enter your password and credit card details to confirm.

PayPal Security Team
"""

NORMAL_EMAIL = """From: John Smith <john.smith@company.com>
Subject: Meeting notes from today
Received: from mail.company.com (192.168.1.5)

Hi team,

Thanks for joining the meeting today. Here are the notes:
- Project timeline confirmed for Q3
- Next sync on Friday at 2pm

Let me know if you have questions.

Best,
John
"""

SAMPLES = [
    ("PHISHING (ควรได้ score สูง)", PHISHING_EMAIL),
    ("NORMAL   (ควรได้ score ต่ำ)", NORMAL_EMAIL),
]


def run_test(label: str, email_text: str):
    print("=" * 60)
    print(f"TEST: {label}")
    print("=" * 60)
    try:
        resp = requests.post(
            f"{BASE_URL}/analyze",
            json={"text": email_text, "recipient": "victim@corp.com"},
            headers=HEADERS,
            timeout=30,
        )
    except requests.exceptions.RequestException as e:
        print(f"  ❌ เชื่อมต่อไม่ได้: {e}\n")
        return

    if resp.status_code != 200:
        print(f"  ❌ HTTP {resp.status_code}: {resp.text}\n")
        return

    data    = resp.json()
    summary = data.get("summary", {})
    print(f"  Risk Score : {summary.get('final_risk_score')}")
    print(f"  Risk Level : {summary.get('risk_level')}")
    print(f"  Attack Type: {summary.get('attack_type')}")
    if "details" in data:
        d = data["details"]
        print(f"  ai_score={d.get('ai_score')}  link_risk={d.get('link_risk')}  "
              f"header_anomaly={d.get('header_anomaly')}  dmarc={d.get('dmarc_status')}")
    print()


if __name__ == "__main__":
    # เช็ค /health ก่อน
    try:
        h = requests.get(f"{BASE_URL}/health", timeout=10).json()
        print(f"Health: {h}\n")
    except requests.exceptions.RequestException as e:
        print(f"❌ /health เชื่อมต่อไม่ได้: {e}")
        raise SystemExit(1)

    for label, text in SAMPLES:
        run_test(label, text)

    print("เสร็จแล้ว — ลองเช็คว่าข้อมูลถูก INSERT ลง DB ผ่าน  GET /logs")
