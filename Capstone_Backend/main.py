import os
import re
import email
from email import policy
import base64
import requests

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# ================= 🗄️ Database Setup (SQLAlchemy) =================
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from datetime import datetime, timedelta

# ================= Risk Scoring Engine =================
from risk_scoring import RiskScoringEngine, RiskInput


# ================= Config =================

# แนะนำให้ใส่ API Key จริงผ่าน Environment Variable
# ถ้าไม่ได้ตั้งค่า ระบบยังรันได้ แต่จะไม่เช็ค VirusTotal
VT_API_KEY = os.getenv("VT_API_KEY", "")

DATABASE_URL = "postgresql://cap_db:123456@localhost:5432/phishing_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class EmailLog(Base):
    __tablename__ = "email_logs"

    id             = Column(Integer, primary_key=True, index=True)
    timestamp      = Column(DateTime, default=datetime.utcnow, index=True)
    sender_domain  = Column(String, index=True)
    recipient      = Column(String, default="unknown@corp.com")
    subject        = Column(String)

    final_score    = Column(Float)
    ai_score       = Column(Float)
    link_risk      = Column(Float)
    domain_risk    = Column(Float)
    header_anomaly = Column(Float)

    risk_level     = Column(String)   # block / quarantine / warning / allow
    is_phishing    = Column(Boolean, default=False)
    attack_type    = Column(String, default="Normal")


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ================= โหลด AI Model =================

MODEL_PATH = "phishing_bert_model"

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
model.eval()


# ================= FastAPI Setup =================

app = FastAPI()
risk_engine = RiskScoringEngine()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailRequest(BaseModel):
    text: str
    recipient: str = "unknown@corp.com"


# ================= Email Parser =================

def parse_raw_email(raw_content: str):
    msg = email.message_from_string(raw_content, policy=policy.default)

    sender       = msg.get("From", "")
    reply_to     = msg.get("Reply-To", "")
    subject      = msg.get("Subject", "No Subject")
    auth_results = str(msg.get("Authentication-Results", ""))

    body_text = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text += payload.decode(errors="ignore")
                except Exception:
                    pass

            if part.get_filename():
                attachments.append(part.get_filename())

    else:
        try:
            payload = msg.get_payload(decode=True)

            if payload:
                body_text = payload.decode(errors="ignore")
            else:
                body_text = str(msg.get_payload())

        except Exception:
            body_text = str(msg.get_payload())

    return {
        "Sender": sender,
        "Subject": subject,
        "Reply_To": reply_to,
        "Body": body_text.strip() or raw_content,
        "Attachments": attachments,
        "Auth_Results": auth_results,
    }


# ================= Feature Extraction =================

def extract_features(parsed_data):
    features = {}

    sender_email = re.search(
        r"[\w\.-]+@[\w\.-]+",
        parsed_data["Sender"]
    )

    features["sender_email"] = sender_email.group(0) if sender_email else "unknown"

    features["sender_domain"] = (
        sender_email.group(0).split("@")[1]
        if sender_email
        else "unknown"
    )

    if parsed_data["Reply_To"]:
        reply_email = re.search(
            r"[\w\.-]+@[\w\.-]+",
            parsed_data["Reply_To"]
        )

        reply_domain = (
            reply_email.group(0).split("@")[1]
            if reply_email
            else ""
        )

        features["reply_to_mismatch"] = features["sender_domain"] != reply_domain
    else:
        features["reply_to_mismatch"] = False

    # ในระบบจริง sender_spoofing อาจมาจาก feature extractor แยก
    # ตอนนี้ใช้ reply_to_mismatch เป็น signal เบื้องต้น
    features["sender_spoofing"] = features["reply_to_mismatch"]

    features["attachment_type"] = [
        os.path.splitext(filename)[1].lower()
        for filename in parsed_data["Attachments"]
    ]

    auth_text = parsed_data["Auth_Results"].lower()

    features["spf_result"] = (
        "fail" if "spf=fail" in auth_text
        else "pass" if "spf=pass" in auth_text
        else "none"
    )

    features["dkim_result"] = (
        "fail" if "dkim=fail" in auth_text
        else "pass" if "dkim=pass" in auth_text
        else "none"
    )

    features["dmarc_result"] = (
        "fail" if "dmarc=fail" in auth_text
        else "pass" if "dmarc=pass" in auth_text
        else "none"
    )

    return features


# ================= External Threat Intel: VirusTotal =================

def check_virustotal(url: str):
    """
    ส่ง URL ไปเช็คกับ VirusTotal
    ถ้าไม่ได้ตั้ง VT_API_KEY จะ return 0 เพื่อไม่ให้ระบบพัง
    """

    if not VT_API_KEY:
        return 0

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}

    try:
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(vt_url, headers=headers, timeout=3)

        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)

            if malicious > 0:
                return 100

        return 0

    except Exception as e:
        print(f"[VT Error] {e}")
        return 0


def check_link_risk(text: str):
    urls_found = re.findall(r"https?://[^\s]+", text)

    if not urls_found:
        return 0, []

    max_risk = 0
    suspicious_links = []

    for url in urls_found:
        risk = 10

        # URL เป็น IP Address เช่น http://192.168.1.100/login
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            risk += 80

        # TLD ที่มักพบใน phishing URL
        if any(tld in url.lower() for tld in [".xyz", ".top", ".click", ".tk"]):
            risk += 60

        vt_risk = check_virustotal(url)

        if vt_risk == 100:
            risk = 100
            url = f"{url} 🚨 [VT: ตรวจพบ Malware/Phishing!]"

        if risk > 10:
            suspicious_links.append(url)

        max_risk = max(max_risk, risk)

    return max_risk, suspicious_links


# ================= Attack Categorization =================

def categorize_attack(features, link_risk_score, ai_score, recipient, final_score):
    if final_score < 30:
        return "Normal"

    high_value_targets = [
        "ceo",
        "cfo",
        "finance",
        "hr",
        "admin",
        "director",
        "manager"
    ]

    recipient_prefix = (
        recipient.split("@")[0].lower()
        if "@" in recipient
        else recipient.lower()
    )

    dangerous_extensions = [
        ".exe",
        ".bat",
        ".scr",
        ".vbs",
        ".js",
        ".jar",
        ".zip",
        ".docm"
    ]

    # 1. Malware Attachment
    if any(ext in dangerous_extensions for ext in features["attachment_type"]):
        return "Malware Attachment"

    # 2. Business Email Compromise (BEC)
    if (
        features["reply_to_mismatch"] is True
        or features["spf_result"] == "fail"
    ) and link_risk_score <= 10:
        return "Business Email Compromise (BEC)"

    # 3. Spear Phishing
    is_high_value_target = any(
        target in recipient_prefix
        for target in high_value_targets
    )

    if is_high_value_target and (link_risk_score > 0 or ai_score > 60):
        return "Spear Phishing"

    # 4. General Phishing
    return "Phishing"


# ================= API: /analyze =================

@app.post("/analyze")
def analyze_email(request: EmailRequest, db: Session = Depends(get_db)):
    raw_text = request.text

    # 1. Parser
    parsed = parse_raw_email(raw_text)

    # 2. Feature Extraction
    features = extract_features(parsed)

    # 3. AI Detection Engine
    inputs = tokenizer(
        parsed["Body"],
        padding="max_length",
        max_length=64,
        truncation=True,
        return_tensors="pt"
    )

    with torch.no_grad():
        outputs = model(**inputs)
        raw_ai_score = F.softmax(outputs.logits, dim=1)[0][1].item() * 100

    # 4. Link Risk / Threat Intelligence
    raw_link_score, bad_links = check_link_risk(raw_text)

    # 5. Risk Scoring Engine
    risk_input = RiskInput(
        email_id="",
        sender_domain=features.get("sender_domain", "unknown"),
        sender_email=features.get("sender_email", "unknown"),
        recipient=request.recipient,

        spf_result=features.get("spf_result", "none"),
        dkim_result=features.get("dkim_result", "none"),
        dmarc_result=features.get("dmarc_result", "none"),

        reply_to_mismatch=features.get("reply_to_mismatch", False),
        sender_spoofing=features.get("sender_spoofing", False),

        attachment_type=features.get("attachment_type", []),

        raw_ai_score=raw_ai_score,
        raw_link_score=raw_link_score,

        subject=parsed["Subject"],
        body_text=parsed["Body"],

        extra_features=features
    )

    risk_result = risk_engine.calculate(risk_input)

    final_score = risk_result.final_score
    risk_level = risk_result.action
    display_level = risk_result.display_level
    action_color = risk_result.action_color

    ai_score_component = risk_result.components["ai_score"]
    link_risk_component = risk_result.components["link_risk"]
    domain_risk_component = risk_result.components["domain_risk"]
    header_anomaly_component = risk_result.components["header_anomaly"]

    # 6. Attack Categorization
    attack_type = categorize_attack(
        features=features,
        link_risk_score=raw_link_score,
        ai_score=raw_ai_score,
        recipient=request.recipient,
        final_score=final_score
    )

    # 7. Save to PostgreSQL
    # ไม่บันทึก reasons ลง DB เพื่อไม่ต้อง ALTER TABLE เพิ่ม
    db.add(EmailLog(
        sender_domain      = features["sender_domain"],
        recipient          = request.recipient,
        subject            = parsed["Subject"],
        final_score        = round(final_score, 2),
        ai_score           = round(ai_score_component, 2),
        link_risk          = round(link_risk_component, 2),
        domain_risk        = round(domain_risk_component, 2),
        header_anomaly     = round(header_anomaly_component, 2),
        risk_level         = risk_level,
        is_phishing        = final_score >= 30,
        attack_type        = attack_type
    ))

    db.commit()

    # 8. Return result to Mail Gateway / Dashboard
    return {
        "summary": {
            "final_risk_score": round(final_score, 2),
            "risk_level": display_level,
            "risk_category": risk_result.risk_level,
            "action_color": action_color,
            "attack_type": attack_type
        },
        "details": {
            "ai_score": round(ai_score_component, 2),
            "link_risk": round(link_risk_component, 2),
            "domain_risk": round(domain_risk_component, 2),
            "header_anomaly": round(header_anomaly_component, 2),
            "attachment_risk": risk_result.components.get("attachment_risk", 0),
            "language_risk": risk_result.components.get("language_risk", 0),
            "detected_links": bad_links,
            "extracted_features": features,
            "reasons": risk_result.reasons,
            "risk_flags": risk_result.flags
        },
    }


# ================= API: /dashboard =================

@app.get("/dashboard")
def get_dashboard(period: str = "7days", db: Session = Depends(get_db)):
    today = datetime.utcnow().date()

    days_map = {
        "today": 0,
        "7days": 6,
        "30days": 29
    }

    days = days_map.get(period, 6)

    date_labels = []
    date_keys = []

    if period == "today":
        today_start = datetime.utcnow().replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )

        for h in range(24):
            hour_time = today_start + timedelta(hours=h)
            date_labels.append(hour_time.strftime("%H:00"))
            date_keys.append(hour_time)

    else:
        for i in range(days, -1, -1):
            d = today - timedelta(days=i)
            date_labels.append(d.strftime("%b %d"))
            date_keys.append(d)

    # ── Query Volume ──
    if period == "today":
        vol_rows = (
            db.query(
                func.date_trunc("hour", EmailLog.timestamp).label("hour"),
                func.count(EmailLog.id).label("total"),
                func.sum(func.cast(EmailLog.is_phishing, Integer)).label("phishing"),
            )
            .filter(
                EmailLog.timestamp >= today_start,
                EmailLog.timestamp < today_start + timedelta(days=1)
            )
            .group_by(func.date_trunc("hour", EmailLog.timestamp))
            .all()
        )

        vol_map = {
            row.hour: (row.total, row.phishing or 0)
            for row in vol_rows
        }

        volume_total = [
            vol_map.get(hour_time, (0, 0))[0]
            for hour_time in date_keys
        ]

        volume_phishing = [
            vol_map.get(hour_time, (0, 0))[1]
            for hour_time in date_keys
        ]

    else:
        vol_rows = (
            db.query(
                func.date(EmailLog.timestamp).label("day"),
                func.count(EmailLog.id).label("total"),
                func.sum(func.cast(EmailLog.is_phishing, Integer)).label("phishing"),
            )
            .filter(
                EmailLog.timestamp >= datetime.utcnow() - timedelta(days=days + 1)
            )
            .group_by(func.date(EmailLog.timestamp))
            .all()
        )

        vol_map = {
            row.day: (row.total, row.phishing or 0)
            for row in vol_rows
        }

        volume_total = [
            vol_map.get(d, (0, 0))[0]
            for d in date_keys
        ]

        volume_phishing = [
            vol_map.get(d, (0, 0))[1]
            for d in date_keys
        ]

    # ── Metric Cards เฉพาะวันนี้ ──
    today_start_metric = datetime.utcnow().replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0
    )

    today_rows = (
        db.query(EmailLog)
        .filter(EmailLog.timestamp >= today_start_metric)
        .all()
    )

    emails_today = len(today_rows)
    phishing_today = sum(1 for row in today_rows if row.is_phishing)

    allowed_today = sum(
        1 for row in today_rows if row.risk_level == "allow"
    )

    warning_today = sum(
        1 for row in today_rows if row.risk_level == "warning"
    )

    blocked_today = sum(
        1 for row in today_rows if row.risk_level == "block"
    )

    quarantined_today = sum(
        1 for row in today_rows if row.risk_level == "quarantine"
    )

    phishing_rate = (
        round(phishing_today / emails_today * 100, 1)
        if emails_today
        else 0
    )

    block_rate = (
        round((blocked_today + quarantined_today) / phishing_today * 100, 1)
        if phishing_today
        else 0
    )

    avg_risk = (
        round(sum(row.final_score for row in today_rows) / emails_today, 1)
        if emails_today
        else 0
    )

    # ── Risk Distribution ตาม period ──
    if period == "today":
        all_rows = (
            db.query(EmailLog)
            .filter(EmailLog.timestamp >= today_start_metric)
            .all()
        )
    else:
        all_rows = (
            db.query(EmailLog)
            .filter(
                EmailLog.timestamp >= datetime.utcnow() - timedelta(days=days + 1)
            )
            .all()
        )

    low = sum(1 for row in all_rows if row.final_score < 40)
    med = sum(1 for row in all_rows if 40 <= row.final_score < 70)
    high = sum(1 for row in all_rows if row.final_score >= 70)

    # ── Top Attacker Domains ──
    if period == "today":
        domain_filter = EmailLog.timestamp >= today_start_metric
    else:
        domain_filter = EmailLog.timestamp >= datetime.utcnow() - timedelta(days=days + 1)

    domain_rows = (
        db.query(
            EmailLog.sender_domain,
            func.count(EmailLog.id).label("cnt")
        )
        .filter(
            EmailLog.is_phishing == True,
            domain_filter
        )
        .group_by(EmailLog.sender_domain)
        .order_by(func.count(EmailLog.id).desc())
        .limit(5)
        .all()
    )

    top_domains = [
        {
            "name": row.sender_domain,
            "count": row.cnt
        }
        for row in domain_rows
    ]

    # ── Most Targeted Users ──
    if period == "today":
        user_filter = EmailLog.timestamp >= today_start_metric
    else:
        user_filter = EmailLog.timestamp >= datetime.utcnow() - timedelta(days=days + 1)

    user_rows = (
        db.query(
            EmailLog.recipient,
            func.count(EmailLog.id).label("cnt")
        )
        .filter(
            EmailLog.is_phishing == True,
            user_filter
        )
        .group_by(EmailLog.recipient)
        .order_by(func.count(EmailLog.id).desc())
        .limit(5)
        .all()
    )

    top_users = [
        {
            "email": row.recipient,
            "dept": "N/A",
            "hits": row.cnt
        }
        for row in user_rows
    ]

    # ── Attack Types Distribution ──
    type_rows = (
        db.query(
            EmailLog.attack_type,
            func.count(EmailLog.id).label("cnt")
        )
        .filter(
            EmailLog.is_phishing == True,
            user_filter
        )
        .group_by(EmailLog.attack_type)
        .all()
    )

    color_map = {
        "Malware Attachment": "#ef4444",
        "Business Email Compromise (BEC)": "#8b5cf6",
        "Spear Phishing": "#f59e0b",
        "Phishing": "#3b82f6"
    }

    attack_types_data = [
        {
            "label": row.attack_type,
            "count": row.cnt,
            "color": color_map.get(row.attack_type, "#6b7280")
        }
        for row in type_rows
        if row.attack_type != "Normal"
    ]

    return {
        "stats": {
            "emailsToday": emails_today,
            "emailsChange": 0,
            "phishingDetected": phishing_today,
            "phishingRate": phishing_rate,
            "allowed": allowed_today,
            "warning": warning_today,
            "quarantined": quarantined_today,
            "blocked": blocked_today,
            "blockRate": block_rate,
            "avgRiskScore": avg_risk,
        },
        "volume": {
            "labels": date_labels,
            "total": volume_total,
            "phishing": volume_phishing
        },
        "riskDist": [
            {
                "label": "Low (0–40)",
                "count": low,
                "color": "#22c55e"
            },
            {
                "label": "Med (41–70)",
                "count": med,
                "color": "#f59e0b"
            },
            {
                "label": "High (71–100)",
                "count": high,
                "color": "#ef4444"
            },
        ],
        "domains": top_domains,
        "users": top_users,
        "types": attack_types_data,
    }


# ================= API: /logs =================

@app.get("/logs")
def get_email_logs(db: Session = Depends(get_db)):
    logs = (
        db.query(EmailLog)
        .order_by(EmailLog.timestamp.desc())
        .limit(10)
        .all()
    )

    return {
        "status": "success",
        "data": logs
    }