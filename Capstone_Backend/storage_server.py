"""
Storage + Risk Scoring Server: this machine owns the database (EmailLog
table, /dashboard, /logs) and the risk scoring engine (risk_scoring/).

The AI Model Server (running on a teammate's machine) does email parsing,
BERT classification, and threat-intel lookups (link/IPQS/DMARC), then calls
POST /assess here with the raw signals. This server runs the risk_scoring
engine to compute the final score/action, persists it to the DB, and
returns the result so the caller can enforce the policy (block/quarantine/
allow).

No BERT/XGBoost/email-parsing code lives here - that stays on the AI server.
"""
import os
from datetime import datetime, timedelta
from typing import List

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, create_engine, func
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from risk_scoring import RiskScoringEngine, RiskInput

load_dotenv()

risk_engine = RiskScoringEngine()

# ================= FastAPI Initialization =================
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================================
# 🛡️ Zero-Trust API Shield - shared secret with the AI Model Server
# =====================================================================
API_KEY_NAME = "X-Security-Token"
API_SECRET_KEY = os.getenv("STORAGE_SECRET_KEY", "cap_super_secret_key_2026")

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)


def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="⛔ SOC Access Denied: Invalid Security Token",
        )


# ================= 🗄️ Database Setup (SQLAlchemy) =================
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
    risk_level     = Column(String)
    is_phishing    = Column(Boolean, default=False)
    attack_type    = Column(String, default="Normal")


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ================= API: /assess (เรียกจาก AI Model Server ของเพื่อน) =================
class AssessRequest(BaseModel):
    sender_domain: str = "unknown"
    sender_email: str = ""
    recipient: str = "unknown@corp.com"

    spf_result: str = "none"
    dkim_result: str = "none"
    dmarc_result: str = "none"

    reply_to_mismatch: bool = False
    sender_spoofing: bool = False
    attachment_type: List[str] = []

    raw_ai_score: float = 0.0
    raw_link_score: float = 0.0
    abuseipdb_score: float = 0.0   # IP reputation จาก AbuseIPDB
    ipqs_score: float = 0.0        # ชื่อเก่า (deprecated) - รับไว้กันพังช่วงเปลี่ยนผ่าน

    subject: str = ""
    body_text: str = ""

    attack_type: str = "Normal"  # ผลจาก Stage-2 classifier ฝั่ง AI server


@app.post("/assess", dependencies=[Depends(verify_api_key)])
def assess_email(request: AssessRequest, db: Session = Depends(get_db)):
    risk_input = RiskInput(
        sender_domain=request.sender_domain,
        sender_email=request.sender_email,
        recipient=request.recipient,
        spf_result=request.spf_result,
        dkim_result=request.dkim_result,
        dmarc_result=request.dmarc_result,
        reply_to_mismatch=request.reply_to_mismatch,
        sender_spoofing=request.sender_spoofing,
        attachment_type=request.attachment_type,
        raw_ai_score=request.raw_ai_score,
        raw_link_score=request.raw_link_score,
        abuseipdb_score=request.abuseipdb_score or request.ipqs_score,
        subject=request.subject,
        body_text=request.body_text,
    )
    result = risk_engine.calculate(risk_input)

    db.add(EmailLog(
        sender_domain=request.sender_domain,
        recipient=request.recipient,
        subject=request.subject,
        final_score=result.final_score,
        ai_score=result.components["ai_score"],
        link_risk=result.components["link_risk"],
        domain_risk=result.components["domain_risk"],
        header_anomaly=result.components["header_anomaly"],
        risk_level=result.action,
        is_phishing=result.final_score >= 30,
        attack_type=request.attack_type,
    ))
    db.commit()

    return {
        "summary": {
            "final_risk_score": result.final_score,
            "risk_level": result.display_level,
            "action_color": result.action_color,
            "attack_type": request.attack_type,
        },
        "details": {
            "ai_score": result.components["ai_score"],
            "link_risk": result.components["link_risk"],
            "domain_risk": result.components["domain_risk"],
            "header_anomaly": result.components["header_anomaly"],
            "attachment_risk": result.components["attachment_risk"],
            "language_risk": result.components["language_risk"],
            "reasons": result.reasons,
        }
    }


# ================= API: /dashboard =================
@app.get("/dashboard")
def get_dashboard(period: str = "7days", db: Session = Depends(get_db)):
    today = datetime.utcnow().date()

    days_map = {"today": 0, "7days": 6, "30days": 29}
    days = days_map.get(period, 6)

    date_labels, date_keys = [], []
    if period == "today":
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        for h in range(24):
            hour_time = today_start + timedelta(hours=h)
            date_labels.append(hour_time.strftime("%H:00"))
            date_keys.append(hour_time)
    else:
        for i in range(days, -1, -1):
            d = today - timedelta(days=i)
            date_labels.append(d.strftime("%b %d"))
            date_keys.append(d)

    if period == "today":
        vol_rows = (
            db.query(
                func.date_trunc('hour', EmailLog.timestamp).label("hour"),
                func.count(EmailLog.id).label("total"),
                func.sum(func.cast(EmailLog.is_phishing, Integer)).label("phishing"),
            )
            .filter(EmailLog.timestamp >= today_start, EmailLog.timestamp < today_start + timedelta(days=1))
            .group_by(func.date_trunc('hour', EmailLog.timestamp))
            .all()
        )
        vol_map = {row.hour: (row.total, row.phishing or 0) for row in vol_rows}
        volume_total    = [vol_map.get(hour_time, (0, 0))[0] for hour_time in date_keys]
        volume_phishing = [vol_map.get(hour_time, (0, 0))[1] for hour_time in date_keys]
    else:
        vol_rows = (
            db.query(
                func.date(EmailLog.timestamp).label("day"),
                func.count(EmailLog.id).label("total"),
                func.sum(func.cast(EmailLog.is_phishing, Integer)).label("phishing"),
            )
            .filter(EmailLog.timestamp >= datetime.utcnow() - timedelta(days=days + 1))
            .group_by(func.date(EmailLog.timestamp))
            .all()
        )
        vol_map = {row.day: (row.total, row.phishing or 0) for row in vol_rows}
        volume_total    = [vol_map.get(d, (0, 0))[0] for d in date_keys]
        volume_phishing = [vol_map.get(d, (0, 0))[1] for d in date_keys]

    today_start_metric = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_rows  = db.query(EmailLog).filter(EmailLog.timestamp >= today_start_metric).all()

    emails_today      = len(today_rows)
    phishing_today    = sum(1 for r in today_rows if r.is_phishing)
    allowed_today     = sum(1 for r in today_rows if r.risk_level == "allow")
    warning_today     = sum(1 for r in today_rows if r.risk_level == "warning")
    blocked_today     = sum(1 for r in today_rows if r.risk_level == "block")
    quarantined_today = sum(1 for r in today_rows if r.risk_level == "quarantine")
    phishing_rate     = round(phishing_today / emails_today * 100, 1) if emails_today else 0
    block_rate        = round((blocked_today + quarantined_today) / phishing_today * 100, 1) if phishing_today else 0
    avg_risk          = round(sum(r.final_score for r in today_rows) / emails_today, 1) if emails_today else 0

    if period == "today":
        all_rows = db.query(EmailLog).filter(EmailLog.timestamp >= today_start_metric).all()
    else:
        all_rows = db.query(EmailLog).filter(EmailLog.timestamp >= datetime.utcnow() - timedelta(days=days + 1)).all()

    low  = sum(1 for r in all_rows if r.final_score < 40)
    med  = sum(1 for r in all_rows if 40 <= r.final_score < 70)
    high = sum(1 for r in all_rows if r.final_score >= 70)

    if period == "today":
        domain_filter = EmailLog.timestamp >= today_start_metric
    else:
        domain_filter = EmailLog.timestamp >= datetime.utcnow() - timedelta(days=days + 1)

    domain_rows = (
        db.query(EmailLog.sender_domain, func.count(EmailLog.id).label("cnt"))
        .filter(EmailLog.is_phishing == True, domain_filter)
        .group_by(EmailLog.sender_domain)
        .order_by(func.count(EmailLog.id).desc())
        .limit(5)
        .all()
    )
    top_domains = [{"name": r.sender_domain, "count": r.cnt} for r in domain_rows]

    if period == "today":
        user_filter = EmailLog.timestamp >= today_start_metric
    else:
        user_filter = EmailLog.timestamp >= datetime.utcnow() - timedelta(days=days + 1)

    user_rows = (
        db.query(EmailLog.recipient, func.count(EmailLog.id).label("cnt"))
        .filter(EmailLog.is_phishing == True, user_filter)
        .group_by(EmailLog.recipient)
        .order_by(func.count(EmailLog.id).desc())
        .limit(5)
        .all()
    )
    top_users = [{"email": r.recipient, "dept": "N/A", "hits": r.cnt} for r in user_rows]

    type_rows = (
        db.query(EmailLog.attack_type, func.count(EmailLog.id).label("cnt"))
        .filter(EmailLog.is_phishing == True, user_filter)
        .group_by(EmailLog.attack_type)
        .all()
    )

    color_map = {
        "Malware Attachment": "#ef4444",
        "Business Email Compromise (BEC)": "#8b5cf6",
        "Spear Phishing": "#f59e0b",
        "Phishing": "#3b82f6",
        "Spam (High-Risk Source)": "#a855f7"
    }

    attack_types_data = [
        {"label": r.attack_type, "count": r.cnt, "color": color_map.get(r.attack_type, "#6b7280")}
        for r in type_rows if r.attack_type != "Normal"
    ]

    return {
        "stats": {
            "emailsToday":      emails_today,
            "emailsChange":     0,
            "phishingDetected": phishing_today,
            "phishingRate":     phishing_rate,
            "allowed":          allowed_today,
            "warning":          warning_today,
            "quarantined":      quarantined_today,
            "blocked":          blocked_today,
            "blockRate":        block_rate,
            "avgRiskScore":     avg_risk,
        },
        "volume":   {"labels": date_labels, "total": volume_total, "phishing": volume_phishing},
        "riskDist": [
            {"label": "Low (0–40)",    "count": low,  "color": "#22c55e"},
            {"label": "Med (41–70)",   "count": med,  "color": "#f59e0b"},
            {"label": "High (71–100)", "count": high, "color": "#ef4444"},
        ],
        "domains": top_domains,
        "users":   top_users,
        "types":   attack_types_data,
    }


@app.get("/logs")
def get_email_logs(risk_level: str = "", limit: int = 10, db: Session = Depends(get_db)):
    """ดึง log ผลวิเคราะห์ - กรองตามสถานะได้ เช่น /logs?risk_level=quarantine
    (เมลที่ยังไม่ถึงกล่องผู้ใช้ = risk_level "quarantine" กับ "block")"""
    query = db.query(EmailLog)
    if risk_level:
        query = query.filter(EmailLog.risk_level == risk_level.lower())
    logs = query.order_by(EmailLog.timestamp.desc()).limit(min(max(limit, 1), 200)).all()
    return {"status": "success", "count": len(logs), "data": logs}


# ================= 📬 Mail Server: เก็บอีเมลจริงที่ Gateway ส่งมอบ =================
from mail_store import MAIL_STORE_ROOT, MAIL_FOLDERS, deliver as store_deliver, store_maildir, safe_name as _safe_name


class DeliverRequest(BaseModel):
    recipient: str
    sender: str = ""
    subject: str = ""
    folder: str = "inbox"        # "inbox" | "quarantine"
    raw_email: str               # เนื้ออีเมลดิบทั้งฉบับ (.eml)


@app.post("/deliver", dependencies=[Depends(verify_api_key)])
def deliver_mail(request: DeliverRequest):
    if request.folder not in MAIL_FOLDERS:
        raise HTTPException(status_code=422, detail=f"folder must be one of {sorted(MAIL_FOLDERS)}")

    filename = store_deliver(request.folder, request.recipient, request.raw_email.encode("utf-8"))
    return {"status": "delivered", "folder": request.folder, "filename": filename}


@app.get("/mailbox/{folder}", dependencies=[Depends(verify_api_key)])
def list_mailbox(folder: str, user: str = "", db: Session = Depends(get_db)):
    if folder not in MAIL_FOLDERS:
        raise HTTPException(status_code=404, detail=f"folder must be one of {sorted(MAIL_FOLDERS)}")

    folder_path = os.path.join(MAIL_STORE_ROOT, folder)
    if not os.path.isdir(folder_path):
        return {"status": "success", "folder": folder, "count": 0, "messages": [], "items": []}

    prefix = _safe_name(user.split("@")[0].lower()) + "_" if user else ""
    messages = sorted(
        (f for f in os.listdir(folder_path) if f.endswith(".eml") and f.startswith(prefix)),
        reverse=True,
    )

    # items: รายละเอียดต่อฉบับ + log_id จับคู่กับ email_logs แบบ best-effort
    # (ไฟล์เมลมาทาง SMTP ส่วน log มาทาง /assess - ไม่มี key ตรงกลาง จึงเทียบด้วย ผู้รับ+หัวข้อ)
    import email as email_lib
    from email import policy as email_policy

    items = []
    for filename in messages:
        recipient_user = filename.rsplit("_", 1)[0]
        subject, sender = "", ""
        try:
            with open(os.path.join(folder_path, filename), "rb") as f:
                msg = email_lib.message_from_bytes(f.read(), policy=email_policy.default)
            subject = str(msg.get("Subject", "") or "")
            sender = str(msg.get("From", "") or "")
        except Exception:
            pass

        log_id = None
        if subject:
            row = (
                db.query(EmailLog)
                .filter(EmailLog.subject == subject, EmailLog.recipient.like(f"{recipient_user}@%"))
                .order_by(EmailLog.timestamp.desc())
                .first()
            ) or (
                db.query(EmailLog)
                .filter(EmailLog.subject == subject)
                .order_by(EmailLog.timestamp.desc())
                .first()
            )
            if row:
                log_id = row.id

        items.append({
            "filename": filename,
            "recipient": recipient_user,
            "sender": sender,
            "subject": subject,
            "log_id": log_id,   # null = ไม่พบแถวที่จับคู่ได้ใน email_logs
        })

    return {"status": "success", "folder": folder, "count": len(messages), "messages": messages, "items": items}


@app.post("/mailbox/quarantine/{filename}/release", dependencies=[Depends(verify_api_key)])
def release_from_quarantine(filename: str, log_id: int = 0, db: Session = Depends(get_db)):
    """Admin ตรวจแล้วว่าเมลกักกันปลอดภัย -> ย้ายเข้า inbox ให้ user เห็น"""
    if _safe_name(filename) != filename:
        raise HTTPException(status_code=404, detail="Not found")

    src = os.path.join(MAIL_STORE_ROOT, "quarantine", filename)
    if not os.path.isfile(src):
        raise HTTPException(status_code=404, detail="Not found")

    inbox_path = os.path.join(MAIL_STORE_ROOT, "inbox")
    os.makedirs(inbox_path, exist_ok=True)
    os.rename(src, os.path.join(inbox_path, filename))

    # เข้า Maildir ของ user ด้วย ให้เปิดเห็นผ่าน IMAP/POP3
    recipient = filename.rsplit("_", 1)[0]
    with open(os.path.join(inbox_path, filename), "rb") as f:
        store_maildir(recipient, f.read())

    # ถ้า Dashboard ส่ง log_id มาด้วย ปรับสถิติใน email_logs ให้ตรงคำตัดสินของ admin
    log_updated = False
    if log_id:
        row = db.query(EmailLog).filter(EmailLog.id == log_id).first()
        if row:
            row.risk_level = "allow"
            row.is_phishing = False
            db.commit()
            log_updated = True

    return {"status": "released", "filename": filename, "moved_to": "inbox", "log_updated": log_updated}


@app.get("/mailbox/{folder}/{filename}", dependencies=[Depends(verify_api_key)])
def read_mail(folder: str, filename: str):
    if folder not in MAIL_FOLDERS or _safe_name(filename) != filename:
        raise HTTPException(status_code=404, detail="Not found")

    path = os.path.join(MAIL_STORE_ROOT, folder, filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Not found")

    with open(path, encoding="utf-8") as f:
        return {"status": "success", "folder": folder, "filename": filename, "raw_email": f.read()}


# ================= 🛡️ Rule Base: กฎที่ admin flag ว่า "เมลแบบนี้ไม่ดี" =================
# ใช้โดย 2 ฝั่ง: smtp_mail_server.py ดักเมลรอบสองก่อนเข้ากล่อง (อ่านกฎจากตารางเดียวกัน)
# และ Proxmox Gateway ดึง GET /rules ไป block ที่ด่านแรก
import rule_base


class RuleIn(BaseModel):
    rule_type: str = ""    # "sender" | "subject" | "body"
    pattern: str = ""      # ข้อความที่ใช้จับ (เว้นว่างได้ถ้าส่ง log_id มาให้ดึงจาก log)
    note: str = ""
    log_id: int = 0        # อ้างอิงแถวใน email_logs เพื่อสร้างกฎจากเมลที่ admin ตรวจ


@app.post("/rules", dependencies=[Depends(verify_api_key)])
def create_rule(request: RuleIn, db: Session = Depends(get_db)):
    rule_type, pattern, note = request.rule_type, request.pattern, request.note

    # admin flag จาก log: ดึงข้อมูลเมลจริงมาสร้างกฎให้อัตโนมัติ
    if request.log_id and not pattern:
        row = db.query(EmailLog).filter(EmailLog.id == request.log_id).first()
        if not row:
            raise HTTPException(status_code=404, detail=f"log_id {request.log_id} not found")
        if rule_type == "subject":
            pattern = row.subject or ""
        else:
            rule_type = rule_type or "sender"
            pattern = row.sender_domain or ""
        note = note or f"flagged from log #{request.log_id} ({row.attack_type})"

    try:
        rule = rule_base.add_rule(rule_type, pattern, note)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return {"status": "created", "rule": rule}


@app.get("/rules", dependencies=[Depends(verify_api_key)])
def get_rules():
    rules = rule_base.list_rules()
    return {"status": "success", "count": len(rules), "rules": rules}


@app.delete("/rules/{rule_id}", dependencies=[Depends(verify_api_key)])
def remove_rule(rule_id: int):
    if not rule_base.delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "deleted", "id": rule_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
