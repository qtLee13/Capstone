import os
import re
import json
import email
from email import policy
from pathlib import Path
import base64
import requests
import checkdmarc
import dns.resolver
from dotenv import load_dotenv
import xgboost as xgb
import joblib
import numpy as np
import hashlib
import secrets
import threading
import time
import unicodedata
import logging
import traceback
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, wait as futures_wait

from fastapi import Depends, FastAPI, HTTPException, Security, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# ส่วนคำนวณ Risk Score ทั้งหมดแยกไปอยู่ risk_score.py (แก้สูตรที่ไฟล์นั้นไฟล์เดียว)
import risk_score
# การแปลง text ก่อนเข้า BERT (strip HTML + subject + mask URL) — ใช้ร่วมกับ extractor กัน train/serving skew
import email_preprocess as ep

# ================= Logging Setup =================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ================= FastAPI Initialization =================
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter

# ---- ดัก 500 ที่ไม่มีใครดัก ----------------------------------------------------
# 🐛 2026-08-25: PMG แจ้งว่า POST /analyze ตอบ 500 ติดกัน 3 ครั้ง แต่ฝั่งเราสืบไม่ได้เลย
#    เพราะ (ก) FastAPI default ตอบแค่ข้อความ "Internal Server Error" ไม่มีตัวอ้างอิง
#         (ข) traceback ไปอยู่ใน uvicorn.log ที่โดน restart ทับทิ้ง
#    -> ตอบ request_id กลับไปด้วย เวลาทีมอื่นแจ้งปัญหาจะได้แนบ id มา แล้วเรา grep เจอทันที
#    ⚠️ ห้ามหลุดรายละเอียด exception ออกไปใน response (เป็นช่องรั่วข้อมูลภายใน) — ลง log ฝั่งเราเท่านั้น
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    rid = secrets.token_hex(4)
    client = request.client.host if request.client else "?"
    logger.error(
        f"[500 rid={rid}] {request.method} {request.url.path} จาก {client} — "
        f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
    )
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "request_id": rid,
                 "message": "AI server ทำงานผิดพลาด — แจ้งทีม AI พร้อม request_id นี้"},
    )

app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # ต้อง False เมื่อใช้ allow_origins="*" (CORS spec)
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailRequest(BaseModel):
    text: str = Field(..., max_length=500_000)  # ป้องกัน payload ขนาดใหญ่
    recipient: str = "unknown@corp.com"
    # ผล SPF/DKIM/DMARC ที่ PMG (Proxmox Mail Gateway) เช็คแล้วส่งมา — ถ้าส่งมา "ยึดเป็นหลัก"
    # (PMG เห็น connection-level IP จริง เชื่อถือกว่า AI อ่านจาก Received header ที่ปลอมได้)
    # optional ทั้งหมด -> backward-compatible กับ caller เดิมที่ไม่ส่ง (จะ fallback ไปอ่าน header เอง)
    spf_result: Optional[str] = None    # pass | fail | softfail | neutral | none | error
    dkim_valid: Optional[bool] = None   # true | false | null
    dmarc_result: Optional[str] = None  # pass | fail | none
    # IP ที่เชื่อมต่อเข้ามาจริงตอนรับเมล (PMG เห็นระดับ connection) — เชื่อถือกว่า Received header ที่ปลอมได้
    # ถ้าส่งมา จะใช้ตัวนี้เช็ค AbuseIPDB แทนการเดาจาก header
    sender_ip: Optional[str] = None

class ParseRequest(BaseModel):
    # ใช้กับ POST /parse — รับ raw .eml อย่างเดียว (ไม่มี auth signal เพราะ /parse ไม่ verify อะไร แค่แกะ)
    text: str = Field(..., max_length=500_000)
    # 🐛 2026-08-24: ตอนเพิ่ม sender_spoofing เรียก req.recipient โดยไม่ได้ประกาศ field นี้
    #    -> Pydantic ทิ้ง field ที่ไม่ประกาศทิ้งเงียบ ๆ -> AttributeError ตอน runtime = /parse พัง 500 ทุก request
    #    (กับดักเดิมของโปรเจกต์นี้: field มาถึงแต่ถูกมองข้าม — ครั้งนี้กลับด้าน คือโค้ดเรียกของที่ไม่มี)
    #    ไม่บังคับส่ง เพราะ caller เดิมของ /parse ไม่เคยส่ง recipient มา -> ต้อง backward-compatible
    recipient: str = ""

# ================= Database Setup (SQLAlchemy) =================
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from datetime import datetime, timedelta, timezone

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

load_dotenv()
VT_API_KEY        = os.getenv("VT_API_KEY", "")
IPQS_API_KEY      = os.getenv("IPQS_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
# ⚠️ ห้าม hardcode ความลับไว้เป็น default — ไฟล์นี้ขึ้น git · ค่าจริงอยู่ใน .env เท่านั้น (ดู .env.example)
DATABASE_URL  = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/phishing_db")
API_SECRET_KEY = os.getenv("API_SECRET_KEY", "")
if not API_SECRET_KEY:
    # ไม่ fail-closed เพื่อไม่ให้ระบบที่รันอยู่ล้มกลางคัน แต่ต้องดังพอให้เห็นแน่ๆ
    API_SECRET_KEY = "MISSING_API_SECRET_KEY"
    logger.critical("!!! ไม่พบ API_SECRET_KEY ใน .env — ทุก request จะถูกปฏิเสธ 403 "
                    "ให้เพิ่มบรรทัด API_SECRET_KEY=<token> ลงใน .env แล้ว restart")

# ---- Zero-downtime token rotation ----
# ระหว่างหมุน token: ตั้ง API_SECRET_KEY = ตัวใหม่ · API_SECRET_KEY_OLD = ตัวเก่า (ชั่วคราว)
# AI จะรับได้ทั้งคู่ -> แต่ละทีม (Gateway/Dashboard/.92) ค่อยย้ายมา token ใหม่ทีละเครื่อง ไม่มี downtime
# ทุกครั้งที่ยังมีใครใช้ตัวเก่า จะ log WARNING -> พอ log เงียบ = ทุกคนย้ายครบ ค่อยลบ API_SECRET_KEY_OLD ออก
API_SECRET_KEY_OLD = os.getenv("API_SECRET_KEY_OLD", "").strip()
# 🐛 .env.example เคยเขียนคอมเมนต์ต่อท้ายบรรทัดเดียวกัน -> คนคัดลอกไปทำ .env แล้วได้
#    ค่าเป็นข้อความคอมเมนต์ภาษาไทยทั้งก้อน · ระบบเห็นเป็น "อยู่ในโหมดหมุน token" ทั้งที่ไม่ใช่
#    ค่าที่ขึ้นต้นด้วย # ไม่มีทางเป็น token -> ทิ้ง แล้วตะโกนบอกให้ไปแก้ .env
if API_SECRET_KEY_OLD.startswith("#"):
    logger.error("!!! API_SECRET_KEY_OLD ใน .env เป็นคอมเมนต์ ไม่ใช่ token — ไม่ใช้ค่านี้ "
                 "ให้ลบบรรทัดนั้นทิ้ง หรือใส่ token เก่าจริง ๆ (คอมเมนต์ต้องอยู่คนละบรรทัด)")
    API_SECRET_KEY_OLD = ""
if API_SECRET_KEY_OLD:
    logger.warning("⏳ โหมดหมุน token: ยังรับ API_SECRET_KEY_OLD อยู่ชั่วคราว "
                   "— เมื่อทุกทีมย้ายมา token ใหม่แล้ว (ไม่มี log 'ใช้ token เก่า') ให้ลบบรรทัดนี้ออกจาก .env")

# หมายเหตุ flow: AI server (.94) รับ /analyze จาก Gateway (10.22.1.66) แล้ว "ตอบ raw_signals
# กลับ Gateway ตรงๆ" (synchronous response) — ไม่ push ไป .92 เองอีกแล้ว
# Gateway + mail server จะเอา raw_signals ไปคิด risk score + เขียน DB + ตัดสิน deliver/quarantine กันเอง

# Dataset capture (feedback loop): เก็บ feature+text ของทุกอีเมลที่วิเคราะห์ ไว้ทำ dataset retrain
# ⚠️ ไฟล์นี้มี "เนื้อหาอีเมลจริง" (PII) → เปิดเฉพาะเมื่อยินยอม + ป้องกันไฟล์ให้ดี (default ปิด)
DATASET_CAPTURE      = os.getenv("DATASET_CAPTURE", "0") == "1"
DATASET_CAPTURE_PATH = os.getenv("DATASET_CAPTURE_PATH", "logs/dataset_capture.jsonl")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class EmailLog(Base):
    __tablename__ = "email_logs"

    id             = Column(Integer, primary_key=True, index=True)
    timestamp      = Column(DateTime, default=utcnow, index=True)
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

# ================= โหลด AI Model (Stage 1 - BERT) =================
# v3 = mBERT (bert-base-multilingual-cased) — P7 รองรับไทย: Thai held-out legit-recall 0.52->0.94,
#      อังกฤษไม่ตก (EN+TH test acc 0.99), inference ~เท่าเดิม 11ms. ของเก่า: phishing_bert_model_v2 (อังกฤษล้วน)
# ⚠️ Stage 2 XGBoost ถูก retrain ด้วย ai_score จาก mBERT แล้ว (ต้อง deploy คู่กัน ไม่งั้น ai_score skew)
MODEL_PATH = "phishing_bert_model_v3"
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
model.eval()

# ================= โหลด AI Model (Stage 2 - XGBoost) =================
logger.info("กำลังโหลดโมเดล XGBoost และ Label Encoder สำหรับ Stage 2...")
try:
    xgb_model = xgb.XGBClassifier()
    xgb_model.load_model("xgboost_type_classifier.json")
    label_encoder = joblib.load("label_encoder.pkl")
    logger.info("โหลดโมเดล XGBoost สำเร็จ!")
except Exception as e:
    logger.warning(f"ไม่พบโมเดล XGBoost หรือโหลดล้มเหลว: {e}")
    xgb_model = None
    label_encoder = None

def stage2_xgboost_predict(feature_vector):
    if xgb_model is None or label_encoder is None:
        return "Phishing (Fallback)"
    try:
        features_array = np.array([feature_vector])
        prediction = xgb_model.predict(features_array)
        if len(prediction.shape) > 1 or isinstance(prediction[0], np.ndarray):
            predicted_class_num = int(np.argmax(prediction[0]))
        else:
            predicted_class_num = int(prediction[0])
        return label_encoder.inverse_transform([predicted_class_num])[0]
    except Exception as e:
        logger.error(f"XGBoost prediction error: {e}")
        return "Unknown Threat"

# ================= Email Parser & Feature Extraction =================
_EMAIL_HEADER_RE = re.compile(r"^(from|to|subject|date|received|message-id)\s*:", re.I | re.M)


def inspect_payload(raw: str) -> tuple[str, str]:
    """
    ตรวจว่า text ที่ส่งมา "หน้าตาเป็นอีเมลดิบ" จริงไหม ก่อนเอาเข้าโมเดล
    คืน (ระดับปัญหา, ข้อความอธิบาย) — ระดับ: "ok" | "warn" | "reject"

    ⚠️ ทำไมต้องมี: ถ้า caller ส่งอย่างอื่นมา (เช่น JSON ของ mailbox API ทั้งก้อน)
       ตัวแกะอีเมลจะไม่ error แต่จะได้ subject="No Subject" / sender="unknown" / body=JSON
       แล้ว BERT ก็ยังให้คะแนนออกมาเป็นตัวเลขสวยๆ ตามปกติ -> ผิดแบบเงียบสนิท
       (เคสจริง 2026-07-22: เมลถูกอ่านกลับจาก mailbox API แล้วยัด JSON ทั้งก้อนเข้ามา
        ทุกฉบับได้ ai_score ~100 -> โดน quarantine ยกชุด)
       บทเรียนเดิมของโปรเจกต์: ข้อมูลผิดต้อง "ดังตอนเข้า" ไม่ใช่เงียบแล้วไปโผล่ปลายทาง
    """
    s = (raw or "").lstrip()
    if not s:
        return "reject", "payload ว่างเปล่า"

    # เคสที่ชัดเจนที่สุด: ส่ง JSON response ของ mailbox API มาทั้งก้อน
    if s.startswith("{"):
        try:
            obj = json.loads(s)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            for k in ("raw_email", "raw_message", "eml", "content"):
                if isinstance(obj.get(k), str) and _EMAIL_HEADER_RE.search(obj[k]):
                    return "reject", (
                        f"payload เป็น JSON ไม่ใช่อีเมลดิบ — เนื้อเมลจริงอยู่ในฟิลด์ '{k}' "
                        f"กรุณาส่งเฉพาะค่าในฟิลด์นั้นมาเป็น text "
                        f"(ถ้าส่ง JSON ทั้งก้อน จะได้ subject='No Subject' / sender='unknown' "
                        f"และ ai_score จะเพี้ยนโดยไม่มี error)")
            return "reject", "payload เป็น JSON ไม่ใช่อีเมลดิบ (RFC 5322)"

    # ไม่มี header ของอีเมลเลยสักตัว — ยังประมวลผลต่อได้ แต่ผลจะไม่น่าเชื่อถือ
    if not _EMAIL_HEADER_RE.search(s[:4000]):
        return "warn", ("ไม่พบ header ของอีเมล (From/Subject/Received) — "
                        "อาจถูกส่งมาเป็นข้อความล้วนแทน .eml · sender/subject จะว่าง "
                        "และผลวิเคราะห์จะเชื่อถือได้น้อยลง")
    return "ok", ""


def parse_raw_email(raw_content: str):
    # ⚠️ ต้อง parse จาก "bytes" เท่านั้น — message_from_string() กับข้อความ non-ASCII (ไทย/CJK)
    # จะ encode payload ด้วย raw-unicode-escape -> body กลายเป็น '\\u0e2a\\u0e27...' (ขยะ)
    # ทำให้ BERT ไม่เคยเห็นภาษาไทยจริงเลย (อีเมลไทยปกติเคยได้ ai_score 98.8 เพราะเหตุนี้)
    # หมายเหตุ: สคริปต์สร้าง training data อ่าน .eml เป็น bytes อยู่แล้ว -> เดิมนี่คือ train/serving skew
    msg = email.message_from_bytes(raw_content.encode("utf-8", errors="replace"), policy=policy.default)

    plain, html_body, attachments = "", "", []
    attachment_exts = []          # นามสกุลที่หาได้จริง (อาจมาจาก MIME/magic bytes ตอนไม่มีชื่อไฟล์)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_filename():                       # ไฟล์แนบ → เก็บชื่อ ไม่เอาเนื้อหาเป็น body
                attachments.append(part.get_filename())
                attachment_exts.append(ep.attachment_ext(part))
                continue
            # ⚠️ ไฟล์แนบที่ "ไม่มี filename=" — เดิมถูกข้ามทั้งหมด = มัลแวร์หลุด (Gateway รายงาน 2026-08-10)
            #    ตอนนี้ไล่หานามสกุลจาก Content-Type / magic bytes ต่อ
            ext = ep.attachment_ext(part)
            if ext:
                attachments.append(f"(ไม่มีชื่อไฟล์){ext}")
                attachment_exts.append(ext)
                continue
            if "attachment" in str(part.get("Content-Disposition")):
                continue
            ct = part.get_content_type()
            if ct == "text/plain":
                try: plain += part.get_payload(decode=True).decode(errors='ignore')
                except: pass
            elif ct == "text/html":                       # เก็บ HTML ไว้ strip ถ้าไม่มี text/plain
                try: html_body += part.get_payload(decode=True).decode(errors='ignore')
                except: pass
    else:
        try: payload = msg.get_payload(decode=True).decode(errors='ignore')
        except: payload = msg.get_payload() or ""
        if msg.get_content_type() == "text/html": html_body = payload
        else: plain = payload

    # เลือก body: text/plain ก่อน ถ้าไม่มีค่อย strip จาก text/html (เดิม HTML-only → fallback raw ทั้งฉบับ = noise)
    body = ep.choose_body(plain, html_body) or raw_content
    return {
        "Sender":      msg.get('From', ''),
        "Subject":     msg.get('Subject', 'No Subject'),
        "Message_ID":  msg.get('Message-ID', ''),   # ให้ .92 ใช้คู่กับ email_hash ทำ safe-dedup (hash เดี่ยวชนเมลไทยได้)
        "Reply_To":    msg.get('Reply-To', ''),
        "Received":    msg.get_all('Received', []),
        "Auth_Results": msg.get_all('Authentication-Results', []),   # ผล SPF/DKIM/DMARC จริงจาก gateway
        "Body":        body,
        # ข้อความที่ "ถอดรหัสแล้ว" ทั้ง plain + HTML ต้นฉบับ (ยังไม่ strip tag)
        # ⚠️ ใช้สำหรับนับลิงก์เท่านั้น ห้ามเอาเข้า BERT (Body คือตัวที่โมเดลใช้)
        #    เหตุผล: html_to_text ทิ้ง href ทั้งหมด (เก็บแค่ handle_data) -> Body ไม่มี URL เลย
        #    ส่วนอีเมลดิบก็ใช้ไม่ได้ เพราะ base64 ซ่อน URL ไว้ (วัดแล้ว 24.2% หาลิงก์ไม่เจอ
        #    เทียบกับ 12.5% เมื่อถอดรหัสก่อน — phishing_pot 600 ฉบับ 2026-08-26)
        "BodyDecoded": " ".join(x for x in (plain, html_body) if x),
        "Attachments": attachments,
        # นามสกุลที่หาได้จริง (ชื่อไฟล์ > MIME > magic bytes) — อย่าไปแยกนามสกุลจากชื่อไฟล์เองอีก
        "AttachmentExts": [e for e in attachment_exts if e],
    }

def extract_features(parsed_data):
    features = {}
    sender_email = re.search(r'[\w\.-]+@[\w\.-]+', parsed_data["Sender"])
    features["sender_domain"] = sender_email.group(0).split('@')[1] if sender_email else "unknown"

    if parsed_data["Reply_To"]:
        reply_email  = re.search(r'[\w\.-]+@[\w\.-]+', parsed_data["Reply_To"])
        reply_domain = reply_email.group(0).split('@')[1] if reply_email else ""
        features["reply_to_mismatch"] = features["sender_domain"] != reply_domain
    else:
        features["reply_to_mismatch"] = False

    # ใช้นามสกุลที่ parser หาไว้แล้ว (ครอบคลุมเคสไม่มีชื่อไฟล์) — fallback เป็นวิธีเดิมถ้าไม่มี key นี้
    features["attachment_type"] = parsed_data.get("AttachmentExts") or [
        os.path.splitext(f)[1].lower() for f in parsed_data["Attachments"]
    ]
    return features

# หมายเหตุ: compute_header_anomaly() ย้ายไปอยู่ risk_score.py แล้ว

# ================= Stage 2: Threat Intel =================
# executor กลางสำหรับยิงเช็ค external (link/abuseipdb/dmarc) แบบ parallel
THREAT_INTEL_EXECUTOR = ThreadPoolExecutor(max_workers=12)
EXTERNAL_TIMEOUT      = 5.0  # รอแต่ละเช็คได้ไม่เกิน 5 วิ ถ้าเกินใช้ค่า default

def extract_sender_ip(received_headers):
    for header in received_headers:
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header)
        for ip in ips:
            if not ip.startswith(('10.', '192.168.', '127.', '172.')):
                return ip
    return None

def check_ipqs(ip_address: str):
    if not ip_address or not IPQS_API_KEY:
        return 0
    url = f"https://www.ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip_address}"
    try:
        res = requests.get(url, timeout=3)
        if res.status_code == 200 and res.json().get("success"):
            return res.json().get("fraud_score", 0)
    except:
        pass
    return 0

def check_abuseipdb(ip_address: str):
    """
    เช็ค IP reputation ผ่าน AbuseIPDB → คืน abuseConfidenceScore (0-100, สูง=อันตราย)
    ⚠️ คืน None เมื่อ "วัดไม่ได้" (ไม่มี public IP / ไม่มี key / API ล้ม) — ไม่ใช่ 0
       เพราะ 0 แปลว่า "ตรวจแล้ว IP สะอาด" ซึ่งคนละความหมายกับ "ตรวจไม่ได้"
       ตอนเทรนใช้ NaN แทนกรณีนี้ -> ถ้า serve คืน 0 จะเป็น train/serving skew (P2)
    """
    if not ip_address or not ABUSEIPDB_API_KEY:
        return None
    try:
        res = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip_address, "maxAgeInDays": 90},
            timeout=3,
        )
        if res.status_code == 200:
            return res.json().get("data", {}).get("abuseConfidenceScore", 0)
    except:
        pass
    return None

def check_email_auth_dmarc(domain: str):
    if domain == "unknown":
        return {"dmarc": "fail", "penalty": 15}
    try:
        dmarc_res = checkdmarc.check_dmarc_record(domain)
        return {"dmarc": "pass" if dmarc_res.get('parsed') else "fail", "penalty": 0}
    except:
        return {"dmarc": "fail", "penalty": 15}

def check_virustotal(url: str):
    if not VT_API_KEY: return 0
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    try:
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(vt_url, headers=headers, timeout=3)
        if response.status_code == 200:
            malicious = response.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
            if malicious > 0: return 100
    except: pass
    return 0

def check_link_risk(text: str):
    """
    คืน (คะแนนสูงสุด 0–100, รายการลิงก์ที่น่าสงสัย)
    เกณฑ์การให้คะแนนอยู่ใน email_preprocess (single source เดียวกับสคริปต์เทรน) — อย่าเขียนซ้ำที่นี่
    """
    urls_found = ep.URL_RE.findall(text or "")
    if not urls_found:
        return 0, []

    max_risk = 0
    suspicious_links = []

    for url in urls_found:
        vt_bad = check_virustotal(url) == 100
        risk = ep.score_one_url(url, vt_malicious=vt_bad)
        if vt_bad:
            url = f"{url} [VT: Malware!]"
        if risk > ep.LINK_PLAIN:
            suspicious_links.append(url)
        max_risk = max(max_risk, risk)

    return max_risk, suspicious_links

# =====================================================================
# ZERO-TRUST API SHIELD
# =====================================================================
API_KEY_NAME   = "X-Security-Token"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

def _same_token(given: str, expected: str) -> bool:
    """เทียบ token แบบ constant-time กัน timing attack

    🐛 2026-08-25: เดิมส่ง str เข้า compare_digest ตรง ๆ -> ถ้าฝั่งใดมีอักขระนอก ASCII
       Python โยน TypeError ทันที = /analyze ตอบ 500 ทุก request (PMG เจอ 3 วัน)
       ต้นเหตุจริงคือ .env รับคอมเมนต์ภาษาไทยมาเป็นค่า แต่ประเด็นคือ
       "ค่า config ที่ผิดรูป ไม่ควรทำให้ API ล้ม ควรได้ 403 ตามปกติ"
       -> encode เป็น bytes ก่อนเสมอ (UTF-8 เทียบ byte ต่อ byte ได้ทุกภาษา)
    """
    try:
        return secrets.compare_digest(given.encode("utf-8"), expected.encode("utf-8"))
    except Exception:
        return False

def verify_api_key(api_key: str = Security(api_key_header)):
    if _same_token(api_key, API_SECRET_KEY):
        return
    if API_SECRET_KEY_OLD and _same_token(api_key, API_SECRET_KEY_OLD):
        # ยังใช้ token เก่าอยู่ — ผ่านได้ (ช่วง grace) แต่ดังไว้ให้รู้ว่ายังมีคนไม่ย้าย
        logger.warning("⚠️ มี request ใช้ token เก่า (API_SECRET_KEY_OLD) — ทีมนี้ยังไม่ย้ายมา token ใหม่")
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="SOC Access Denied: Invalid Security Token",
    )

# =====================================================================
# L1 CACHE + TEXT SANITIZER
# =====================================================================
L1_RESPONSE_CACHE = {}
CACHE_MAX_ENTRIES = 5000
CACHE_LOCK        = threading.Lock()
IN_PROGRESS_HASHES = set()

def sanitize_text_before_hash(text: str) -> str:
    if not text:
        return ""
    cleaned = re.sub(r"[​-‍﻿\x00-\x1F\x7F]", "", text)
    cleaned = (
        unicodedata.normalize("NFKD", cleaned)
        .encode("ascii", "ignore")
        .decode("utf-8")
    )
    return " ".join(cleaned.split()).lower()

def get_email_fingerprint(text: str) -> str:
    clean_text = sanitize_text_before_hash(text)
    return hashlib.sha256(clean_text.encode("utf-8")).hexdigest()

def update_l1_cache(fingerprint: str, response_data: dict):
    if len(L1_RESPONSE_CACHE) >= CACHE_MAX_ENTRIES:
        oldest_key = next(iter(L1_RESPONSE_CACHE))
        del L1_RESPONSE_CACHE[oldest_key]
    L1_RESPONSE_CACHE[fingerprint] = response_data

# =====================================================================
# SENDER HELPERS
# =====================================================================
def extract_sender_email(from_header: str) -> str:
    m = re.search(r'[\w\.-]+@[\w\.-]+', from_header or "")
    return m.group(0) if m else ""


def extract_display_name(from_header: str) -> str:
    """ชื่อที่ผู้ส่งตั้งไว้ — From: "SCB Bank" <x@evil.xyz> -> 'SCB Bank' (ไม่มีก็คืน '')"""
    hdr = (from_header or "").strip()
    m = re.search(r"<[^>]+>", hdr)
    return hdr[:m.start()].strip().strip('"').strip("'").strip() if m else ""

# ================= Dataset Capture (feedback loop) =================
def capture_for_dataset(email_hash: str, raw: dict):
    """append feature+text ครบ 1 อีเมล ลง JSONL (ไว้ export เป็น dataset retrain)
    ปลอดภัยเสมอ: ถ้า error ไม่กระทบ /analyze · เปิดด้วย env DATASET_CAPTURE=1 เท่านั้น"""
    if not DATASET_CAPTURE:
        return
    try:
        rec = {
            "hash":                email_hash,
            "subject":             raw.get("subject", ""),
            "body_text":           raw.get("body_text", ""),
            # feature ตามสัญญา ep.STAGE2_FEATURES (schema v2)
            # ⚠️ abuseipdb_score เก็บ None ไว้ตามจริง (ไม่แปลงเป็น 0) — dataset ที่ export ไปเทรนรอบหน้า
            #    ต้องแยก "ตรวจแล้วสะอาด" ออกจาก "ตรวจไม่ได้" ให้ได้ ไม่งั้นวนกลับไปเป็นปัญหา P2 เดิม
            "ai_score":            raw.get("raw_ai_score"),
            "link_risk":           raw.get("raw_link_score"),
            "abuseipdb_score":     raw.get("abuseipdb_score") if raw.get("abuseipdb_measured") else None,
            "abuseipdb_missing":   0 if raw.get("abuseipdb_measured") else 1,
            "reply_to_mismatch":   1 if raw.get("reply_to_mismatch") else 0,
            "attachment_risk":     1 if raw.get("has_malware") else 0,
            # เก็บ dmarc ต่อไปเพื่อไว้ดู แต่ไม่ใช่ feature ของโมเดลแล้ว (P2)
            "dmarc_result":        raw.get("dmarc_result"),
            "predicted_attack_type": raw.get("attack_type"),   # weak label (โมเดลทาย) — ให้ analyst แก้ทีหลัง
            "ts":                  utcnow().isoformat(),
        }
        p = Path(DATASET_CAPTURE_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning(f"[DATASET] capture ล้มเหลว (ไม่กระทบการวิเคราะห์): {e}")


# ================= Health Check =================
@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "model_loaded":    model is not None,
        "xgboost_loaded":  xgb_model is not None,
    }

# ================= API: /model/info =================
# ให้ Dashboard (10.22.1.181) ใช้แทน mock data ในหน้า AiModelPage / ItDashboard
# ตัวเลข metric อ่านจาก model_metrics.json (อย่า hardcode ที่นี่ ไม่งั้นค้างเก่าเวลา deploy โมเดลใหม่)
MODEL_METRICS_PATH = os.getenv("MODEL_METRICS_PATH", "model_metrics.json")


def _file_mtime_iso(path: str):
    """เวลาแก้ไขไฟล์จริงบนดิสก์ -> ยืนยันว่าไฟล์โมเดลที่โหลดอยู่เป็นตัวไหน"""
    try:
        return datetime.utcfromtimestamp(Path(path).stat().st_mtime).isoformat() + "Z"
    except Exception:
        return None


@app.get("/model/info", dependencies=[Depends(verify_api_key)])
def model_info():
    """ข้อมูลโมเดลที่ active อยู่ + metric จริง (สำหรับ Dashboard)
    ปลอดภัยเสมอ: ถ้าไฟล์ metric หาย ยังคืนสถานะ runtime ได้ (metrics = null)"""
    try:
        metrics = json.loads(Path(MODEL_METRICS_PATH).read_text(encoding="utf-8"))
        metrics.pop("_comment", None)
    except Exception as e:
        logger.warning(f"[MODEL_INFO] อ่าน {MODEL_METRICS_PATH} ไม่ได้: {e}")
        metrics = {"stage1": None, "stage2": None}

    s1 = metrics.get("stage1") or {}
    s2 = metrics.get("stage2") or {}

    # ผสมสถานะ "ของจริงตอนรัน" เข้าไป — กันกรณีไฟล์ metric ไม่ตรงกับโมเดลที่โหลดจริง
    s1 = {**s1, "model_path": MODEL_PATH,
          "loaded": model is not None,
          "file_updated_at": _file_mtime_iso(f"{MODEL_PATH}/model.safetensors")}
    s2 = {**s2, "model_path": "xgboost_type_classifier.json",
          "loaded": xgb_model is not None and label_encoder is not None,
          "file_updated_at": _file_mtime_iso("xgboost_type_classifier.json")}
    # คลาสจริงจาก label_encoder ที่โหลดอยู่ (ถือเป็นแหล่งความจริง ทับค่าในไฟล์ metric)
    if label_encoder is not None:
        try:
            s2["classes"] = list(label_encoder.classes_)
        except Exception:
            pass

    return {
        "stage1": s1,
        "stage2": s2,
        "server_time": utcnow().isoformat() + "Z",
        "retrain_supported": {
            # ตอบตรงๆ ให้ UI ตัดสินใจแสดงปุ่มถูก: Stage 1 เทรนบน VM นี้ไม่ได้ (ไม่มี GPU)
            "stage1": False,
            "stage2": False,
            "note": "Stage 1 (BERT) ต้องเทรน offline บนเครื่อง GPU · Stage 2 retrain endpoint ยังไม่ deploy "
                    "(รอ email_hash จากฝั่ง Dashboard/Gateway ตาม Path A)",
        },
    }


# ================= API: /model/history + /model/activate (rollback) =================
# ให้ Dashboard ทำปุ่ม "ย้อนกลับโมเดล" ได้ — ทะเบียนเวอร์ชันอยู่ใน model_registry.json
MODEL_REGISTRY_PATH = os.getenv("MODEL_REGISTRY_PATH", "model_registry.json")
MODEL_SWAP_LOCK = threading.Lock()      # กันสลับโมเดลกลางคัน ขณะ /analyze กำลังใช้อยู่


def _load_registry() -> dict:
    try:
        reg = json.loads(Path(MODEL_REGISTRY_PATH).read_text(encoding="utf-8"))
        reg.pop("_comment", None)
        return reg
    except Exception as e:
        logger.warning(f"[REGISTRY] อ่าน {MODEL_REGISTRY_PATH} ไม่ได้: {e}")
        return {"stage2": {"active": None, "versions": {}}}


def _save_registry(reg: dict):
    Path(MODEL_REGISTRY_PATH).write_text(
        json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")


class ActivateRequest(BaseModel):
    version: str
    force: bool = False      # ต้องใส่ true ถ้าจะฝืนสลับทั้งที่ไม่ compatible กับ Stage 1 ปัจจุบัน


@app.get("/model/history", dependencies=[Depends(verify_api_key)])
def model_history():
    """รายการเวอร์ชัน Stage 2 ที่ย้อนกลับได้ + บอกว่าเข้ากับ Stage 1 ที่ใช้อยู่ไหม"""
    reg = _load_registry()
    s2 = reg.get("stage2", {})
    active = s2.get("active")
    out = []
    for vid, v in (s2.get("versions") or {}).items():
        files_ok = (Path(v.get("archive_model", "")).exists()
                    and Path(v.get("archive_encoder", "")).exists())
        # ⚠️ กันยิงเท้าตัวเอง: โมเดล Stage 2 ผูกกับ ai_score ของ Stage 1 ที่ใช้ตอนเทรน
        # ถ้า Stage 1 ปัจจุบันคนละตัว -> feature เพี้ยน (train/serving skew)
        compatible = (v.get("trained_with_stage1") == MODEL_PATH)
        schema = v.get("feature_schema", "v1")
        schema_ok = (schema == "v2")     # v2 = สัญญา feature ที่โค้ดรุ่นนี้ป้อนให้โมเดล
        if not schema_ok:
            warning = (f"โมเดลนี้ใช้ feature schema '{schema}' (มี dmarc_fail) แต่โค้ดที่รันอยู่ป้อน schema 'v2' "
                       f"— จำนวน feature เท่ากันแต่ความหมายคนละช่อง จะทำนายผิดแบบไม่มี error "
                       f"**ย้อนกลับไม่ได้ แม้กด force** ต้อง deploy โค้ดรุ่นเก่าคู่กันเท่านั้น")
        elif not compatible:
            warning = (f"โมเดลนี้เทรนคู่กับ Stage 1 '{v.get('trained_with_stage1')}' "
                       f"แต่ตอนนี้ระบบใช้ '{MODEL_PATH}' — ai_score จะไม่ตรงกับตอนเทรน "
                       f"(train/serving skew) ต้องส่ง force=true ถึงจะสลับได้")
        else:
            warning = None
        out.append({
            "version": vid,
            "active": vid == active,
            "trained_at": v.get("trained_at"),
            "trained_with_stage1": v.get("trained_with_stage1"),
            "feature_schema": schema,
            "features": v.get("features"),
            "n_train": v.get("n_train"),
            "note": v.get("note"),
            "metrics": v.get("metrics"),
            "metrics_note": v.get("metrics_note"),
            "files_available": files_ok,
            "compatible_with_active_stage1": compatible,
            "compatible_feature_schema": schema_ok,
            "activatable": files_ok and schema_ok and vid != active,
            "warning": warning,
        })
    out.sort(key=lambda r: r["trained_at"] or "", reverse=True)
    return {"stage1_active": MODEL_PATH, "stage2_active": active,
            "active_feature_schema": "v2", "features": list(ep.STAGE2_FEATURES),
            "versions": out}


@app.post("/model/activate", dependencies=[Depends(verify_api_key)])
def model_activate(req: ActivateRequest):
    """สลับโมเดล Stage 2 ไปเวอร์ชันที่เลือก (ใช้ทำปุ่ม rollback) — ใช้เวลาไม่ถึงวินาที"""
    global xgb_model, label_encoder

    reg = _load_registry()
    s2 = reg.get("stage2", {})
    versions = s2.get("versions") or {}
    if req.version not in versions:
        raise HTTPException(status_code=404, detail=f"ไม่พบเวอร์ชัน '{req.version}'")

    v = versions[req.version]
    src_model, src_enc = Path(v.get("archive_model", "")), Path(v.get("archive_encoder", ""))
    if not (src_model.exists() and src_enc.exists()):
        raise HTTPException(status_code=409, detail=f"ไฟล์ของเวอร์ชัน '{req.version}' หายไปจากดิสก์")

    prev_active = s2.get("active")
    if req.version == prev_active:
        return {"status": "unchanged", "active": prev_active, "message": "เวอร์ชันนี้ใช้งานอยู่แล้ว"}

    # 🔒 ตัวกัน schema — ห้าม force ข้ามได้ ต่างจาก stage1_mismatch
    # โมเดล schema v1 รับ 6 feature ที่มี dmarc_fail · โค้ด serve ตอนนี้ป้อน schema v2 (ไม่มี dmarc_fail
    # แต่มี abuseipdb_missing) · XGBoost รับ array ล้วน ไม่เช็คชื่อคอลัมน์ -> จำนวนตรงแต่ความหมายสลับช่อง
    # จะทำนายผิดโดยไม่มี error ให้เห็นเลย ซึ่งอันตรายเกินกว่าจะให้ปุ่มไหนกดผ่านได้
    want_schema = "v2"
    got_schema = v.get("feature_schema", "v1")
    if got_schema != want_schema:
        raise HTTPException(status_code=409, detail={
            "error": "feature_schema_mismatch",
            "message": f"เวอร์ชันนี้ใช้ feature schema '{got_schema}' แต่โค้ดที่รันอยู่ป้อน schema "
                       f"'{want_schema}' ({', '.join(ep.STAGE2_FEATURES)}) — จำนวน feature เท่ากันแต่ความหมาย "
                       f"คนละช่อง โมเดลจะทำนายผิดแบบเงียบๆ · **force ข้ามไม่ได้** ต้อง deploy โค้ดรุ่นที่ตรงกันแทน",
            "expected_features": list(ep.STAGE2_FEATURES),
            "version_features": v.get("features"),
            "forceable": False,
        })

    if v.get("trained_with_stage1") != MODEL_PATH and not req.force:
        raise HTTPException(status_code=409, detail={
            "error": "stage1_mismatch",
            "message": f"เวอร์ชันนี้เทรนคู่กับ Stage 1 '{v.get('trained_with_stage1')}' "
                       f"แต่ระบบใช้ '{MODEL_PATH}' อยู่ — สลับแล้ว ai_score จะไม่ตรงกับตอนเทรน "
                       f"(train/serving skew) ถ้ายืนยันจริงให้ส่ง force=true",
            "requires": "force=true",
        })

    import shutil
    with MODEL_SWAP_LOCK:
        try:
            shutil.copy(src_model, "xgboost_type_classifier.json")
            shutil.copy(src_enc, "label_encoder.pkl")
            new_model = xgb.XGBClassifier()
            new_model.load_model("xgboost_type_classifier.json")
            new_enc = joblib.load("label_encoder.pkl")
        except Exception as e:
            logger.error(f"[ACTIVATE] สลับไป {req.version} ล้มเหลว: {e}")
            raise HTTPException(status_code=500, detail=f"สลับโมเดลล้มเหลว: {e}")

        xgb_model, label_encoder = new_model, new_enc
        s2["active"] = req.version
        _save_registry(reg)

        # ⚠️ ผลใน L1 cache คิดด้วยโมเดลเก่า -> ต้องล้าง ไม่งั้นจะคืนคำตอบเก่าให้ Gateway
        with CACHE_LOCK:
            n_cleared = len(L1_RESPONSE_CACHE)
            L1_RESPONSE_CACHE.clear()

    # sync ตัวเลขใน /model/info ให้ตรงกับเวอร์ชันที่เพิ่งสลับ (ไม่งั้น dashboard โชว์ metric ผิดรุ่น)
    try:
        mp = Path(MODEL_METRICS_PATH)
        m = json.loads(mp.read_text(encoding="utf-8"))
        m.setdefault("stage2", {})
        m["stage2"]["active_version"] = req.version
        m["stage2"]["trained_at"] = v.get("trained_at")
        m["stage2"]["n_train_total"] = v.get("n_train")
        if v.get("metrics") is not None:
            # merge ไม่ใช่เขียนทับ — กัน field อธิบาย (dataset/n_train/n_test) หายไป
            hold = m["stage2"].setdefault("evaluations", {}).setdefault("holdout", {})
            hold.update(v["metrics"])
        mp.write_text(json.dumps(m, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        logger.warning(f"[ACTIVATE] sync {MODEL_METRICS_PATH} ไม่สำเร็จ: {e}")

    logger.info(f"[ACTIVATE] Stage2: {prev_active} -> {req.version} (ล้าง cache {n_cleared} รายการ)")
    return {
        "status": "activated",
        "active": req.version,
        "previous": prev_active,
        "classes": list(label_encoder.classes_),
        "cache_cleared": n_cleared,
        "forced": bool(req.force),
        "warning": None if v.get("trained_with_stage1") == MODEL_PATH else
                   f"สลับแบบ force ทั้งที่ไม่ตรงกับ Stage 1 '{MODEL_PATH}' — ai_score อาจเพี้ยน ควรกลับไปใช้รุ่นที่คู่กัน",
    }


# ================= API: /analyze =================
@app.post("/parse", dependencies=[Depends(verify_api_key)])
@limiter.limit("60/minute")
def parse_email_endpoint(request: Request, req: ParseRequest):
    """
    แกะ raw .eml เป็น signals ด้วย "ตัวแกะตัวเดียวกับที่โมเดลใช้ตอนเทรน" — กัน train/serving skew
    เปิดให้ทีม mail server (.92) เรียกแทนการเขียน parser เอง (ตกลงกันแล้ว 2026-07-25)

    เป็นการ "แกะล้วนๆ": ไม่เรียก BERT / ไม่ยิง external API (AbuseIPDB/VT/checkdmarc)
      -> เร็ว + deterministic + ไม่กิน quota · spf/dkim/dmarc อ่านจาก Authentication-Results
         header ในเมล (รายงานค่าที่ gateway ใส่มา ไม่ได้ verify ซ้ำเอง)
    sender_ip_header = IP จาก Received header (ปลอมได้) ไม่ใช่ connection-level IP จาก PMG
    """
    raw_text = req.text
    # payload guard ตัวเดียวกับ /analyze — JSON ทั้งก้อนต้องโดนปฏิเสธที่นี่ด้วย (บั๊กเดิมที่ทำให้ ai≈100)
    level, msg = inspect_payload(raw_text)
    if level == "reject":
        raise HTTPException(status_code=400, detail={
            "error": "invalid_email_payload",
            "message": msg,
            "expected": "field 'text' ต้องเป็นอีเมลดิบรูปแบบ RFC 5322 (มี header From/Subject/Received)",
        })

    parsed = parse_raw_email(raw_text)                       # ← ตัวแกะเดียวกับ /analyze
    feats  = extract_features(parsed)
    auth   = ep.parse_authentication_results(parsed["Auth_Results"])
    attachments = parsed["Attachments"]
    spoof  = ep.spoofing_from_headers(parsed["Sender"], req.recipient, parsed["Reply_To"])
    evidence = ep.attack_evidence(
        spoof_reasons=spoof["reasons"],
        body_text=parsed.get("BodyDecoded", ""),
        sender_domain=feats["sender_domain"],
        reply_to_mismatch=bool(feats["reply_to_mismatch"]),
        attachment_risk=any(ep.is_risky_attachment(a) for a in attachments),
        subject=parsed["Subject"],
    )
    return {
        # canonical hash ตัวเดียวกับที่ /analyze ใช้ (raw_signals.email_hash) — ให้ .92 เอาไป dedup
        # กัน re-ingest ได้โดยไม่ต้องเขียนสูตร normalize เอง (เขียนเองแล้วเพี้ยน = key ไม่ตรง)
        "email_hash":        get_email_fingerprint(raw_text),
        "message_id":        parsed["Message_ID"],   # ให้ .92 dedup แบบ hash+Message-ID (ปลอดภัยกับเมลไทย)
        "sender":            extract_sender_email(parsed["Sender"]),
        "sender_domain":     feats["sender_domain"],
        "subject":           parsed["Subject"],
        "reply_to":          parsed["Reply_To"],
        "body":              parsed["Body"],
        "attachments":       attachments,
        "attachment_risk":   any(ep.is_risky_attachment(a) for a in attachments),
        "reply_to_mismatch": bool(feats["reply_to_mismatch"]),
        # ปลอมตัวผู้ส่ง — ค่าเดียวกับที่ /analyze ส่งใน raw_signals (ตรรกะเดียวกัน ไม่ต้องคำนวณซ้ำ)
        "sender_spoofing":   spoof["spoofing"],
        "spoofing_score":    spoof["score"],
        "spoofing_reasons":  spoof["reasons"],
        "sender_display_name": extract_display_name(parsed["Sender"]),
        # ตัวแปรหลักฐานแยกประเภทการโจมตี — ค่าเดียวกับที่ /analyze ส่งใน raw_signals
        # (/parse ไม่เรียก BERT จึงไม่มี ai_score แต่หลักฐานพวกนี้ไม่ต้องใช้ ai_score เลย)
        "attack_evidence":   evidence,
        # /parse ไม่เรียก BERT -> ไม่มี ai_score -> ส่ง None
        # ผลคือเคส "หลักฐานไม่พอ" จะได้ Normal เสมอ (ไม่มีทางรู้ว่าเป็น Unknown Threat)
        # ถ้าต้องการแยกสองกรณีนี้ ให้เรียก /analyze แทน
        "attack_type_v2":    ep.classify_attack_type(evidence, ai_score=None),
        "sender_ip_header":  extract_sender_ip(parsed["Received"]),
        "spf":               auth["spf"],
        "dkim":              auth["dkim"],
        "dmarc":             auth["dmarc"],
        "payload_warning":   msg if level == "warn" else None,
        "parser_version":    "v3-mbert-aligned",
    }


@app.post("/analyze", dependencies=[Depends(verify_api_key)])
@limiter.limit("30/minute")
def analyze_email(request: Request, req: EmailRequest):
    raw_text   = req.text
    # ---- ตรวจ payload ก่อนทำอะไรทั้งสิ้น: ผิดต้อง "ดังตรงนี้" ไม่ใช่ไปโผล่เป็นคะแนนเพี้ยนปลายทาง ----
    payload_level, payload_msg = inspect_payload(raw_text)
    if payload_level == "reject":
        logger.error(f"[PAYLOAD] ปฏิเสธคำขอจาก {request.client.host if request.client else '?'}: {payload_msg}")
        raise HTTPException(status_code=400, detail={
            "error": "invalid_email_payload",
            "message": payload_msg,
            "expected": "field 'text' ต้องเป็นอีเมลดิบรูปแบบ RFC 5322 (มี header From/Subject/Received)",
        })

    email_hash = get_email_fingerprint(raw_text)   # content-based — เป็น join key ของ feedback loop
    # cache key ต้องรวม auth ที่ PMG ส่งมาด้วย: body เดียวกันแต่ auth ต่าง = คนละผล (เช่น phishing
    # template ส่งจากหลายโดเมน spf ต่างกัน) ถ้า key ด้วย text อย่างเดียว spoofed จะได้ auth "pass" ของเก่าจาก cache
    # ⚠️ ทุก input ที่ "เปลี่ยนคำตอบได้" ต้องอยู่ใน cache key ไม่ใช่แค่เนื้อความ
    #    (เคยพลาดมาแล้วกับ spf/dkim/dmarc — body เดียวกันแต่ auth ต่าง ได้คำตอบเก่า)
    #    sender_ip ก็เช่นกัน: ฟิชชิ่งชุดเดียวกันยิงจากหลาย IP -> reputation ต่างกัน
    cache_key  = (f"{email_hash}|{req.spf_result}|{req.dkim_valid}|{req.dmarc_result}"
                  f"|{req.sender_ip}")

    # log ทันทีที่รับ request เข้ามา (เห็นว่า Gateway ยิงมาถึงจริง ก่อนเริ่มวิเคราะห์)
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"[INCOMING] รับอีเมลจาก {client_ip} → recipient: {req.recipient} (hash: {email_hash[:8]})")
    if payload_level == "warn":
        logger.warning(f"[PAYLOAD] hash={email_hash[:8]}: {payload_msg}")

    with CACHE_LOCK:
        if cache_key in L1_RESPONSE_CACHE:
            logger.info(f"[L1 CACHE HIT] Hash: {email_hash[:8]}")
            return L1_RESPONSE_CACHE[cache_key]

        is_already_processing = cache_key in IN_PROGRESS_HASHES
        if not is_already_processing:
            IN_PROGRESS_HASHES.add(cache_key)

    if is_already_processing:
        logger.info(f"[QUEUE WAIT] Hash: {email_hash[:8]}")
        wait_time = 0.0
        while cache_key not in L1_RESPONSE_CACHE and wait_time < 5.0:
            time.sleep(0.05)
            wait_time += 0.05

        if cache_key in L1_RESPONSE_CACHE:
            logger.info(f"[QUEUE DONE] Hash: {email_hash[:8]}")
            return L1_RESPONSE_CACHE[cache_key]
        else:
            return {"raw_signals": {"attack_type": "Timeout Fallback"}, "status": "timeout_fallback"}

    try:
        parsed        = parse_raw_email(raw_text)
        features      = extract_features(parsed)
        sender_domain = features["sender_domain"]
        # ตรวจการปลอมตัวผู้ส่ง (ทีม .92 ขอมา) — ใช้ From header ดิบเพราะต้องดู display name
        spoof         = ep.spoofing_from_headers(parsed["Sender"], req.recipient, parsed["Reply_To"])
        if spoof["spoofing"]:
            logger.warning(f"[SPOOF] hash={email_hash[:8]} score={spoof['score']} "
                           f"เหตุผล={';'.join(spoof['reasons'])}")

        # Stage 1: BERT
        # ให้ตรงกับตอน train เป๊ะ: (subject + ". " + body) → mask URL → tokenize (ผ่าน email_preprocess)
        # เดิม serve ป้อน body อย่างเดียว/ไม่มี subject = train/serving skew (train รวม subject แล้ว)
        body_for_bert = ep.build_bert_text(parsed["Subject"], parsed["Body"])
        inputs = tokenizer(body_for_bert, padding='max_length', max_length=256, truncation=True, return_tensors="pt")
        with torch.no_grad():
            outputs      = model(**inputs)
            raw_ai_score = F.softmax(outputs.logits, dim=1)[0][1].item() * 100

        # ใช้ตัวเช็คนามสกุลเสี่ยงกลาง (email_preprocess.is_risky_ext) ให้ตรงกับตอน train เป๊ะ
        has_malware = any(ep.is_risky_ext(ext) for ext in features["attachment_type"])

        # ---- หลักฐานสำหรับแยกประเภทการโจมตี (ยังไม่เอาไปตัดสิน แค่ส่งออกให้เห็นก่อน) ----
        # 🎯 เป้าหมาย: ให้ทุกทีมเห็น "ตัวเลขดิบ" ที่จะใช้คำนวณประเภท แทนที่จะได้แต่ชื่อคลาส
        #    จาก XGBoost ที่อธิบายที่มาไม่ได้ (73% ของจุดตัดคือ ai_score > 99.99x)
        # ⚠️ additive อย่างเดียว — ไม่แตะ attack_type เดิม ทีมอื่นที่ใช้อยู่จึงไม่พัง
        evidence = ep.attack_evidence(
            spoof_reasons=spoof["reasons"],
            body_text=parsed.get("BodyDecoded", ""),   # ถอดรหัสแล้ว ไม่ใช่ Body ที่ strip tag ทิ้ง href
            sender_domain=sender_domain,
            reply_to_mismatch=features["reply_to_mismatch"],
            attachment_risk=has_malware,
            subject=parsed["Subject"],
        )

        # ถ้ามี URL ใน body → บังคับผ่าน Stage 2 (link check) เสมอ ห้าม fast path
        has_urls = bool(re.findall(r'https?://[^\s]+', raw_text))
        if risk_score.is_fast_path_safe(raw_ai_score, has_malware) and not has_urls:
            # AI ต่ำ + ไม่มีไฟล์อันตราย → ข้าม Stage 2 (external checks) เพื่อความเร็ว
            # (raw_signals ยังถูกส่งกลับ Gateway ครบเหมือนเดิม — Dashboard จะได้นับ safe ด้วย)
            raw_link_score, abuseipdb_score = 0, None   # None = ไม่ได้วัด (fast path ข้าม external check)
            ip_src = "not_checked"
            auth_results = {"dmarc": "none"}
            attack_type  = "Normal"
        else:
            # Stage 2: Threat Intel + XGBoost
            # ยิง 3 เช็ค external พร้อมกัน (parallel) แล้วรอทั้งหมดใน deadline เดียว
            # PMG ส่ง connection-level IP มาก็ใช้ตัวนั้น (ปลอมไม่ได้) ไม่งั้น fallback อ่าน Received header
            hdr_ip = extract_sender_ip(parsed["Received"])
            if req.sender_ip:
                sender_ip, ip_src = req.sender_ip.strip(), "pmg"
                if hdr_ip and hdr_ip != sender_ip:
                    logger.warning(f"[AUTH] sender_ip ไม่ตรง: PMG='{sender_ip}' header='{hdr_ip}' "
                                   f"— ยึด PMG (header อาจถูกปลอม)")
            else:
                sender_ip, ip_src = hdr_ip, ("header" if hdr_ip else "none")
            f_link  = THREAT_INTEL_EXECUTOR.submit(check_link_risk, raw_text)
            f_abuseipdb  = THREAT_INTEL_EXECUTOR.submit(check_abuseipdb, sender_ip)  # abuseipdb_score = IP reputation (AbuseIPDB)
            f_dmarc = THREAT_INTEL_EXECUTOR.submit(check_email_auth_dmarc, sender_domain)

            # รอทั้ง 3 พร้อมกันไม่เกิน EXTERNAL_TIMEOUT (ไม่ใช่ 5+5+5) — ตัวไหนไม่เสร็จใช้ default
            futures_wait([f_link, f_abuseipdb, f_dmarc], timeout=EXTERNAL_TIMEOUT)

            def _get(fut, default, name):
                if not fut.done():
                    logger.warning(f"[STAGE2] {name} timeout (>{EXTERNAL_TIMEOUT}s) — ใช้ค่า default")
                    return default
                try:
                    return fut.result()
                except Exception as e:
                    logger.warning(f"[STAGE2] {name} error: {e}")
                    return default

            raw_link_score, _         = _get(f_link, (0, []), "link")
            abuseipdb_score                = _get(f_abuseipdb, None, "abuseipdb")   # None = วัดไม่ได้
            auth_results              = _get(f_dmarc, {"dmarc": "fail", "penalty": 15}, "dmarc")

            # ⚠️ dmarc ไม่ใช่ feature ของโมเดลแล้ว (P2, schema v2) — ยังเรียกอยู่เพราะเป็นสัญญาณ scoring ให้ Gateway
            #    เหตุผลที่ตัดออก: ข้อมูลเทรนที่ "วัดได้" มีแต่ค่า fail -> ค่า 0 ที่โมเดลเคยเห็นคือ "DNS lookup ล้ม"
            #    ไม่ใช่ "DMARC ผ่าน" · พออีเมลองค์กรที่ DMARC ผ่านจริงเข้ามา จะถูกดันไปทาง Malware/BEC
            # ลำดับ feature มาจาก ep.STAGE2_FEATURES (single source เดียวกับสคริปต์เทรน) — อย่าสร้าง list เอง
            attack_type = stage2_xgboost_predict(ep.stage2_vector(
                ai_score=raw_ai_score,
                link_risk=raw_link_score,
                abuseipdb_score=abuseipdb_score,          # None -> ตั้ง abuseipdb_missing=1 ให้อัตโนมัติ
                reply_to_mismatch=features["reply_to_mismatch"],
                attachment_risk=has_malware,
            ))

        # AI Server ไม่คิดคะแนน/ไม่เขียน DB — รวบ raw signals แล้ว "ตอบกลับ Gateway (10.22.1.66) ตรงๆ"
        # (HTTP response ของ /analyze) จากนั้น Gateway + mail server ไปคำนวณ risk + log + ตัดสิน deliver กันเอง
        # ---- resolve SPF/DKIM/DMARC (สัญญาณ scoring ส่งกลับ Gateway) ----
        # ลำดับความน่าเชื่อ: PMG payload (เช็คที่ connection-level IP จริง) > Authentication-Results header > checkdmarc
        # PMG ที่ปิด L7 เห็น IP จริงตอนรับเมล -> เชื่อถือกว่า header ที่ upstream ปลอมได้
        # ⚠️ ไม่เอา auth เข้าเป็น feature ของ Stage 2 (spam corpus ตอนเทรนไม่มี header นี้ = cross-source artifact)
        auth_hdr = ep.parse_authentication_results(parsed["Auth_Results"])

        def _resolve(pmg_val, hdr_val, name):
            """PMG payload ก่อน, ไม่มีค่อยใช้ header. log ถ้าสองค่าขัดกัน (อาจเจอ header ปลอม)"""
            if pmg_val is not None:
                pmg_val = str(pmg_val).lower()
                if hdr_val not in ("none", "") and hdr_val != pmg_val:
                    logger.warning(f"[AUTH] {name} ไม่ตรง: PMG='{pmg_val}' header='{hdr_val}' "
                                   f"(hash {email_hash[:8]}) — ยึด PMG")
                return pmg_val, "pmg"
            if hdr_val not in ("none", ""):
                return hdr_val, "header"
            return "none", "none"

        # DKIM: PMG ส่งเป็น bool (dkim_valid) -> แปลงเป็น string ให้ contract raw_signals คงเดิม
        dkim_pmg = None if req.dkim_valid is None else ("pass" if req.dkim_valid else "fail")
        spf_final,  spf_src  = _resolve(req.spf_result,  auth_hdr["spf"],  "spf")
        dkim_final, dkim_src = _resolve(dkim_pmg,         auth_hdr["dkim"], "dkim")
        # dmarc: PMG > header > checkdmarc (auth_results มีเฉพาะตอนผ่าน Stage 2)
        if req.dmarc_result is not None:
            dmarc_for_score, dmarc_src = str(req.dmarc_result).lower(), "pmg"
        elif auth_hdr["dmarc"] != "none":
            dmarc_for_score, dmarc_src = auth_hdr["dmarc"], "header"
        else:
            dmarc_for_score, dmarc_src = auth_results.get("dmarc", "none"), "checkdmarc"

        raw_signals = {
            "email_hash":        email_hash,   # join key: ให้ Gateway/feedback อ้างอิงกลับมาได้ (feedback loop)
            "message_id":        parsed["Message_ID"],   # ให้ .92 dedup แบบ hash+Message-ID (กัน re-ingest ปลอดภัยกับเมลไทย)
            "sender_domain":     sender_domain,
            "sender_email":      extract_sender_email(parsed["Sender"]),
            "recipient":         req.recipient,
            "spf_result":        spf_final,     # ยึด PMG payload > header > (none)
            "dkim_result":       dkim_final,    # PMG dkim_valid(bool) -> string | header
            "dmarc_result":      dmarc_for_score,  # PMG > header > checkdmarc
            "auth_source":       {"spf": spf_src, "dkim": dkim_src, "dmarc": dmarc_src,
                                  "sender_ip": ip_src},   # pmg | header | none | not_checked
            "reply_to_mismatch": features["reply_to_mismatch"],
            # ตรวจการปลอมตัวผู้ส่งจริงแล้ว (เดิมเป็น False ตายตัว = กฎ +4 ของ .92 เป็น dead code)
            # ⚠️ ไม่ใช่ feature ของโมเดล -> ไม่กระทบ ai_score / attack_type
            "sender_spoofing":   spoof["spoofing"],
            "spoofing_score":    spoof["score"],      # 0-100 ให้ .92 ตั้งน้ำหนักเองได้
            "spoofing_reasons":  spoof["reasons"],    # รหัสสัญญาณ เช่น brand_mismatch:paypal!=evil.top
            # ตัวแปรหลักฐานแยกประเภทการโจมตี (ดู ep.ATTACK_EVIDENCE) — 🆕 2026-08-26
            # ทีม .92 เอาไปตั้งน้ำหนักเองได้ทันที ไม่ต้องคำนวณลิงก์/ปลอมตัวซ้ำฝั่งตัวเอง
            "attack_evidence":   evidence,
            # ประเภทการโจมตีแบบ "อธิบายที่มาได้" — คิดจากหลักฐานข้างบน ไม่ใช่จาก XGBoost
            # ⚠️ ห้ามเอา attack_type_v2.score ไปบวกเข้า risk score ของ .92 (จะนับซ้ำกับ LANGUAGE)
            #    มันเป็นคนละแกน: บอก "ชนิด" ไม่ได้บอก "ความเสี่ยง"
            "attack_type_v2":    ep.classify_attack_type(evidence, ai_score=raw_ai_score),
            "attachment_type":   features["attachment_type"],
            "has_malware":       has_malware,   # คำนวณด้วย email_preprocess.is_risky_ext แล้ว — Gateway/mail server ใช้ค่านี้ตรงๆ อย่าคำนวณใหม่
            "raw_ai_score":      round(raw_ai_score, 2),
            "raw_link_score":    round(float(raw_link_score), 2),
            # ระดับความมั่นใจของสัญญาณลิงก์ — ฝั่ง scoring จะได้ไม่ต้องเดาจากตัวเลข
            # confirmed = VirusTotal ยืนยัน (ใช้ block เดี่ยวๆ ได้)
            # suspicious = เดาจากรูปแบบ URL เท่านั้น (ต้องรวมกับสัญญาณอื่นก่อนตัดสิน) ⚠️
            # low = มีลิงก์แต่ไม่มีอะไรน่าสงสัย · none = ไม่มีลิงก์
            "link_confidence":   ep.link_confidence(int(raw_link_score)),
            # contract เดิมของ Gateway/.92 คาดหวังตัวเลขเสมอ -> วัดไม่ได้ยังส่ง 0 (backward-compatible)
            # แต่เพิ่ม abuseipdb_measured ให้แยกออกว่า 0 นี้คือ "IP สะอาดจริง" หรือ "ตรวจไม่ได้"
            "abuseipdb_score":        0 if abuseipdb_score is None else abuseipdb_score,
            "abuseipdb_measured":     abuseipdb_score is not None,
            "subject":           parsed["Subject"],
            "body_text":         parsed["Body"],
            "attack_type":       attack_type,
        }

        # เก็บ dataset (feedback loop) — opt-in, ไม่กระทบการตอบกลับ
        capture_for_dataset(email_hash, raw_signals)

        # ตอบ raw signals กลับ Gateway (synchronous HTTP response) — Gateway + mail server คำนวณ risk + เขียน DB เอง
        result = {"raw_signals": raw_signals}
        logger.info(f"[SIGNALS] Hash: {email_hash[:8]} → ส่ง raw signals กลับ Gateway "
                    f"(ai={round(raw_ai_score, 1)} attack_type={attack_type})")

        with CACHE_LOCK:
            update_l1_cache(cache_key, result)
            IN_PROGRESS_HASHES.remove(cache_key)

        return result

    except Exception as e:
        with CACHE_LOCK:
            if cache_key in IN_PROGRESS_HASHES:
                IN_PROGRESS_HASHES.remove(cache_key)
        raise e

# ================= API: /dashboard =================
@app.get("/dashboard", dependencies=[Depends(verify_api_key)])
def get_dashboard(period: str = "7days", db: Session = Depends(get_db)):
    now      = utcnow()
    today    = now.date()
    days_map = {"today": 0, "7days": 6, "30days": 29}
    days     = days_map.get(period, 6)

    # ช่วงเวลาของ period นี้ — ใช้ชุดเดียวกันทั้ง stats / volume / riskDist / domains
    if period == "today":
        period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        period_start = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)

    period_rows = db.query(EmailLog).filter(EmailLog.timestamp >= period_start).all()

    # แกนเวลา + bucket ปริมาณอีเมล (คิดใน Python — กันปัญหา date_trunc/timezone ข้าม DB)
    date_labels, volume_total, volume_phishing = [], [], []
    if period == "today":
        for h in range(24):
            slot = period_start + timedelta(hours=h)
            date_labels.append(slot.strftime("%H:00"))
            in_slot = [r for r in period_rows if slot <= r.timestamp < slot + timedelta(hours=1)]
            volume_total.append(len(in_slot))
            volume_phishing.append(sum(1 for r in in_slot if r.is_phishing))
    else:
        for i in range(days, -1, -1):
            d = today - timedelta(days=i)
            date_labels.append(d.strftime("%b %d"))
            in_day = [r for r in period_rows if r.timestamp.date() == d]
            volume_total.append(len(in_day))
            volume_phishing.append(sum(1 for r in in_day if r.is_phishing))

    # stats — คิดจาก period_rows ให้ตรงกับ period ที่เลือก (bug เดิม: fix ที่ "วันนี้" เสมอ → 0)
    emails_today      = len(period_rows)
    phishing_today    = sum(1 for r in period_rows if r.is_phishing)
    allowed_today     = sum(1 for r in period_rows if r.risk_level == "allow")
    warning_today     = sum(1 for r in period_rows if r.risk_level == "warning")
    blocked_today     = sum(1 for r in period_rows if r.risk_level == "block")
    quarantined_today = sum(1 for r in period_rows if r.risk_level == "quarantine")
    phishing_rate     = round(phishing_today / emails_today * 100, 1) if emails_today else 0
    block_rate        = round((blocked_today + quarantined_today) / phishing_today * 100, 1) if phishing_today else 0
    avg_risk          = round(sum(r.final_score for r in period_rows) / emails_today, 1) if emails_today else 0

    # riskDist — จากชุดเดียวกัน
    low  = sum(1 for r in period_rows if r.final_score < 40)
    med  = sum(1 for r in period_rows if 40 <= r.final_score < 70)
    high = sum(1 for r in period_rows if r.final_score >= 70)

    # domains / users / types — group_by ตามช่วง period เดียวกัน
    time_filter = EmailLog.timestamp >= period_start

    domain_rows = (
        db.query(EmailLog.sender_domain, func.count(EmailLog.id).label("cnt"))
        .filter(EmailLog.is_phishing == True, time_filter)
        .group_by(EmailLog.sender_domain)
        .order_by(func.count(EmailLog.id).desc())
        .limit(5)
        .all()
    )
    top_domains = [{"name": r.sender_domain, "count": r.cnt} for r in domain_rows]

    user_rows = (
        db.query(EmailLog.recipient, func.count(EmailLog.id).label("cnt"))
        .filter(EmailLog.is_phishing == True, time_filter)
        .group_by(EmailLog.recipient)
        .order_by(func.count(EmailLog.id).desc())
        .limit(5)
        .all()
    )
    top_users = [{"email": r.recipient, "dept": "N/A", "hits": r.cnt} for r in user_rows]

    type_rows = (
        db.query(EmailLog.attack_type, func.count(EmailLog.id).label("cnt"))
        .filter(EmailLog.is_phishing == True, time_filter)
        .group_by(EmailLog.attack_type)
        .all()
    )

    # หมายเหตุ: Spear Phishing ยุบรวมเข้า BEC (แยกไม่ได้ด้วย feature ปัจจุบัน — ไม่มีสัญญาณ personalization)
    # โมเดล Stage 2 เป็น 4 คลาส: BEC / Malware / Phishing / Spam (ไม่มีคลาส Spear แยก)
    color_map = {
        "Malware Attachment":              "#ef4444",
        "Business Email Compromise (BEC)": "#8b5cf6",
        "Phishing":                        "#3b82f6",
        "Spam (High-Risk Source)":         "#a855f7",
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

# ================= API: /logs (with pagination) =================
@app.get("/logs", dependencies=[Depends(verify_api_key)])
def get_email_logs(page: int = 1, limit: int = 20, db: Session = Depends(get_db)):
    limit  = min(limit, 100)
    offset = (page - 1) * limit
    total  = db.query(func.count(EmailLog.id)).scalar()
    logs   = db.query(EmailLog).order_by(EmailLog.timestamp.desc()).offset(offset).limit(limit).all()
    return {"status": "success", "total": total, "page": page, "limit": limit, "data": logs}

# ================= API: /model/feedback-label (feedback loop) =================
# Dashboard (.181) ยิงผ่าน backend ของตัวเองมาที่นี่ เมื่อเจ้าหน้าที่กด "ผลนี้ไม่ถูกต้อง"
# นี่คือชิ้นที่ปิด feedback loop: label จริงจากคนทำงาน -> ใช้เทรน Stage 2 รอบถัดไป
#
# ทำไมเก็บเป็นไฟล์ append-only ไม่ใช่ตาราง DB:
#   - label คือ "ประวัติการตัดสินของคน" ต้องแก้ย้อนหลังไม่ได้ (audit trail) · เขียนทับ = เสียหลักฐาน
#   - ถ้า analyst เปลี่ยนใจ ให้ต่อบรรทัดใหม่ ตอนเทรนใช้บรรทัดล่าสุดต่อ hash
#   - join กับ dataset_capture.jsonl ด้วย email_hash ตอน export ชุดเทรน
FEEDBACK_LABEL_PATH = os.getenv("FEEDBACK_LABEL_PATH", "logs/feedback_labels.jsonl")
# label ที่รับได้ = คลาสของโมเดล + "Normal" (analyst บอกว่าจริงๆ ไม่ใช่ภัย)
# อ่านจาก model_metrics.json เพื่อให้ตรงกับโมเดลที่ deploy อยู่เสมอ (เปลี่ยนโมเดล = รายการนี้ตามอัตโนมัติ)
def _load_valid_labels() -> tuple:
    try:
        with open(MODEL_METRICS_PATH, encoding="utf-8") as f:
            classes = json.load(f)["stage2"]["classes"]
        if classes:
            return tuple(list(classes) + ["Normal"])
    except Exception as e:
        logger.warning(f"[FEEDBACK] อ่านคลาสจาก {MODEL_METRICS_PATH} ไม่ได้ ใช้ค่าสำรอง: {e}")
    return ("Business Email Compromise (BEC)", "Malware Attachment",
            "Phishing", "Spam (High-Risk Source)", "Normal")

VALID_FEEDBACK_LABELS = _load_valid_labels()
RETRAIN_MIN_LABELS = 50   # ตรงกับเงื่อนไขใน /model/retrain


class FeedbackLabelRequest(BaseModel):
    email_hash: str = Field(..., min_length=8, max_length=128)
    true_label:  str          # ต้องเป็น 1 ใน VALID_FEEDBACK_LABELS
    is_phishing: bool
    analyst:     str = ""     # อีเมลเจ้าหน้าที่ (Dashboard ใส่มาให้) — audit trail


def _count_feedback_labels() -> tuple[int, int]:
    """คืน (จำนวนบรรทัดทั้งหมด, จำนวน email_hash ที่ไม่ซ้ำ) — ตัวหลังคือตัวที่นับเข้าเกณฑ์ retrain"""
    p = Path(FEEDBACK_LABEL_PATH)
    if not p.exists():
        return 0, 0
    total, hashes = 0, set()
    try:
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    hashes.add(json.loads(line).get("email_hash"))
                except Exception:
                    pass          # บรรทัดเสียไม่ทำให้ทั้ง endpoint ล้ม
    except Exception as e:
        logger.warning(f"[FEEDBACK] อ่านไฟล์ label ไม่ได้: {e}")
    return total, len(hashes)


@app.post("/model/feedback-label", dependencies=[Depends(verify_api_key)])
@limiter.limit("120/minute")
def feedback_label(request: Request, req: FeedbackLabelRequest, db: Session = Depends(get_db)):
    # ---- ตรวจ label ก่อน: ผิดต้อง "ดังตรงนี้" ไม่ใช่ไปโผล่ตอนเทรนแล้วคลาสเพี้ยน ----
    if req.true_label not in VALID_FEEDBACK_LABELS:
        raise HTTPException(status_code=400, detail={
            "error": "invalid_label",
            "message": f"true_label '{req.true_label}' ไม่ใช่คลาสที่โมเดลรู้จัก",
            "valid_labels": list(VALID_FEEDBACK_LABELS),
        })

    rec = {
        "email_hash":  req.email_hash,
        "true_label":  req.true_label,
        "is_phishing": bool(req.is_phishing),
        "analyst":     req.analyst or "unknown",
        "ts":          utcnow().isoformat(),
        "source":      "dashboard",
    }

    # ---- 1) เขียน label ลงไฟล์ (สำคัญสุด — ถ้าพลาดต้องแจ้ง error ไม่ใช่เงียบ) ----
    try:
        p = Path(FEEDBACK_LABEL_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"[FEEDBACK] เขียน label ไม่สำเร็จ: {e}")
        raise HTTPException(status_code=500, detail={
            "error": "label_store_unavailable",
            "message": "บันทึก label ไม่สำเร็จ — กรุณาลองใหม่ (ยังไม่ถูกบันทึก)",
        })

    # ---- 2) อัปเดตแถวใน DB ที่ Dashboard แสดงอยู่ ให้ตรงกับที่ analyst แก้ ----
    # best-effort: ถ้าไม่เจอแถว/DB ล่ม label ก็ยังถูกเก็บไว้แล้วจากขั้นที่ 1
    db_updated = False
    try:
        rows = db.query(EmailLog).filter(EmailLog.email_hash == req.email_hash).all()
        for row in rows:
            row.is_phishing = bool(req.is_phishing)
            row.attack_type = req.true_label
        if rows:
            db.commit()
            db_updated = True
    except Exception as e:
        db.rollback()
        logger.warning(f"[FEEDBACK] อัปเดต DB ไม่สำเร็จ (label ถูกเก็บแล้ว): {e}")

    total, unique = _count_feedback_labels()
    logger.info(f"[FEEDBACK] {req.analyst or 'unknown'} -> {req.true_label} "
                f"(hash={req.email_hash[:8]}, db_updated={db_updated}) · unique={unique}")

    return {
        "status":          "recorded",
        "email_hash":      req.email_hash,
        "true_label":      req.true_label,
        "db_row_updated":  db_updated,   # False = ยังไม่มีแถวนี้ใน DB (label ยังถูกเก็บไว้แล้ว)
        # ให้ Dashboard โชว์ความคืบหน้าไปยัง retrain ได้
        "labels_total":    total,
        "labels_unique":   unique,
        "labels_required": RETRAIN_MIN_LABELS,
        "ready_to_retrain": unique >= RETRAIN_MIN_LABELS,
    }


@app.get("/model/feedback-stats", dependencies=[Depends(verify_api_key)])
def feedback_stats():
    """ความคืบหน้าการเก็บ label (ให้ Dashboard โชว์ progress bar ไปยัง retrain)"""
    total, unique = _count_feedback_labels()
    return {
        "labels_total":     total,
        "labels_unique":    unique,
        "labels_required":  RETRAIN_MIN_LABELS,
        "ready_to_retrain": unique >= RETRAIN_MIN_LABELS,
        "valid_labels":     list(VALID_FEEDBACK_LABELS),
    }


# ================= API: /feedback (เก่า — อ้างด้วย log_id) =================
# ⚠️ ตัวนี้แก้ได้แค่ is_phishing และต้องรู้ log_id · ของใหม่ให้ใช้ /model/feedback-label
class FeedbackRequest(BaseModel):
    log_id: int
    is_actually_phishing: bool

@app.post("/feedback", dependencies=[Depends(verify_api_key)])
def submit_feedback(req: FeedbackRequest, db: Session = Depends(get_db)):
    log = db.query(EmailLog).filter(EmailLog.id == req.log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    log.is_phishing = req.is_actually_phishing
    db.commit()
    logger.info(f"[FEEDBACK] Log #{req.log_id} -> is_phishing={req.is_actually_phishing}")
    return {"status": "updated", "log_id": req.log_id}
