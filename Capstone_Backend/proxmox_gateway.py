"""
Proxmox Mail Gateway (PMG) boundary - ทุกอย่างที่คุยกับเครื่อง Gateway อยู่ไฟล์นี้

storage_server.py เป็น "ตัวกลาง" ระหว่าง PMG กับ Mail Server 2 ทาง:

  ทางเข้า (PMG -> เรา -> Mail Server)
    PMG ส่งเมลดิบมาที่ POST /gateway/ingest -> เราตรวจ (rule base + risk engine)
    -> เขียน log -> ถ้าไม่ block ก็ relay ต่อไปที่ smtp_mail_server.py :25
       พร้อม header X-Risk-Action ให้ปลายทางรู้ว่าเข้า inbox หรือ quarantine
    ฟังก์ชันในไฟล์นี้: parse_signals(), relay_to_mail_server()

  ทางจัดการ (เรา -> PMG API)
    เรียก PMG REST API (พอร์ต 8006) เพื่อดูสถานะ/กล่องกักกันของ Gateway
    และ push กฎจากตาราง block_rules ขึ้นไป block ตั้งแต่ด่านแรก
    ฟังก์ชันในไฟล์นี้: PMGClient

ตั้งค่าผ่าน .env (ไม่ hardcode IP เพราะเครื่อง Gateway ย้ายบ่อย):
    PMG_HOST=10.22.1.66
    PMG_PORT=8006
    PMG_VERIFY_SSL=false            # PMG ใช้ self-signed cert
    # เลือกอย่างใดอย่างหนึ่ง - API token (แนะนำ) หรือ user/password
    PMG_TOKEN_ID=root@pam!capstone
    PMG_TOKEN_SECRET=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    PMG_USER=root@pam
    PMG_PASSWORD=...
    PMG_BLOCK_OGROUP=1              # id ของ Who-object group ที่ใช้เก็บ blacklist
    MAIL_SERVER_HOST=127.0.0.1
    MAIL_SERVER_PORT=25
"""
import os
import re
import smtplib
from email import message_from_bytes, policy
from typing import List, Optional

import requests

# ================= ปลายทางฝั่ง Mail Server (ขาออกจากตัวกลาง) =================
MAIL_SERVER_HOST = os.getenv("MAIL_SERVER_HOST", "127.0.0.1")
MAIL_SERVER_PORT = int(os.getenv("MAIL_SERVER_PORT", "25"))

# ================= ปลายทางฝั่ง PMG (ขาไปคุย API) =================
PMG_HOST = os.getenv("PMG_HOST", "")
PMG_PORT = int(os.getenv("PMG_PORT", "8006"))
PMG_VERIFY_SSL = os.getenv("PMG_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
PMG_TOKEN_ID = os.getenv("PMG_TOKEN_ID", "")
PMG_TOKEN_SECRET = os.getenv("PMG_TOKEN_SECRET", "")
PMG_USER = os.getenv("PMG_USER", "")
PMG_PASSWORD = os.getenv("PMG_PASSWORD", "")
PMG_BLOCK_OGROUP = os.getenv("PMG_BLOCK_OGROUP", "")
PMG_TIMEOUT = float(os.getenv("PMG_TIMEOUT", "10"))

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "js", "vbs", "bat", "cmd", "com", "pif", "jar",
    "docm", "xlsm", "pptm", "iso", "img", "lnk", "html", "htm", "zip", "rar", "7z",
}


class PMGError(RuntimeError):
    """ติดต่อ PMG ไม่ได้ / PMG ตอบ error - storage_server จะแปลงเป็น HTTP 502"""


# =====================================================================
# ทางเข้า: แกะ signal จากเมลดิบที่ PMG ส่งมา
# =====================================================================
def _auth_result(msg, mechanism: str) -> str:
    """อ่านผล spf/dkim/dmarc จาก header ที่ PMG (หรือ MTA ต้นทาง) ประทับไว้

    รองรับทั้ง Authentication-Results และ Received-SPF คืน "pass"/"fail"/
    "softfail"/"none" ตามที่ risk engine คาดหวัง
    """
    blobs = [str(v) for v in msg.get_all("Authentication-Results", [])]
    if mechanism == "spf":
        blobs += [str(v) for v in msg.get_all("Received-SPF", [])]

    for blob in blobs:
        match = re.search(rf"\b{mechanism}\s*=\s*(\w+)", blob, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        # Received-SPF: Pass (mailfrom) ...
        if mechanism == "spf" and blob:
            first = blob.strip().split()[0].lower()
            if first in ("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"):
                return first
    return "none"


def _addr(value: str) -> str:
    match = re.search(r"[\w.+-]+@[\w.-]+", value or "")
    return match.group(0).lower() if match else ""


def _body_text(msg) -> str:
    try:
        part = msg.get_body(preferencelist=("plain", "html"))
        return part.get_content() if part else ""
    except Exception:
        return ""


def _attachment_types(msg) -> List[str]:
    types = []
    for part in msg.walk() if msg.is_multipart() else []:
        name = part.get_filename()
        if not name or "." not in name:
            continue
        # ส่งแบบมีจุด ".exe" ให้ตรงสัญญา /assess (ASSESS_API_SPEC.md) และ
        # ตาราง DANGEROUS_ATTACHMENTS ใน risk_config.py
        ext = "." + name.rsplit(".", 1)[-1].lower()
        types.append(ext)
    return types


def parse_signals(raw_email: bytes, envelope_sender: str = "", envelope_rcpt: str = "") -> dict:
    """แกะเมลดิบเป็น signal ชุดเดียวกับที่ RiskInput ต้องการ

    ตัวกลางแกะได้เฉพาะสิ่งที่อยู่ในตัวเมล (header auth, attachment, ข้อความ)
    ส่วน raw_ai_score / raw_link_score / abuseipdb_score เป็นของ AI server
    ถ้า PMG ส่งมาด้วยก็ใช้ค่านั้น ไม่งั้นเป็น 0 (ดูใน storage_server.py)
    """
    msg = message_from_bytes(raw_email, policy=policy.default)

    sender = _addr(str(msg.get("From", ""))) or _addr(envelope_sender)
    reply_to = _addr(str(msg.get("Reply-To", "")))
    recipient = _addr(envelope_rcpt) or _addr(str(msg.get("To", ""))) or "unknown@corp.com"
    return_path = _addr(str(msg.get("Return-Path", ""))) or _addr(envelope_sender)

    sender_domain = sender.split("@")[-1] if "@" in sender else "unknown"

    return {
        "sender_email": sender,
        "sender_domain": sender_domain,
        "recipient": recipient,
        "subject": str(msg.get("Subject", "") or ""),
        "body_text": _body_text(msg),
        "spf_result": _auth_result(msg, "spf"),
        "dkim_result": _auth_result(msg, "dkim"),
        "dmarc_result": _auth_result(msg, "dmarc"),
        "reply_to_mismatch": bool(reply_to and sender and reply_to != sender),
        # envelope sender ไม่ตรงกับ From: = อาการปลอมผู้ส่งแบบคลาสสิก
        "sender_spoofing": bool(return_path and sender and return_path != sender),
        "attachment_type": _attachment_types(msg),
    }


def relay_to_mail_server(raw_email: bytes, sender: str, recipients: List[str], action: str) -> None:
    """ส่งเมลต่อไปที่ smtp_mail_server.py พร้อมบอกคำตัดสินผ่าน X-Risk-Action

    เติม header ใหม่ไว้บนสุดโดยไม่แตะเนื้อเมลเดิม (ปลายทางอ่านแค่บรรทัดแรกๆ)
    """
    header = f"X-Risk-Action: {action}\r\n".encode()
    payload = header + raw_email

    with smtplib.SMTP(MAIL_SERVER_HOST, MAIL_SERVER_PORT, timeout=15) as smtp:
        smtp.sendmail(sender or "gateway@corp.com", recipients or ["unknown@corp.com"], payload)


# =====================================================================
# ทางจัดการ: PMG REST API client
# =====================================================================
class PMGClient:
    """client บางๆ ของ PMG API - auth ด้วย API token ถ้ามี ไม่งั้นขอ ticket

    ทุก error (ต่อไม่ติด / 401 / PMG ตอบ 5xx) โยน PMGError ออกมาอย่างเดียว
    เพื่อให้ storage_server ไม่ล้มตามเวลา Gateway ดับ
    """

    def __init__(self):
        if not PMG_HOST:
            raise PMGError("ยังไม่ได้ตั้ง PMG_HOST ใน .env")
        self.base = f"https://{PMG_HOST}:{PMG_PORT}/api2/json"
        self.session = requests.Session()
        self.session.verify = PMG_VERIFY_SSL
        self._csrf = ""

        if PMG_TOKEN_ID and PMG_TOKEN_SECRET:
            self.session.headers["Authorization"] = f"PMGAPIToken={PMG_TOKEN_ID}={PMG_TOKEN_SECRET}"
        elif PMG_USER and PMG_PASSWORD:
            self._login()
        else:
            raise PMGError("ต้องตั้ง PMG_TOKEN_ID/PMG_TOKEN_SECRET หรือ PMG_USER/PMG_PASSWORD")

    def _login(self):
        try:
            resp = self.session.post(
                f"{self.base}/access/ticket",
                data={"username": PMG_USER, "password": PMG_PASSWORD},
                timeout=PMG_TIMEOUT,
            )
        except requests.RequestException as e:
            raise PMGError(f"ต่อ PMG ที่ {PMG_HOST}:{PMG_PORT} ไม่ได้: {e}")
        if resp.status_code != 200:
            raise PMGError(f"PMG ปฏิเสธ login ({resp.status_code}): {resp.text[:200]}")

        data = resp.json().get("data") or {}
        self.session.cookies.set("PMGAuthCookie", data.get("ticket", ""))
        self._csrf = data.get("CSRFPreventionToken", "")

    def request(self, method: str, path: str, **kwargs):
        """เรียก API ดิบๆ เช่น request("GET", "/nodes") - คืนค่าใน key "data" """
        headers = {}
        if self._csrf and method.upper() != "GET":
            headers["CSRFPreventionToken"] = self._csrf
        try:
            resp = self.session.request(
                method, f"{self.base}{path}", headers=headers, timeout=PMG_TIMEOUT, **kwargs
            )
        except requests.RequestException as e:
            raise PMGError(f"เรียก PMG {method} {path} ไม่สำเร็จ: {e}")
        if resp.status_code >= 400:
            raise PMGError(f"PMG ตอบ {resp.status_code} ที่ {path}: {resp.text[:200]}")
        try:
            return resp.json().get("data")
        except ValueError:
            raise PMGError(f"PMG ตอบไม่ใช่ JSON ที่ {path}: {resp.text[:200]}")

    # ---------- อ่านสถานะ ----------
    def status(self) -> dict:
        nodes = self.request("GET", "/nodes") or []
        return {"host": PMG_HOST, "port": PMG_PORT, "nodes": nodes}

    def quarantine(self, kind: str = "spam", limit: int = 50) -> list:
        """กล่องกักกันฝั่ง Gateway - kind: spam | virus | attachment"""
        items = self.request("GET", f"/quarantine/{kind}") or []
        return items[:limit]

    # ---------- push กฎขึ้น Gateway ----------
    def sync_rules(self, rules: list) -> dict:
        """เอากฎ block_rules ไปใส่ Who-object group ของ PMG ให้ block ที่ด่านแรก

        เฉพาะกฎ type "sender" (PMG จับผู้ส่งได้ตรงๆ) - กฎ subject/body ยังคง
        ทำงานที่ rule_base ฝั่ง mail server เหมือนเดิม
        """
        if not PMG_BLOCK_OGROUP:
            raise PMGError("ยังไม่ได้ตั้ง PMG_BLOCK_OGROUP (id ของ Who-object group ที่ใช้เก็บ blacklist)")

        existing = {
            (obj.get("email") or "").lower()
            for obj in (self.request("GET", f"/config/ruledb/who/{PMG_BLOCK_OGROUP}") or [])
        }

        pushed, skipped = [], []
        for rule in rules:
            if rule.get("rule_type") != "sender":
                skipped.append({"id": rule.get("id"), "reason": f"rule_type={rule.get('rule_type')} ไม่รองรับที่ PMG"})
                continue
            pattern = (rule.get("pattern") or "").strip().lower()
            if not pattern:
                continue
            # โดเมนล้วน -> จับทั้งโดเมนด้วย *@domain
            match = pattern if "@" in pattern else f"*@{pattern}"
            if match in existing:
                skipped.append({"id": rule.get("id"), "reason": "มีอยู่แล้วบน PMG"})
                continue
            self.request("POST", f"/config/ruledb/who/{PMG_BLOCK_OGROUP}/email", data={"email": match})
            pushed.append(match)

        return {"pushed": pushed, "skipped": skipped, "ogroup": PMG_BLOCK_OGROUP}


def get_client() -> Optional[PMGClient]:
    return PMGClient()
