"""
Mail storage helper ใช้ร่วมกันระหว่าง smtp_mail_server.py (ตัวรับ SMTP)
และ storage_server.py (HTTP API สำหรับ Dashboard)

เก็บ 2 รูปแบบพร้อมกัน:
1. Flat .eml ใน Mail_Server_DB/{inbox,quarantine}/ - ให้ Dashboard list/อ่าน/release ง่าย
2. Maildir ใน Mail_Server_DB/maildir/<user>/Maildir/ - ให้ Dovecot เสิร์ฟ IMAP/POP3
   (เฉพาะเมล inbox เท่านั้น - เมลกักกันต้องไม่โผล่ใน mailbox ของ user)
"""
import os
import socket
import time
from datetime import datetime, timezone

MAIL_STORE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Mail_Server_DB")
MAILDIR_ROOT = os.path.join(MAIL_STORE_ROOT, "maildir")
MAIL_FOLDERS = {"inbox", "quarantine"}

_maildir_seq = 0


def safe_name(value: str) -> str:
    keep = "".join(c if c.isalnum() or c in "._-" else "_" for c in value)
    return keep.strip("._") or "unknown"


def user_from_address(address: str) -> str:
    return safe_name(address.split("@")[0].lower())


def store_flat(folder: str, recipient: str, content: bytes) -> str:
    """เก็บ .eml แบนๆ สำหรับ Dashboard คืนชื่อไฟล์"""
    folder_path = os.path.join(MAIL_STORE_ROOT, folder)
    os.makedirs(folder_path, exist_ok=True)
    user = user_from_address(recipient)
    filename = f"{user}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}.eml"
    with open(os.path.join(folder_path, filename), "wb") as f:
        f.write(content)
    return filename


def store_maildir(recipient: str, content: bytes) -> str:
    """เก็บลง Maildir ให้ Dovecot (เขียน tmp ก่อนแล้ว rename เข้า new ตามสเปก Maildir)"""
    global _maildir_seq
    _maildir_seq += 1

    user = user_from_address(recipient)
    maildir = os.path.join(MAILDIR_ROOT, user, "Maildir")
    for sub in ("tmp", "new", "cur"):
        os.makedirs(os.path.join(maildir, sub), exist_ok=True)

    unique = f"{int(time.time())}.P{os.getpid()}Q{_maildir_seq}.{socket.gethostname()}"
    tmp_path = os.path.join(maildir, "tmp", unique)
    with open(tmp_path, "wb") as f:
        f.write(content)
    os.rename(tmp_path, os.path.join(maildir, "new", unique))
    return unique


def deliver(folder: str, recipient: str, content: bytes) -> str:
    """ทางเข้าหลัก: เก็บ flat เสมอ และถ้าเป็น inbox ก็เข้า Maildir ของ user ด้วย"""
    filename = store_flat(folder, recipient, content)
    if folder == "inbox":
        store_maildir(recipient, content)
    return filename
