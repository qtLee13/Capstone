"""
Mail Server (เครื่อง 7 ตาม architecture diagram): รับอีเมลที่ผ่านการกรอง
จาก Mail Gateway ทาง SMTP (พอร์ต 25 ตามภาพ) แล้วเก็บลง mailbox แยกตาม user

Gateway บอกผลการกรองผ่าน header "X-Risk-Action":
  - ไม่มี header / ค่าอื่น  -> inbox
  - มีคำว่า quarantine      -> quarantine

ไฟล์เก็บที่ Mail_Server_DB/{inbox,quarantine}/<user>_<timestamp>.eml
(ที่เดียวกับที่ storage_server.py เปิดให้ Dashboard อ่าน/ปล่อยเมลผ่าน HTTP)

รัน: python smtp_mail_server.py  (พอร์ตตั้งผ่าน env SMTP_PORT, default 25 -
พอร์ตต่ำกว่า 1024 ต้องรันผ่าน systemd ที่ให้ CAP_NET_BIND_SERVICE ไว้แล้ว)
"""
import os
import time
from email import message_from_bytes
from email.policy import default as default_policy

from aiosmtpd.controller import Controller

from mail_store import deliver

SMTP_HOST = os.getenv("SMTP_HOST", "0.0.0.0")
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))


class MailServerHandler:
    async def handle_DATA(self, server, session, envelope):
        msg = message_from_bytes(envelope.content, policy=default_policy)
        action = (msg.get("X-Risk-Action") or "").lower()
        folder = "quarantine" if "quarantine" in action else "inbox"

        saved = [
            deliver(folder, rcpt, envelope.content)
            for rcpt in envelope.rcpt_tos or ["unknown@corp.com"]
        ]

        print(f"[{time.strftime('%X')}] 📬 SMTP รับเมล {envelope.mail_from} -> {envelope.rcpt_tos} | {folder} | {saved}")
        return "250 Message accepted for delivery"


if __name__ == "__main__":
    controller = Controller(MailServerHandler(), hostname=SMTP_HOST, port=SMTP_PORT)
    controller.start()
    print(f"[Mail Server] รับอีเมลทาง SMTP ที่ {SMTP_HOST}:{SMTP_PORT}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        print("\n🛑 ปิด Mail Server")
