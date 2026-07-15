"""
Rule Base - ด่านตรวจรอบสองของ Mail Server

เก็บกฎที่ admin flag ไว้ว่า "เมลแบบนี้ไม่ดี" ลงตาราง block_rules ใน PostgreSQL
แล้วให้ smtp_mail_server.py เรียก check_email() ดักเมลทุกฉบับก่อนเก็บเข้ากล่อง:
โดนกฎ -> เข้า quarantine (user ไม่เห็น), ผ่าน -> เข้า inbox ตามปกติ

ฝั่ง Proxmox (Gateway) ดึงกฎชุดเดียวกันไป block ที่ด่านแรกได้ผ่าน GET /rules
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "postgresql://cap_db:123456@localhost:5432/phishing_db"

_engine = create_engine(DATABASE_URL)
_Session = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
_Base = declarative_base()

# ประเภทกฎ: จับกับส่วนไหนของอีเมล (เทียบแบบ substring ไม่สนตัวพิมพ์เล็กใหญ่)
RULE_TYPES = {"sender", "subject", "body"}


class BlockRule(_Base):
    __tablename__ = "block_rules"

    id         = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    rule_type  = Column(String, nullable=False)   # "sender" | "subject" | "body"
    pattern    = Column(String, nullable=False)   # ข้อความที่ใช้จับ
    note       = Column(String, default="")       # เหตุผล/ที่มา เช่น "flag จาก log #12"


_Base.metadata.create_all(bind=_engine)


def _row_to_dict(rule: BlockRule) -> dict:
    return {
        "id": rule.id,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "rule_type": rule.rule_type,
        "pattern": rule.pattern,
        "note": rule.note,
    }


def list_rules() -> list:
    with _Session() as db:
        return [_row_to_dict(r) for r in db.query(BlockRule).order_by(BlockRule.id).all()]


def add_rule(rule_type: str, pattern: str, note: str = "") -> dict:
    if rule_type not in RULE_TYPES:
        raise ValueError(f"rule_type must be one of {sorted(RULE_TYPES)}")
    pattern = (pattern or "").strip()
    if not pattern:
        raise ValueError("pattern must not be empty")
    with _Session() as db:
        rule = BlockRule(rule_type=rule_type, pattern=pattern, note=note)
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return _row_to_dict(rule)


def delete_rule(rule_id: int) -> bool:
    with _Session() as db:
        rule = db.query(BlockRule).filter(BlockRule.id == rule_id).first()
        if not rule:
            return False
        db.delete(rule)
        db.commit()
        return True


def check_email(sender: str, subject: str, body: str) -> Optional[dict]:
    """เช็คเมลกับกฎทุกข้อ - คืนกฎแรกที่โดน หรือ None ถ้าผ่าน

    อ่านกฎสดจาก DB ทุกครั้ง เพื่อให้กฎที่ admin เพิ่งเพิ่มมีผลทันที
    แม้ smtp_mail_server กับ storage_server จะเป็นคนละ process
    """
    fields = {
        "sender": (sender or "").lower(),
        "subject": (subject or "").lower(),
        "body": (body or "").lower(),
    }
    with _Session() as db:
        for rule in db.query(BlockRule).all():
            target = fields.get(rule.rule_type, "")
            if rule.pattern.lower() in target:
                return _row_to_dict(rule)
    return None
