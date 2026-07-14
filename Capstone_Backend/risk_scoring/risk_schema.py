# risk_scoring/risk_schema.py

from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class RiskInput:
    """
    Input ที่ Risk Scoring Engine รับจากระบบอื่น

    ข้อมูลควรมาจาก:
    - Email Parser
    - Feature Extraction
    - AI Detection Engine
    - Link Risk / Threat Intelligence
    """

    email_id: str = ""
    sender_domain: str = "unknown"
    sender_email: str = ""
    recipient: str = "unknown@corp.com"

    spf_result: str = "none"
    dkim_result: str = "none"
    dmarc_result: str = "none"

    reply_to_mismatch: bool = False
    sender_spoofing: bool = False

    attachment_type: List[str] = field(default_factory=list)

    raw_ai_score: float = 0.0
    raw_link_score: float = 0.0
    abuseipdb_score: float = 0.0   # IP reputation จาก AbuseIPDB (เดิมชื่อ ipqs_score)

    subject: str = ""
    body_text: str = ""

    extra_features: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskResult:
    """
    Output ที่ Risk Scoring Engine ส่งกลับให้ main.py
    """

    final_score: float
    risk_level: str
    action: str
    display_level: str
    action_color: str

    components: Dict[str, float]
    reasons: List[str]
    flags: Dict[str, bool]