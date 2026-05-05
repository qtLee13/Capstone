# risk_scoring/risk_config.py

"""
Risk Scoring Configuration

ไฟล์นี้ใช้เก็บค่าน้ำหนักคะแนนและ threshold
เพื่อให้ปรับแก้ได้ง่ายโดยไม่ต้องไปแก้ logic หลัก
"""

# =========================
# Component Weights
# รวมคะแนนเต็ม 100
# =========================

AI_WEIGHT = 0.35              # AI confidence สูงสุด 35 คะแนน
LINK_WEIGHT = 0.25            # Link risk สูงสุด 25 คะแนน
DOMAIN_MAX_SCORE = 15         # SPF / DKIM / DMARC สูงสุด 15 คะแนน
HEADER_MAX_SCORE = 10         # Reply-To mismatch / spoofing สูงสุด 10 คะแนน
ATTACHMENT_MAX_SCORE = 10     # ไฟล์แนบอันตราย สูงสุด 10 คะแนน
LANGUAGE_MAX_SCORE = 5        # ภาษาเชิง social engineering สูงสุด 5 คะแนน

# =========================
# Risk Thresholds
# =========================

LOW_THRESHOLD = 0
MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 60
CRITICAL_THRESHOLD = 80

# =========================
# Policy Actions
# =========================

ACTION_ALLOW = "allow"
ACTION_WARNING = "warning"
ACTION_QUARANTINE = "quarantine"
ACTION_BLOCK = "block"

# =========================
# Dangerous Attachments
# =========================

DANGEROUS_ATTACHMENTS = {
    ".exe",
    ".bat",
    ".scr",
    ".vbs",
    ".js",
    ".jar",
    ".zip",
    ".docm",
    ".xlsm",
    ".ps1",
    ".cmd"
}

# =========================
# Social Engineering Keywords
# =========================

URGENCY_KEYWORDS = {
    "urgent",
    "immediately",
    "verify now",
    "account locked",
    "suspended",
    "payment failed",
    "overdue",
    "wire transfer",
    "bank account",
    "confidential",
    "password",
    "reset your account",
    "click here",
    "login now",
    "verify your identity",
    "permanent suspension"
}

# =========================
# Override Thresholds
# =========================

AI_HIGH_CONFIDENCE = 85
AI_MEDIUM_CONFIDENCE = 65
LINK_MALICIOUS_SCORE = 100