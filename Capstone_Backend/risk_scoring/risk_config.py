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

AI_WEIGHT = 0.20               # AI confidence สูงสุด 20 คะแนน
LINK_WEIGHT = 0.20             # Link risk สูงสุด 20 คะแนน
DOMAIN_MAX_SCORE = 20          # SPF / DKIM / DMARC / AbuseIPDB สูงสุด 20 คะแนน
HEADER_MAX_SCORE = 15          # Reply-To mismatch / spoofing สูงสุด 15 คะแนน
ATTACHMENT_MAX_SCORE = 15      # ไฟล์แนบอันตราย สูงสุด 15 คะแนน
LANGUAGE_MAX_SCORE = 10        # ภาษาเชิง social engineering สูงสุด 10 คะแนน

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

# =========================
# Soft-signal Floors (ลด False-Positive อีเมล legit-but-suspicious)
# ที่มา: AI Server (.94) วัด FP 50% -> 0% โดยยังจับ threat 100%
# หลักการ: สัญญาณอ่อนตัวเดียว (Reply-To ไม่ตรง / DMARC fail) ไม่พอจะ Quarantine
#          ต้องมีสัญญาณยืนยัน (IP abuse แรง หรือ AI สูง+auth ผิด) ถึงจะดันขึ้น
# =========================

SUSPICIOUS_FLOOR = 45          # อ่อน >= 2 สัญญาณ -> อย่างมากแค่ Warning (อยู่ในแบนด์ 30-60)
QUARANTINE_FLOOR = 60          # อันตรายน่าจะจริง -> Quarantine (= HIGH_THRESHOLD)
SUSPICIOUS_AI = 50             # AI เกินนี้ = BERT มองว่าคุกคาม (ใช้คู่กับสัญญาณอ่อน)
AUTH_TRUST_ABUSE_MAX = 25      # IP สะอาดกว่านี้ = น่าเชื่อถือ
AUTH_TRUST_AI_MAX = 40         # AI ต่ำกว่านี้ = ไม่ใช่ phishing
ABUSEIPDB_HIGH_THRESHOLD = 80  # IP abuse แรงเกินนี้ = สัญญาณยืนยันเดี่ยวๆ ได้เลย