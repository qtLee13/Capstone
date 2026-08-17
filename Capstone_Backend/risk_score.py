"""
risk_score.py — ส่วนคำนวณ Risk Score ทั้งหมด (แก้สูตรที่ไฟล์นี้ไฟล์เดียว)

⚠️ ไฟล์นี้ "ไม่ยิง API external" ใดๆ — เป็นการคำนวณล้วนๆ
   ส่วนที่ยิงเช็คแบบ parallel (VirusTotal / IPQS / AbuseIPDB / DMARC / link)
   ยังอยู่ใน main.py เหมือนเดิม แล้วส่ง "ผลลัพธ์ที่ได้มาแล้ว" เข้ามาที่ไฟล์นี้

เวลาปรับ risk score: แก้ค่าคงที่ด้านล่าง หรือแก้ตรรกะใน compute_final_score()
main.py เรียกใช้ผ่าน 4 ฟังก์ชัน: compute_header_anomaly, is_fast_path_safe,
compute_final_score, risk_level_from_score
"""

# =====================================================================
# ค่าคงที่ / น้ำหนัก — ปรับจูนได้ตรงนี้
# =====================================================================
# น้ำหนักถ่วงของแต่ละสัญญาณ (รวม 0.80 + penalty แบบแบน)
WEIGHT_AI     = 0.35   # คะแนนจาก BERT (Stage 1)
WEIGHT_LINK   = 0.25   # ความเสี่ยงจากลิงก์
WEIGHT_ABUSEIPDB   = 0.10   # IP reputation (AbuseIPDB/IPQS)
WEIGHT_HEADER = 0.10   # ความผิดปกติของ header

REPLY_MISMATCH_BONUS = 10.0  # Reply-To ไม่ตรง Sender → บวกเพิ่ม
SUSPICIOUS_FLOOR     = 45    # สัญญาณอ่อน >=2 (ai ต่ำ) → ดันขั้นต่ำเป็น "Warning" (เดิม 65 ทำให้ legit โดน Quarantine)
QUARANTINE_FLOOR     = 60    # อันตรายน่าจะจริง (ai สูง+สัญญาณ หรือ IP แข็ง) → ดันเป็น Quarantine
SUSPICIOUS_AI        = 50    # raw_ai_score เกินนี้ = BERT มองว่าคุกคาม (ใช้แยก BEC/phishing ออกจาก legit-but-suspicious)
ABUSEIPDB_HIGH_THRESHOLD  = 80    # IP reputation เกินค่านี้ = อันตรายชัด
# auth trust override — ผ่านเงื่อนไขนี้ = เชื่อได้ กัน false-positive อีเมล legit-but-suspicious
AUTH_TRUST_ABUSE_MAX = 25    # IP reputation ต่ำกว่านี้ = สะอาด
AUTH_TRUST_AI_MAX    = 40    # ai ต่ำกว่านี้ = BERT ไม่คิดว่า phishing

# Fast path: AI ต่ำกว่าค่านี้ + ไม่มีไฟล์แนบอันตราย = ปล่อยผ่านเลย (ไม่เข้า Stage 2)
SAFE_AI_THRESHOLD = 30

# นามสกุลไฟล์แนบเสี่ยง: ย้ายไปเป็น single source ที่ email_preprocess (is_risky_ext / RISKY_EXT)
# main.py เรียก email_preprocess.is_risky_ext() โดยตรง — ที่นี่ไม่ต้องเก็บสำเนา list แล้ว

# เกณฑ์แปลงคะแนนรวม → ระดับ + สี (score >= threshold)
LEVEL_BLOCK      = 80
LEVEL_QUARANTINE = 60
LEVEL_WARNING    = 30

PHISHING_THRESHOLD = 30  # score >= ค่านี้ = ถือว่า phishing (ใช้ตอนบันทึก DB)


# =====================================================================
# 1) คะแนนความผิดปกติของ Header (คำนวณจาก header ที่ parse มาแล้ว)
# =====================================================================
def compute_header_anomaly(parsed_data: dict) -> float:
    score = 0.0
    # Reply-To ต่างจาก Sender → น่าสงสัย
    if parsed_data.get("Reply_To") and parsed_data["Reply_To"] != parsed_data["Sender"]:
        score += 30
    # Received chain ยาวผิดปกติ → อาจผ่าน proxy ซ่อนตัว
    received_count = len(parsed_data.get("Received", []))
    if received_count > 5:
        score += 20
    elif received_count > 3:
        score += 10
    # ไม่มี Subject
    if not parsed_data.get("Subject") or parsed_data["Subject"] == "No Subject":
        score += 10
    return min(score, 100.0)


# =====================================================================
# 2) เช็คว่าเข้า fast path (ปลอดภัยชัดเจน) ไหม
# =====================================================================
def is_fast_path_safe(raw_ai_score: float, has_malware: bool) -> bool:
    return raw_ai_score < SAFE_AI_THRESHOLD and not has_malware


# =====================================================================
# 3) รวมคะแนนทั้งหมดเป็น final risk score (0–100)
#    รับ "ผลที่ยิง API มาแล้ว" เป็น argument — ไม่ยิงเองในนี้
# =====================================================================
def compute_final_score(
    raw_ai_score: float,
    raw_link_score: float,
    abuseipdb_score: float,
    header_anomaly_score: float,
    dmarc_status: str,      # "pass" / "fail"
    dmarc_penalty: float,   # penalty จากผล DMARC
    reply_to_mismatch: bool,
    has_malware: bool,
) -> float:
    final_score = (
        (raw_ai_score         * WEIGHT_AI) +
        (raw_link_score       * WEIGHT_LINK) +
        (abuseipdb_score           * WEIGHT_ABUSEIPDB) +
        (header_anomaly_score * WEIGHT_HEADER) +
        float(dmarc_penalty)
    )

    if reply_to_mismatch:
        final_score += REPLY_MISMATCH_BONUS

    # กฎ override: อันตรายชัดเจน → เต็ม 100
    if raw_link_score == 100 or has_malware:
        final_score = 100
    else:
        # ② auth trust override: DMARC ผ่าน + IP สะอาด + AI ต่ำ = เชื่อได้
        #    ต่อให้ reply-to เพี้ยน/header แปลก ก็ไม่ดันขึ้น Quarantine (กัน legit-but-suspicious)
        authenticated = (dmarc_status == "pass"
                         and abuseipdb_score < AUTH_TRUST_ABUSE_MAX
                         and raw_ai_score < AUTH_TRUST_AI_MAX)
        if authenticated:
            final_score = min(final_score, LEVEL_WARNING - 1)   # อย่างมากแค่ก่อนถึง Warning
        else:
            # ① ต้องมีสัญญาณยืนยัน — สัญญาณอ่อน (reply-to/dmarc) ตัวเดียวไม่พอดัน floor
            strong_signal = abuseipdb_score > ABUSEIPDB_HIGH_THRESHOLD      # IP อันตราย = สัญญาณแข็ง
            weak_signals  = int(bool(reply_to_mismatch)) + int(dmarc_status == "fail")
            if strong_signal or (raw_ai_score >= SUSPICIOUS_AI and weak_signals >= 1):
                # BERT มองว่าคุกคาม + มีสัญญาณยืนยัน (เช่น BEC) หรือ IP แข็ง → Quarantine
                final_score = max(final_score, QUARANTINE_FLOOR)
            elif weak_signals >= 2:
                # สัญญาณอ่อน >=2 แต่ ai ต่ำ (เช่น mailing list) → แค่ Warning ไม่ Quarantine
                final_score = max(final_score, SUSPICIOUS_FLOOR)

    # clamp ให้อยู่ 0–100
    return min(max(final_score, 0), 100)


# =====================================================================
# 4) แปลงคะแนนรวม → ระดับ (risk_level) + สี (action_color)
# =====================================================================
def risk_level_from_score(final_score: float) -> tuple[str, str]:
    if final_score >= LEVEL_BLOCK:
        return "🔴 Block", "#c53030"
    elif final_score >= LEVEL_QUARANTINE:
        return "🟠 Quarantine", "#dd6b20"
    elif final_score >= LEVEL_WARNING:
        return "🟡 Warning", "#d69e2e"
    else:
        return "🟢 Allow", "#2f855a"