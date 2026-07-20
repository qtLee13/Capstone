# risk_scoring/risk_engine.py

from typing import Dict, List, Tuple

from .risk_schema import RiskInput, RiskResult
from .risk_config import (
    AI_WEIGHT,
    LINK_WEIGHT,
    DOMAIN_MAX_SCORE,
    HEADER_MAX_SCORE,
    ATTACHMENT_MAX_SCORE,
    LANGUAGE_MAX_SCORE,
    DANGEROUS_ATTACHMENTS,
    URGENCY_KEYWORDS,
    AI_HIGH_CONFIDENCE,
    AI_MEDIUM_CONFIDENCE,
    LINK_MALICIOUS_SCORE,
    MEDIUM_THRESHOLD,
    SUSPICIOUS_FLOOR,
    QUARANTINE_FLOOR,
    SUSPICIOUS_AI,
    AUTH_TRUST_ABUSE_MAX,
    AUTH_TRUST_AI_MAX,
    ABUSEIPDB_HIGH_THRESHOLD,
    ACTION_ALLOW,
    ACTION_WARNING,
    ACTION_QUARANTINE,
    ACTION_BLOCK,
)


class RiskScoringEngine:
    """
    Risk Scoring Engine System

    หน้าที่:
    1. รับ feature จาก Email Parser / Feature Extraction
    2. รับคะแนนจาก AI Detection Engine
    3. รับคะแนน Link Risk จาก Threat Intelligence
    4. คำนวณ Risk Score 0-100
    5. จัดระดับ Low / Medium / High / Critical
    6. กำหนด action: allow / warning / quarantine / block
    7. สร้าง reasons เพื่ออธิบายว่าทำไมอีเมลถึงเสี่ยง
    """

    def calculate(self, risk_input: RiskInput) -> RiskResult:
        reasons: List[str] = []

        flags = {
            "ai_suspicious": False,
            "malicious_link": False,
            "auth_failed": False,
            "spoofing_detected": False,
            "dangerous_attachment": False,
            "social_engineering_language": False,
        }

        ai_score, ai_reasons, ai_flags = self._score_ai(risk_input.raw_ai_score)
        link_score, link_reasons, link_flags = self._score_link(risk_input.raw_link_score)
        domain_score, domain_reasons, domain_flags = self._score_domain(risk_input)
        header_score, header_reasons, header_flags = self._score_header(risk_input)
        attachment_score, attachment_reasons, attachment_flags = self._score_attachment(risk_input)
        language_score, language_reasons, language_flags = self._score_language(risk_input)

        reasons.extend(ai_reasons)
        reasons.extend(link_reasons)
        reasons.extend(domain_reasons)
        reasons.extend(header_reasons)
        reasons.extend(attachment_reasons)
        reasons.extend(language_reasons)

        flags.update(ai_flags)
        flags.update(link_flags)
        flags.update(domain_flags)
        flags.update(header_flags)
        flags.update(attachment_flags)
        flags.update(language_flags)

        base_score = (
            ai_score
            + link_score
            + domain_score
            + header_score
            + attachment_score
            + language_score
        )

        final_score, override_reasons = self._apply_security_overrides(
            base_score=base_score,
            risk_input=risk_input,
            flags=flags
        )

        reasons.extend(override_reasons)

        final_score = min(round(final_score, 2), 100)

        risk_level, action, display_level, action_color = self._classify(final_score)

        if not reasons:
            reasons.append("No significant risk indicators detected")

        return RiskResult(
            final_score=final_score,
            risk_level=risk_level,
            action=action,
            display_level=display_level,
            action_color=action_color,
            components={
                "ai_score": round(ai_score, 2),
                "link_risk": round(link_score, 2),
                "domain_risk": round(domain_score, 2),
                "header_anomaly": round(header_score, 2),
                "attachment_risk": round(attachment_score, 2),
                "language_risk": round(language_score, 2),
            },
            reasons=reasons,
            flags=flags
        )

    def _score_ai(self, raw_ai_score: float) -> Tuple[float, List[str], Dict[str, bool]]:
        reasons = []
        flags = {"ai_suspicious": False}

        raw_ai_score = self._clamp(raw_ai_score)
        score = raw_ai_score * AI_WEIGHT

        if raw_ai_score >= AI_HIGH_CONFIDENCE:
            reasons.append("AI model classified this email as highly suspicious")
            flags["ai_suspicious"] = True

        elif raw_ai_score >= AI_MEDIUM_CONFIDENCE:
            reasons.append("AI model detected phishing-like content")
            flags["ai_suspicious"] = True

        return score, reasons, flags

    def _score_link(self, raw_link_score: float) -> Tuple[float, List[str], Dict[str, bool]]:
        reasons = []
        flags = {"malicious_link": False}

        raw_link_score = self._clamp(raw_link_score)
        score = raw_link_score * LINK_WEIGHT

        if raw_link_score >= LINK_MALICIOUS_SCORE:
            reasons.append("Threat intelligence detected malicious URL")
            flags["malicious_link"] = True

        elif raw_link_score >= 70:
            reasons.append("Suspicious URL pattern detected")
            flags["malicious_link"] = True

        elif raw_link_score >= 40:
            reasons.append("URL has moderate suspicious indicators")

        return score, reasons, flags

    def _score_domain(self, risk_input: RiskInput) -> Tuple[float, List[str], Dict[str, bool]]:
        reasons = []
        flags = {"auth_failed": False}
        score = 0.0

        if risk_input.spf_result == "fail":
            score += 6
            reasons.append("SPF authentication failed")
            flags["auth_failed"] = True

        if risk_input.dkim_result == "fail":
            score += 4
            reasons.append("DKIM authentication failed")
            flags["auth_failed"] = True

        if risk_input.dmarc_result == "fail":
            score += 5
            reasons.append("DMARC authentication failed")
            flags["auth_failed"] = True

        abuseipdb_score = self._clamp(risk_input.abuseipdb_score)
        if abuseipdb_score >= 50:
            score += abuseipdb_score * 0.10
            reasons.append(f"Sender IP has poor reputation (AbuseIPDB confidence score {abuseipdb_score:.0f})")

        score = min(score, DOMAIN_MAX_SCORE)

        return score, reasons, flags

    def _score_header(self, risk_input: RiskInput) -> Tuple[float, List[str], Dict[str, bool]]:
        reasons = []
        flags = {"spoofing_detected": False}
        score = 0.0

        if risk_input.reply_to_mismatch:
            score += 6
            reasons.append("Reply-To domain does not match sender domain")
            flags["spoofing_detected"] = True

        if risk_input.sender_spoofing:
            score += 4
            reasons.append("Sender spoofing indicator detected")
            flags["spoofing_detected"] = True

        score = min(score, HEADER_MAX_SCORE)

        return score, reasons, flags

    def _score_attachment(self, risk_input: RiskInput) -> Tuple[float, List[str], Dict[str, bool]]:
        reasons = []
        flags = {"dangerous_attachment": False}
        score = 0.0

        attachment_types = {
            ext.lower()
            for ext in risk_input.attachment_type
        }

        dangerous_found = attachment_types.intersection(DANGEROUS_ATTACHMENTS)

        if dangerous_found:
            score = ATTACHMENT_MAX_SCORE
            reasons.append(
                "Dangerous attachment type detected: "
                + ", ".join(sorted(dangerous_found))
            )
            flags["dangerous_attachment"] = True

        return score, reasons, flags

    def _score_language(self, risk_input: RiskInput) -> Tuple[float, List[str], Dict[str, bool]]:
        reasons = []
        flags = {"social_engineering_language": False}

        text = f"{risk_input.subject} {risk_input.body_text}".lower()

        matched_keywords = [
            keyword
            for keyword in URGENCY_KEYWORDS
            if keyword in text
        ]

        if matched_keywords:
            score = min(len(matched_keywords) * 1.5, LANGUAGE_MAX_SCORE)
            reasons.append(
                "Social engineering language detected: "
                + ", ".join(matched_keywords[:5])
            )
            flags["social_engineering_language"] = True
            return score, reasons, flags

        return 0.0, reasons, flags

    def _apply_security_overrides(
        self,
        base_score: float,
        risk_input: RiskInput,
        flags: Dict[str, bool]
    ) -> Tuple[float, List[str]]:
        reasons = []
        final_score = base_score

        # --- Hard threats: จับได้แน่ ดันขึ้นสูงเสมอ ไม่ผ่อนปรน (ชนะทุกอย่าง) ---
        if flags.get("malicious_link"):
            final_score = max(final_score, 85)
            reasons.append("Security override applied: malicious link indicator")
            return final_score, reasons

        if flags.get("dangerous_attachment"):
            final_score = max(final_score, 80)
            reasons.append("Security override applied: dangerous attachment type")
            return final_score, reasons

        # --- Soft signals: ต้องมีสัญญาณยืนยัน อ่อนตัวเดียวไม่พอ (ลด false-positive) ---
        # ที่มา: AI Server (.94) - FP legit-but-suspicious 50% -> 0%, threat ยัง 100%
        dmarc = risk_input.dmarc_result
        abuse = self._clamp(risk_input.abuseipdb_score)
        ai = self._clamp(risk_input.raw_ai_score)

        # ② auth trust: DMARC ผ่าน + IP สะอาด + AI ต่ำ = เชื่อได้ กดไม่ให้เกิน Warning
        authenticated = (
            dmarc == "pass"
            and abuse < AUTH_TRUST_ABUSE_MAX
            and ai < AUTH_TRUST_AI_MAX
        )
        if authenticated:
            capped = min(final_score, MEDIUM_THRESHOLD - 1)   # อย่างมากแค่ก่อน Warning = Allow
            if capped < final_score:
                reasons.append("Trust override applied: DMARC pass + clean IP + low AI confidence")
            return capped, reasons

        # ① สัญญาณยืนยัน: IP abuse แรงเดี่ยวๆ / AI สูงมาก / AI สูง+auth ผิดอย่างน้อย 1
        strong_signal = abuse > ABUSEIPDB_HIGH_THRESHOLD or ai >= AI_HIGH_CONFIDENCE
        weak_signals = int(bool(risk_input.reply_to_mismatch)) + int(dmarc == "fail")

        if strong_signal or (ai >= SUSPICIOUS_AI and weak_signals >= 1):
            final_score = max(final_score, QUARANTINE_FLOOR)   # BEC/phishing/IP แข็ง -> Quarantine
            reasons.append("Security override applied: confirmed threat signal (strong abuse/AI or AI + auth anomaly)")
        elif weak_signals >= 2:
            final_score = max(final_score, SUSPICIOUS_FLOOR)   # ③ AI ต่ำ + อ่อน 2 -> แค่ Warning
            reasons.append("Security override applied: multiple weak signals flagged for review")

        return final_score, reasons

    def _classify(self, final_score: float) -> Tuple[str, str, str, str]:
        if final_score >= 80:
            return "Critical", ACTION_BLOCK, "🔴 Critical / Block", "#c53030"

        if final_score >= 60:
            return "High", ACTION_QUARANTINE, "🟠 High / Quarantine", "#dd6b20"

        if final_score >= 30:
            return "Medium", ACTION_WARNING, "🟡 Medium / Warning", "#d69e2e"

        return "Low", ACTION_ALLOW, "🟢 Low / Allow", "#2f855a"

    @staticmethod
    def _clamp(value: float, min_value: float = 0.0, max_value: float = 100.0) -> float:
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0.0

        return max(min_value, min(value, max_value))