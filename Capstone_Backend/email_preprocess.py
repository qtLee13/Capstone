"""
email_preprocess.py — การแปลง text ก่อนเข้า BERT (Stage 1) ใช้ร่วมกันทั้ง 2 ฝั่ง
================================================================================
⚠️ ต้องให้ตรงกับตอน train (Cap Stone AI/scripts/preprocess_data.py):
     text = subject + ". " + body   (clean_text = collapse whitespace)
   จากนั้น train_bert.py: mask URL (regex URL -> [URL]) แล้ว tokenize max_length=256

ไฟล์นี้เป็น "แหล่งเดียว" ของ transform → serve (main.py) และ extractor (scripts/build_*) import ไปใช้
เพื่อกัน train/serving skew (ก่อนหน้านี้ serve ป้อน body อย่างเดียว/ไม่ strip HTML)

ใช้ stdlib ล้วน (html.parser) — ไม่ต้องลง dependency เพิ่มบนเครื่อง VM
"""
import os
import re
from html.parser import HTMLParser

URL_RE = re.compile(r"https?://[^\s]+")
_WS_RE = re.compile(r"\s+")

# =====================================================================
# การให้คะแนนความเสี่ยงของลิงก์ (single source of truth — serve + extractor ใช้ตัวนี้ตัวเดียว)
#
# 🐛 บั๊กที่แก้ 2026-07-22 (ทีม Gateway รายงาน):
#    เดิมเช็คด้วย `'.click' in url.lower()` = เทียบแบบ "มีคำนี้อยู่ที่ไหนก็ได้ใน URL"
#    -> https://us.click.yahoo.com/...      โดน (มี ".click" เป็น subdomain)
#    -> https://www.topgear.com/news        โดน (มี ".top" อยู่ในชื่อ)
#    -> https://erp.clicksuite.com.br/...   โดน (มี ".click" ใน "clicksuite")
#    วัดบน corpus จริง 8,612 ฉบับ: 25.3% ของ URL ที่ "ติดกฎ" เป็น false positive
#    ตอนนี้เทียบเฉพาะ "ท้าย hostname" เท่านั้น (TLD จริง) ไม่ใช่ substring ทั้ง URL
# =====================================================================
RISKY_TLDS = (".xyz", ".top", ".click", ".tk")

_IP_IN_URL_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
# ดึง hostname แบบทนพัง — ไม่ใช้ urlparse เพราะมันโยน ValueError กับ URL เพี้ยนใน spam จริง
_HOST_RE = re.compile(r"^[a-z][a-z0-9+.-]*://(?:[^/@\s]*@)?([^/:?#\s\[\]]+)", re.I)

# ระดับคะแนน — ตัวเลขต้องตรงกันทั้งตอนเทรนและตอน serve
LINK_NONE       = 0     # ไม่มีลิงก์เลย
LINK_PLAIN      = 10    # มีลิงก์ แต่ไม่เข้าเงื่อนไขน่าสงสัย
LINK_RISKY_TLD  = 70    # TLD เสี่ยง (.xyz/.top/.click/.tk)
LINK_IP_LITERAL = 90    # ใช้ IP แทนชื่อโดเมน
LINK_MAX_HEURISTIC = 99  # เพดานของ "การเดาจากรูปแบบ" — สงวนเลข 100 ไว้ให้ของที่ยืนยันแล้ว
LINK_CONFIRMED  = 100   # VirusTotal ยืนยันว่าเป็นมัลแวร์


def url_host(url: str) -> str:
    """ดึง hostname จาก URL (ตัวพิมพ์เล็ก) — คืน '' ถ้าแกะไม่ได้"""
    m = _HOST_RE.match((url or "").strip())
    return m.group(1).lower().rstrip(".") if m else ""


def has_risky_tld(url: str) -> bool:
    """TLD ของ URL นี้อยู่ในรายการเสี่ยงไหม — เทียบที่ 'ท้าย hostname' เท่านั้น"""
    return url_host(url).endswith(RISKY_TLDS)


def score_one_url(url: str, vt_malicious: bool = False) -> int:
    """คะแนนความเสี่ยงของ URL เดียว (0–100)"""
    if vt_malicious:
        return LINK_CONFIRMED
    score = LINK_PLAIN
    if _IP_IN_URL_RE.search(url or ""):
        score += 80
    if has_risky_tld(url):
        score += 60
    return min(score, LINK_MAX_HEURISTIC)


def link_confidence(score: int) -> str:
    """
    แปลงคะแนนเป็น 'ระดับความมั่นใจ' ให้ฝั่ง scoring ใช้ตัดสินใจได้โดยไม่ต้องเดาจากตัวเลข
    ⚠️ 'suspicious' คือ "รูปแบบน่าสงสัย" ไม่ใช่ "ยืนยันว่าอันตราย" — ไม่ควรใช้ block เดี่ยวๆ
    """
    if score >= LINK_CONFIRMED:
        return "confirmed"      # VirusTotal ยืนยัน — ใช้ตัดสินเดี่ยวๆ ได้
    if score >= LINK_RISKY_TLD:
        return "suspicious"     # เดาจากรูปแบบ — ต้องรวมกับสัญญาณอื่นก่อนตัดสิน
    if score > LINK_NONE:
        return "low"            # มีลิงก์ ไม่มีอะไรน่าสงสัย
    return "none"               # ไม่มีลิงก์

# =====================================================================
# นามสกุลไฟล์แนบเสี่ยง (single source of truth — main.py serve + extractor ใช้ตัวนี้ตัวเดียว)
# executable/script/office-macro/shortcut + archive/container + split-archive parts
# ครอบคลุม malspam ยุคใหม่: .tar/.gz/.xz/.txz/.lzh archive, .one (OneNote), split .r00/.z01
# =====================================================================
RISKY_EXT = (
    # executable / script / office-macro / shortcut / installer / java
    ".exe", ".scr", ".js", ".vbs", ".doc", ".docm", ".xls", ".xlsm", ".lnk", ".bat", ".msi", ".jar",
    # archive / container
    ".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".ace", ".arj",
    ".tar", ".gz", ".tgz", ".xz", ".txz", ".bz2", ".z", ".lzh", ".lha",
    # other malspam carriers
    ".one", ".uue",
)
# split-archive parts: .r00-.r99, .z01-.z99, .001-.999 (7z/zip split)
_SPLIT_ARCHIVE_RE = re.compile(r"^\.(r\d{2}|z\d{2}|\d{3})$")


# =====================================================================
# สัญญา feature ของ Stage 2 (single source of truth — train + serve ใช้ตัวนี้ตัวเดียว)
# ⚠️ XGBoost รับ array ล้วน ไม่ได้ดูชื่อคอลัมน์ -> ถ้าลำดับสองฝั่งไม่ตรงกัน
#    มันจะเอาค่าผิดช่องไปทำนายโดยไม่มี error ใดๆ ให้เห็น
#
# v2 (2026-07-22, P2): ตัด `dmarc_fail` ออก — เหลือ 5 feature
#   เหตุผล: dmarc_fail ในข้อมูลเทรน "วัดได้" มีค่าเดียวคือ 1.0 ทั้ง 927 แถว
#           -> ค่า 0 ที่โมเดลเห็นคือ "หา DNS record ไม่ได้" ล้วนๆ ไม่ใช่ "DMARC ผ่าน"
#           แต่ตอน serve ค่า 0 แปลว่า "ผ่านจริง" = คนละความหมาย
#           มันจึงเป็นช่องที่ไม่มีข้อมูล DMARC จริงอยู่เลย มีแต่ร่องรอยว่า DNS lookup ล้ม
#   วัดแล้ว: ตัดทิ้งไม่กระทบคุณภาพ (5-fold CV 0.6891 ±0.028 vs ของเดิม 0.6953 ±0.022 = เสมอ)
#
# ❌ ทำไม "ไม่" ใส่ abuseipdb_missing แม้จะเป็นวิธีมาตรฐาน:
#   ข้อมูลเทรนมีเคส missing แค่ 17/952 แถว (1.8%) -> โมเดลสร้าง branch ใหญ่บนตัวอย่างน้อยเกินไป
#   ทดสอบแล้ว: ถ้า AbuseIPDB ล่ม/คีย์หมดอายุ (missing=1 ทั้งหมด)
#       มี flag    -> คำทำนายเปลี่ยน 52.7%   ‼️ ระบบพลิกทั้งระบบเพราะ API เจ้าเดียวล่ม
#       ไม่มี flag -> คำทำนายเปลี่ยน  2.5%
#   ความถูกต้องเชิงตรรกะแลกมาด้วยความเปราะระดับนี้ไม่คุ้ม — รอให้ feedback loop จาก production
#   สะสมเคส missing มากพอก่อน (ดู results/stage2_p2_missing_flags.json)
# =====================================================================
STAGE2_FEATURES = (
    "ai_score",
    "link_risk",
    "abuseipdb_score",     # วัดไม่ได้ -> 0 (ข้อจำกัดที่ยังเหลือ ดูหมายเหตุด้านบน)
    "reply_to_mismatch",
    "attachment_risk",
)
STAGE2_FEATURES_V1 = (
    "ai_score", "link_risk", "abuseipdb_score", "dmarc_fail", "reply_to_mismatch", "attachment_risk",
)   # ของเดิม เก็บไว้อ้างอิงตอน rollback โมเดลเก่า


def stage2_vector(ai_score, link_risk, abuseipdb_score, reply_to_mismatch, attachment_risk):
    """
    สร้าง feature vector ของ Stage 2 ให้ลำดับตรงกับ STAGE2_FEATURES เสมอ
    ใช้ทั้งฝั่ง serve (main.py) และฝั่งเทรน เพื่อกันลำดับสลับ

    ⚠️ `abuseipdb_score=None` (วัดไม่ได้) ยังถูกเติมเป็น 0 เหมือน "IP สะอาด"
       เป็นข้อจำกัดที่รู้ตัวและยอมรับไว้ชั่วคราว (เหตุผลอยู่ในหมายเหตุของ STAGE2_FEATURES)
       ฝั่ง response ยังส่ง `abuseipdb_measured` กลับไปให้ Gateway แยกเองได้
    """
    return [
        float(ai_score),
        float(link_risk or 0),
        float(abuseipdb_score or 0),
        1.0 if reply_to_mismatch else 0.0,
        1.0 if attachment_risk else 0.0,
    ]


def is_risky_ext(ext: str) -> bool:
    """นามสกุล (รวมจุด เช่น '.zip') เสี่ยงไหม — literal list + split-archive pattern"""
    ext = (ext or "").lower()
    return ext in RISKY_EXT or bool(_SPLIT_ARCHIVE_RE.match(ext))


def is_risky_attachment(filename: str) -> bool:
    """ชื่อไฟล์แนบเสี่ยงไหม (ดูจากนามสกุลท้าย)"""
    return is_risky_ext(os.path.splitext(filename or "")[1])


# ---------------------------------------------------------------------------
# หานามสกุลไฟล์แนบแบบหลายชั้น (ทีม Gateway รายงาน 2026-08-10)
# ช่องโหว่เดิม: ดูแต่ชื่อไฟล์ -> ถ้าผู้โจมตี "ไม่ใส่ filename=" มา ไฟล์แนบอันตรายหลุดทั้งหมด
#   พิสูจน์แล้ว: .js ไม่มี filename -> attachment_type=[] has_malware=False -> score 7.09 "Normal"
#               .js มี filename    -> ['.js'] True                        -> score 80  "Malware Attachment"
# แก้: ไล่หาเป็นชั้น ชั้นไหนตอบได้ใช้ชั้นนั้น (ชั้นล่างปลอมยากขึ้นเรื่อยๆ)
#   ① filename= / name=  ② Content-Type (MIME)  ③ magic bytes ของเนื้อไฟล์
# ⚠️ อ่านเนื้อไฟล์ในหน่วยความจำเท่านั้น — ไม่เขียนลงดิสก์ ไม่รัน (นโยบายความปลอดภัยของโปรเจกต์)
# ---------------------------------------------------------------------------

# ชั้น ② MIME -> นามสกุล · ใส่เฉพาะชนิดที่สื่อถึงไฟล์อันตรายชัดเจน
MIME_TO_EXT = {
    "application/javascript": ".js", "text/javascript": ".js", "application/x-javascript": ".js",
    "application/x-msdownload": ".exe", "application/x-msdos-program": ".exe",
    "application/x-dosexec": ".exe", "application/vnd.microsoft.portable-executable": ".exe",
    "application/x-msi": ".msi", "application/java-archive": ".jar",
    "application/zip": ".zip", "application/x-zip-compressed": ".zip",
    "application/x-rar-compressed": ".rar", "application/vnd.rar": ".rar",
    "application/x-7z-compressed": ".7z", "application/x-iso9660-image": ".iso",
    "application/x-tar": ".tar", "application/gzip": ".gz", "application/x-gzip": ".gz",
    "application/x-bzip2": ".bz2", "application/x-cab-compressed": ".cab",
    "application/msword": ".doc", "application/vnd.ms-excel": ".xls",
    "application/vnd.ms-word.document.macroEnabled.12": ".docm",
    "application/vnd.ms-excel.sheet.macroEnabled.12": ".xlsm",
    "application/onenote": ".one", "text/vbscript": ".vbs", "application/x-ms-shortcut": ".lnk",
}

# ชั้น ③ magic bytes -> นามสกุล · ปลอมยากที่สุด (ต้องแก้เนื้อไฟล์จริง)
_MAGIC = (
    (b"MZ",                       ".exe"),   # PE executable / DLL
    (b"PK\x03\x04",               ".zip"),   # zip family (รวม docm/xlsm/jar ที่เป็น zip)
    (b"Rar!\x1a\x07",             ".rar"),
    (b"7z\xbc\xaf\x27\x1c",       ".7z"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1", ".doc"),   # OLE2 (doc/xls รุ่นเก่า — พาหะ macro)
    (b"\x1f\x8b",                 ".gz"),
    (b"BZh",                      ".bz2"),
    (b"MSCF",                     ".cab"),
    (b"L\x00\x00\x00\x01\x14\x02", ".lnk"),  # Windows shortcut
)
_MAGIC_MAX_BYTES = 2_000_000   # ไม่ decode ไฟล์ใหญ่เกินนี้ (กันเปลือง RAM)


def ext_from_mime(content_type: str) -> str:
    """ชั้น ② — เดานามสกุลจาก Content-Type · ไม่รู้จักคืน '' """
    return MIME_TO_EXT.get((content_type or "").lower().strip(), "")


def ext_from_magic(payload: bytes) -> str:
    """ชั้น ③ — เดานามสกุลจาก magic bytes · ไม่รู้จักคืน '' """
    if not payload:
        return ""
    head = payload[:16]
    for sig, ext in _MAGIC:
        if head.startswith(sig):
            return ext
    return ""


def attachment_ext(part) -> str:
    """
    หานามสกุลของ email part หนึ่งชิ้น ไล่ 3 ชั้น — คืน '' ถ้าไม่ใช่ไฟล์แนบ/หาไม่ได้เลย
    ใช้ร่วมกันทั้งตอนเทรนและตอน serve (อย่าเขียนตรรกะนี้ซ้ำที่อื่น)
    """
    # ① ชื่อไฟล์ — get_filename() ของ Python ดูให้แล้วทั้ง Content-Disposition:filename= และ Content-Type:name=
    fn = part.get_filename()
    if fn:
        ext = os.path.splitext(fn)[1].lower()
        if ext:
            return ext

    ct = (part.get_content_type() or "").lower()
    disp = str(part.get("Content-Disposition") or "").lower()
    # ไม่ใช่ไฟล์แนบ (เป็นเนื้อเมล) -> ข้าม
    if ct.startswith("multipart/"):
        return ""
    if not ("attachment" in disp or ct in MIME_TO_EXT):
        return ""

    # ② MIME
    ext = ext_from_mime(ct)
    if ext:
        return ext

    # ③ magic bytes — ทำเฉพาะตอนสองชั้นบนตอบไม่ได้ (ผู้โจมตีตั้งใจซ่อน)
    try:
        payload = part.get_payload(decode=True)
        if payload and len(payload) <= _MAGIC_MAX_BYTES:
            ext = ext_from_magic(payload)
            if ext:
                return ext
    except Exception:
        pass

    # เป็นไฟล์แนบแน่ๆ แต่ระบุชนิดไม่ได้ -> ทำเครื่องหมายไว้ ไม่ปล่อยหายเงียบ
    return ".unknown" if "attachment" in disp else ""


class _TextExtractor(HTMLParser):
    """ดึง visible text จาก HTML (ข้าม <script>/<style>) — แปลง entity ให้อัตโนมัติ"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._skip = 0
        self._parts = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self._parts.append(data)


def html_to_text(html_str: str) -> str:
    """strip HTML tag -> plain text (fallback regex ถ้า parser ล้ม)"""
    if not html_str:
        return ""
    try:
        p = _TextExtractor()
        p.feed(html_str)
        return " ".join("".join(p._parts).split())
    except Exception:
        return _WS_RE.sub(" ", re.sub(r"<[^>]+>", " ", html_str)).strip()


def clean(text) -> str:
    """collapse whitespace + strip (เหมือน clean_text ตอน train)"""
    return _WS_RE.sub(" ", str(text or "")).strip()


def choose_body(plain: str, html: str) -> str:
    """เลือก body: text/plain ก่อน ถ้าไม่มีค่อย strip จาก text/html"""
    b = clean(plain)
    if b:
        return b
    return clean(html_to_text(html))


_AUTH_RE = {m: re.compile(r"\b" + m + r"\s*=\s*([a-zA-Z]+)", re.I) for m in ("spf", "dkim", "dmarc")}


def parse_authentication_results(headers) -> dict:
    """
    อ่านผล SPF/DKIM/DMARC "จริงต่อฉบับ" จาก Authentication-Results header (Proxmox/รับเมลใส่มา)
    รองรับทั้ง RFC8601 ('dmarc=pass ...') และ Microsoft-style ('spf=none (sender IP is ...)')
    คืน {'spf','dkim','dmarc'} (ค่า pass/fail/none/softfail/temperror...) — ไม่เจอ = 'none'
    เอาค่าแรกที่เจอต่อ method (header บนสุด = ของ gateway ที่รับ = น่าเชื่อสุด)
    """
    result = {"spf": "none", "dkim": "none", "dmarc": "none"}
    found = {"spf": False, "dkim": False, "dmarc": False}
    for h in headers or []:
        h = str(h)
        for m, rx in _AUTH_RE.items():
            if not found[m]:
                mt = rx.search(h)
                if mt:
                    result[m] = mt.group(1).lower()
                    found[m] = True
    return result


def build_bert_text(subject, body) -> str:
    """
    สร้าง input ของ BERT ให้ตรงกับ training เป๊ะ:
      (subject + ". " + body) -> collapse whitespace -> mask URL
    body ควรเป็น plain text แล้ว (ผ่าน choose_body มาก่อน)
    """
    subj = clean(subject)
    bod = clean(body)
    combined = f"{subj}. {bod}".strip()      # ตรงกับ str.cat(sep=". ") ตอน train
    return URL_RE.sub("[URL]", combined)


# =====================================================================
# ตรวจการปลอมตัวผู้ส่ง (sender spoofing) — ทีม .92 ขอมา 2026-08-10
#
# เดิม main.py ส่ง `"sender_spoofing": False` ตายตัว ไม่เคยคำนวณเลย
# -> กฎ "+4 ถ้า sender_spoofing" ของ .92 เป็น dead code มาตลอด
#
# ⚠️ ค่านี้ "ไม่ใช่" feature ของโมเดล (ดู STAGE2_FEATURES) — เพิ่มได้โดยไม่ต้องเทรนใหม่
#    เป็นสัญญาณดิบให้ฝั่ง rule engine ตัดสินเอง
#
# บทเรียนที่เอามาใช้ในไฟล์นี้ (บั๊ก .click/.top ปี 2026-07):
#    "อย่าเทียบโดเมนด้วย substring" — เทียบที่ระดับโดเมนจดทะเบียน (eTLD+1) เท่านั้น
# =====================================================================

# TLD หลายส่วน — ต้องมีรายการชัดเจน ห้ามเดาจากจำนวนจุด
# (ถ้าไม่มีรายการนี้ scb.co.th จะถูกตัดเป็น "co.th" = โดเมนไทยทุกอันกลายเป็นอันเดียวกัน)
_MULTI_TLD = frozenset((
    "co.th", "or.th", "ac.th", "go.th", "in.th", "net.th", "mi.th",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "or.jp", "ne.jp", "co.kr", "com.sg", "com.my", "com.cn",
    "com.hk", "com.tw", "com.br", "com.mx", "co.id", "co.in", "co.nz", "co.za",
))

FREE_MAILERS = frozenset((
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.co.th", "outlook.com",
    "outlook.co.th", "live.com", "yahoo.com", "yahoo.co.th", "icloud.com",
    "aol.com", "protonmail.com", "proton.me", "mail.com", "gmx.com", "yandex.com",
    "163.com", "126.com", "qq.com", "naver.com",
))

# แบรนด์ที่ถูกปลอมบ่อย -> โดเมนจริงที่ยอมรับได้
# ⚠️ ใส่เฉพาะคำที่ "เจาะจงพอ" — คำกว้าง ๆ อย่าง "line" / "กรุงเทพ" ทำ false positive มหาศาล
BRAND_DOMAINS = {
    "microsoft":      {"microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                       "live.com", "outlook.com", "sharepointonline.com", "azure.com"},
    "office 365":     {"microsoft.com", "microsoftonline.com", "office.com", "office365.com"},
    "onedrive":       {"microsoft.com", "microsoftonline.com", "onedrive.com"},
    "google":         {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "apple":          {"apple.com", "icloud.com"},
    "paypal":         {"paypal.com"},
    "netflix":        {"netflix.com"},
    "linkedin":       {"linkedin.com"},
    "facebook":       {"facebook.com", "fb.com", "meta.com"},
    "instagram":      {"instagram.com", "facebook.com", "meta.com"},
    "whatsapp":       {"whatsapp.com", "meta.com"},
    "amazon":         {"amazon.com", "amazon.co.th", "amazonaws.com", "amazon.co.jp"},
    "dropbox":        {"dropbox.com", "dropboxmail.com"},
    "docusign":       {"docusign.com", "docusign.net"},
    "adobe":          {"adobe.com"},
    "dhl":            {"dhl.com", "dhl.co.th", "dhl.de"},
    "fedex":          {"fedex.com"},
    "shopee":         {"shopee.co.th", "shopee.com", "shopee.sg"},
    "lazada":         {"lazada.co.th", "lazada.com"},
    "kerry express":  {"kerryexpress.com", "kerrylogistics.com"},
    # ธนาคาร/สถาบันการเงินไทย
    "scb":            {"scb.co.th", "scbeasy.com", "scb.com", "scbam.com", "scbs.com"},
    "ไทยพาณิชย์":      {"scb.co.th", "scbeasy.com", "scbam.com"},
    "kasikorn":       {"kasikornbank.com", "kasikornsecurities.com", "kasikornasset.com", "kbank.co.th"},
    "kbank":          {"kasikornbank.com", "kbank.co.th"},
    "กสิกรไทย":        {"kasikornbank.com", "kasikornsecurities.com", "kasikornasset.com", "kbank.co.th"},
    "krungthai":      {"krungthai.com", "ktb.co.th", "ktbst.co.th"},
    "กรุงไทย":         {"krungthai.com", "ktb.co.th"},
    "bangkok bank":   {"bangkokbank.com", "bbl.co.th"},
    "ธนาคารกรุงเทพ":   {"bangkokbank.com", "bbl.co.th"},
    "krungsri":       {"krungsri.com", "krungsriauto.com"},
    "กรุงศรี":         {"krungsri.com"},
    "ธนาคารกรุงศรี":   {"krungsri.com"},
    "ttb bank":       {"ttbbank.com", "tmbbank.com"},
    "promptpay":      {"promptpay.io", "bot.or.th"},
    "พร้อมเพย์":       {"bot.or.th"},
    # ราชการไทย
    "สรรพากร":         {"rd.go.th"},
    "revenue department": {"rd.go.th"},
    "ไปรษณีย์ไทย":     {"thailandpost.co.th", "thailandpost.com"},
    "thailand post":  {"thailandpost.co.th", "thailandpost.com"},
    "การไฟฟ้า":        {"mea.or.th", "pea.co.th", "egat.co.th"},
    "การประปา":        {"mwa.co.th", "pwa.co.th"},
    "ประกันสังคม":     {"sso.go.th"},
    "social security": {"sso.go.th"},
    # เพิ่มตามข้อเสนอทีม .92 (2026-08-17) — รอรายชื่อจริงจาก quarantine ของ PMG/Mailcow มาเสริม
    "ออมสิน":          {"gsb.or.th"},
    "gsb":            {"gsb.or.th"},
    "ธ.ก.ส.":          {"baac.or.th"},
    "baac":           {"baac.or.th"},
    "ธกส":            {"baac.or.th"},
    "ttb":            {"ttbbank.com", "tmbbank.com"},
    "ทีทีบี":          {"ttbbank.com"},
    "ais":            {"ais.co.th", "ais.th", "advanc.co.th"},
    "เอไอเอส":         {"ais.co.th", "ais.th"},
    "true":           {"truecorp.co.th", "true.th", "trueid.net", "truemoney.com"},
    "ทรูมูฟ":          {"truecorp.co.th", "true.th"},
    "dtac":           {"dtac.co.th", "dtac.th"},
}

# ---------------------------------------------------------------------------
# 🔴 โดเมนขององค์กรเราเอง — สำคัญที่สุดตามที่ทีม .92 ชี้ (2026-08-17):
#    "BEC ที่อันตรายที่สุดคือปลอมเป็นคนในองค์กรเอง ไม่ใช่ปลอมเป็นแบรนด์ภายนอก"
#
# เดิมกันได้เฉพาะโดเมนที่โผล่ใน `recipient` ของ request นั้น ๆ ซึ่งพลาดได้เมื่อ:
#    - ส่งหาหลายโดเมนในเครือ (บริษัทลูก)  - recipient เป็น alias/list  - header ไม่ครบ
# ตั้งค่าใน .env:  PROTECTED_DOMAINS=sammitr.com,sammitr.co.th
# ---------------------------------------------------------------------------
PROTECTED_DOMAINS = frozenset(
    d.strip().lower() for d in os.getenv("PROTECTED_DOMAINS", "").split(",") if d.strip()
)

# น้ำหนักของแต่ละสัญญาณ (รวมกันแล้ว cap ที่ 100)
# ตัวที่ ">= SPOOF_THRESHOLD ตัวเดียว" = ยืนยันได้ด้วยตัวเอง
# ตัวที่น้อยกว่านั้น = ต้องมีสัญญาณอื่นประกอบ (ตั้งใจให้ไม่ fire เดี่ยว ๆ เพราะ false positive สูง)
SPOOF_WEIGHTS = {
    "display_name_other_email": 60,   # display name เป็นอีเมลคนละโดเมนกับผู้ส่งจริง
    "homoglyph_domain":         60,   # โดเมนมีอักษรที่ไม่ใช่ ASCII / punycode
    "lookalike_domain":         55,   # โดเมนคล้ายแบรนด์จริงมาก (แก้ 1-2 ตัวอักษร)
    "brand_mismatch":           50,   # อ้างแบรนด์ในชื่อ แต่โดเมนไม่เกี่ยวกับแบรนด์นั้นเลย
    # อ้างแบรนด์ และ "ชื่อแบรนด์อยู่ในโดเมนผู้ส่งด้วย" (googlealert.com, adobesystems-macromedia.com)
    # มักเป็นโดเมนในเครือ/พาร์ตเนอร์จริง -> ให้น้ำหนักต่ำ ต้องมีสัญญาณอื่นเสริม
    "brand_related_domain":     20,
    "impersonates_recipient_org": 30,  # อ้างชื่อองค์กรผู้รับ แต่ส่งมาจากข้างนอก
    "freemail_corporate_claim": 20,   # อ้างเป็นบริษัท/หน่วยงาน แต่ส่งจากเมลฟรี
}
# >= นี้ -> sender_spoofing = True
# 🔧 45 -> 50 ตามข้อเสนอทีม .92 (2026-08-17): ที่ 45 ตัว brand_mismatch (แม่นแค่ 30%) ยิงเดี่ยวได้
#    ทำให้ธง "เมลนี้ปลอมตัว" ผิด 7 ใน 10 ครั้ง · ที่ 50 ตัวที่แม่นกว่า (lookalike 55+) ยังยิงเดี่ยวได้เหมือนเดิม
SPOOF_THRESHOLD = 50

_DISPLAY_EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_ASCII_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")
# ตัวเลข/อักษรที่ใช้แทนกันเพื่อลวงตา (paypa1.com, rnicrosoft.com)
_CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})
_CORP_WORDS = ("co., ltd", "co.,ltd", "company limited", "corporation", "public company",
               "บริษัท", "จำกัด", "ธนาคาร", "กรม", "สำนักงาน", "department", "helpdesk",
               "it support", "ฝ่ายบุคคล", "human resource", "hr department", "การเงิน", "บัญชี",
               "bank", "accounting", "payroll", "security team", "support team",
               "administrator", "notification")


_DOMAIN_JUNK_RE = re.compile(r"[^\w.\-¡-￿]")   # ตัด <>"' ช่องว่าง ฯลฯ (เก็บ non-ASCII ไว้ให้ ② จับ)


def registrable_domain(domain: str) -> str:
    """
    โดเมนระดับที่จดทะเบียนได้ (eTLD+1) — mail.scb.co.th -> scb.co.th, a.b.evil.xyz -> evil.xyz

    ⚠️ ล้างขยะก่อนเสมอ — ข้อมูลจริงส่งโดเมนติด '>' มา ('sammitr.com>') 1,475/6,939 แถว
       ถ้าไม่ล้าง 'sammitr.com' กับ 'sammitr.com>' จะกลายเป็นคนละโดเมน = ติดธงปลอมทั้งกอง
    """
    d = _DOMAIN_JUNK_RE.sub("", (domain or "").strip().lower()).strip(".")
    if not d or "." not in d:
        return d
    parts = d.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_TLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _edit_distance(a: str, b: str, cap: int = 2) -> int:
    """ระยะแก้ไข (Levenshtein) แบบตัดจบเร็ว — เกิน cap คืน cap+1 พอ"""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _domain_skeleton(domain: str) -> str:
    """
    ลดรูปโดเมนให้เทียบ 'ตาลวง' ได้ — ตัด -/_ และแทนตัวที่หน้าตาเหมือนกัน
    paypa1 / pay-pal -> paypal · rnicrosoft -> microsoft · vvhatsapp -> whatsapp
    """
    name = domain.split(".")[0] if "." in domain else domain
    name = name.replace("-", "").replace("_", "").translate(_CONFUSABLE)
    return name.replace("rn", "m").replace("vv", "w")


def _is_lookalike(sender_reg: str, target_reg: str) -> bool:
    """
    โดเมนผู้ส่งคล้ายโดเมนเป้าหมายจน "ตั้งใจลวง" ไหม (ต้องไม่ใช่โดเมนเดียวกัน)

    ⚠️ เกณฑ์แคบโดยตั้งใจ — วัดบน CEAS_08 (อีเมลปกติ 17,312 ฉบับ) แล้วพบว่าเกณฑ์หลวมทำ FP เพียบ:
         mail.com ~ gmail.com · email.si ~ gmail.com · unimi.it ~ unimib.it · tbank.hu ~ kbank.co.th
       ทุกอันเกิดจาก "ต่างกัน 1 ตัวอักษรโดยการเพิ่ม/ลบ" ซึ่งชื่อโดเมนจริงคนละอันก็บังเอิญเป็นแบบนั้นได้
       การปลอมจริงคือ "แทนที่ตัวอักษรให้ยาวเท่าเดิม" (netflix->netflir) หรือ "ลดรูปแล้วเหมือนเป๊ะ"
    """
    if not sender_reg or not target_reg or sender_reg == target_reg:
        return False
    s_name, t_name = sender_reg.split(".")[0], target_reg.split(".")[0]
    if len(t_name) < 5:          # ชื่อสั้นเกินไป (scb, ktb, dhl) — แก้ 1 ตัวก็ชนคำอื่นเต็มไปหมด
        return False
    # ① ลดรูปแล้วเหมือนกันเป๊ะ = ตั้งใจลวงชัดเจน (paypa1 / pay-pal / rnicrosoft)
    if _domain_skeleton(sender_reg) == _domain_skeleton(target_reg):
        return True
    # ② "แทนที่ตัวอักษร 1 ตัว โดยความยาวเท่าเดิม" เท่านั้น — เพิ่ม/ลบตัวอักษรไม่นับ (FP สูงเกิน)
    if len(s_name) != len(t_name) or len(t_name) < 6:
        return False
    return _edit_distance(s_name, t_name, cap=1) == 1


# ระบบ mailing list / ticket / relay เอา "อีเมลผู้ส่งเดิม" มาใส่ใน display name เป็นเรื่องปกติ
#   "ysgt@lac.uic.edu (via RT)" <bugs@perl.org>   <- ถูกต้อง ไม่ใช่การปลอม
# วัดบน CEAS_08: เคสแบบนี้คือ 50 จาก 73 ของ false positive ทั้งหมด
_RELAY_MARKER_RE = re.compile(r"\bvia\b|\(via|on behalf of|forwarded|mailing list|listserv", re.I)


def detect_sender_spoofing(display_name: str, sender_domain: str,
                           recipient_domain: str = "", reply_to_domain: str = "",
                           sender_email: str = "") -> dict:
    """
    ตรวจว่า "ผู้ส่งพยายามทำให้ดูเป็นคนอื่น" ไหม

    คืน {"spoofing": bool, "score": 0-100, "reasons": [...]}
      - reasons เป็นรายการรหัสสัญญาณ ให้ฝั่ง .92 ตั้งน้ำหนักเองต่อได้
      - ไม่รู้จัก/ข้อมูลไม่พอ -> score 0, spoofing False (ไม่เดา)

    ⚠️ ตรวจ "การแอบอ้างตัวตน" เท่านั้น ไม่ได้ตรวจว่า SPF/DKIM ผ่านไหม
       (อันนั้น PMG ทำแล้วและแม่นกว่า — ดู spf_result/dkim_result ใน raw_signals)
    """
    name = (display_name or "").strip()
    sender_reg = registrable_domain(sender_domain)
    recip_reg = registrable_domain(recipient_domain)
    # โดเมนองค์กรเราเอง (จาก .env) + โดเมนผู้รับฉบับนี้ — ใช้ตรวจ BEC ที่ปลอมเป็นคนใน
    own_domains = {registrable_domain(d) for d in PROTECTED_DOMAINS} - {""}
    reasons, hits = [], []

    def _hit(code, detail=""):
        reasons.append(f"{code}:{detail}" if detail else code)
        hits.append(SPOOF_WEIGHTS[code])

    if not sender_reg:
        return {"spoofing": False, "score": 0, "reasons": []}

    name_low = name.lower()

    # ① display name เป็น/มีอีเมลของโดเมนอื่น — From: "billing@scb.co.th" <x@evil.xyz>
    #    ข้ามถ้าเป็น mailing list / relay ที่ประกาศตัวชัดเจน หรือโดเมนนั้นอยู่ในอีเมลผู้ส่งอยู่แล้ว
    if not _RELAY_MARKER_RE.search(name_low):
        addr_low = (sender_email or "").lower()
        for m in _DISPLAY_EMAIL_RE.finditer(name_low):
            other = registrable_domain(m.group(1))
            if other and other != sender_reg and other not in addr_low:
                _hit("display_name_other_email", other)
                break

    # ② โดเมนมีอักษรตาลวง (ซีริลลิก/กรีก) หรือเป็น punycode
    if not _ASCII_DOMAIN_RE.match(sender_reg) or sender_reg.startswith("xn--") or ".xn--" in sender_reg:
        _hit("homoglyph_domain", sender_reg)

    # ③ + ④ เทียบกับแบรนด์ที่ถูกปลอมบ่อย
    #     ③ โดเมนคล้ายแบรนด์ (typosquatting) — ตรวจทุกฉบับ ไม่ต้องรอให้ชื่อพูดถึงแบรนด์
    #     ④ ชื่อพูดถึงแบรนด์ แต่โดเมนไม่ใช่ของแบรนด์
    protected = set()
    for domains in BRAND_DOMAINS.values():
        protected |= domains
    if recip_reg:
        protected.add(recip_reg)      # ปลอมเป็นโดเมนของผู้รับเองก็นับ
    protected |= own_domains          # โดเมนองค์กรเราเอง (ตั้งใน .env) — กัน BEC ภายใน
    # ผู้ส่งเป็นโดเมนจริงของแบรนด์เอง (amazon.co.th, dhl.de) -> ไม่ต้องเทียบ ไม่งั้นชนกันเอง
    if sender_reg not in protected:
        for target in protected:
            if _is_lookalike(sender_reg, target):
                _hit("lookalike_domain", f"{sender_reg}~{target}")
                break

    for brand, ok_domains in BRAND_DOMAINS.items():
        if not _brand_in_name(brand, name_low):
            continue
        if sender_reg in ok_domains:
            break                     # อ้างแบรนด์และเป็นโดเมนแบรนด์จริง -> ปกติ
        # โดเมนมีชื่อแบรนด์อยู่ด้วยไหม (googlealert.com มี "google") -> มักเป็นของในเครือจริง
        # วัดแล้ว: อีเมลปกติที่ติดผิด 4/7 เป็นแบบนี้ · ฟิชชิ่งที่จับได้ 0/6 เป็นแบบนี้
        flat = sender_reg.replace("-", "").replace(".", "")
        related = brand.replace(" ", "") in flat
        _hit("brand_related_domain" if related else "brand_mismatch", f"{brand}!={sender_reg}")
        break

    # ⑤ อ้างชื่อองค์กรของผู้รับ/องค์กรเรา แต่ส่งมาจากข้างนอก (เมล "จากฝ่ายไอทีของคุณ" ยอดฮิต)
    #    เทียบทั้งโดเมนผู้รับฉบับนี้ และ PROTECTED_DOMAINS (กรณีบริษัทลูก/alias ที่ recipient ไม่บอก)
    inside = {d for d in ({recip_reg} | own_domains) if d}
    if inside and sender_reg not in inside:
        for org in {d.split(".")[0] for d in inside}:
            if len(org) >= 5 and org in name_low.replace(" ", ""):
                _hit("impersonates_recipient_org", org)
                break

    # ⑥ อ้างเป็นองค์กร/แผนก แต่ส่งจากเมลฟรี (เดี่ยว ๆ ไม่พอตัดสิน ตั้งใจให้ต่ำกว่า threshold)
    if sender_reg in FREE_MAILERS and any(w in name_low for w in _CORP_WORDS):
        _hit("freemail_corporate_claim", sender_reg)

    score = min(100, sum(hits))
    return {"spoofing": score >= SPOOF_THRESHOLD, "score": score, "reasons": reasons}


def _brand_in_name(brand: str, name_low: str) -> bool:
    """
    ชื่อผู้ส่งพูดถึงแบรนด์นี้ไหม — ภาษาอังกฤษต้องเป็น "คำเต็ม" (กัน scb ไปชน scbx/discbrake)
    ภาษาไทยไม่มีตัวคั่นคำ จึงเทียบแบบ substring ได้ (คำที่ใส่ไว้เจาะจงพออยู่แล้ว)
    """
    if brand.isascii():
        return re.search(r"(?<![a-z0-9])" + re.escape(brand) + r"(?![a-z0-9])", name_low) is not None
    return brand in name_low


def spoofing_from_headers(from_header: str, recipient: str = "", reply_to: str = "") -> dict:
    """
    เวอร์ชันที่รับ header ดิบ (ใช้ใน main.py) — แกะ display name / โดเมน ให้เอง
    From: "SCB Bank" <noreply@random.xyz>  ->  display='SCB Bank', domain='random.xyz'
    """
    hdr = (from_header or "").strip()
    m = re.search(r"<([^>]+)>", hdr)
    if m:
        addr = m.group(1)
        display = hdr[:m.start()].strip().strip('"').strip("'").strip()
    else:
        addr, display = hdr, ""
    sender_domain = addr.split("@")[-1].strip().strip(">").lower() if "@" in addr else ""
    recip_domain = recipient.split("@")[-1].lower() if "@" in (recipient or "") else ""
    reply_domain = reply_to.split("@")[-1].strip().strip(">").lower() if "@" in (reply_to or "") else ""
    return detect_sender_spoofing(display, sender_domain, recip_domain, reply_domain,
                                  sender_email=addr.strip().strip("<>").lower())


# =====================================================================
# ATTACK EVIDENCE — ตัวแปรหลักฐานสำหรับ "แยกประเภทการโจมตี"
#
# ทำไมต้องมี: Stage 2 ปัจจุบันรับ 5 ตัวเลข (ai_score, link_risk, abuseipdb,
#   reply_to_mismatch, attachment_risk) แล้วเลือก 1 ใน 4 คลาส
#   แต่ 4 คลาสนั้นมี ai_score เฉลี่ย 96-99 เท่ากันหมด -> แยกกันไม่ได้จริง
#   (วัดแล้ว 2026-08-26: 73% ของจุดแตกกิ่งในโมเดลคือ "ai_score > 99.99x ?"
#    = โมเดลจำ noise ของ softmax แทนที่จะใช้สัญญาณจริง ดู docs/)
#
# หลักการ: ประเภทการโจมตีเป็นเรื่อง "นิยาม" ไม่ใช่เรื่องที่ต้องค้นจากข้อมูล
#   BEC      = ปลอมตัวเป็นคน/องค์กร ขอให้ทำอะไร มัก "ไม่มีลิงก์"
#   Phishing = ล่อไปหน้า login ปลอม -> ปลอมแบรนด์ + มีลิงก์
#   Spam     = ส่งกระจาย ขายของ -> ลิงก์เยอะ ซ้ำโดเมน มี unsubscribe
#   Malware  = มีไฟล์แนบอันตราย
# ตัวแปรข้างล่างคือ "หลักฐาน" ของนิยามเหล่านั้น — ใช้ได้ทั้งกับกฎและกับโมเดลที่จะเทรนทีหลัง
#
# ⚠️ ATTACK_EVIDENCE คือ single source ของลำดับ/ชื่อ — ห้ามสร้าง list เองที่อื่น
#    (บทเรียนเดิม: STAGE2_FEATURES ลำดับสลับระหว่าง train กับ serve)
# =====================================================================

# รหัสเหตุผลจาก detect_sender_spoofing -> ชื่อตัวแปร
SPOOF_FLAGS = {
    "display_name_other_email":   "spoof_display_name",
    "homoglyph_domain":           "spoof_homoglyph",
    "lookalike_domain":           "spoof_lookalike",
    "brand_mismatch":             "spoof_brand",
    "brand_related_domain":       "spoof_brand_related",
    "impersonates_recipient_org": "spoof_own_org",
    "freemail_corporate_claim":   "spoof_freemail_corp",
}

# 🐛 กันเงียบ: ถ้ามีคนเพิ่มสัญญาณใน SPOOF_WEIGHTS แล้วลืมเพิ่มที่นี่
#    ตัวแปรนั้นจะหายไปจากหลักฐานโดยไม่มีใครรู้ -> ให้พังตอน import ไปเลย
_missing_flags = set(SPOOF_WEIGHTS) - set(SPOOF_FLAGS)
if _missing_flags:
    raise RuntimeError(
        f"SPOOF_WEIGHTS มีสัญญาณที่ยังไม่มีใน SPOOF_FLAGS: {sorted(_missing_flags)} "
        "— เพิ่มชื่อตัวแปรให้ครบ ไม่งั้นหลักฐานจะหายเงียบ ๆ")

ATTACK_EVIDENCE = (
    # --- ปลอมตัวผู้ส่ง (แตกจาก spoofing_reasons ให้เป็นตัวแปรรายตัว) ---
    "spoof_display_name",       # display name เป็นอีเมลคนละโดเมนกับผู้ส่งจริง
    "spoof_homoglyph",          # โดเมนใช้อักษรหลอกตา / punycode
    "spoof_lookalike",          # โดเมนคล้ายแบรนด์จริง (ต่างตัวอักษรเดียว)
    "spoof_brand",              # อ้างแบรนด์ในชื่อ แต่โดเมนไม่เกี่ยวกับแบรนด์
    "spoof_brand_related",      # อ้างแบรนด์ และชื่อแบรนด์อยู่ในโดเมนด้วย (มักเป็นพาร์ตเนอร์จริง)
    "spoof_own_org",            # อ้างเป็นองค์กรของผู้รับ แต่ส่งจากข้างนอก (BEC ที่อันตรายสุด)
    "spoof_freemail_corp",      # อ้างเป็นบริษัท/หน่วยงาน แต่ส่งจากเมลฟรี
    # --- ลิงก์ (นิยามตรงกับ data_dictionary ของบริษัท เพื่อให้เทียบตัวเลขกันได้) ---
    "link_count",               # จำนวนลิงก์ทั้งหมด
    "unique_link_domains",      # จำนวนโดเมนไม่ซ้ำ
    "link_domain_ratio",        # link_count / unique_link_domains (สูง = ยัดลิงก์ซ้ำโดเมน)
    "external_link_ratio",      # สัดส่วนลิงก์ที่ไม่ได้อยู่โดเมนผู้ส่ง
    "has_unsubscribe",          # มีลิงก์/ข้อความยกเลิกรับข่าว = ลักษณะเมลกระจาย
    "link_login_lure",          # 🔑 URL ชี้ไปหน้า login/verify — หัวใจของนิยาม "ฟิชชิ่ง"
    "link_text_mismatch",       # ข้อความลิงก์อ้างโดเมนหนึ่ง แต่ href พาไปอีกโดเมน
    "no_links",                 # ไม่มีลิงก์เลย — สัญญาณสำคัญของ BEC
    # --- อื่น ๆ ที่มีอยู่แล้ว ---
    "reply_to_mismatch",
    "attachment_risk",
    "asks_credential",          # ขอให้ยืนยันตัวตน/รหัสผ่าน — แยกจาก has_urgency ไม่ให้นับซ้ำ
    "has_urgency",              # คำเร่งด่วน/ขู่ (อังกฤษ + ไทย — ของบริษัทตรวจอังกฤษอย่างเดียว)
    "sender_is_free_mailer",
)

# คำเร่งด่วน: ของบริษัทใช้ regex อังกฤษล้วน (ระบุไว้ใน data_dictionary ว่าเป็นข้อจำกัด)
# เติมไทยเข้าไปเพราะเมลไทยคือประชากรจริงของระบบนี้
# ⚠️ แยก "เร่งด่วน/ขู่" ออกจาก "ขอข้อมูลยืนยันตัวตน" — เดิมปนกันอยู่ใน _URGENCY_RE
#    ทำให้เมลฉบับเดียวได้คะแนนสองเด้งจากประโยคเดียว ("ยืนยันตัวตนด่วน")
#    หลักการเดียวกับที่ทีม .92 แยก 6 กลุ่มความหมาย: ตรวจคนละเรื่อง ห้ามนับซ้ำ
_URGENCY_RE = re.compile(
    r"\b(urgent|immediately|asap|suspend|suspended|expire[sd]?|"
    r"claim\s+now|act\s+now|final\s+notice|last\s+warning|within\s+24\s*hours?|"
    r"account\s+(locked|closed)|will\s+be\s+(deleted|terminated))\b"
    r"|ด่วน|เร่งด่วน|ภายใน\s*24|ระงับบัญชี|ถูกระงับ|บัญชีถูกล็อก|"
    r"หมดอายุ|ครั้งสุดท้าย|กรุณาดำเนินการทันที|หมดเขต",
    re.I)

# ขอให้ "ส่งมอบข้อมูลยืนยันตัวตน" — แก่นของฟิชชิ่ง (ต่างจากการเร่งเฉย ๆ)
_CREDENTIAL_RE = re.compile(
    r"\b(verify\s+your\s+(account|identity|email|information)|"
    r"confirm\s+your\s+(account|identity|password|details)|"
    r"update\s+your\s+(account|payment|billing|password)|"
    r"reset\s+your\s+password|sign\s+in\s+to\s+(confirm|verify|continue)|"
    r"enter\s+your\s+(password|credentials|pin)|validate\s+your\s+account|"
    r"one[\s-]?time\s+password|security\s+code)\b"
    r"|ยืนยันตัวตน|ยืนยันบัญชี|ยืนยันข้อมูล|รีเซ็ตรหัสผ่าน|ตั้งรหัสผ่านใหม่|"
    r"กรอกรหัสผ่าน|รหัสผ่านของท่าน|รหัส\s*otp|แจ้งรหัส|เข้าสู่ระบบเพื่อยืนยัน",
    re.I)

_UNSUB_RE = re.compile(
    r"unsubscribe|opt[\s-]?out|manage\s+(your\s+)?preferences|list-unsubscribe"
    r"|ยกเลิกการรับ|เลิกรับข่าว|ยกเลิกรับอีเมล",
    re.I)

# ตัดอักขระท้าย URL ที่ติดมาจากประโยค/HTML (">, ], ) และจุดท้ายประโยค)
_URL_TAIL_RE = re.compile(r'[)\]>"\'.,;!]+$')


# คำใน path/query ของ URL ที่บ่งว่าปลายทางเป็นหน้ากรอกข้อมูลยืนยันตัวตน
# 🔑 เพิ่ม 2026-08-26: วัดแล้วพบว่าเดิมไม่มีสัญญาณที่ "เฉพาะเจาะจงกับฟิชชิ่ง" เลย
#    ทำให้เมลฟิชชิ่งที่มีลิงก์เยอะถูกจัดเป็น Spam ถึง 62.4% บน phishing_pot (ซึ่งเป็นฟิชชิ่งล้วน)
# ⚠️ ดูเฉพาะส่วนหลังชื่อโฮสต์ (path/query) ไม่ดูทั้ง URL
#    ไม่งั้นโดเมนปกติอย่าง secure-bank.co.th หรือ accounts.google.com จะติดทุกฉบับ
_LOGIN_LURE_RE = re.compile(
    r"(login|signin|sign-in|log-in|verify|verification|account|secure|"
    r"confirm|update|password|passwd|auth|recover|unlock|validate|billing)",
    re.I)


# <a href="ปลายทางจริง">ข้อความที่ผู้ใช้เห็น</a>
# เทคนิคฟิชชิ่งคลาสสิก: โชว์ข้อความว่า paypal.com แต่ href พาไปที่อื่น
# ⚠️ FP ที่ต้องระวัง: จดหมายข่าวถูกกฎหมายก็ทำแบบนี้ผ่าน click-tracker
#    (โชว์ shop.example.com แต่ href เป็น click.mailer.net) -> วัดอัตราการติดก่อนตั้งน้ำหนัก
_A_TAG_RE = re.compile(r"""<a\b[^>]*?href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>(.*?)</a>""", re.I | re.S)
_ANY_TAG_RE = re.compile(r"<[^>]+>")
_TEXT_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,})\b", re.I)


def link_text_mismatch(html: str) -> int:
    """ข้อความของลิงก์อ้างโดเมนหนึ่ง แต่ href พาไปอีกโดเมน -> 1

    นับเฉพาะกรณีที่ "ข้อความมีชื่อโดเมนอยู่จริง" เท่านั้น
    ข้อความอย่าง "คลิกที่นี่" ไม่มีอะไรให้เทียบ จึงไม่นับ (ไม่ใช่หลักฐาน ไม่ใช่หลักฐานว่าไม่ผิด)
    """
    for href, inner in _A_TAG_RE.findall(html or ""):
        if not href.lower().startswith(("http://", "https://")):
            continue                              # mailto:/tel:/# ไม่เกี่ยว
        hd = _url_host(href)
        if not hd:
            continue
        m = _TEXT_DOMAIN_RE.search(_ANY_TAG_RE.sub(" ", inner))
        if not m:
            continue
        td = registrable_domain(m.group(1))
        if td and "." in td and td != hd:
            return 1
    return 0


def _url_host(url: str) -> str:
    """โฮสต์ของ URL -> โดเมนจดทะเบียน (eTLD+1) · ใช้ registrable_domain ตัวเดียวกับ spoofing"""
    u = _URL_TAIL_RE.sub("", (url or "").strip())
    m = re.match(r"https?://([^/?#\s]+)", u, re.I)
    if not m:
        return ""
    host = m.group(1).split("@")[-1].split(":")[0]     # ตัด user:pass@ และ :port
    return registrable_domain(host)


def spoof_flags(reasons) -> dict:
    """แตก spoofing_reasons เป็นตัวแปร 0/1 รายตัว

    reasons มาในรูป 'brand_mismatch:paypal!=evil.top' -> เอาเฉพาะรหัสหน้า ':'
    """
    out = {name: 0 for name in SPOOF_FLAGS.values()}
    for r in reasons or ():
        code = str(r).split(":", 1)[0].strip()
        key = SPOOF_FLAGS.get(code)
        if key:
            out[key] = 1
    return out


def link_features(text: str, sender_domain: str = "") -> dict:
    """นับลิงก์จากข้อความ

    ⚠️ ต้องส่ง "ข้อความที่ถอดรหัสแล้ว" (text/plain + text/html) เข้ามา ไม่ใช่อีเมลดิบ
       วัดแล้ว 2026-08-26 บน phishing_pot 600 ฉบับ: อ่านจาก raw ทำให้ 24.2% หาลิงก์ไม่เจอเลย
       แต่พอถอดรหัส base64 ก่อน เหลือ 12.5% -> อ่านจาก raw = ตาบอดกับเมลที่เข้ารหัส
       (อีกทางหนึ่ง raw ยังเจอ URL ใน header เช่น Received/DKIM ซึ่งไม่ใช่ลิงก์ในเนื้อเมล)
    """
    urls = URL_RE.findall(text or "")
    doms = [d for d in (_url_host(u) for u in urls) if d]
    lure = 0
    for u in urls:
        m = re.match(r"https?://[^/?#\s]+([/?#][^\s]*)?", _URL_TAIL_RE.sub("", u.strip()), re.I)
        if m and m.group(1) and _LOGIN_LURE_RE.search(m.group(1)):
            lure = 1
            break
    uniq = set(doms)
    sd = registrable_domain(sender_domain or "")
    ext = sum(1 for d in doms if d != sd) if sd else len(doms)
    return {
        "link_count":          len(urls),
        "unique_link_domains": len(uniq),
        # นิยามเดียวกับ data_dictionary ของบริษัท: link_count / unique_link_domains
        "link_domain_ratio":   round(len(urls) / len(uniq), 3) if uniq else 0.0,
        "external_link_ratio": round(ext / len(doms), 3) if doms else 0.0,
        "has_unsubscribe":     1 if _UNSUB_RE.search(text or "") else 0,
        "link_login_lure":     lure,
        "link_text_mismatch":  link_text_mismatch(text),
        "no_links":            1 if not urls else 0,
    }


def attack_evidence(spoof_reasons, body_text: str, sender_domain: str = "",
                    reply_to_mismatch: bool = False, attachment_risk: bool = False,
                    subject: str = "") -> dict:
    """รวมหลักฐานทั้งหมดเป็น dict เดียว คีย์ตรงกับ ATTACK_EVIDENCE เสมอ

    body_text = ข้อความที่ถอดรหัสแล้ว (plain + html) — ดูหมายเหตุใน link_features
    """
    ev = spoof_flags(spoof_reasons)
    ev.update(link_features(body_text, sender_domain))
    blob = f"{subject or ''} {body_text or ''}"
    ev["reply_to_mismatch"]     = 1 if reply_to_mismatch else 0
    ev["attachment_risk"]       = 1 if attachment_risk else 0
    ev["has_urgency"]           = 1 if _URGENCY_RE.search(blob) else 0
    ev["asks_credential"]       = 1 if _CREDENTIAL_RE.search(blob) else 0
    ev["sender_is_free_mailer"] = 1 if registrable_domain(sender_domain or "") in FREE_MAILERS else 0
    # เรียงตามสัญญา + กันตกหล่น
    missing = set(ATTACK_EVIDENCE) - set(ev)
    if missing:
        raise RuntimeError(f"attack_evidence ขาดตัวแปร {sorted(missing)}")
    return {k: ev[k] for k in ATTACK_EVIDENCE}


# =====================================================================
# ATTACK TYPE v2 — คิดประเภทการโจมตีจาก "หลักฐาน" ด้วยคะแนนที่อธิบายได้
#
# ทำไมไม่ใช้ XGBoost: วัดแล้ว (2026-08-26) 73% ของจุดแตกกิ่งในโมเดลคือ
#   "ai_score > 99.99x ?" เพราะทั้ง 4 คลาสมี ai_score เฉลี่ย 96-99 เท่ากันหมด
#   -> โมเดลจำเศษทศนิยมของ softmax ตอบไม่ได้ว่าทำไมถึงเป็นประเภทนี้
#   และ label ตอนเทรนมาจาก "ไฟล์ต้นทาง + regex คำ" ไม่ใช่คนตัดสิน (n=952)
#
# หลักการ: ประเภทการโจมตีเป็นเรื่อง "นิยาม" ไม่ใช่สิ่งที่ต้องค้นพบจากข้อมูล
#   เมื่อ label ยังเชื่อไม่ได้ กฎที่เขียนตามนิยามย่อมแม่นกว่าโมเดลที่เรียนจาก label ปลอม
#   และสำคัญกว่านั้น: ชี้ได้ทีละบรรทัดว่าคะแนนมาจากหลักฐานตัวไหน
#
# ⚠️ ห้ามเอา attack_type/คะแนนนี้ไปบวกเข้า risk score ของทีม .92
#    engine เขาแบ่ง 6 องค์ประกอบให้ตรวจคนละเรื่อง (AI/Link/Attachment/Domain/Language/Header)
#    ที่ปรึกษาเขาย้ำว่าห้ามนับซ้ำ · ตัวนี้เป็น "คนละแกน" คือบอกชนิด ไม่ได้บอกความเสี่ยง
#    ถ้าเอาไปบวกจะกลายเป็นวนนับซ้ำ (โดยเฉพาะ has_urgency ที่ทับกับ LANGUAGE ของเขา)
#
# ⚠️ ตั้งใจ "ไม่" ใช้ ai_score เป็นคะแนนของประเภทใด — ai_score บอกว่า "อันตรายแค่ไหน"
#    ไม่ได้บอกว่า "แบบไหน" (พิสูจน์แล้วว่าทั้ง 4 คลาสมีค่าเท่ากัน)
#    ใช้แค่ตอนตัดสินว่าจะเรียกว่า Normal หรือ "ระบุประเภทไม่ได้"
# =====================================================================

ATTACK_TYPE_WEIGHTS = {
    # มีไฟล์แนบรันโค้ดได้ = การส่งมัลแวร์ตามนิยาม ไม่ต้องมีอย่างอื่นประกอบ
    "Malware Attachment": {
        "attachment_risk": 100,
    },
    # BEC = ปลอมตัวเป็น "คน/องค์กร" เพื่อให้เหยื่อลงมือทำอะไร (มักโอนเงิน)
    # ลักษณะเด่นคือ "ไม่มีลิงก์" เพราะไม่ได้ล่อไปหน้าเว็บ แต่คุยกับคนตรง ๆ
    "Business Email Compromise (BEC)": {
        "spoof_own_org":        45,   # อ้างเป็นองค์กรของผู้รับเอง = BEC ที่อันตรายสุด (.92 ชี้ 2026-08-17)
        "spoof_display_name":   40,   # display name เป็นอีเมลคนละโดเมน
        "spoof_freemail_corp":  25,   # อ้างเป็นบริษัท แต่ส่งจากเมลฟรี
        "reply_to_mismatch":    15,   # ให้ตอบกลับไปที่อื่น = ดักบทสนทนา
        "no_links":             15,
        "has_urgency":          10,
    },
    # Phishing = ล่อไปกรอกข้อมูลที่หน้าเว็บปลอม -> ต้องมีลิงก์ + ปลอมแบรนด์
    "Phishing": {
        "spoof_homoglyph":      45,
        "spoof_lookalike":      45,
        "spoof_brand":          40,
        "spoof_brand_related":  10,   # อาจเป็นพาร์ตเนอร์จริง ให้น้ำหนักต่ำ
        # ── น้ำหนักสามตัวล่างตั้งจาก "อัตราการติดที่วัดจริง" ไม่ได้เดา (2026-08-26)
        #    ฟิชชิ่ง / สแปม / เมลปกติ  ->  ยิ่งห่างกัน ยิ่งได้น้ำหนักมาก
        "link_text_mismatch":   45,   # 5.4% / 1.5% / 0.0%  — เจาะจงที่สุด ไม่ติดเมลปกติเลย
        "link_login_lure":      40,   # 5.3% / 0.9% / 0.3%
        "asks_credential":      35,   # 3.6% / 0.4% / 0.0%
        "has_links":            10,   # "มีลิงก์" เฉย ๆ ไม่ได้แปลว่าฟิชชิ่ง
        # has_urgency ให้แค่ 5: วัดแล้วติดฟิชชิ่ง 16.8% สแปม 16.5% = แยกสองอย่างนี้ไม่ได้เลย
        # (มันแยก "ร้าย vs ปกติ" ได้ 7 เท่า แต่นั่นเป็นหน้าที่ของ risk score ไม่ใช่การบอกชนิด)
        "has_urgency":           5,
    },
    # Spam = ส่งกระจายเชิงพาณิชย์ ไม่ได้เจาะจงเหยื่อ
    # 🐛 ปรับน้ำหนัก 2026-08-26 หลังวัดบน phishing_pot 8,612 ฉบับ (ฟิชชิ่งล้วน)
    #    ชุดแรกให้ many_links/all_links_external/link_repeat_domain -> จัดเป็น Spam ถึง 62.4%
    #    เพราะสัญญาณพวกนั้น "ไม่ได้เฉพาะเจาะจงกับสแปม" ฟิชชิ่งก็ลิงก์เยอะและซ้ำโดเมนเหมือนกัน
    #    เหลือไว้เฉพาะสิ่งที่เป็นของเมลกระจายจริง ๆ: ปุ่มยกเลิกรับข่าว + ลิงก์ไปหลายโดเมนต่างกัน
    # 🔍 ผลวัด 2026-08-26: สแปม "ไม่มีสัญญาณบวกที่เป็นของตัวเอง" เลย
    #    has_unsubscribe ติดฟิชชิ่ง 32.6% แต่ติดสแปม 26.3% — ติดในฟิชชิ่งมากกว่าด้วยซ้ำ
    #    เพราะฟิชชิ่งลอกเทมเพลตจดหมายข่าวมาใช้ทั้งดุ้น
    #    -> นิยาม Spam ว่า "เมลกระจายที่ไม่มีสัญญาณฟิชชิ่ง" คือพึ่งน้ำหนักติดลบเป็นหลัก
    "Spam (High-Risk Source)": {
        "has_unsubscribe":      30,   # เมลกระจายเชิงพาณิชย์ต้องมีปุ่มยกเลิกตามกฎหมาย
        "many_link_domains":    25,   # ลิงก์ไปหลายโดเมนต่างกัน = โฆษณาหลายเจ้า (ฟิชชิ่งมักโดเมนเดียว)
        "many_links":           10,
        # 🔻 น้ำหนักติดลบ: สแปมโฆษณา "ไม่ต้องปลอมตัว" เพราะขายของจริง อยากให้คนรู้ว่าใครส่ง
        #    ถ้ามีการปลอมตัวหรือลิงก์ล่อไปหน้า login แปลว่าเจตนาไม่ใช่การขายของ
        #    วัดแล้ว 2026-08-26: ฟิชชิ่ง 32.6% มีข้อความ unsubscribe (ลอกเทมเพลตจดหมายข่าวมา)
        #    ถ้าไม่หักคะแนน สแปมจะกินเคสฟิชชิ่งไปเยอะ (39.5% บน phishing_pot ซึ่งเป็นฟิชชิ่งล้วน)
        "spoof_any":           -40,
        "link_login_lure":     -30,
        "link_text_mismatch":  -35,   # ร้านค้าจริงไม่ต้องปิดบังปลายทางของลิงก์
        "asks_credential":     -30,   # คนขายของไม่ขอรหัสผ่านลูกค้า
    },
}

# 🐛 ขึ้นจาก 25 -> 35 (2026-08-26): ที่ 25 สัญญาณอ่อนตัวเดียวก็ตัดสินได้แล้ว
#    เช่น has_unsubscribe เดี่ยว ๆ -> Spam · reply_to_mismatch+no_links -> BEC
#    ที่ 35 ต้องมีสัญญาณหนัก 1 ตัว หรือสัญญาณอ่อน 2 ตัวขึ้นไป ถึงจะกล้าบอกประเภท
ATTACK_TYPE_MIN_SCORE = 35   # ต่ำกว่านี้ = หลักฐานไม่พอจะบอกประเภท
ATTACK_TYPE_MARGIN_HIGH = 30 # ห่างจากอันดับสองเท่านี้ = มั่นใจ
ATTACK_TYPE_MARGIN_MED  = 15


def _derived_flags(ev: dict) -> dict:
    """แปลงตัวเลขดิบเป็นเงื่อนไข 0/1 ที่ตารางน้ำหนักใช้

    แยกออกมาเป็นฟังก์ชันเพื่อให้ "จุดตัด" อยู่ที่เดียว แก้แล้วเปลี่ยนทั้งระบบ
    """
    return {
        "has_links":         1 if ev.get("link_count", 0) >= 1 else 0,
        "many_links":        1 if ev.get("link_count", 0) >= 5 else 0,
        # ratio = link_count/unique_domains -> >=3 คือลิงก์เดิมซ้ำ ๆ อย่างน้อย 3 เท่า
        "link_repeat_domain": 1 if ev.get("link_domain_ratio", 0) >= 3 else 0,
        # โดเมนปลายทางหลากหลาย = ลักษณะเมลโฆษณา (ฟิชชิ่งมักชี้ไปโดเมนเดียวที่คุมอยู่)
        "many_link_domains":  1 if ev.get("unique_link_domains", 0) >= 4 else 0,
        # มีสัญญาณปลอมตัวอย่างน้อยหนึ่งอย่าง (ใช้หักคะแนน Spam)
        "spoof_any":          1 if any(ev.get(k) for k in SPOOF_FLAGS.values()) else 0,
        "all_links_external": 1 if (ev.get("link_count", 0) > 0
                                    and ev.get("external_link_ratio", 0) >= 0.99) else 0,
    }


def classify_attack_type(evidence: dict, ai_score=None) -> dict:
    """คิดประเภทการโจมตีจากหลักฐาน — คืนคะแนนทุกประเภทพร้อมที่มาของคะแนน

    คืน:
      attack_type  ชื่อประเภท | "Normal" | "Unknown Threat"
      score        คะแนนของประเภทที่ชนะ
      scores       คะแนนทุกประเภท (ให้เห็นว่าอันดับสองห่างแค่ไหน)
      reasons      ["spoof_own_org(+45)", ...] เรียงจากมากไปน้อย
      confidence   สูง/กลาง/ต่ำ — จากระยะห่างของอันดับ 1 กับ 2
    """
    vals = dict(evidence or {})
    vals.update(_derived_flags(vals))

    scores, why = {}, {}
    for t, weights in ATTACK_TYPE_WEIGHTS.items():
        total, hits = 0, []
        for k, w in weights.items():
            if vals.get(k):
                total += w
                hits.append((abs(w), f"{k}({w:+d})"))
        total = max(total, 0)          # คะแนนติดลบไม่มีความหมาย ปัดเป็น 0
        scores[t] = total
        why[t] = [s for _, s in sorted(hits, reverse=True)]

    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    top, top_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else 0
    margin = top_score - second_score

    if top_score < ATTACK_TYPE_MIN_SCORE:
        # หลักฐานไม่พอ — ต้องแยกให้ชัดว่า "ไม่ใช่ภัย" กับ "เป็นภัยแต่บอกชนิดไม่ได้"
        # 🐛 ของเดิมยัดให้เป็น BEC/Phishing เสมอ เพราะ Stage 2 ไม่มีคลาส Normal
        #    -> เมลปกติที่มีลิงก์ถูกแปะป้าย BEC ทั้งที่ ai_score = 0.0 (PMG เจอ 2026-08-26)
        if ai_score is not None and float(ai_score) >= 50:
            return {"attack_type": "Unknown Threat", "score": int(top_score), "scores": scores,
                    "reasons": ["ai_score สูงแต่ไม่มีหลักฐานบอกชนิด"], "confidence": "ต่ำ"}
        return {"attack_type": "Normal", "score": int(top_score), "scores": scores,
                "reasons": [], "confidence": "สูง" if top_score == 0 else "กลาง"}

    # 🐛 2026-08-26: เดิมดูแค่ระยะห่างจากอันดับสอง -> เมลที่ได้ 30 คะแนนจากสัญญาณอ่อน
    #    (reply_to_mismatch + no_links) แต่ประเภทอื่นได้ 0 กลับรายงานว่า "มั่นใจสูง"
    #    ซึ่งเป็นความผิดแบบเดียวกับที่เราติ XGBoost คือมั่นใจบนหลักฐานที่ไม่มีน้ำหนัก
    #    -> ต้องผ่านทั้งสองเงื่อนไข: หลักฐานหนักพอ "และ" ทิ้งห่างอันดับสอง
    if top_score >= 60 and margin >= ATTACK_TYPE_MARGIN_HIGH:
        conf = "สูง"
    elif top_score >= 40 and margin >= ATTACK_TYPE_MARGIN_MED:
        conf = "กลาง"
    else:
        conf = "ต่ำ"
    return {"attack_type": top, "score": int(top_score), "scores": scores,
            "reasons": why[top], "confidence": conf}
