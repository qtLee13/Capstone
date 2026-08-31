# docs/ — สารบัญ

> อัปเดต: 2026-08-09 · เอกสารที่ **ยัง active** อยู่ที่นี่ · เรื่องที่จบแล้วย้ายไป [`_archive/`](_archive/)

---

## 📤 ส่งให้ทีมอื่น (ค้างอยู่ รอเขาทำ)

| ไฟล์ | ถึงใคร | สรุป |
|---|---|---|
| [FOR_dashboard_team.md](FOR_dashboard_team.md) | **Dashboard** | 4 บั๊กต้องแก้ + ข้อมูล/endpoint ที่มีแล้วแต่ยังไม่แสดง (หน้าโมเดล, quarantine, feedback) |
| [FOR_storage_team.md](FOR_storage_team.md) | **Storage (.92)** | 1 บั๊ก (`Spear Phishing`) + ขอเก็บ `reasons` ลง DB + field ที่ตกหล่นใน `/assess` |
| [MIGRATION_to_new_ai_server.md](MIGRATION_to_new_ai_server.md) | **ทุกทีม** | 🔴 **AI ย้ายเครื่อง** — ต้องเปลี่ยน base URL + token · ขอความเห็นเรื่อง ZeroTier vs เปิด port |
| [FOR_storage_attack_evidence.md](FOR_storage_attack_evidence.md) | **Storage (.92)** | 🆕 `attack_evidence` 20 ตัวแปร + `attack_type_v2` พร้อมใช้ · แก้ 3 จุดในเอกสาร SCORING (`impersonates_recipient_org` 0% = วัดไม่ได้ ไม่ใช่แม่น 0%) |
| [REPLY_to_dashboard_2026-08-26.md](REPLY_to_dashboard_2026-08-26.md) | **Dashboard** | 🆕 ตอบ 4 คำถาม · AI ย้ายจาก .94 แล้ว · bind ไม่ใช่ 127.0.0.1 · feedback-label ใช้ได้ · retrain ยังไม่มี (404) |
| [REPLY2_to_storage_spoofing_threshold.md](REPLY2_to_storage_spoofing_threshold.md) | **Storage (.92)** | 🆕 **ฉบับล่าสุด** — เกณฑ์ 50 · แยก `brand_mismatch` 2 ระดับ · FP 0.029% · ⏳ รอ (ก) รายชื่อแบรนด์จาก quarantine (ข) โดเมนทั้งหมดของบริษัท |
| [REPLY_to_storage_sender_spoofing.md](REPLY_to_storage_sender_spoofing.md) | *(รอบแรก)* | `sender_spoofing` คำนวณจริงแล้ว (กฎ +4 เลิกเป็น dead code) · ตัวเลขของเกณฑ์ 45 |
| [NOTE_for_dashboard_data_contract.md](NOTE_for_dashboard_data_contract.md) | *(ฉบับเต็ม)* | บทวิเคราะห์รวมทั้ง 3 ฝั่ง — ใช้อ้างอิงเวลาสงสัยว่าข้อมูลมาจากไหน |

## 📖 เอกสารอ้างอิง (ใช้ประจำ)

| ไฟล์ | ใช้ตอนไหน |
|---|---|
| [INTEGRATION.md](INTEGRATION.md) | สเปก API ของ AI server — ให้ทีมอื่นเชื่อมต่อ |
| [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) | ภาพรวมโปรเจกต์ · ⚠️ ตัวเลขลงวันที่ 2026-07-15 (ก่อน P2) บางส่วนเก่าแล้ว |

## 🔧 Runbook (ยังไม่ได้ทำ)

| ไฟล์ | สถานะ |
|---|---|
| [ROTATE_token_runbook.md](ROTATE_token_runbook.md) | ⏸️ **รอเริ่ม Phase 1** — โค้ดรับ 2 token พร้อมแล้วบน VM · Gateway รอสัญญาณว่าจะหมุนเมื่อไหร่ |

> การ deploy ปกติใช้ [`../deploy_p2_to_vm.sh`](../deploy_p2_to_vm.sh) (มีตัวกัน `.env` ไม่มี `API_SECRET_KEY` ในตัว)

---

## 📦 [`_archive/`](_archive/) — เรื่องที่จบแล้ว (เก็บเป็นประวัติ/หลักฐาน)

ทั้งหมด **deploy ขึ้น production แล้ว** หรือ **อีกฝ่ายยืนยันว่าไม่ต้องทำอะไรต่อ** — ไม่มีงานค้าง

| ไฟล์ | เรื่อง |
|---|---|
| `REPLY_to_gateway_link_fp.md` | บั๊กเทียบ TLD แบบ substring (`us.click.yahoo.com` ได้ 70) + `link_confidence` ✅ |
| `REPLY_to_gateway_payload.md` | payload เป็น JSON ทำให้ทุกฉบับได้ ai≈100 + payload guard 400 ✅ |
| `REPLY_to_mailserver_parse.md` | `POST /parse` — ตัวแกะอีเมลตัวเดียวกับที่โมเดลใช้ ✅ |
| `REPLY_to_mailserver_dedup.md` | dedup ด้วย hash + Message-ID (กับดัก hash ชนของเมลไทย) ✅ |
| `NOTE_for_gateway_forward_message_id.md` | ขอ Gateway forward `message_id` → **เขายืนยันว่า forward ทั้งก้อนอยู่แล้ว ไม่ต้องแก้** ✅ |
| `NOTE_for_gateway_p2.md` | P2 — ตัด `dmarc_fail` ออกจาก feature ✅ |
| `NOTE_for_gateway.md` | เปลี่ยน contract: AI ตอบ `raw_signals` กลับ Gateway ตรงๆ ✅ |
| `NOTE_for_92*.md` (5 ไฟล์) | `abuseipdb_score` rename · `has_malware` · SPF/DKIM/DMARC จริงต่อฉบับ · `email_hash` · ลด FP |
| [`references/`](references/) | 📚 **เอกสารอ้างอิงสำหรับตอบอาจารย์** — สมการมาจากไหน อะไรมีอ้างอิง อะไรเป็นของเราเอง |
| `stage1_wrote_shortcut.json` | 🔴 **ต้นตอ FP ตัวจริง** — โมเดลใช้บรรทัด `X wrote:` เป็นสัญญาณว่าปลอดภัย · เติม 1 บรรทัดทำให้สแปมหลุด 43.5% |
| `REPLY2_model_info_ready.md` · `REPLY3_rollback_endpoints.md` · `REPLY_to_dashboard_retrain.md` | `/model/info`, `/model/history`, `/model/activate`, เรื่อง retrain ✅ |
| `REPLY_to_gateway_auth.md` | ใช้ผล SPF/DKIM/DMARC ที่ PMG ส่งมา ✅ |
| `DEPLOY_v3_mBERT.md` | runbook deploy mBERT v3 (P7) — deploy แล้ว · ⚠️ วิธี restart ในไฟล์นี้ใช้ `systemctl` ซึ่ง**ไม่ตรงกับของจริง** (VM รัน `uvicorn` ใน venv) ให้ใช้ `deploy_p2_to_vm.sh` แทน |

---

## สถานะระบบปัจจุบัน (2026-08-09)

| ส่วน | สถานะ |
|---|---|
| Stage 1 — mBERT `phishing_bert_model_v3` (EN+TH) | ✅ live |
| Stage 2 — XGBoost `xgb_20260722_171012` schema **v2** (5 features) | ✅ live |
| `/parse` · `email_hash` · `message_id` · payload guard · `link_confidence` | ✅ live |
| `sender_spoofing` + `spoofing_score` + `spoofing_reasons` | 🆕 เขียน+วัดผลแล้ว ⏳ **รอ deploy** |
| grace-mode รับ 2 token (เตรียมหมุน token) | ✅ live *(ยังไม่เริ่มหมุน)* |
| feedback loop (`/model/feedback-label`, `/model/feedback-stats`) | ✅ live · ⏸️ รอ Dashboard ทำปุ่ม (label 0/50) |
| ~~`/model/retrain`~~ | ❌ **ยกเลิกถาวร 2026-08-26** — Stage 2 แยกประเภทจาก `ai_score` เป็นหลัก เทรนซ้ำไม่ช่วย · ใช้ `attack_type_v2` แทน |
| สูตร Risk Score (`risk_score.py`) | ❌ **ลบแล้ว 2026-08-26** — ยกความเป็นเจ้าของให้ทีม .92 (`risk_config.py`) |
