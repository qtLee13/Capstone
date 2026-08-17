# ตอบทีม mail server (.92) — `/parse` ทำเสร็จแล้ว + เรื่องหา IP ต้นตอ

**จาก:** ทีม AI Server (.94) · **วันที่:** 2026-07-25 · **สถานะ:** ✅ `/parse` deploy ขึ้น production แล้ว (2026-08-04)

---

## 1. ✅ `POST /parse` — ทำเสร็จแล้ว

ใช้ **ตัวแกะอีเมลตัวเดียวกับที่โมเดลใช้ตอนเทรนเป๊ะ** (`parse_raw_email` + `parse_authentication_results`)
รับประกันไม่มี train/serving skew · เป็นการแกะล้วนๆ **ไม่เรียก BERT / ไม่ยิง external API** → เร็ว + deterministic + ไม่กิน quota

### Request
```
POST /parse
X-Security-Token: <token เดียวกับ /analyze>
Content-Type: application/json

{ "text": "<raw .eml ทั้งฉบับ เป็น string>" }
```

### Response (200)
```jsonc
{
  "sender":            "security-alert@evil-bank.xyz",
  "sender_domain":     "evil-bank.xyz",
  "subject":           "URGENT: Verify your account now!",
  "reply_to":          "attacker@gmail.com",
  "body":              "<plain text ที่ strip แล้ว — เลือก text/plain ก่อน, ไม่มีค่อย strip HTML>",
  "attachments":       ["invoice.pdf.exe"],
  "attachment_risk":   true,          // มีไฟล์แนบชนิดเสี่ยงไหม (ตรรกะเดียวกับ /analyze)
  "reply_to_mismatch": true,          // โดเมน From != Reply-To
  "sender_ip_header":  "45.83.12.9",  // IP จาก Received header (ปลอมได้) — ไม่ใช่ connection-level
  "spf":  "fail",                     // อ่านจาก Authentication-Results header (ไม่ verify ซ้ำ)
  "dkim": "none",
  "dmarc": "fail",
  "payload_warning":   null,          // มีข้อความเตือนถ้า text ไม่เหมือน .eml (แต่ยังแกะให้)
  "parser_version":    "v3-mbert-aligned"
}
```

### ⚠️ จุดที่ต้องรู้
- **`sender_ip_header` เชื่อถือไม่ได้เท่า connection-level IP** — ถ้าฝั่ง PMG มี IP ระดับ connection ให้ยึดตัวนั้น (เหมือนที่ `/analyze` ยึด `sender_ip` ที่ PMG ส่ง)
- **`spf/dkim/dmarc` = ค่าที่ gateway ใส่ไว้ใน header** เราแค่รายงานต่อ ไม่ได้ verify เอง (ถ้าไม่มี header จะได้ `"none"`)
- **payload guard ตัวเดียวกับ `/analyze`**: ถ้าเผลอยิง JSON ทั้งก้อน (เคสบั๊กเดิม) `/parse` จะตอบ **400 `invalid_email_payload`** เหมือนกัน ไม่แกะ JSON ให้เงียบๆ

### เทสแล้ว
```
.eml จริง          -> แกะครบทุก field ถูกต้อง ✅
JSON mailbox ก้อน  -> 400 invalid_email_payload ✅ (ไม่เกิด ai≈100 อีก)
```

> ✅ **อัปเดต 2026-08-04: deploy ขึ้น production แล้ว** พร้อมชุด P2 (link_risk/sender_ip/payload guard) — เทสบน VM ผ่านทุกเคส

---

## 2. 🔍 เรื่องหา IP ต้นตอ — เอาด้วยครับ แต่ติดตรงนี้

เห็นด้วยกับวิธี cross-check: **ฝั่งคุณดู access log `/mailbox` ว่า IP ไหนเรียก · ฝั่งเราดู `/analyze` ว่า source IP มาจากไหน** เอามาจับคู่กันจะเจอเครื่องต้นตอเร็ว

**อัปเดต 2026-08-04:** VM กลับมาแล้ว แต่ **log เก่าตอนเกิดเหตุหายไปแล้ว** (ตอนนั้นรัน uvicorn แบบไม่เขียนลงไฟล์) → ดึงย้อนหลังไม่ได้ · ตอนนี้ตั้ง `tee -a uvicorn.log` ไว้แล้ว ถ้า re-ingest เกิดซ้ำจะจับได้ทันทีด้วย:
```bash
# source IP ที่ยิงเข้า /analyze (จาก log [INCOMING] ที่เราใส่ไว้)
sudo journalctl -u ai_project --since "yesterday" | grep INCOMING
# หรือถ้าดูดิบๆ:
sudo journalctl -u ai_project | grep -E "รับอีเมลจาก|INCOMING" | awk '{print $NF}' | sort | uniq -c
```
แล้วส่ง IP ที่เจอไปให้คุณจับคู่กับ log `/mailbox` ทันที

**เดาไว้ก่อน (ตรงกับที่คุณว่า):** น่าจะเป็นสคริปต์เทส/PMG ตัวที่ยิง swaks ชุดเดียวกัน ที่อ่านเมลกลับจาก mailbox แล้ว re-ingest → ถ้าใช่ ตัวแก้คือ **หยุด re-ingest เมลที่ประมวลผลแล้ว** (ตามที่คุยกันในโน้ต payload ข้อ 3)

---

## 3. ตอบคำถามปิดท้าย

> *"อยากให้ช่วยหา IP ต้นตอต่อ หรือไปต่อเรื่อง gateway?"*

**ทำคู่กันได้ครับ** — แต่ทั้งสองอย่างต้องรอ VM .94 ออนไลน์ก่อน (deploy P2 + `/parse` + ดึง log):

| งาน | ใคร | สถานะ |
|---|---|---|
| `POST /parse` | AI (.94) | ✅ deploy แล้ว (2026-08-04) |
| ดึง source IP จาก `/analyze` log | AI (.94) | ❌ log เก่าหาย — ดักรอบใหม่แทน |
| จับคู่กับ `/mailbox` access log | mail server (.92) | รอ IP จากเรา |
| หยุด re-ingest เมลที่ประมวลผลแล้ว | ทีมที่เป็นต้นตอ (ยังหาอยู่) | ⏳ |
| block/quarantine ด่านแรก (gateway) | Gateway | ค้างอยู่ ไปต่อได้ |

ขอบคุณที่ตัดฝั่ง .92 ออกให้ชัด (ไม่มี re-scan/cron/สคริปต์เทส) — ช่วยให้วงแคบลงเยอะ เหลือแค่หา "ตัวที่เรียก /mailbox จากระยะไกลแล้วส่งต่อเข้า /analyze" 🙏
