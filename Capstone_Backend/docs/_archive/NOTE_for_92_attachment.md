# [ต้องแก้เล็กน้อย] ใช้ `has_malware` จาก raw_signals ตรงๆ อย่าคำนวณนามสกุลไฟล์เอง

**ถึง:** เจ้าของเครื่อง Storage/Risk Server (.92)
**จาก:** AI Server (10.22.1.94)
**สรุป:** AI server แก้รายการนามสกุลไฟล์แนบเสี่ยงจาก 4 → **14 นามสกุล** (ให้ตรงกับตอน train) และ
ตอนนี้ **ส่ง `has_malware` (คำนวณเสร็จแล้ว) มาใน `raw_signals`** → `.92` ให้ใช้ค่านี้ตรงๆ ตอนทำ block-override

---

## ทำไมต้องแก้
เดิม `compute_final_score` มีกฎ `if raw_link_score == 100 or has_malware: final_score = 100`
ถ้า `.92` คำนวณ `has_malware` เองจาก `attachment_type` ด้วยรายการนามสกุล **คนละชุด** กับ AI server
→ มัลแวร์ที่แนบไฟล์ `.docm / .js / .iso / .lnk / .rar / .7z ...` จะ **ไม่ถูกบล็อก** (train/serving skew)

## สิ่งที่เปลี่ยนฝั่ง AI server (ทำแล้ว)
- `risk_score.RISKY_EXT` = 14 นามสกุล: `.zip .exe .scr .js .vbs .doc .docm .xls .xlsm .rar .7z .iso .lnk .bat`
- `raw_signals` เพิ่ม key ใหม่: **`"has_malware": true/false`**

## สิ่งที่ `.92` ต้องทำ
```python
# เดิม (ถ้ามี): คำนวณ has_malware เองจาก attachment_type -> ลบทิ้ง
# ใหม่: อ่านจาก payload ตรงๆ
has_malware = raw_signals.get("has_malware", False)
final = compute_final_score(..., has_malware=has_malware)
```
> ถ้า `.92` ไม่เคยคำนวณ has_malware เอง (รับจาก payload อยู่แล้ว) — key แค่เปลี่ยนมามีค่าที่ครบ 14 นามสกุล ไม่ต้องแก้อะไรเพิ่ม

## ไม่ต้องแก้
- ตรรกะ `compute_final_score` อื่นๆ (ดู `NOTE_for_92_scoring.md`) — เท่าเดิม
- payload key อื่น — เท่าเดิม (แค่ **เพิ่ม** `has_malware`)
