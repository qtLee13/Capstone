#!/usr/bin/env bash
# =============================================================================
# deploy_p2_to_vm.sh — deploy การแก้ P2 + link_risk + sender_ip + payload guard
#                      + เอา secret ออก  ขึ้น VM .94 (AI Server)
#
# รันจากเครื่อง Windows (Git Bash):  bash deploy_p2_to_vm.sh
#
# ⚠️ ต้องรันตอน VM เปิดอยู่และต่อเครือข่ายได้ (ZeroTier 10.22.1.94 หรือ host-only .101)
#    จะถาม password ของ ford หลายรอบ (ยังไม่ได้ตั้ง SSH key) — พิมพ์ตามปกติ
#
# ตัวกันที่ใส่ไว้:
#   1. ตรวจไฟล์ครบก่อนเริ่ม  2. เช็ค VM ต่อได้ก่อน  3. backup ไฟล์เดิมบน VM ก่อนทับ
#   4. *** ไม่ restart ถ้า .env บน VM ไม่มี API_SECRET_KEY *** (กัน 403 ทั้งระบบ)
#   5. health-check /model/current หลัง restart
# =============================================================================
set -euo pipefail

# ---- ตั้งค่า -----------------------------------------------------------------
VM="${VM:-ford@192.168.56.101}"          # เปลี่ยนเป็น ford@10.22.1.94 ได้ถ้าใช้ ZeroTier
DEST="/home/ford/ai_project"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# ไฟล์ที่ต้อง deploy (ทั้งชุด v2 ต้องไปพร้อมกัน ไม่งั้น train/serving skew)
CODE=(main.py email_preprocess.py risk_score.py)
META=(model_registry.json model_metrics.json)
MODEL=(xgboost_type_classifier.json label_encoder.pkl)
STORE=(model_store/xgb_20260722_171012.json model_store/enc_20260722_171012.pkl)

echo "===== 0) ตรวจไฟล์ครบก่อนเริ่ม ====="
miss=0
for f in "${CODE[@]}" "${META[@]}" "${MODEL[@]}" "${STORE[@]}"; do
  if [[ -f "$f" ]]; then echo "  ✅ $f"; else echo "  ❌ ไม่พบ $f"; miss=1; fi
done
[[ $miss -eq 0 ]] || { echo "หยุด: ไฟล์ไม่ครบ"; exit 1; }

# กันเผลอ: ต้องไม่มี secret ค้างใน main.py
if grep -qE "cap_super_secret_key_2026|:123456@" main.py; then
  echo "❌ พบ secret hardcode ใน main.py — หยุด"; exit 1
fi
echo "  ✅ main.py ไม่มี secret hardcode"

echo "===== 1) เช็คว่า VM ต่อได้ ====="
if ! ssh -o ConnectTimeout=8 "$VM" 'echo ok' >/dev/null 2>&1; then
  echo "❌ ต่อ $VM ไม่ได้ — เปิด VM / ต่อ ZeroTier ก่อน แล้วรันใหม่"
  echo "   (ถ้าใช้ ZeroTier ให้รัน:  VM=ford@10.22.1.94 bash deploy_p2_to_vm.sh )"
  exit 1
fi
echo "  ✅ ต่อ $VM ได้"

echo "===== 2) backup ไฟล์เดิมบน VM ====="
TS=$(date +%Y%m%d_%H%M%S)
ssh "$VM" "cd $DEST && mkdir -p _backup_$TS && \
  for f in main.py email_preprocess.py risk_score.py model_registry.json model_metrics.json \
           xgboost_type_classifier.json label_encoder.pkl; do \
    [ -f \"\$f\" ] && cp -v \"\$f\" _backup_$TS/ ; done; \
  echo 'backup -> _backup_$TS'"

echo "===== 3) ส่งไฟล์ขึ้น VM ====="
scp "${CODE[@]}" "${META[@]}" "${MODEL[@]}" "$VM:$DEST/"
ssh "$VM" "mkdir -p $DEST/model_store"
scp "${STORE[@]}" "$VM:$DEST/model_store/"

echo "===== 4) เช็ค .env มี API_SECRET_KEY ก่อน restart ====="
if ssh "$VM" "grep -qE '^API_SECRET_KEY=.+' $DEST/.env"; then
  echo "  ✅ .env มี API_SECRET_KEY — restart ได้"
else
  echo "  ❌❌ .env บน VM ไม่มี API_SECRET_KEY (หรือค่าว่าง)"
  echo "     ไฟล์ถูกอัปแล้ว แต่ *ยังไม่ restart* เพราะจะทำให้ทุก request โดน 403"
  echo "     แก้: ssh $VM  แล้วเพิ่มบรรทัด  API_SECRET_KEY=<token>  ลงใน $DEST/.env"
  echo "     จากนั้นค่อย restart uvicorn เอง"
  exit 2
fi

echo "===== 5) restart uvicorn (venv, ไม่ใช่ systemd) ====="
# service รันด้วย: source venv/bin/activate; uvicorn main:app --host 0.0.0.0 --port 8000
# ปิดตัวเก่า แล้วเปิดใหม่แบบ background (subshell + nohup ให้ ssh หลุดออกได้)
ssh "$VM" "pkill -f 'uvicorn main:app' 2>/dev/null; sleep 1; \
  cd $DEST && source venv/bin/activate && \
  ( nohup uvicorn main:app --host 0.0.0.0 --port 8000 > uvicorn.log 2>&1 & ) && \
  sleep 3 && echo 'uvicorn เริ่มแล้ว (log: $DEST/uvicorn.log)'"

echo "===== 6) health-check ====="
sleep 3
ssh "$VM" "curl -s http://127.0.0.1:8000/model/current || echo 'curl ล้ม — ดู log: tail -40 $DEST/uvicorn.log'"
echo ""
echo "✅ เสร็จ — ตรวจว่า active_feature_schema เป็น v2 และ stage2_active = xgb_20260722_171012"
