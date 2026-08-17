#!/usr/bin/env bash
# =============================================================================
# deploy_to_vm.sh — deploy โค้ด AI server ขึ้น VM .94
#   รวม: P2 + link_risk + sender_ip + payload guard + ไฟล์แนบ 4 ชั้น + sender_spoofing
#
# รันจากเครื่อง Windows (Git Bash):  bash deploy_p2_to_vm.sh
#
# ⚠️ ต้องรันตอน VM เปิดอยู่และต่อเครือข่ายได้ (ZeroTier 10.22.1.94 หรือ host-only .101)
#    จะถาม password ของ ford หลายรอบ (ยังไม่ได้ตั้ง SSH key) — พิมพ์ตามปกติ
#
# ⚠️ ไม่ scp .env เด็ดขาด — ค่าแต่ละเครื่องไม่เหมือนกัน และเป็นความลับ
#
# ตัวกันที่ใส่ไว้:
#   1. ตรวจไฟล์ครบก่อนเริ่ม  2. เช็ค VM ต่อได้ก่อน  3. backup ไฟล์เดิมบน VM ก่อนทับ
#   4. *** ไม่ restart ถ้า .env บน VM ไม่มี API_SECRET_KEY *** (กัน 403 ทั้งระบบ)
#   5. เตือนถ้ายังไม่ตั้ง PROTECTED_DOMAINS (spoofing ทำงานได้ แต่กัน BEC ภายในไม่ครบ)
#   6. health-check /model/info + ทดสอบ sender_spoofing ของจริงหลัง restart
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
# PROTECTED_DOMAINS — ไม่บังคับ แต่ถ้าไม่มีจะกัน BEC ที่ปลอมเป็นคนในองค์กรได้ไม่ครบ
# (กันได้เฉพาะโดเมนที่บังเอิญโผล่ใน recipient ของแต่ละ request)
if ssh "$VM" "grep -qE '^PROTECTED_DOMAINS=.+' $DEST/.env" 2>/dev/null; then
  echo "  ✅ .env มี PROTECTED_DOMAINS"
else
  echo "  ⚠️  .env ยังไม่มี PROTECTED_DOMAINS — sender_spoofing ยังทำงาน แต่กัน BEC ภายในไม่ครบ"
  echo "     เพิ่มทีหลังได้:  ssh $VM  แล้วเติม  PROTECTED_DOMAINS=<โดเมนบริษัท,คั่นด้วย comma>"
fi

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
# ⚠️ route จริงคือ /model/info ไม่ใช่ /model/current (ของเดิมในสคริปต์นี้ผิด -> ได้ 404 ทุกครั้ง)
sleep 3
ssh "$VM" "curl -s http://127.0.0.1:8000/model/info || echo 'curl ล้ม — ดู log: tail -40 $DEST/uvicorn.log'"
echo ""

echo "===== 7) ทดสอบ sender_spoofing ของจริง ====="
# ยิงเมลปลอมเป็น PayPal (typosquat) — ต้องได้ sender_spoofing=true
# อ่าน token จาก .env บน VM · tr -d ตัด \r ออก (.env เป็น CRLF -> header เพี้ยน "Invalid HTTP request")
ssh "$VM" "cd $DEST && TOKEN=\$(grep '^API_SECRET_KEY=' .env | cut -d= -f2- | tr -d '\r\n') && \
  curl -s -X POST http://127.0.0.1:8000/parse \
    -H \"X-API-Key: \$TOKEN\" -H 'Content-Type: application/json' \
    -d '{\"text\":\"From: \\\"PayPal Service\\\" <service@paypa1.com>\r\nTo: staff@corp.co.th\r\nSubject: verify your account\r\nReceived: from x ([203.0.113.9])\r\n\r\nplease verify\r\n\",\"recipient\":\"staff@corp.co.th\"}' \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(\"  sender_spoofing =\", d.get(\"sender_spoofing\"), \"| score =\", d.get(\"spoofing_score\"), \"| reasons =\", d.get(\"spoofing_reasons\"))' \
  || echo '  ❌ ทดสอบไม่ผ่าน — ดู log: tail -40 $DEST/uvicorn.log'"

echo ""
echo "✅ เสร็จ — ต้องเห็น:"
echo "   • active_feature_schema = v2 · stage2_active = xgb_20260722_171012"
echo "   • sender_spoofing = True · score = 100 · reasons มี lookalike_domain:paypa1.com~paypal.com"
