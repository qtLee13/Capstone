#!/usr/bin/env bash
# =============================================================================
# deploy_p2_to_vm.sh — deploy โค้ดฝั่ง AI ขึ้น VM .94 (AI Server)
#   รอบ 2026-08-17: sender_spoofing (main.py + email_preprocess.py)
#   รอบก่อน: P2 + link_risk + sender_ip + payload guard + เอา secret ออก
#
# ⚠️ ไม่ส่ง .env ขึ้นไปเด็ดขาด — ค่าแต่ละเครื่องไม่เหมือนกัน ต้องแก้บน VM เอง
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
if grep -qE "cap_super_secret|:123456@" main.py; then
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
# 🐛 บั๊กที่เจอ 2026-08-17: เดิมใช้ pkill -f 'uvicorn main:app' ตรง ๆ
#    -> command line ของ ssh shell ตัวนี้เองก็มีข้อความ "uvicorn main:app" อยู่
#       pkill เลย "ฆ่า shell ตัวเอง" ก่อนได้สั่งเปิดตัวใหม่ = uvicorn ดับ ไม่มีอะไรขึ้นมาแทน
#       แถม ssh ตายกลางคัน -> exit code != 0 -> set -e ทำให้สคริปต์จบเงียบ ๆ ที่ขั้นนี้
#    แก้: เขียน pattern เป็น 'uvicorn [m]ain:app' — regex ยังตรงกับ process จริง
#         แต่ "ไม่ตรงกับบรรทัดคำสั่งของตัวเอง" (ที่มีวงเล็บอยู่) · + || true กัน set -e
#    setsid + </dev/null ให้ uvicorn หลุดจาก session ของ ssh จริง ๆ (ไม่โดน SIGHUP ตอน ssh ปิด)
ssh "$VM" "cd $DEST && { pkill -f 'uvicorn [m]ain:app' 2>/dev/null || true; }; sleep 1; \
  source venv/bin/activate && \
  setsid nohup uvicorn main:app --host 0.0.0.0 --port 8000 > uvicorn.log 2>&1 < /dev/null & \
  sleep 5; \
  pgrep -f 'uvicorn [m]ain:app' >/dev/null && echo 'uvicorn เริ่มแล้ว (log: $DEST/uvicorn.log)' \
    || { echo '❌ uvicorn ไม่ขึ้น — 40 บรรทัดท้ายของ log:'; tail -40 $DEST/uvicorn.log; exit 1; }"

echo "===== 6) health-check ====="
# โมเดล (mBERT + XGBoost) ใช้เวลาโหลดหลายวินาที — ต้องวนรอ ไม่ใช่ยิงครั้งเดียวแล้วสรุปว่าล้ม
ssh "$VM" "for i in \$(seq 1 12); do \
    out=\$(curl -s --max-time 5 http://127.0.0.1:8000/model/info 2>/dev/null); \
    if [ -n \"\$out\" ]; then echo \"\$out\" | head -c 400; echo; echo '  ✅ API ตอบแล้ว'; exit 0; fi; \
    echo \"  ...รอโมเดลโหลด (\$i/12)\"; sleep 5; \
  done; \
  echo '❌ API ไม่ตอบใน 60 วิ — 40 บรรทัดท้ายของ log:'; tail -40 $DEST/uvicorn.log; exit 1"
echo ""

echo "===== 7) เช็ค sender_spoofing ทำงานจริง ====="
# ส่ง payload เป็น "ไฟล์" แล้วใช้ -d @file — เลี่ยงการ escape ซ้อนหลายชั้น
# (PowerShell -> bash -> ssh -> bash -> curl) ซึ่งพังง่ายมากถ้าใส่ JSON ตรง ๆ ในบรรทัดคำสั่ง
scp -q docs/sample_spoof_test.json "$VM:/tmp/spoof_test.json"
# tr -d '\r' เพราะ .env บน VM เป็น CRLF — ไม่ตัดแล้ว token จะมี \r ทำให้ header พัง
ssh "$VM" "cd $DEST && TOKEN=\$(grep '^API_SECRET_KEY=' .env | cut -d= -f2- | tr -d '\r\n') && \
  curl -s -X POST http://127.0.0.1:8000/parse \
    -H \"X-Security-Token: \$TOKEN\" -H 'Content-Type: application/json' \
    -d @/tmp/spoof_test.json \
  | python3 -c \"
import sys, json
d = json.load(sys.stdin)
print('  sender_display_name =', d.get('sender_display_name'))
print('  sender_spoofing     =', d.get('sender_spoofing'))
print('  spoofing_score      =', d.get('spoofing_score'))
print('  spoofing_reasons    =', d.get('spoofing_reasons'))
print()
print('  ✅ ผ่าน — sender_spoofing ทำงานบน VM แล้ว' if d.get('sender_spoofing') is True
      else '  ❌ ไม่ผ่าน — ยังรันโค้ดเก่าอยู่ หรือ /parse ไม่ได้อัปเดต')
\""

echo ""
echo "===== 8) เตือนเรื่อง PROTECTED_DOMAINS ====="
if ssh "$VM" "grep -qE '^PROTECTED_DOMAINS=.+' $DEST/.env"; then
  echo "  ✅ .env มี PROTECTED_DOMAINS แล้ว (กัน BEC ปลอมเป็นคนในองค์กร)"
else
  echo "  ⚠️  .env ยังไม่มี PROTECTED_DOMAINS — ระบบยังทำงานได้ แต่กัน BEC ภายในได้ไม่เต็มที่"
  echo "     เพิ่มบน VM (อย่า scp .env ขึ้นไป):"
  echo "       ssh $VM \"echo 'PROTECTED_DOMAINS=<โดเมนบริษัท,คั่นด้วยจุลภาค>' >> $DEST/.env\""
  echo "     แล้ว restart uvicorn อีกรอบ"
fi

echo ""
echo "✅ เสร็จ — ตรวจว่า active_feature_schema เป็น v2 และ stage2_active = xgb_20260722_171012"
