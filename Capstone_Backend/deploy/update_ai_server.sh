#!/usr/bin/env bash
# =============================================================================
# update_ai_server.sh — อัปเดตโค้ดบนเครื่องพี่ หลังติดตั้งครั้งแรกไปแล้ว
#
#   USER=<username> bash deploy/update_ai_server.sh              # แก้โค้ด (git pull)
#   USER=<username> MODEL=1 bash deploy/update_ai_server.sh      # เปลี่ยนไฟล์โมเดลด้วย
#
# ขั้นตอนปกติ:  แก้โค้ดในเครื่อง -> git push -> รันคำสั่งนี้ -> จบ
# ไม่ต้อง scp ทีละไฟล์ ไม่ต้องพิมพ์ password (ใช้ SSH key ที่ตั้งไว้ตอน setup)
# =============================================================================
set -euo pipefail

HOST="${HOST:-119.46.226.124}"
PORT="${PORT:-2223}"
USER="${USER:?ต้องระบุ username: USER=xxx bash deploy/update_ai_server.sh}"
DEST="${DEST:-/home/$USER/ai_project}"
BRANCH="${BRANCH:-hord}"
MODEL="${MODEL:-0}"
SSH="ssh -p $PORT $USER@$HOST"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

echo "===== 0) เตือนถ้ายังมีของยังไม่ push ====="
if [[ -n "$(git status --porcelain -- . 2>/dev/null | grep -vE '^\?\?' || true)" ]]; then
  echo "  ⚠️ มีไฟล์แก้แล้วแต่ยังไม่ commit/push — เครื่องปลายทางจะยังได้ของเก่า"
  git status --short -- . | grep -vE '^\?\?' | head -8
  read -rp "  จะไปต่อไหม? (y/N) " a; [[ "$a" == "y" ]] || exit 1
fi

echo "===== 1) สำรองของเดิมไว้ก่อน (เผื่อต้องย้อนกลับ) ====="
$SSH "cd $DEST && git rev-parse --short HEAD > .last_good_commit 2>/dev/null || true; \
      echo '  commit ก่อนอัปเดต:' \$(cat .last_good_commit 2>/dev/null || echo 'ไม่ทราบ')"

echo "===== 2) ดึงโค้ดใหม่จาก git ====="
$SSH "cd $DEST && git fetch origin $BRANCH && git reset --hard origin/$BRANCH && \
      echo '  อัปเดตเป็น:' \$(git log -1 --format='%h %s')"

if [[ "$MODEL" == "1" ]]; then
  echo "===== 3) ส่งไฟล์โมเดลใหม่ขึ้น ====="
  scp -P "$PORT" phishing_bert_model_v3/* "$USER@$HOST:$DEST/phishing_bert_model_v3/"
  scp -P "$PORT" xgboost_type_classifier.json label_encoder.pkl model_registry.json model_metrics.json \
      "$USER@$HOST:$DEST/"
  echo "  ส่งโมเดลเสร็จ"
else
  echo "===== 3) ข้ามการส่งโมเดล (ใส่ MODEL=1 ถ้าต้องการ) ====="
fi

echo "===== 4) restart ====="
if $SSH "sudo -n systemctl is-enabled ai-model >/dev/null 2>&1"; then
  $SSH "sudo systemctl restart ai-model && sleep 8 && sudo systemctl is-active ai-model"
else
  $SSH "cd $DEST && { pkill -f 'uvicorn [m]ain:app' || true; }; sleep 1; source venv/bin/activate && \
        setsid nohup uvicorn main:app --host 127.0.0.1 --port 8000 > uvicorn.log 2>&1 </dev/null & \
        sleep 8; pgrep -f 'uvicorn [m]ain:app' >/dev/null && echo '  ขึ้นแล้ว' || tail -30 uvicorn.log"
fi

echo "===== 5) health-check + ย้อนกลับอัตโนมัติถ้าพัง ====="
if $SSH "for i in \$(seq 1 12); do curl -sf --max-time 5 http://127.0.0.1:8000/model/info >/dev/null && exit 0; sleep 5; done; exit 1"; then
  echo "  ✅ API ตอบปกติ — อัปเดตสำเร็จ"
  $SSH "cd $DEST && curl -s http://127.0.0.1:8000/model/info | head -c 300; echo"
else
  echo "  ❌ API ไม่ตอบหลังอัปเดต — กำลังย้อนกลับ commit เดิม"
  $SSH "cd $DEST && git reset --hard \$(cat .last_good_commit) && \
        { sudo systemctl restart ai-model 2>/dev/null || { pkill -f 'uvicorn [m]ain:app' || true; sleep 1; \
          source venv/bin/activate; setsid nohup uvicorn main:app --host 127.0.0.1 --port 8000 \
          > uvicorn.log 2>&1 </dev/null & }; }; sleep 8; echo '  ย้อนกลับแล้ว'; tail -30 uvicorn.log"
  exit 1
fi
