#!/usr/bin/env bash
# =============================================================================
# update_ai_server.sh — อัปเดตโค้ดบนเครื่องเซิร์ฟเวอร์ หลังติดตั้งครั้งแรกแล้ว
#
#   USER=admin bash deploy/update_ai_server.sh              # แก้โค้ด
#   USER=admin MODEL=1 bash deploy/update_ai_server.sh      # ส่งไฟล์โมเดลใหม่ด้วย
#
# ขั้นตอนปกติ:  แก้โค้ด -> git push -> รันคำสั่งนี้ -> จบ
#
# 📁 โครงสร้างบนเครื่องปลายทาง (แยก 2 โฟลเดอร์โดยตั้งใจ):
#    ~/capstone_src  = git clone ของ repo ทั้งก้อน (ต้นทางโค้ด)
#    ~/ai_project    = ที่รันจริง (โมเดล, .env, venv, log, DB) + โค้ดที่ copy มาจาก src
#
#    ทำไมไม่ git pull ใน ~/ai_project ตรง ๆ: โค้ดเราอยู่ใน subdirectory Capstone_Backend/
#    ของ repo ถ้า reset --hard ในนั้น git จะกาง repo ทั้งก้อน (รวม capstone-dashboard/) ทับลงมา
# =============================================================================
set -euo pipefail

HOST="${HOST:-119.46.226.124}"
PORT_SSH="${PORT_SSH:-2223}"
USER="${USER:?ต้องระบุ username: USER=admin bash deploy/update_ai_server.sh}"
DEST="${DEST:-/home/$USER/ai_project}"
SRC="${SRC:-/home/$USER/capstone_src}"
BRANCH="${BRANCH:-hord}"
SUBDIR="${SUBDIR:-Capstone_Backend}"
MODEL="${MODEL:-0}"
# ไม่ตั้ง default ที่นี่ — ถ้าส่ง BIND_HOST ไปเสมอ มันจะทับค่าใน .env ของเซิร์ฟเวอร์
# (env ชนะ .env) ทำให้ตั้งค่าถาวรใน .env ไม่มีผล ต้องพิมพ์ใหม่ทุกครั้ง
# ส่งไปเฉพาะตอนผู้ใช้ระบุมาเองเท่านั้น เช่น BIND_HOST=0.0.0.0 bash deploy/update_ai_server.sh
BIND_PREFIX=""
[[ -n "${BIND_HOST:-}" ]] && BIND_PREFIX="BIND_HOST=$BIND_HOST "
SSH="ssh -p $PORT_SSH $USER@$HOST"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

# โค้ดที่ sync ไป runtime (เฉพาะที่จำเป็น — ไม่เอา simulator/test/ของเก่าไปรก)
CODE="main.py email_preprocess.py risk_score.py .env.example"

echo "===== 0) เตือนถ้ายังมีของยังไม่ push ====="
if [[ -n "$(git status --porcelain -- . 2>/dev/null | grep -vE '^\?\?' || true)" ]]; then
  echo "  ⚠️ มีไฟล์แก้แล้วแต่ยังไม่ commit/push — เครื่องปลายทางจะยังได้ของเก่า"
  git status --short -- . | grep -vE '^\?\?' | head -8
  read -rp "  ไปต่อไหม? (y/N) " a; [[ "$a" == "y" ]] || exit 1
fi

# บอก watchdog ว่ากำลัง deploy อยู่ อย่าเพิ่งปลุกแข่ง (ไฟล์นี้หมดอายุเองใน 10 นาที)
$SSH "touch $DEST/.deploying" 2>/dev/null || true
trap '$SSH "rm -f $DEST/.deploying" 2>/dev/null || true' EXIT

echo "===== 1) จำ commit ปัจจุบันไว้ (เผื่อย้อนกลับ) ====="
$SSH "cd $SRC 2>/dev/null && git rev-parse --short HEAD > ~/.last_good_commit 2>/dev/null || echo 'ยังไม่มี src'; \
      echo '  commit ก่อนอัปเดต:' \$(cat ~/.last_good_commit 2>/dev/null || echo '-')"

echo "===== 2) ดึงโค้ดใหม่ + sync เข้าที่รันจริง ====="
$SSH "set -e; \
  if [ -d $SRC/.git ]; then cd $SRC && git fetch -q origin $BRANCH && git reset -q --hard origin/$BRANCH; \
  else rm -rf $SRC && git clone -q -b $BRANCH https://github.com/qtLee13/Capstone.git $SRC; fi; \
  cd $SRC && echo '  อัปเดตเป็น:' \$(git log -1 --format='%h %s'); \
  cd $SRC/$SUBDIR && cp -f $CODE $DEST/ 2>/dev/null || true; \
  mkdir -p $DEST/deploy $DEST/docs && cp -rf deploy/. $DEST/deploy/ && cp -rf docs/. $DEST/docs/; \
  chmod +x $DEST/deploy/*.sh; \
  echo '  sync โค้ดเข้า $DEST แล้ว'"

if [[ "$MODEL" == "1" ]]; then
  echo "===== 3) ส่งไฟล์โมเดลใหม่ขึ้น ====="
  scp -P "$PORT_SSH" phishing_bert_model_v3/* "$USER@$HOST:$DEST/phishing_bert_model_v3/"
  scp -P "$PORT_SSH" xgboost_type_classifier.json label_encoder.pkl model_registry.json model_metrics.json \
      "$USER@$HOST:$DEST/"
  echo "  ส่งโมเดลเสร็จ"
else
  echo "===== 3) ข้ามการส่งโมเดล (ใส่ MODEL=1 ถ้าต้องการ) ====="
fi

echo "===== 4) restart + health-check ====="
# run_server.sh เช็ค /health ให้ในตัวแล้ว และ exit 1 ถ้าไม่ขึ้น
if $SSH "${BIND_PREFIX}bash $DEST/deploy/run_server.sh"; then
  echo ""
  echo "✅ อัปเดตสำเร็จ"
else
  echo ""
  echo "  ❌ API ไม่ตอบหลังอัปเดต — ย้อนกลับ commit เดิม"
  $SSH "set -e; cd $SRC && git reset -q --hard \$(cat ~/.last_good_commit) && \
        cd $SRC/$SUBDIR && cp -f $CODE $DEST/ 2>/dev/null || true; \
        ${BIND_PREFIX}bash $DEST/deploy/run_server.sh || tail -30 $DEST/uvicorn.log"
  echo "  ย้อนกลับแล้ว — ดู log ด้านบนว่าโค้ดใหม่พังเพราะอะไร"
  exit 1
fi
