#!/usr/bin/env bash
# =============================================================================
# setup_ai_server.sh — ติดตั้ง AI server ครั้งแรกบนเครื่องของพี่ (119.46.226.124:2223)
#
# รันจากเครื่องเราด้วย Git Bash:
#   USER=<username> bash deploy/setup_ai_server.sh
#
# ทำครั้งเดียวพอ · หลังจากนี้อัปเดตด้วย deploy/update_ai_server.sh (git pull + restart)
#
# ⚠️ เครื่องนี้อยู่บน internet ไม่ใช่ ZeroTier — ตัวกันที่ใส่ไว้:
#     - ไม่ส่ง .env ขึ้นไป (สร้างบนเครื่องนั้นเอง)
#     - ไม่ส่ง datasets/ ขึ้นไป (มีอีเมลจริงของบริษัท)
#     - ปิด port 8000 ไม่ให้ทั้ง internet เข้า (เปิดเฉพาะ IP ของ PMG)
# =============================================================================
set -euo pipefail

HOST="${HOST:-119.46.226.124}"
PORT="${PORT:-2223}"
USER="${USER:?ต้องระบุ username: USER=xxx bash deploy/setup_ai_server.sh}"
DEST="${DEST:-/home/$USER/ai_project}"
REPO="${REPO:-https://github.com/qtLee13/Capstone.git}"
BRANCH="${BRANCH:-hord}"
SSH="ssh -p $PORT $USER@$HOST"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

echo "===== 0) ตรวจไฟล์โมเดลครบก่อน (ไฟล์ใหญ่ ไม่ได้อยู่ใน git) ====="
MODEL_FILES=(phishing_bert_model_v3/config.json phishing_bert_model_v3/model.safetensors
             phishing_bert_model_v3/tokenizer.json phishing_bert_model_v3/tokenizer_config.json
             xgboost_type_classifier.json label_encoder.pkl
             model_registry.json model_metrics.json)
for f in "${MODEL_FILES[@]}"; do
  [[ -f "$f" ]] && echo "  ✅ $f" || { echo "  ❌ ไม่พบ $f"; exit 1; }
done

echo "===== 1) ตั้ง SSH key (จะได้ไม่ต้องพิมพ์ password ทุกครั้ง) ====="
if [[ ! -f ~/.ssh/id_ed25519.pub ]]; then
  ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
  echo "  สร้าง key ใหม่แล้ว"
fi
if $SSH -o BatchMode=yes -o ConnectTimeout=8 'echo ok' >/dev/null 2>&1; then
  echo "  ✅ key ใช้ได้อยู่แล้ว ไม่ต้องพิมพ์ password"
else
  echo "  กำลังส่ง public key ขึ้นเครื่อง — จะถาม password ครั้งสุดท้าย"
  ssh-copy-id -p "$PORT" "$USER@$HOST"
fi

echo "===== 2) เช็คเครื่องปลายทาง ====="
$SSH "echo '  OS      :' \$(lsb_release -ds 2>/dev/null || cat /etc/os-release | head -1); \
       echo '  CPU     :' \$(nproc) core; \
       echo '  RAM     :' \$(free -g | awk '/^Mem:/{print \$2}') GB; \
       echo '  Disk ว่าง:' \$(df -h / | awk 'NR==2{print \$4}'); \
       echo '  Python  :' \$(python3 --version)"

echo "===== 3) clone โค้ดจาก git ====="
$SSH "if [ -d $DEST/.git ]; then cd $DEST && git fetch origin $BRANCH && git checkout $BRANCH && git pull --ff-only; \
      else git clone -b $BRANCH $REPO /tmp/_capstone && mkdir -p $DEST && \
           cp -r /tmp/_capstone/Capstone_Backend/. $DEST/ && rm -rf /tmp/_capstone && \
           cd $DEST && git init -q && git remote add origin $REPO 2>/dev/null || true; fi; \
      echo '  โค้ดพร้อมที่ $DEST'"

echo "===== 4) venv + torch เวอร์ชัน CPU (สำคัญ: เล็กกว่า CUDA build 4 GB) ====="
$SSH "cd $DEST && python3 -m venv venv 2>/dev/null; source venv/bin/activate && \
      pip install -q --upgrade pip && \
      pip install -q torch --index-url https://download.pytorch.org/whl/cpu && \
      pip install -q transformers fastapi uvicorn python-dotenv sqlalchemy slowapi \
                     xgboost scikit-learn joblib requests checkdmarc dnspython && \
      echo '  ติดตั้ง dependency เสร็จ' && \
      python -c 'import torch; print(\"  torch\", torch.__version__, \"| CUDA build:\", torch.version.cuda)'"

echo "===== 5) ส่งไฟล์โมเดลขึ้น (ไม่ได้อยู่ใน git เพราะใหญ่ 682 MB) ====="
$SSH "mkdir -p $DEST/phishing_bert_model_v3 $DEST/model_store $DEST/logs"
scp -P "$PORT" phishing_bert_model_v3/* "$USER@$HOST:$DEST/phishing_bert_model_v3/"
scp -P "$PORT" xgboost_type_classifier.json label_encoder.pkl model_registry.json model_metrics.json \
    "$USER@$HOST:$DEST/"
[[ -d model_store ]] && scp -P "$PORT" model_store/* "$USER@$HOST:$DEST/model_store/" || true

echo "===== 6) .env — สร้างบนเครื่องนั้นเอง (ไม่ส่งขึ้นไปเด็ดขาด) ====="
if $SSH "[ -f $DEST/.env ]"; then
  echo "  ✅ มี .env อยู่แล้ว ไม่แตะ"
else
  $SSH "cd $DEST && cp .env.example .env && \
        NEWTOK=\$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))') && \
        sed -i \"s|^API_SECRET_KEY=.*|API_SECRET_KEY=\$NEWTOK|\" .env && \
        chmod 600 .env && \
        echo '  สร้าง .env พร้อม token ใหม่แล้ว (chmod 600)'"
  echo ""
  echo "  🔑 token ใหม่ของเครื่องนี้ — เอาไปแจกทีมอื่นแบบส่วนตัว (อย่าใส่ใน git/แชท):"
  $SSH "grep '^API_SECRET_KEY=' $DEST/.env"
  echo ""
fi

echo "===== 6.5) ZeroTier — ให้เครื่องนี้เข้าวงเดียวกับ Gateway/.92/Dashboard ====="
# ทำไมต้องมี: ย้าย AI มาเครื่องนี้แล้ว Gateway(.66)/.92/Dashboard(.181) ยังอยู่บน ZeroTier
#   ถ้าไม่ลง ZeroTier -> ต้องเปิด port 8000 ออก internet ให้เขายิงเข้ามา = เสี่ยงกว่ามาก
#   ลง ZeroTier แล้ว -> เครื่องนี้ได้ IP 10.22.1.x เหมือนเดิม ทุกทีมแค่เปลี่ยนเลข IP อย่างเดียว
if [[ -n "${ZT_NETWORK:-}" ]]; then
  $SSH "command -v zerotier-cli >/dev/null 2>&1 || (curl -s https://install.zerotier.com | sudo bash);         sudo zerotier-cli join $ZT_NETWORK && sleep 10 &&         echo '  ขอเข้าวงแล้ว — ต้องไป authorize เครื่องนี้ที่หน้า ZeroTier Central ก่อน' &&         sudo zerotier-cli listnetworks | tail -2"
  echo "  หลัง authorize แล้ว เช็ค IP ด้วย: ssh -p $PORT $USER@$HOST 'sudo zerotier-cli listnetworks'"
else
  echo "  ข้าม (ไม่ได้ระบุ ZT_NETWORK) — ถ้าจะให้เข้าวง ZeroTier ให้รันใหม่แบบ:"
  echo "    ZT_NETWORK=<network id> USER=$USER bash deploy/setup_ai_server.sh"
fi

echo "===== 7) systemd service (รีบูตแล้วขึ้นเอง · restart คำสั่งเดียว) ====="
if $SSH "sudo -n true 2>/dev/null"; then
  $SSH "sudo tee /etc/systemd/system/ai-model.service >/dev/null <<UNIT
[Unit]
Description=Capstone AI Model API
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$DEST
EnvironmentFile=$DEST/.env
ExecStart=$DEST/venv/bin/uvicorn main:app --host ${BIND_HOST:-127.0.0.1} --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  sudo systemctl daemon-reload && sudo systemctl enable --now ai-model && sleep 8 && \
  sudo systemctl is-active ai-model && echo '  ✅ service ทำงานแล้ว'"
  echo "  หมายเหตุ: bind 127.0.0.1 (ไม่ใช่ 0.0.0.0) = คนนอกยิงตรงไม่ได้"
else
  echo "  ⚠️ ไม่มีสิทธิ์ sudo — ใช้วิธี nohup แทน (รีบูตแล้วต้องสั่งเองใหม่)"
  $SSH "cd $DEST && { pkill -f 'uvicorn [m]ain:app' || true; }; sleep 1; source venv/bin/activate && \
        setsid nohup uvicorn main:app --host 127.0.0.1 --port 8000 > uvicorn.log 2>&1 </dev/null & \
        sleep 8; pgrep -f 'uvicorn [m]ain:app' >/dev/null && echo '  ✅ uvicorn ขึ้นแล้ว' || tail -30 uvicorn.log"
fi

echo "===== 8) health-check ====="
$SSH "for i in \$(seq 1 12); do o=\$(curl -s --max-time 5 http://127.0.0.1:8000/model/info); \
      [ -n \"\$o\" ] && { echo \"\$o\" | head -c 300; echo; echo '  ✅ API ตอบแล้ว'; exit 0; }; \
      echo \"  ...รอโมเดลโหลด (\$i/12)\"; sleep 5; done; echo '  ❌ ไม่ตอบ'; exit 1"

cat <<'NEXT'

=============================================================
✅ ติดตั้งเสร็จ — เหลือ 2 อย่างที่ต้องตัดสินใจเอง
=============================================================
1) เปิดให้ PMG ยิงเข้ามา (ตอนนี้ bind 127.0.0.1 = ยิงจากข้างนอกไม่ได้เลย)
   เลือกทางใดทางหนึ่ง:
   (ก) PMG อยู่เครื่องเดียวกัน  -> ไม่ต้องทำอะไร เรียก 127.0.0.1:8000 ได้เลย
   (ข) PMG อยู่คนละเครื่อง      -> เปิดเฉพาะ IP ของ PMG เท่านั้น:
        sudo ufw allow from <IP ของ PMG> to any port 8000 proto tcp
        แล้วแก้ ExecStart เป็น --host 0.0.0.0 + systemctl restart ai-model
   ❌ อย่าเปิด 8000 ให้ 0.0.0.0/0 เด็ดขาด

2) แจก token ใหม่ให้ Gateway / Storage(.92) / Dashboard แบบส่วนตัว

จากนี้ไปอัปเดตด้วย:  USER=<username> bash deploy/update_ai_server.sh
NEXT
