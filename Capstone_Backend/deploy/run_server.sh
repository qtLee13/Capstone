#!/usr/bin/env bash
# =============================================================================
# run_server.sh — สตาร์ท/รีสตาร์ท AI API (อยู่บนเครื่องเซิร์ฟเวอร์)
#
#   bash ~/ai_project/deploy/run_server.sh
#   BIND_HOST=0.0.0.0 bash ~/ai_project/deploy/run_server.sh   # ให้เครื่องอื่นเรียกได้
#
# 🐛 ทำไมต้องเป็น "ไฟล์" ห้ามเขียนรวมในบรรทัด ssh:
#    pkill -f จับจาก command line เต็ม -> ถ้าคำสั่ง pkill กับคำสั่งสตาร์ท uvicorn
#    อยู่บรรทัดเดียวกัน pkill จะเจอข้อความ "uvicorn main:app" ในบรรทัดของ "ตัวเอง"
#    แล้วฆ่า shell ตัวเองทิ้งก่อนได้สตาร์ท = uvicorn ดับ ไม่มีอะไรขึ้นมาแทน ไม่มีแม้แต่ log
#    (เจอ 2 รอบ: 2026-08-17 บน VM เดิม · 2026-08-24 บนเครื่องใหม่ — แก้ด้วย [m] ไม่พอ)
#    พออยู่คนละไฟล์ บรรทัด ssh มีแค่ "bash run_server.sh" ไม่มีคำว่า uvicorn เลย
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PORT="${PORT:-8000}"
# BIND_HOST: env > .env > 127.0.0.1
# อ่านจาก .env ด้วย เพื่อให้ restart ครั้งหน้า/หลัง update ยัง bind ที่เดิม ไม่ต้องจำใส่ทุกครั้ง
if [[ -z "${BIND_HOST:-}" && -f .env ]]; then
  BIND_HOST="$(grep -E '^BIND_HOST=' .env | head -1 | cut -d= -f2- | tr -d '
 	')"
fi
BIND_HOST="${BIND_HOST:-127.0.0.1}"

# ที่อยู่ที่ใช้ "เช็คสุขภาพ" ต้องตามที่ bind จริง
# 🐛 เดิม hardcode 127.0.0.1 -> พอ bind เป็น IP ของ LAN (ให้ PMG เรียกได้) health-check ยิงไม่ถึง
#    สคริปต์เลยรายงานว่าสตาร์ทไม่สำเร็จ ทั้งที่ API ทำงานปกติ (false alarm ที่จะทำให้ rollback มั่ว)
if [[ "$BIND_HOST" == "0.0.0.0" || "$BIND_HOST" == "::" ]]; then
  HEALTH_HOST="127.0.0.1"
else
  HEALTH_HOST="$BIND_HOST"
fi

pkill -f "uvicorn main:app" 2>/dev/null
sleep 2

# 🐛 2026-08-25: เดิมสตาร์ทด้วย "> uvicorn.log" = ทับทิ้งทุกครั้งที่ restart
#    วันนั้น PMG เจอ /analyze ตอบ 500 เวลา 15:25 UTC พอเรา restart 15:31 traceback หายเกลี้ยง
#    สืบสาเหตุไม่ได้เลย -> "การ restart เพื่อแก้ปัญหา ไปทำลายหลักฐานของปัญหานั้นเอง"
#    แก้: หมุนเก็บของเก่าไว้ 5 รอบ (uvicorn.log.1 = รอบก่อนหน้า) ก่อนเริ่มรอบใหม่
if [[ -s uvicorn.log ]]; then
  for i in 4 3 2 1; do
    [[ -f "uvicorn.log.$i" ]] && mv -f "uvicorn.log.$i" "uvicorn.log.$((i+1))"
  done
  mv -f uvicorn.log uvicorn.log.1
fi

# ใช้ >> (append) ไม่ใช่ > : เปิดแบบ append แล้วใครมา truncate ทีหลังก็ปลอดภัย
# (ถ้าเปิดด้วย > แล้วโดน truncate ระหว่างรัน fd ยังจำ offset เดิม -> ได้ไฟล์ sparse ใหญ่หลอก ๆ)
setsid nohup venv/bin/uvicorn main:app --host "$BIND_HOST" --port "$PORT" \
  >> uvicorn.log 2>&1 < /dev/null &
disown 2>/dev/null || true

sleep 3
if pgrep -f "uvicorn main:app" > /dev/null; then
  echo "  uvicorn เริ่มแล้ว (pid $(pgrep -f "uvicorn main:app" | head -1)) · bind $BIND_HOST:$PORT"
else
  echo "  ❌ uvicorn ไม่ขึ้น — 30 บรรทัดท้ายของ log:"
  tail -30 uvicorn.log
  exit 1
fi

# รอโมเดลโหลด (mBERT + XGBoost ใช้เวลาหลายวินาที) แล้วเช็คว่าตอบจริง
for i in $(seq 1 18); do
  if curl -sf --max-time 5 "http://$HEALTH_HOST:$PORT/health" >/dev/null 2>&1; then
    echo "  ✅ API ตอบแล้ว: $(curl -s http://$HEALTH_HOST:$PORT/health)"
    exit 0
  fi
  sleep 5
done
echo "  ❌ โหลดโมเดลไม่สำเร็จใน 90 วิ — 30 บรรทัดท้ายของ log:"
tail -30 uvicorn.log
exit 1
