#!/usr/bin/env bash
# =============================================================================
# watchdog.sh — เช็คว่า AI API ยังตอบอยู่ไหม ถ้าไม่ตอบให้ปลุกใหม่
#
# ใช้แทน systemd ชั่วคราวในเครื่องที่ "ไม่มีสิทธิ์ sudo"
# ติดตั้ง:  bash deploy/install_watchdog.sh   (ลง cron ให้เอง)
#
# ครอบ 2 กรณีที่ systemd เคยทำให้:
#   1. process ตายเอง (OOM / exception) -> cron ทุก 5 นาที ปลุกให้
#   2. เครื่องรีบูต                      -> cron @reboot สตาร์ทให้
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
PROJ="$PWD"

PORT="${PORT:-8000}"
if [[ -f .env ]]; then
  BIND_HOST="$(grep -E '^BIND_HOST=' .env | head -1 | cut -d= -f2- | tr -d '\r\n \t')"
fi
BIND_HOST="${BIND_HOST:-127.0.0.1}"
if [[ "$BIND_HOST" == "0.0.0.0" || "$BIND_HOST" == "::" ]]; then
  HEALTH_HOST="127.0.0.1"
else
  HEALTH_HOST="$BIND_HOST"
fi

LOG="$PROJ/logs/watchdog.log"
mkdir -p "$PROJ/logs"
# กัน log โตไม่จำกัด — เกิน 1 MB ตัดให้เหลือ 200 บรรทัดท้าย
if [[ -f "$LOG" ]] && [[ "$(stat -c %s "$LOG" 2>/dev/null || echo 0)" -gt 1048576 ]]; then
  tail -200 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

ts() { date '+%Y-%m-%d %H:%M:%S'; }

# uvicorn.log ของ process ที่รันยาว ๆ โตได้ไม่จำกัด — ดิสก์เต็ม = API พังแบบหาสาเหตุยาก
# ตัดได้ปลอดภัยเพราะ run_server.sh เปิดไฟล์แบบ append (>>) : fd จะเขียนต่อท้ายเสมอ ไม่เกิดไฟล์ sparse
UVLOG="$PROJ/uvicorn.log"
if [[ -f "$UVLOG" ]] && [[ "$(stat -c %s "$UVLOG" 2>/dev/null || echo 0)" -gt 52428800 ]]; then
  tail -c 5000000 "$UVLOG" > "$UVLOG.keep" && cat "$UVLOG.keep" > "$UVLOG" && rm -f "$UVLOG.keep"
  echo "$(ts) ✂️ ตัด uvicorn.log (เกิน 50MB)" >> "$LOG"
fi

# กันสองตัวชนกัน (cron รอบก่อนยังปลุกไม่เสร็จ รอบใหม่มาอีก)
exec 9>"$PROJ/logs/.watchdog.lock"
flock -n 9 || { echo "$(ts) ข้าม — watchdog ตัวก่อนยังทำงานอยู่" >> "$LOG"; exit 0; }

# ระหว่าง deploy ให้หยุดยุ่ง (update_ai_server.sh แตะไฟล์นี้ไว้)
if [[ -f "$PROJ/.deploying" ]]; then
  age=$(( $(date +%s) - $(stat -c %Y "$PROJ/.deploying" 2>/dev/null || echo 0) ))
  if [[ $age -lt 600 ]]; then
    echo "$(ts) ข้าม — กำลัง deploy อยู่" >> "$LOG"; exit 0
  fi
  rm -f "$PROJ/.deploying"        # ค้างเกิน 10 นาที = deploy พังไปแล้ว ไม่ต้องรอ
fi

if curl -sf --max-time 8 "http://$HEALTH_HOST:$PORT/health" > /dev/null 2>&1; then
  exit 0                          # ปกติ — ไม่ต้อง log ให้รก
fi

echo "$(ts) 🔴 API ไม่ตอบที่ $HEALTH_HOST:$PORT — กำลังปลุกใหม่" >> "$LOG"
if bash "$PROJ/deploy/run_server.sh" >> "$LOG" 2>&1; then
  echo "$(ts) ✅ ปลุกสำเร็จ" >> "$LOG"
else
  echo "$(ts) ❌ ปลุกไม่ขึ้น — ดู uvicorn.log" >> "$LOG"
fi
