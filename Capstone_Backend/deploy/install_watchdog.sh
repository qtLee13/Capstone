#!/usr/bin/env bash
# ลง cron ให้ watchdog — รันบนเครื่องเซิร์ฟเวอร์ ไม่ต้องใช้ sudo
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
PROJ="$PWD"
chmod +x "$PROJ/deploy/"*.sh

# ลบของเดิมออกก่อน (กันซ้ำเวลารันหลายรอบ) แล้วใส่ใหม่
CUR="$(crontab -l 2>/dev/null | grep -v 'ai_project/deploy/watchdog.sh' | grep -v 'ai_project/deploy/run_server.sh' || true)"
{
  [[ -n "$CUR" ]] && echo "$CUR"
  echo "# --- Capstone AI: ปลุก API ถ้าดับ (แทน systemd เพราะไม่มีสิทธิ์ sudo) ---"
  echo "*/5 * * * * $PROJ/deploy/watchdog.sh"
  echo "@reboot sleep 45 && $PROJ/deploy/run_server.sh >> $PROJ/logs/watchdog.log 2>&1"
} | crontab -

echo "  ✅ ลง cron แล้ว:"
crontab -l | grep -A2 "Capstone AI"
echo
echo "  ตรวจทุก 5 นาที · รีบูตแล้วรอ 45 วิ แล้วสตาร์ทเอง"
echo "  ดู log: tail -f $PROJ/logs/watchdog.log"
