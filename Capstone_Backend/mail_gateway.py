import asyncio
import os
import time
import requests
from aiosmtpd.controller import Controller

# กำหนด URL ของ AI Backend ของเรา
BACKEND_URL = "http://127.0.0.1:8000/analyze"

class MailGatewayHandler:
    async def handle_DATA(self, server, session, envelope):
        # 1. รับข้อมูลจาก Internet
        raw_email = envelope.content.decode('utf8', errors='replace')
        sender = envelope.mail_from
        recipient = envelope.rcpt_tos[0] if envelope.rcpt_tos else "unknown@corp.com"

        print(f"\n[{time.strftime('%X')}] 📥 มีอีเมลส่งเข้ามาจาก: {sender} -> {recipient}")
        print("⏳ กำลังส่งเข้า AI Detection Engine...")

        try:
            # 2. ส่งให้ Backend ทำ (Parser -> Feature -> AI -> Risk -> Policy)
            response = requests.post(BACKEND_URL, json={
                "text": raw_email,
                "recipient": recipient
            })
            result = response.json()
            
            risk_level = result['summary']['risk_level']
            final_score = result['summary']['final_risk_score']
            
            print(f"📊 Risk Score: {final_score}/100 | Policy: {risk_level}")

            # 3. Email Delivery & Policy Enforcement (ส่งเข้า Mail Server)
            if "Block" in risk_level:
                print("🚫 Action: DROP (บล็อกทิ้ง ไม่ส่งต่อให้ User)")
                
            elif "Quarantine" in risk_level:
                print("🟨 Action: QUARANTINE (กักกันไว้ในโฟลเดอร์แยก)")
                self.deliver_to_mail_server("quarantine", recipient, raw_email)
                
            else: # Allow หรือ Warning
                print("✅ Action: DELIVER (ส่งต่อเข้า Inbox ของ User อย่างปลอดภัย)")
                self.deliver_to_mail_server("inbox", recipient, raw_email)

            return '250 Message accepted for delivery'

        except Exception as e:
            print(f"❌ ระบบขัดข้อง: {e}")
            return '451 Requested action aborted: local error in processing'

    # ฟังก์ชันจำลองการส่งเข้า Mail Server (เซฟเป็นไฟล์ .eml)
    def deliver_to_mail_server(self, folder, recipient, content):
        path = f"Mail_Server_DB/{folder}"
        os.makedirs(path, exist_ok=True)
        filename = f"{path}/{recipient.split('@')[0]}_{int(time.time())}.eml"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"💾 บันทึกอีเมลลงใน {filename}")

if __name__ == '__main__':
    handler = MailGatewayHandler()
    controller = Controller(handler, hostname='127.0.0.1', port=2526)
    
    print("[Mail Gateway] กำลังทำงาน...")
    print("เปิดพอร์ตรอรับอีเมลที่ 127.0.0.1:2526")
    # print("คิดถึงเด็กดื้อจังเลยยย <3")
    
    controller.start()
    try:
        # ปล่อยให้รันค้างไว้
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        print("\n🛑 ปิดระบบ Mail Gateway")