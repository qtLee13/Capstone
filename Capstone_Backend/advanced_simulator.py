import smtplib
import time
from email.message import EmailMessage
from email.utils import make_msgid, formatdate

# กำหนด IP ปลอมที่จะฝังลงใน Header เพื่อหลอก Gateway ว่าส่งมาจากที่ไหน
CLEAN_IP = "8.8.8.8"        # Google DNS (IP สะอาด)
SUSPICIOUS_IP = "185.15.59.224" # ตัวอย่าง IP รัสเซีย/หรือ IP ที่มักติด Blacklist

# ================= 🎯 4 สถานการณ์ทดสอบ (Test Scenarios) =================
TEST_CASES = [
    {
        "name": "1. 🟢 อีเมลธุรกิจปกติ (Clean Email)",
        "sender": "nonthaphat.ford@gmail.com", 
        "reply_to": "nonthaphat.ford@gmail.com", # 💥 ต้องตั้งให้ตรงกับ sender เป๊ะๆ
        "recipient": "timepoonphol@gmail.com",
        "subject": "Schedule for next week's meeting",
        "body": "Hi team, please find the schedule for next week's meeting. Let me know if you have any conflicts. Regards.",
        "injected_ip": CLEAN_IP, # 💥 ใช้ IP ตามบ้าน/อินเทอร์เน็ตมือถือทั่วไปในไทย
        "attachment": None
    },
    # {
    #     "name": "2. 🟣 การโจมตีแบบ BEC (ปลอมตัวเป็น CEO)",
    #     "sender": "ceo@company.com", # แกล้งใช้โดเมนคนในบริษัท
    #     "reply_to": "hacker_master@gmail.com", # 💥 จุดสลบ: ตั้งค่าให้ตอบกลับไปหา Gmail ของโจร
    #     "recipient": "finance@company.com",
    #     "subject": "URGENT: Wire Transfer Required",
    #     "body": "I am in a confidential meeting. I need you to process a wire transfer of $50,000 to our new vendor immediately. Do not call me.",
    #     "injected_ip": SUSPICIOUS_IP,
    #     "attachment": None
    # },
    # {
    #     "name": "3. 🔴 การโจมตีแบบ Malware Attachment",
    #     "sender": "hr-recruitment@external-agency.com",
    #     "reply_to": "hr-recruitment@external-agency.com",
    #     "recipient": "victim@company.com",
    #     "subject": "Resume Application - Confidential",
    #     "body": "Dear HR, please review the attached resume for the new candidate. Open the document to see the full profile.",
    #     "injected_ip": CLEAN_IP,
    #     "attachment": "candidate_resume_hidden_macro.vbs" # 💥 จุดสลบ: แนบไฟล์อันตราย
    # },
    # {
    #     "name": "4. 🟠 การโจมตีแบบ Spam (โดเมนขยะ)",
    #     "sender": "marketing@superdeals.top", # 💥 จุดสลบ: ใช้นามสกุลโดเมนเสี่ยง (.top)
    #     "reply_to": "marketing@superdeals.top",
    #     "recipient": "victim@company.com",
    #     "subject": "You won a $1,000 Gift Card!",
    #     "body": "Click here to claim your prize! Limited time offer!",
    #     "injected_ip": SUSPICIOUS_IP,
    #     "attachment": None
    # }
]

# ================= 🛠️ ฟังก์ชันสร้างและยิงอีเมล =================
def send_crafted_email(case):
    msg = EmailMessage()
    msg.set_content(case["body"])
    msg['Subject'] = case["subject"]
    msg['From'] = case["sender"]
    msg['To'] = case["recipient"]
    msg['Reply-To'] = case["reply_to"]
    
    # 💥 ความลับของความสมจริง: สร้าง Header วันที่และ Message-ID แบบของแท้
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=case["sender"].split('@')[1])
    
    # 💥 ฉีด IP ปลอมเข้าไปใน Received Header เพื่อให้ Stage 2 (IPQS) ทำงาน
    fake_received = f"from mail-server.unknown.net ([{case['injected_ip']}]) by my-gateway.local with SMTP id xxxx"
    msg.add_header('Received', fake_received)

    # แนบไฟล์จำลอง
    if case["attachment"]:
        fake_payload = b"This is a fake virus payload for capstone testing."
        msg.add_attachment(
            fake_payload, 
            maintype='application', subtype='octet-stream', 
            filename=case["attachment"]
        )

    try:
        # ยิงเข้า Gateway (พอร์ต 2525)
        with smtplib.SMTP('127.0.0.1', 2526) as server:
            server.send_message(msg)
        print(f"✅ ส่งสำเร็จ: {case['name']}")
    except Exception as e:
        print(f"❌ ส่งไม่สำเร็จ: {e}")

# ================= 🚀 รันระบบ =================
if __name__ == '__main__':
    print("🚀 เริ่มระบบจำลองการโจมตีระดับสูง (Advanced Threat Simulator)")
    print("-" * 60)
    
    for case in TEST_CASES:
        print(f"\n⏳ กำลังสร้างและส่ง: {case['name']}")
        send_crafted_email(case)
        time.sleep(2) # หน่วงเวลาให้ API ทำงานทัน
        
    print("\n" + "=" * 60)
    print("🎉 ยิงทดสอบเสร็จสมบูรณ์! เปิดดู Dashboard เพื่อดูความแม่นยำได้เลยครับ")