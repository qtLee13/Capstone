import smtplib
import random
import time
from email.message import EmailMessage

# ================= 1. Mini Dataset จำลอง =================

# 🟢 Legitimate Emails (ตัวแทนจาก Enron Dataset)
# ลักษณะ: คุยงาน, นัดประชุม, ส่งรายงาน ไม่มีลิงก์อันตราย ไม่เร่งรีบ
LEGITIMATE_DATASET = [
    {
        "subject": "Q3 Financial Report Update",
        "sender": "john.smith@company.com",
        "reply_to": "john.smith@company.com",
        "body": "Hi team,\n\nAttached is the rough draft for the Q3 financial report. Please review the numbers by Friday so we can finalize it before the board meeting next week.\n\nThanks,\nJohn",
        "is_phishing": False
    },
    {
        "subject": "Lunch meeting tomorrow?",
        "sender": "sarah.connor@company.com",
        "reply_to": "sarah.connor@company.com",
        "body": "Hey, \nAre we still on for lunch tomorrow at 12:30? Let me know if we need to reschedule.\n\nBest,\nSarah",
        "is_phishing": False
    },
    {
        "subject": "Re: Server Maintenance Schedule",
        "sender": "it.support@company.com",
        "reply_to": "it.support@company.com",
        "body": "Just a reminder that the main database server will be down for scheduled maintenance tonight from 2 AM to 4 AM. Please save your work.\n\nRegards,\nIT Operations",
        "is_phishing": False
    }
]

# 🔴 Phishing Emails (ตัวแทนจาก Phishing Corpus)
# ลักษณะ: ปลอมแปลงตัวตน, มีลิงก์แปลกๆ, เร่งด่วน, ข่มขู่
PHISHING_DATASET = [
    {
        "subject": "URGENT: Your account has been compromised!",
        "sender": "security@paypal-support.xyz",  # โดเมนปลอม
        "reply_to": "hacker123@yandex.ru",        # Reply-to ไม่ตรงกับ Sender
        "body": "Dear Customer,\n\nWe detected unusual login attempts from Russia. Your account will be locked in 12 hours. Please verify your identity immediately by clicking here: http://192.168.1.100/verify_account\n\nFailure to do so will result in permanent suspension.\n\nSecurity Team",
        "is_phishing": True
    },
    {
        "subject": "Invoice #88492 is Overdue",
        "sender": "billing@netflix-billing.com",
        "reply_to": "billing@netflix-billing.com",
        "body": "Hello,\nYour latest payment failed. To avoid service disruption, please update your billing details here: http://update-billing.click/login\n\nThank you.",
        "is_phishing": True
    },
    {
        "subject": "Important HR Document Attached",
        "sender": "hr-dept@company.com",
        "reply_to": "scam.hr@gmail.com", # แอบให้ตอบกลับเข้าเมลส่วนตัว
        "body": "All Employees,\n\nPlease find the attached updated salary structure for 2026. You must review and sign the document by end of day.\nDownload the secure file here: http://10.0.0.55/salary_update.exe\n\nHR Department",
        "is_phishing": True
    }
]

# รวม Dataset ไว้ด้วยกัน
ALL_EMAILS = LEGITIMATE_DATASET + PHISHING_DATASET

# ================= 2. ฟังก์ชันสุ่มยิงอีเมล =================

def send_simulated_email(email_data, target_email="employee@company.com"):
    msg = EmailMessage()
    msg.set_content(email_data["body"])
    msg['Subject'] = email_data["subject"]
    msg['From'] = email_data["sender"]
    msg['To'] = target_email
    msg['Reply-To'] = email_data["reply_to"]

    try:
        # ยิงเข้า Mail Gateway จำลองของเราที่ Port 2525
        with smtplib.SMTP('127.0.0.1', 2525) as server:
            server.send_message(msg)
        
        email_type = "🔴 PHISHING" if email_data["is_phishing"] else "🟢 LEGITIMATE"
        print(f"✅ ส่งสำเร็จ! | ประเภท: {email_type} | หัวข้อ: {email_data['subject']}")
    except Exception as e:
        print(f"❌ ส่งไม่สำเร็จ: {e} (อย่าลืมเปิด Terminal รัน mail_gateway.py ทิ้งไว้นะครับ)")

# ================= 3. สั่งรันการจำลอง =================

if __name__ == '__main__':
    NUM_EMAILS_TO_SEND = 5 # อยากให้สุ่มส่งกี่ฉบับ ปรับตรงนี้ได้เลย
    
    print(f"🚀 เริ่มต้นการจำลองยิงอีเมล (Traffic Simulator)")
    print("-" * 50)
    
    for i in range(NUM_EMAILS_TO_SEND):
        # สุ่มเลือกอีเมลจาก Dataset ทั้งหมด
        selected_email = random.choice(ALL_EMAILS)
        
        print(f"\n[{i+1}/{NUM_EMAILS_TO_SEND}] กำลังยิงอีเมล...")
        send_simulated_email(selected_email)
        
        # หน่วงเวลา 2 วินาทีก่อนยิงฉบับต่อไป (ให้ Gateway ทำงานทัน และดูสมจริง)
        time.sleep(2)
        
    print("-" * 50)
    print("🎯 จบการจำลอง! ลองเปิดดูหน้า React Dashboard ของคุณได้เลยครับ")