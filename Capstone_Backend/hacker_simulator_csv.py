import smtplib
import time
import random
import pandas as pd
from email.message import EmailMessage

# ================= 1. ตั้งค่า Dataset =================
CEAS_FILE = "CEAS_08.csv"     # ชื่อไฟล์ใหม่ของเรา
NUM_SAFE_TO_SEND = 0        # สุ่มเมลปกติกี่ฉบับ
NUM_PHISH_TO_SEND = 4       # สุ่มเมลหลอกลวงกี่ฉบับ

# ================= 2. ฟังก์ชันโหลดและสุ่มข้อมูลแบบไฟล์เดียว =================
def load_and_sample_emails():
    emails_to_send = []
    
    try:
        print(f"📂 กำลังโหลดข้อมูลจาก {CEAS_FILE}...")
        # โหลดไฟล์แบบระบุว่าให้จัดการ Error บรรทัดที่พังๆ ทิ้งไป (on_bad_lines)
        df = pd.read_csv(CEAS_FILE, on_bad_lines='skip')
        
        # กรองข้อมูลโดยใช้คอลัมน์ label (0 = Safe, 1 = Phishing)
        df_safe = df[df['label'] == 0].sample(n=NUM_SAFE_TO_SEND)
        df_phish = df[df['label'] == 1].sample(n=NUM_PHISH_TO_SEND)
        
        print("✅ โหลดและสุ่มข้อมูลสำเร็จ! กำลังเตรียมส่ง...")

        # 1. จัดเตรียมอีเมลปกติ (Safe)
        for index, row in df_safe.iterrows():
            emails_to_send.append({
                "subject": str(row['subject']) if pd.notna(row['subject']) else "Normal Email",
                "sender": str(row['sender']) if pd.notna(row['sender']) else "employee@company.com",
                "body": str(row['body']) if pd.notna(row['body']) else "",
                "type": "🟢 SAFE"
            })
            
        # 2. จัดเตรียมอีเมลหลอกลวง (Phishing)
        for index, row in df_phish.iterrows():
            emails_to_send.append({
                "subject": str(row['subject']) if pd.notna(row['subject']) else "URGENT Notice",
                "sender": str(row['sender']) if pd.notna(row['sender']) else "hacker@bad-domain.xyz",
                "body": str(row['body']) if pd.notna(row['body']) else "",
                "type": "🔴 PHISHING"
            })
            
    except FileNotFoundError:
        print(f"❌ หาไฟล์ไม่พบ กรุณาตรวจสอบว่ามีไฟล์ {CEAS_FILE} อยู่ในโฟลเดอร์เดียวกับโค้ดไหม")
        exit()
    except Exception as e:
        print(f"❌ เกิดข้อผิดพลาดในการอ่านข้อมูล: {e}")
        exit()
        
    # สับเปลี่ยนลำดับให้มันสุ่มยิงแบบเดาไม่ได้
    random.shuffle(emails_to_send)
    return emails_to_send

# ================= 3. ฟังก์ชันยิงเข้า Gateway =================
def send_email_to_gateway(email_data):
    msg = EmailMessage()
    msg.set_content(email_data["body"])
    msg['Subject'] = email_data["subject"]
    msg['From'] = email_data["sender"]
    msg['To'] = "victim@company.com"

    try:
        with smtplib.SMTP('127.0.0.1', 2525) as server:
            server.send_message(msg)
        print(f"✅ ส่งสำเร็จ! | {email_data['type']} | หัวข้อ: {email_data['subject']}")
    except Exception as e:
        print(f"❌ ส่งไม่สำเร็จ: {e}")

# ================= 4. ระบบหน่วงเวลา (Rate Limit Protection) =================
if __name__ == '__main__':
    print("🚀 เริ่มระบบจำลองยิงอีเมลจาก Dataset จริง")
    
    # ดึงข้อมูลจากไฟล์
    emails_list = load_and_sample_emails()
    total_emails = len(emails_list)
    
    print("-" * 50)
    print(f"🎯 เตรียมยิงทั้งหมด {total_emails} ฉบับ")
    print("⏳ ระบบจะทำการหน่วงเวลา 16 วินาที/ฉบับ เพื่อป้องกัน VirusTotal แบน API")
    print("-" * 50)
    
    for i, email_data in enumerate(emails_list, start=1):
        print(f"\n[{i}/{total_emails}] กำลังยิงอีเมลประเภท {email_data['type']}...")
        send_email_to_gateway(email_data)
        
        # ถ้าไม่ใช่ฉบับสุดท้าย ให้รอ 16 วินาที
        if i < total_emails:
            print("⏳ [Rate Limit] รอ 16 วินาที ก่อนส่งฉบับถัดไป...")
            for sec in range(16, 0, -1):
                # ปริ้นท์นับถอยหลังบรรทัดเดิมให้ดูเท่ๆ
                print(f"   รออีก {sec} วินาที...  ", end='\r')
                time.sleep(1)
            print("                       ", end='\r') # เคลียร์บรรทัด
            
    print("\n" + "-" * 50)
    print("🎉 ยิง Dataset ทดสอบเสร็จสมบูรณ์! กลับไปดูผลที่ Dashboard ได้เลยครับ")