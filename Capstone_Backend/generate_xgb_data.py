import pandas as pd
import re
import random

# 1. โหลดข้อมูลอีเมลดิบ (สมมติว่าเอาไฟล์มาต่อกันแล้วและเลือกเฉพาะอีเมลที่เป็น Spam/Malicious)
# สำหรับเทรน XGBoost เราจะใช้เฉพาะอีเมลที่ Stage 1 มองว่าเป็นอันตรายแล้วเท่านั้น
df = pd.read_csv('spam_emails_all.csv') # สมมติใช้ไฟล์นี้เป็นหลัก

# สร้าง List เก็บข้อมูลใหม่
xgb_data = []

for index, row in df.iterrows():
    text = str(row.get('message', ''))
    
    # --- จำลองการสร้าง 5 Features ---
    
    # 1. ai_score (คะแนนจาก BERT): จำลองว่าถ้าเป็นสแปม BERT มักจะให้คะแนนสูง (70-99)
    ai_score = random.uniform(70.0, 99.9)
    
    # 2. link_risk: เช็คว่ามีลิงก์ไหม ถ้ามีให้สุ่มความเสี่ยง
    has_link = bool(re.search(r'http[s]?://', text))
    link_risk = random.choice([80, 100]) if has_link else 0
    
    # 3. ipqs_score: สุ่มคะแนน IP ความน่าเชื่อถือต่ำ
    ipqs_score = random.randint(50, 100)
    
    # 4. dmarc_fail: สุ่มว่าปลอมโดเมนมาไหม (0=Pass, 1=Fail)
    dmarc_fail = random.choice([0, 1])
    
    # 5. attachment_risk: เช็คว่ามีไฟล์แนบไหม (จำลองจากข้อความ)
    has_attachment = bool(re.search(r'\.(exe|zip|scr|bat)', text.lower()))
    attachment_risk = 1 if has_attachment else 0

    # --- การติดฉลาก (Labeling) ว่าเป็นภัยคุกคามประเภทไหน ---
    # ใช้ Rule-based ในการติด Label เพื่อสอน XGBoost
    if attachment_risk == 1:
        label = "Malware Attachment"
    elif has_link and link_risk == 100:
        label = "Phishing"
    elif not has_link and dmarc_fail == 1:
        label = "Business Email Compromise (BEC)"
    else:
        label = "Spam (High-Risk Source)"

    # เก็บลงตาราง
    xgb_data.append([ai_score, link_risk, ipqs_score, dmarc_fail, attachment_risk, label])

# แปลงเป็น DataFrame และบันทึกเป็น CSV สำหรับเทรน XGBoost
xgb_df = pd.DataFrame(xgb_data, columns=['ai_score', 'link_risk', 'ipqs_score', 'dmarc_fail', 'attachment_risk', 'label'])
xgb_df.to_csv('xgboost_training_data.csv', index=False)
print("✅ สร้างไฟล์ xgboost_training_data.csv สำเร็จ!")