import pandas as pd
import xgboost as xgb
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

print("1. กำลังโหลดชุดข้อมูล...")
df = pd.read_csv('xgboost_training_data.csv')

# กำหนดตัวแปรต้น (X) และตัวแปรตาม (y)
X = df[['ai_score', 'link_risk', 'ipqs_score', 'dmarc_fail', 'attachment_risk']]
y = df['label']

print("2. แปลงชื่อประเภทการโจมตีเป็นตัวเลข...")
# XGBoost ต้องการให้ Label เป็นตัวเลข (เช่น 0, 1, 2, 3) ไม่ใช่ข้อความ
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

# แบ่งข้อมูลสำหรับ Train 80% และ Test 20%
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

print("3. กำลังเทรนโมเดล XGBoost...")
# ตั้งค่าโมเดล (ใช้ objective แบบ multi:softprob สำหรับการแยกหลายประเภท)
model = xgb.XGBClassifier(
    objective='multi:softprob', 
    eval_metric='mlogloss',
    use_label_encoder=False,
    num_class=len(encoder.classes_)
)
model.fit(X_train, y_train)

print("4. ประเมินความแม่นยำของโมเดล (Testing)...")
y_pred_proba = model.predict_proba(X_test)
y_pred = np.argmax(y_pred_proba, axis=1)
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")
print(classification_report(y_test, y_pred, target_names=encoder.classes_))

print("5. บันทึกโมเดลและ Encoder...")
model.save_model("xgboost_type_classifier.json")
joblib.dump(encoder, "label_encoder.pkl")
print("✅ บันทึกไฟล์ xgboost_type_classifier.json และ label_encoder.pkl เสร็จสมบูรณ์!")