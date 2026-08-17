# 📋 สรุปโปรเจกต์ Capstone Email Security

> อัปเดต: 2026-07-15 · ตัวเลขดึงจากไฟล์ CSV/JSON จริงโดยตรง (ไม่ประมาณ)
> 2 โปรเจกต์: `CapStoneG10/Capstone_Backend` (production/deploy) + `Cap Stone AI/capstone-email-security` (train/eval)

---

## 1️⃣ Training / Eval Scripts

### ฝั่ง Cap Stone AI (`capstone-email-security/scripts/`)
| Path | ทำอะไร |
|---|---|
| `train/train_bert.py` | Fine-tune **BERT (bert-base-uncased)** binary phishing vs legit → โมเดล Stage 1 หลัก |
| `train/train_stage1_comparison.py` | เทียบ Stage 1: LR / RF / DistilBERT บน split เดียวกัน → `stage1_comparison.json` |
| `train/train_stage2_comparison.py` | Stage 2 multi-class บนข้อมูล **synthetic** (5 features) → `stage2_comparison.json` |
| `train/train_stage2_real.py` | Stage 2 real **cross-source** 3 คลาส → `stage2_real_comparison.json` |
| `train/train_stage2_consistent.py` | Stage 2 real **same-source** 3 คลาส (Phish/Spam/BEC) → `stage2_consistent_comparison.json` |
| `train/train_stage2_5class.py` | Stage 2 real 5 คลาส (merge) → `stage2_5class_comparison.json` |
| `train/train_stage2_4class_real.py` | **[FINAL]** Stage 2 real same-source 4 คลาส → `stage2_4class_real_comparison.json` |
| `evaluate/eval_bert_old_vs_new.py` | เทียบ BERT เก่า vs ใหม่ (held-out CEAS) → `bert_old_vs_new.json` |
| `evaluate/eval_xgb_old_vs_new.py` | เทียบ XGBoost เก่า vs ใหม่ → `xgb_old_vs_new.json` |
| `evaluate/eval_stage2_real.py` | เอา real data รันกับโมเดลที่เทรน synthetic (พิสูจน์ว่าไม่ generalize) |
| `evaluate/evaluate_bert.py` | ประเมิน BERT ที่เซฟไว้แล้ว (ไม่เทรนใหม่) |
| `evaluate/evaluate_generalization.py` | วัด generalization pipeline บน test set ที่ gen ใหม่ |
| `evaluate/plot_*.py` (9 ไฟล์) | สร้างกราฟ: `plot_comparison`, `plot_experiments`, `plot_stage2_comparison`, `plot_stage2_4class`, `plot_old_vs_new`, `plot_stage2_real`, `plot_experiments_stage2(_real)` |

### ฝั่ง Capstone_Backend (`scripts/`)
| Path | ทำอะไร |
|---|---|
| `scripts/build_phishing_pot_full.py` | สกัด 6 features จาก phishing_pot .eml → `stage2_pp_full.csv` |
| `scripts/build_malware_mta.py` | สกัด Malware จาก malware-traffic-analysis (in-memory) → `stage2_malware_mta.csv` |
| `scripts/build_real_stage2_dataset.py` | สกัด Phishing+Spam จาก text CSV → `stage2_real_dataset.csv` |
| `scripts/build_epvme_spear.py` | สกัด Spear จาก EPVME → `stage2_spear_epvme.csv` |
| `scripts/build_phishing_pot_stage2.py` | BEC+Malware จาก phishing_pot → `stage2_bec_malware_pp.csv` |
| `scripts/build_proofpoint_stage2.py` | สกัด 5 threat rows จาก proofpoint → `stage2_proofpoint_examples.csv` |
| `scripts/build_eml_features.py` | unified .eml → 5-feature extractor (EPVME demo) |
| `scripts/deploy_stage2_model.py` | **เทรน+save โมเดล XGBoost deploy** (4-class real) → `xgboost_type_classifier.json` |
| `scripts/eval_legit_suspicious.py` | วัด false-positive อีเมล legit-but-suspicious |
| `scripts/generate_xgb_data.py` | **[deprecated]** สร้างข้อมูล synthetic → `xgboost_training_data.csv` |
| `scripts/train_xgboost.py` | **[deprecated]** เทรน XGBoost บน synthetic (โมเดลเก่า) |

---

## 2️⃣ Datasets

### `datasets/stage2/` (feature CSV พร้อมเทรน)
| ไฟล์ | rows | cols | label distribution |
|---|---|---|---|
| `stage2_pp_full.csv` | 394 | 8 | Phishing=300, BEC=93, Malware=1 |
| `stage2_sa_spam_full.csv` | 500 | 8 | Spam=500 |
| `stage2_malware_mta.csv` | 26 | 10 | Malware=26 |
| `stage2_real_dataset.csv` | 1000 | 11 | Phishing=500, Spam=500 |
| `stage2_spear_epvme.csv` | 500 | 12 | Spear=500 |
| `stage2_bec_malware_pp.csv` | 94 | 11 | BEC=93, Malware=1 |
| `stage2_epvme_extract.csv` | 32 | 11 | BEC=28, Malware=4 |
| `stage2_eml_spear_phishing.csv` | 25 | 12 | Spear=25 |
| `stage2_proofpoint_examples.csv` | 5 | 14 | BEC=3, Malware=2 (label=`attack_type`) |
| `xgboost_training_data.csv` | 3644 | 6 | Spam=1881, BEC=1763 **(synthetic)** |

คอลัมน์ stage2 หลัก: `ai_score, link_risk, abuseipdb_score, dmarc_fail, [reply_to_mismatch], attachment_risk, label` (+ provenance: has_ip/ai_real/source ฯลฯ) — ไฟล์ที่สกัดใหม่มี `reply_to_mismatch` ครบ 6, ไฟล์เก่ามี 5

### `datasets/raw/` (ข้อมูลดิบต้นทาง)
| ไฟล์ | rows | cols | คอลัมน์ | label distribution |
|---|---|---|---|---|
| `phishing_email.csv` | 82,486 | 2 | text_combined, label | 1=42,891 / 0=39,595 |
| `CEAS_08.csv` | 39,154 | 7 | sender,receiver,date,subject,body,label,urls | 1=21,842 / 0=17,312 |
| `Enron.csv` | 29,767 | 3 | subject, body, label | 0=15,791 / 1=13,976 |
| `good_emails_all.csv` | 13,459 | 4 | mail,status,message,label | Good=13,459 |
| `proofpoint_email.csv` | 5,005 | 36 | detector log (phishScore/impostorScore/malwareName/sendingIp...) | **ไม่มีคอลัมน์ label** |
| `spam_emails_all.csv` | 3,644 | 4 | mail,Status,message,label | Spam=3,644 |
| `spear_phishing_dataset.csv` | 1,000 | 11 | ...body,label,personalization_score,attachment_type,spoofing_detected | 0=712 / 1=288 |
| `synthetic_emails_poisoned.csv` | 4,211 | 3 | subject, body, label | 1.0=4,181 / NaN=30 **(synthetic, label เพี้ยน)** |

---

## 3️⃣ ผลลัพธ์ที่มีอยู่ (results/)

### Stage 1
| ไฟล์ | ผล |
|---|---|
| `stage1_comparison.json` | LR acc **0.9859** (FPR 1.91%, 0.43ms) · RF **0.9910** (FPR 1.10%, 30.9ms) · **DistilBERT 0.9955** (FPR 0.69%, 6.3ms) |
| `bert_results.json` | BERT ใหม่ (bert-base-uncased): test acc **0.9964**, macro-F1 0.9964, val-F1 0.9971, 11.4ms, 418MB, cuda (test 17,400 in-distribution) |
| `bert_old_vs_new.json` | held-out CEAS 3,000: **เก่า 0.8877 → ใหม่ 0.9443** |

### Stage 2
| ไฟล์ | ชนิด | ผลเด่น |
|---|---|---|
| `stage2_comparison.json` | **synthetic** 5-class | LR 0.97 / XGB 0.96 (สูงเพราะ synthetic) |
| `stage2_real_comparison.json` | real cross-source 3-class | LR **0.7733** / XGB 0.7633 (artifact) |
| `stage2_consistent_comparison.json` | real same-source 3-class | XGB acc **0.7039** / RF macroF1 0.6143 |
| `stage2_5class_comparison.json` | real 5-class | LR 0.6937 / RF macroF1 0.6637 (Malware n=5 พัง) |
| **`stage2_4class_real_comparison.json`** | **[FINAL] real same-source 4-class** | **XGB acc 0.6467, macro-F1 0.6028** · per-class F1: Spam 0.74 / Phishing 0.57 / BEC 0.30 / **Malware 0.80** |
| `xgb_old_vs_new.json` | เก่า vs ใหม่ (184 real) | **เก่า 0.0978 → ใหม่ 0.6467** |

### PNG
- **`results/final result/`** : old_vs_new_comparison · stage1_comparison · stage1_experiments · stage2_4class_comparison · **presentation_script.md**
- `results/` (เก่า/superseded) : stage2_comparison, stage2_experiments, stage2_real_comparison, stage2_real_experiments, stage2_cm_{xgboost,lightgbm,random_forest,logistic_regression}

---

## 4️⃣ Feature ที่ใช้ (Stage 1 vs Stage 2)

| | Stage 1 (BERT) | Stage 2 (XGBoost) |
|---|---|---|
| **อินพุต** | **ข้อความ body ทั้งก้อน** (mask URL → `[URL]`) tokenize max_length=256 | **6 ตัวเลข feature** |
| **feature** | ไม่มี hand-crafted — เรียนจาก raw text เอง | `ai_score` (จาก BERT), `link_risk`, `abuseipdb_score`, `dmarc_fail`, `reply_to_mismatch`, `attachment_risk` |
| **เอาต์พุต** | phishing prob 0–100 (2 คลาส) | ประเภทการโจมตี (4 คลาส) |

หมายเหตุ: โมเดลเก่า + dataset เก่าบางตัวใช้ **5 features** (ไม่มี `reply_to_mismatch`) · ตัว deploy ปัจจุบันใช้ **6 features**

---

## 5️⃣ โมเดลที่เทรนแล้ว

### Stage 1 (BERT)
| โมเดล | Path | สถานะ |
|---|---|---|
| BERT ใหม่ (bert-base) | `Cap Stone AI/models/bert/` (418MB) | ต้นฉบับตัวใหม่ |
| = สำเนา deploy | `Capstone_Backend/phishing_bert_model_v2/` | **live (main.py โหลด)** |
| BERT เก่า | `Capstone_Backend/phishing_bert_model/` | backup (2026-04, **ไม่มี result JSON**) |

### Stage 2 (tabular)
| โมเดล | Path | สถานะ |
|---|---|---|
| XGBoost 4-class real (6-feat) | `Capstone_Backend/xgboost_type_classifier.json` + `label_encoder.pkl` | **live (main.py โหลด)** |
| XGBoost เก่า 2-class synthetic (5-feat) | `Capstone_Backend/_archive/*_OLD_synthetic_*` | backup |
| 4 โมเดล real (LR/RF/LightGBM/XGB) | `Cap Stone AI/models/stage2_real/*.joblib` | จากการทดลอง (2026-07-13) |
| XGBoost best (เก่ากว่า) | `Cap Stone AI/models/xgboost/best_model.joblib` + label_encoder.pkl | เก่า (2026-07-09) |

**Pipeline ที่ deploy จริง:** `phishing_bert_model_v2` (BERT) → `xgboost_type_classifier.json` (XGBoost 4-class, 6 features)
