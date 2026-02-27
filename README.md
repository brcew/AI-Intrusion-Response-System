# 🛡️ AI Intrusion Response System

**An intelligent security system that detects cyberattacks in real time, automatically blocks threats, and explains every decision it makes.**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=flat&logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-2ecc71?style=flat)

---

## 🎯 The Problem

Cyberattacks happen in milliseconds. Traditional security tools detect threats too slowly, can't explain their decisions, and require manual intervention. We built a system that **detects, responds, and explains — automatically.**

---

## ✨ What It Does

| | Feature | Impact |
|---|---------|--------|
| 🤖 | **3 ML Models benchmarked automatically** | Best model selected by F1-score |
| 🧠 | **Explains every AI decision** | No more black box security |
| 🚫 | **Auto-blocks malicious IPs** | Zero manual intervention needed |
| 🌍 | **Live world attack map** | See where attacks come from |
| 🎣 | **Phishing URL scanner** | Protects against email attacks |
| 📊 | **One-click Excel reports** | Professional incident documentation |

---

## 🚀 Run It Yourself

```bash
git clone https://github.com/YOUR_USERNAME/AI-Intrusion-Response-System.git
cd AI-Intrusion-Response-System
pip install -r requirements.txt
streamlit run dashboard/app.py
```

> Opens automatically at `http://localhost:8501`

---

## 🧠 How The AI Works

```
Server Logs → Feature Extraction → ML Model (auto-selected best)
                                          ↓
                                   Threat Scoring
                                   ML hit   → +5 pts
                                   Brute force → +3 pts
                                   DDoS     → +4 pts
                                          ↓
                                  Score ≥ 8 → AUTO BLOCK
                                          ↓
                             Explain WHY + Geolocate IP
```

All of this happens in **under 1 second per log entry.**

---

## 📊 Model Results

### Network Intrusion Detection
| Model | F1-Score | Accuracy |
|-------|----------|----------|
| Isolation Forest | 0.92 | 0.94 |
| One-Class SVM ⭐ | **0.94** | **0.95** |
| Local Outlier Factor | 0.94 | 0.95 |

### Phishing URL Detection
| Model | F1-Score | Accuracy |
|-------|----------|----------|
| Random Forest ⭐ | **1.00** | **1.00** |
| Gradient Boosting | 1.00 | 1.00 |
| Logistic Regression | 1.00 | 1.00 |

> ⭐ = auto-selected best model

---

## 🖥️ Dashboard

**5 tabs. Everything live. Nothing manual.**

- **📊 Live Monitor** — real-time traffic, threat scores, blocked IPs
- **🧠 Explainability** — why each IP was flagged, with charts
- **🌍 Attack Map** — world map of attack origins
- **🤖 Model Benchmark** — all models compared side by side
- **🎣 Phishing Scanner** — scan any URL instantly

---

## 📁 Structure

```
├── app/
│   ├── config.py              ← all thresholds in one place
│   ├── core/
│   │   ├── log_generator.py   ← simulates real traffic
│   │   ├── model_manager.py   ← trains & benchmarks 3 models
│   │   ├── threat_engine.py   ← hybrid ML + rule scoring
│   │   ├── firewall.py        ← auto IP blocking
│   │   ├── explainability.py  ← explains AI decisions
│   │   └── phishing_detector.py ← URL threat detection
│   └── utils/
│       └── report_generator.py ← Excel incident reports
└── dashboard/
    └── app.py                 ← Streamlit UI
```

---

## 🛠️ Built With

`Python` `Streamlit` `scikit-learn` `Plotly` `pandas` `openpyxl`

---

## 👥 Team

Built with ❤️ for the **General AI/ML Hackathon**

---

*MIT License*
