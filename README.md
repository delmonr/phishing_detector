# 🛡 PhishGuard AI — Website Phishing Detector

An AI-powered, real-time URL security checker with a cyberpunk-themed dashboard.

---

## ✨ Features

| Feature | Details |
|---|---|
| **ML Detection** | Gradient Boosting model trained on 31 URL-based features |
| **Risk Scoring** | 0–100% risk percentage with animated gauge |
| **Visual Alerts** | Full-screen green (safe) / red (phishing) overlay |
| **Sound Alerts** | Web Audio API tones — ascending chord (safe), alarm (phishing) |
| **Dashboard** | Scan history, donut chart, stat cards |
| **Auth System** | Register / Login with hashed passwords (Werkzeug) |
| **Scan History** | SQLite-backed history per user |
| **Feature Report** | 11 human-readable feature flags per scan |

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.9+
- pip

### 2. Install dependencies
```bash
cd phishing_detector
pip install -r requirements.txt
```

### 3. Run the server
```bash
python app.py
```

### 4. Open your browser
```
http://127.0.0.1:5000
```

---

## 🗂 Project Structure

```
phishing_detector/
├── app.py              ← Flask app, routes, auth, API
├── model.py            ← Feature extractor + Gradient Boosting model
├── requirements.txt
├── README.md
├── instance/
│   └── users.db        ← SQLite database (auto-created)
├── static/
│   ├── css/style.css   ← Cyberpunk dark UI
│   └── js/main.js      ← Scanner logic, audio, overlay
└── templates/
    ├── base.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    └── checker.html
```

---

## 🤖 ML Model Details

**Algorithm:** Gradient Boosting Classifier (scikit-learn)  
**Training samples:** 1,600 synthetic feature vectors (50/50 split)  
**Features extracted (31 total):**

- URL & hostname length
- Dot, hyphen, slash, special-character counts
- IP address in hostname
- HTTPS usage
- Subdomain depth
- Suspicious keyword count (30+ phishing keywords)
- Shannon entropy of hostname & path
- Hex encoding presence
- TLD trust level
- Redirect indicators

---

## 🔐 Security Notes

- Passwords hashed with **Werkzeug PBKDF2-SHA256**
- Sessions secured with a random `SECRET_KEY` per run
- For production: set `SECRET_KEY` as an environment variable, switch to PostgreSQL, and serve behind gunicorn + nginx

---

## 📸 Pages

| Page | URL |
|---|---|
| Login | `/login` |
| Register | `/register` |
| Dashboard | `/dashboard` |
| URL Scanner | `/checker` |
| Scan API | `POST /api/scan` |
| History API | `GET /api/history` |
| Stats API | `GET /api/stats` |

---

## 📄 License
MIT — free to use and modify.
