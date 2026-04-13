from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json
import os
from datetime import datetime
from model import PhishingDetector

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
detector = PhishingDetector()

# ── Models ─────────────────────────────────────────────────────────────────────
class User(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    username  = db.Column(db.String(80),  unique=True, nullable=False)
    email     = db.Column(db.String(120), unique=True, nullable=False)
    password  = db.Column(db.String(200), nullable=False)
    created   = db.Column(db.DateTime, default=datetime.utcnow)
    scans     = db.relationship('ScanHistory', backref='user', lazy=True)

class ScanHistory(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url        = db.Column(db.String(2048), nullable=False)
    result     = db.Column(db.String(20),   nullable=False)   # 'safe' | 'phishing'
    risk_score = db.Column(db.Float,        nullable=False)
    features   = db.Column(db.Text,         nullable=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)


# ── Auth helpers ───────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        email    = request.form.get('email','').strip()
        password = request.form.get('password','')

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')

        user = User(username=username, email=email,
                    password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id']   = user.id
            session['username']  = user.username
            return redirect(url_for('dashboard'))

        flash('Invalid username or password.', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user   = User.query.get(session['user_id'])
    scans  = ScanHistory.query.filter_by(user_id=user.id)\
                               .order_by(ScanHistory.timestamp.desc())\
                               .limit(50).all()
    total     = len(scans)
    safe_cnt  = sum(1 for s in scans if s.result == 'safe')
    phish_cnt = total - safe_cnt
    avg_risk  = round(sum(s.risk_score for s in scans) / total, 1) if total else 0
    return render_template('dashboard.html', user=user, scans=scans,
                           total=total, safe_cnt=safe_cnt,
                           phish_cnt=phish_cnt, avg_risk=avg_risk)


@app.route('/checker')
@login_required
def checker():
    return render_template('checker.html', username=session['username'])


# ── API ────────────────────────────────────────────────────────────────────────
@app.route('/api/scan', methods=['POST'])
@login_required
def scan():
    data = request.get_json()
    url  = (data or {}).get('url','').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # Ensure scheme present for analysis
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    result   = detector.predict(url)
    label    = result['label']          # 'phishing' | 'safe'
    risk_pct = result['risk_percentage']
    features = result['features']

    # Persist scan
    scan_rec = ScanHistory(
        user_id    = session['user_id'],
        url        = url,
        result     = label,
        risk_score = risk_pct,
        features   = json.dumps(features)
    )
    db.session.add(scan_rec)
    db.session.commit()

    return jsonify({
        'url':            url,
        'label':          label,
        'risk_percentage': risk_pct,
        'features':       features,
        'timestamp':      datetime.utcnow().isoformat()
    })


@app.route('/api/history')
@login_required
def history():
    scans = ScanHistory.query.filter_by(user_id=session['user_id'])\
                              .order_by(ScanHistory.timestamp.desc())\
                              .limit(20).all()
    return jsonify([{
        'url':        s.url,
        'result':     s.result,
        'risk_score': s.risk_score,
        'timestamp':  s.timestamp.isoformat()
    } for s in scans])


@app.route('/api/stats')
@login_required
def stats():
    scans     = ScanHistory.query.filter_by(user_id=session['user_id']).all()
    total     = len(scans)
    safe_cnt  = sum(1 for s in scans if s.result == 'safe')
    phish_cnt = total - safe_cnt
    return jsonify({'total': total, 'safe': safe_cnt, 'phishing': phish_cnt})


# ── Bootstrap ──────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
