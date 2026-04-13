"""
PhishingDetector — feature-based ML model for URL classification.

Features extracted from the URL itself (no live DNS required) are fed into a
Random Forest trained on a synthetic, representative dataset.  The model is
trained once at import time so every Flask request gets instant predictions.
"""

import re
import math
import hashlib
from urllib.parse import urlparse
from typing import Dict, Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


# ── Feature extraction ─────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    'login','signin','verify','update','secure','account','banking','paypal',
    'ebay','amazon','apple','google','microsoft','facebook','instagram',
    'verify','confirm','password','credential','alert','urgent','suspend',
    'click','free','win','prize','lucky','congratulation','offer','limited',
    'wallet','crypto','bitcoin','nft','airdrop','reward'
]

TRUSTED_TLDS = {'.com','.org','.net','.edu','.gov','.io','.co'}

IP_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())


def extract_features(url: str) -> Dict[str, Any]:
    parsed   = urlparse(url)
    hostname = parsed.hostname or ''
    path     = parsed.path     or ''
    query    = parsed.query    or ''
    full     = url.lower()

    # ── structural ────────────────────────────────────────────────
    url_length           = len(url)
    hostname_length      = len(hostname)
    path_length          = len(path)
    num_dots_hostname    = hostname.count('.')
    num_dots_url         = url.count('.')
    num_hyphens          = url.count('-')
    num_underscores      = url.count('_')
    num_slashes          = url.count('/')
    num_question_marks   = url.count('?')
    num_equals           = url.count('=')
    num_at               = url.count('@')
    num_percent          = url.count('%')
    num_ampersand        = url.count('&')
    num_hash             = url.count('#')
    num_digits_in_host   = sum(c.isdigit() for c in hostname)
    num_special_chars    = sum(1 for c in url if not c.isalnum() and c not in './:?=&-_#@%+')
    digit_ratio_host     = num_digits_in_host / max(hostname_length, 1)

    # ── protocol / IP ─────────────────────────────────────────────
    uses_https           = int(url.startswith('https://'))
    has_ip_address       = int(bool(IP_RE.match(hostname)))
    port_in_url          = int(bool(re.search(r':\d+', hostname)))

    # ── subdomain ─────────────────────────────────────────────────
    parts                = hostname.split('.')
    num_subdomains       = max(0, len(parts) - 2)

    # ── TLD ───────────────────────────────────────────────────────
    tld                  = '.' + parts[-1] if parts else ''
    trusted_tld          = int(tld in TRUSTED_TLDS)

    # ── suspicious keywords ───────────────────────────────────────
    keyword_count        = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full)
    has_suspicious_kw    = int(keyword_count > 0)

    # ── encoding / obfuscation ────────────────────────────────────
    has_hex_encoding     = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    double_slash_in_path = int('//' in path)

    # ── entropy ───────────────────────────────────────────────────
    host_entropy         = round(_entropy(hostname), 4)
    path_entropy         = round(_entropy(path), 4)

    # ── redirect indicators ───────────────────────────────────────
    redirect_count       = url.count('http', 1)   # extra 'http' occurrences after position 0

    # ── length buckets ────────────────────────────────────────────
    url_len_gt54         = int(url_length > 54)
    url_len_gt75         = int(url_length > 75)

    features = {
        'url_length':          url_length,
        'hostname_length':     hostname_length,
        'path_length':         path_length,
        'num_dots_hostname':   num_dots_hostname,
        'num_dots_url':        num_dots_url,
        'num_hyphens':         num_hyphens,
        'num_underscores':     num_underscores,
        'num_slashes':         num_slashes,
        'num_question_marks':  num_question_marks,
        'num_equals':          num_equals,
        'num_at':              num_at,
        'num_percent':         num_percent,
        'num_ampersand':       num_ampersand,
        'num_hash':            num_hash,
        'num_digits_in_host':  num_digits_in_host,
        'num_special_chars':   num_special_chars,
        'digit_ratio_host':    digit_ratio_host,
        'uses_https':          uses_https,
        'has_ip_address':      has_ip_address,
        'port_in_url':         port_in_url,
        'num_subdomains':      num_subdomains,
        'trusted_tld':         trusted_tld,
        'keyword_count':       keyword_count,
        'has_suspicious_kw':   has_suspicious_kw,
        'has_hex_encoding':    has_hex_encoding,
        'double_slash_in_path':double_slash_in_path,
        'host_entropy':        host_entropy,
        'path_entropy':        path_entropy,
        'redirect_count':      redirect_count,
        'url_len_gt54':        url_len_gt54,
        'url_len_gt75':        url_len_gt75,
    }
    return features


# ── Synthetic training data ────────────────────────────────────────────────────

def _make_training_data():
    """
    Generate a representative synthetic dataset with realistic feature vectors.
    Real-world distribution: ~50 % phishing, ~50 % legitimate.
    """
    rng = np.random.RandomState(42)

    safe_samples = []
    phish_samples = []

    # ── Safe URL templates ────────────────────────────────────────
    for _ in range(800):
        url_len      = rng.randint(20, 60)
        host_len     = rng.randint(6, 20)
        dots_host    = rng.randint(1, 2)
        hyphens      = rng.randint(0, 1)
        slashes      = rng.randint(1, 4)
        q_marks      = rng.randint(0, 1)
        equals       = rng.randint(0, 2)
        at           = 0
        pct          = 0
        digits_host  = rng.randint(0, 2)
        special      = rng.randint(0, 2)
        digit_ratio  = digits_host / max(host_len, 1)
        https        = rng.choice([0, 1], p=[0.1, 0.9])
        ip           = 0
        port         = 0
        subdomains   = rng.randint(0, 1)
        trusted_tld  = rng.choice([0, 1], p=[0.1, 0.9])
        kw_count     = rng.randint(0, 1)
        susp_kw      = int(kw_count > 0)
        hex_enc      = 0
        dbl_slash    = 0
        host_ent     = rng.uniform(2.5, 3.8)
        path_ent     = rng.uniform(1.5, 3.2)
        redirect     = 0
        gt54         = int(url_len > 54)
        gt75         = int(url_len > 75)

        safe_samples.append([
            url_len, host_len, rng.randint(5,30), dots_host,
            dots_host+rng.randint(0,2), hyphens, rng.randint(0,1),
            slashes, q_marks, equals, at, pct, rng.randint(0,1), 0,
            digits_host, special, digit_ratio, https, ip, port,
            subdomains, trusted_tld, kw_count, susp_kw,
            hex_enc, dbl_slash, host_ent, path_ent, redirect, gt54, gt75
        ])

    # ── Phishing URL templates ─────────────────────────────────────
    for _ in range(800):
        url_len      = rng.randint(55, 200)
        host_len     = rng.randint(15, 60)
        dots_host    = rng.randint(2, 5)
        hyphens      = rng.randint(1, 6)
        slashes      = rng.randint(3, 10)
        q_marks      = rng.randint(1, 4)
        equals       = rng.randint(2, 8)
        at           = rng.choice([0, 1], p=[0.6, 0.4])
        pct          = rng.randint(0, 8)
        digits_host  = rng.randint(2, 12)
        special      = rng.randint(3, 15)
        digit_ratio  = digits_host / max(host_len, 1)
        https        = rng.choice([0, 1], p=[0.6, 0.4])
        ip           = rng.choice([0, 1], p=[0.6, 0.4])
        port         = rng.choice([0, 1], p=[0.5, 0.5])
        subdomains   = rng.randint(1, 5)
        trusted_tld  = rng.choice([0, 1], p=[0.8, 0.2])
        kw_count     = rng.randint(1, 6)
        susp_kw      = 1
        hex_enc      = rng.choice([0, 1], p=[0.4, 0.6])
        dbl_slash    = rng.choice([0, 1], p=[0.6, 0.4])
        host_ent     = rng.uniform(3.5, 5.0)
        path_ent     = rng.uniform(3.0, 5.0)
        redirect     = rng.randint(0, 3)
        gt54         = 1
        gt75         = int(url_len > 75)

        phish_samples.append([
            url_len, host_len, rng.randint(20,100), dots_host,
            dots_host+rng.randint(1,5), hyphens, rng.randint(0,3),
            slashes, q_marks, equals, at, pct, rng.randint(1,4), rng.randint(0,2),
            digits_host, special, digit_ratio, https, ip, port,
            subdomains, trusted_tld, kw_count, susp_kw,
            hex_enc, dbl_slash, host_ent, path_ent, redirect, gt54, gt75
        ])

    X = np.array(safe_samples + phish_samples)
    y = np.array([0]*800 + [1]*800)

    # shuffle
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


# ── Model class ───────────────────────────────────────────────────────────────

FEATURE_ORDER = [
    'url_length','hostname_length','path_length','num_dots_hostname',
    'num_dots_url','num_hyphens','num_underscores','num_slashes',
    'num_question_marks','num_equals','num_at','num_percent',
    'num_ampersand','num_hash','num_digits_in_host','num_special_chars',
    'digit_ratio_host','uses_https','has_ip_address','port_in_url',
    'num_subdomains','trusted_tld','keyword_count','has_suspicious_kw',
    'has_hex_encoding','double_slash_in_path','host_entropy','path_entropy',
    'redirect_count','url_len_gt54','url_len_gt75',
]

class PhishingDetector:
    def __init__(self):
        self._train()

    def _train(self):
        X, y = _make_training_data()
        self.model = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', GradientBoostingClassifier(
                n_estimators=150, max_depth=4,
                learning_rate=0.1, random_state=42
            ))
        ])
        self.model.fit(X, y)

    def _vec(self, features: dict) -> np.ndarray:
        return np.array([[features[k] for k in FEATURE_ORDER]])

    def predict(self, url: str) -> dict:
        features = extract_features(url)
        vec      = self._vec(features)

        proba    = self.model.predict_proba(vec)[0]
        phish_p  = float(proba[1])
        label    = 'phishing' if phish_p >= 0.5 else 'safe'
        risk_pct = round(phish_p * 100, 1)

        # Human-readable feature summary for the UI
        feature_summary = {
            'URL Length':           features['url_length'],
            'Uses HTTPS':           bool(features['uses_https']),
            'Has IP Address':       bool(features['has_ip_address']),
            'Suspicious Keywords':  features['keyword_count'],
            'Subdomains':           features['num_subdomains'],
            'Special Characters':   features['num_special_chars'],
            'Hex Encoding':         bool(features['has_hex_encoding']),
            'Has @ Symbol':         bool(features['num_at'] > 0),
            'Host Entropy':         round(features['host_entropy'], 2),
            'Redirect Indicators':  features['redirect_count'],
            'Trusted TLD':          bool(features['trusted_tld']),
        }

        return {
            'label':           label,
            'risk_percentage': risk_pct,
            'features':        feature_summary,
            'raw_features':    features,
        }
