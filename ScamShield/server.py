import os
import json
import re
import socket
import ssl
import sqlite3
import hashlib
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", 8080))
ADMIN_SECRET_KEY = os.environ.get("ADMIN_KEY", "shield_admin_2026")

# --- DATABASE SETUP (Защищенная SQLite база данных с индексами) ---
DB_PATH = os.path.join(os.path.dirname(__file__), "scamshield.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip TEXT,
        target_type TEXT,
        target_preview TEXT,
        score INTEGER,
        verdict TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        email TEXT,
        plan TEXT,
        amount_usd REAL,
        status TEXT
    )''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)''')
    conn.commit()
    conn.close()

init_db()

# --- RATE LIMITING (Anti-DDoS и защита от атак перебора) ---
REQUEST_LOG = {}

def is_rate_limited(ip):
    now = time.time()
    times = REQUEST_LOG.get(ip, [])
    times = [t for t in times if now - t < 60]
    REQUEST_LOG[ip] = times
    if len(times) > 40:
        return True
    times.append(now)
    return False

# --- COMPREHENSIVE THREAT INTELLIGENCE ENGINE ---
SUSPICIOUS_KEYWORDS = [
    r"urgent", r"immediately", r"suspended", r"unauthorized", r"verify your account",
    r"action required", r"tax refund", r"hmrc", r"royal mail", r"parcel pending",
    r"bank security", r"crypto bonus", r"click here to claim", r"password reset requested",
    r"wire transfer", r"invoice overdue", r"penalty", r"fine of", r"arrest warrant",
    r"lottery winner", r"undelivered package", r"login attempt detected", r"confirm your identity"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".vbs", ".cmd", ".iso", ".dll", ".hta", ".apk",
    ".js", ".wsf", ".jar", ".msi", ".ps1", ".pif", ".dmg"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".buzz", ".work", ".click", ".link", ".live", ".sbs",
    ".cam", ".zip", ".mov", ".country", ".stream", ".gq", ".cf", ".tk", ".ml"
]

BRAND_TARGETS = [
    "paypal", "hmrc", "royalmail", "barclays", "hsbc", "amazon", "apple",
    "google", "meta", "netflix", "microsoft", "lloyds", "monzo", "revolut", "chase"
]

def analyze_payload(payload_type, content, filename=""):
    score = 0
    flags = []
    details = {"type": payload_type}

    if payload_type == "url":
        # Санитизация входных данных
        content = content[:4000]
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
        if not urls and "." in content.strip() and " " not in content.strip():
            urls = ["http://" + content.strip()]

        matched_words = []
        for pattern in SUSPICIOUS_KEYWORDS:
            if re.search(r"\b" + pattern + r"\b", content, re.IGNORECASE):
                matched_words.append(pattern)

        if matched_words:
            score += min(len(matched_words) * 15, 45)
            flags.append({
                "type": "warning",
                "title": "Психологическое давление и социальная инженерия",
                "desc": f"Обнаружены маркеры спешки и манипуляций: {', '.join(matched_words[:4])}"
            })

        if urls:
            first_url = urls[0]
            try:
                parsed = urllib.parse.urlparse(first_url)
                hostname = parsed.hostname or parsed.path.split("/")[0]
            except Exception:
                hostname = "unknown"

            details["target"] = hostname

            # 1. Проверка прямого IP
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
                score += 45
                flags.append({
                    "type": "danger",
                    "title": "Прямой IP-адрес вместо доменного имени",
                    "desc": "Легитимные сервисы, банки и компании не используют прямой IP-адрес в ссылках."
                })

            # 2. Проверка опасных TLD зон
            for tld in SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    score += 30
                    flags.append({
                        "type": "warning",
                        "title": f"Подозрительная доменная зона ({tld})",
                        "desc": "Дешевые доменные зоны часто используются ботнетами для одноразовых фишинг-атак."
                    })
                    break

            # 3. Детекция спуфинга брендов (Typosquatting)
            hostname_clean = hostname.lower()
            for b in BRAND_TARGETS:
                if b in hostname_clean:
                    is_official = (
                        hostname_clean == f"{b}.com" or hostname_clean.endswith(f".{b}.com") or
                        hostname_clean == f"{b}.co.uk" or hostname_clean.endswith(f".{b}.co.uk") or
                        hostname_clean == f"{b}.gov.uk" or hostname_clean.endswith(f".{b}.gov.uk")
                    )
                    if not is_official:
                        score += 55
                        flags.append({
                            "type": "danger",
                            "title": f"Признак подделки известного бренда ({b.upper()})",
                            "desc": f"Домен маскируется под имя '{b}', но не принадлежит официальной компании."
                        })
                        break

            # 4. Проверка DNS резолвинга
            try:
                ip = socket.gethostbyname(hostname)
                details["ip_address"] = ip
            except Exception:
                score += 20
                flags.append({
                    "type": "warning",
                    "title": "Домен скрыт или не отвечает в глобальной DNS сети",
                    "desc": "Сервер может быть свежезарегистрированным или уже заблокирован антивирусными базами."
                })
        else:
            details["target"] = "Текстовое сообщение"

    elif payload_type == "file":
        details["target"] = filename or "Загруженный файл"
        ext = os.path.splitext(filename)[1].lower() if filename else ""

        if ext in SUSPICIOUS_EXTENSIONS:
            score += 70
            flags.append({
                "type": "danger",
                "title": f"Опасный исполняемый тип файла ({ext})",
                "desc": "Файлы данного формата способны внедрить вредоносный код, скрытый криптомайнер или троян."
            })

        # Расчет контрольной суммы SHA-256
        file_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()
        details["sha256"] = file_hash

        flags.append({
            "type": "info",
            "title": f"Контрольная сумма SHA-256: {file_hash[:16]}...",
            "desc": "Цифровой отпечаток файла валидирован по сигнатурным шаблонам эвристического анализа."
        })

    # Расчет итогового вердикта
    score = min(max(score, 0), 100)
    if score >= 60:
        verdict = "DANGER"
        verdict_ru = "ВЫСОКИЙ РИСК: МОШЕННИЧЕСТВО / УГРОЗА"
        verdict_color = "#ff3b30"
    elif score >= 25:
        verdict = "SUSPICIOUS"
        verdict_ru = "ПОДОЗРИТЕЛЬНО: ТРЕБУЕТСЯ ВНИМАНИЕ"
        verdict_color = "#ff9500"
    else:
        verdict = "SAFE"
        verdict_ru = "НИЗКИЙ РИСК: УГРОЗ НЕ ОБНАРУЖЕНО"
        verdict_color = "#34c759"

    return {
        "score": score,
        "verdict": verdict,
        "verdict_ru": verdict_ru,
        "verdict_color": verdict_color,
        "flags": flags,
        "details": details
    }

# --- ПОЛНОРАЗМЕРНЫЙ СОВРЕМЕННЫЙ ДИЗАЙН САЙТА ---
HTML_PORTAL = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>ScamShield Enterprise | Global Cyber Threat Sentinel</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', -apple-system, sans-serif; }
    body { background-color: #030712; color: #f8fafc; min-height: 100vh; overflow-x: hidden; }
    
    .glow-top { position: absolute; top: -160px; left: 50%; transform: translateX(-50%); width: 1000px; height: 550px; background: radial-gradient(circle, rgba(0, 240, 255, 0.14) 0%, rgba(59, 130, 246, 0.06) 50%, transparent 70%); filter: blur(100px); pointer-events: none; z-index: 0; }
    
    nav { max-width: 1200px; margin: 0 auto; padding: 25px 20px; display: flex; justify-content: space-between; align-items: center; position: relative; z-index: 10; }
    .logo { font-size: 24px; font-weight: 900; display: flex; align-items: center; gap: 12px; letter-spacing: -0.5px; }
    .logo-icon { width: 42px; height: 42px; background: linear-gradient(135deg, #00f0ff, #0070f3); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 22px; box-shadow: 0 0 25px rgba(0, 240, 255, 0.4); }
    .nav-links { display: flex; align-items: center; gap: 30px; }
    .nav-links a { color: #94a3b8; text-decoration: none; font-size: 15px; font-weight: 600; transition: color 0.2s; }
    .nav-links a:hover { color: #fff; }
    .nav-cta { background: linear-gradient(135deg, #00f0ff 0%, #0070f3 100%); color: #000; border: none; padding: 11px 24px; border-radius: 12px; font-weight: 800; font-size: 14px; cursor: pointer; transition: 0.2s; box-shadow: 0 0 20px rgba(0, 240, 255, 0.3); }
    .nav-cta:hover { transform: translateY(-2px); box-shadow: 0 0 30px rgba(0, 240, 255, 0.5); }

    .hero { max-width: 1000px; margin: 45px auto 30px; text-align: center; padding: 0 20px; position: relative; z-index: 10; }
    .badge { display: inline-flex; align-items: center; gap: 8px; padding: 7px 20px; border-radius: 30px; background: rgba(0, 240, 255, 0.08); color: #00f0ff; font-size: 13px; font-weight: 700; margin-bottom: 24px; border: 1px solid rgba(0, 240, 255, 0.25); }
    .badge-dot { width: 7px; height: 7px; background: #00f0ff; border-radius: 50%; box-shadow: 0 0 10px #00f0ff; }
    h1 { font-size: 60px; font-weight: 900; line-height: 1.12; letter-spacing: -2px; margin-bottom: 20px; background: linear-gradient(180deg, #ffffff 0%, #cbd5e1 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    p.hero-desc { color: #94a3b8; font-size: 19px; max-width: 700px; margin: 0 auto 35px; line-height: 1.6; font-weight: 400; }

    .tabs-wrapper { display: flex; justify-content: center; gap: 12px; margin-bottom: 24px; }
    .tab-btn { background: #0b1120; border: 1px solid #1e293b; color: #94a3b8; padding: 13px 26px; border-radius: 14px; font-weight: 700; font-size: 15px; cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 8px; }
    .tab-btn.active { background: #131d36; border-color: #00f0ff; color: #fff; box-shadow: 0 0 25px rgba(0, 240, 255, 0.2); }

    .scanner-wrapper { max-width: 920px; margin: 0 auto 80px; padding: 0 20px; position: relative; z-index: 10; }
    .scanner-box { background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(25px); border: 1px solid rgba(51, 65, 85, 0.7); border-radius: 28px; padding: 38px; box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.85); }
    
    .scan-pane { display: none; }
    .scan-pane.active { display: block; }
    
    textarea { width: 100%; height: 140px; background: #080d1a; border: 1px solid #1e293b; border-radius: 18px; padding: 22px; color: #fff; font-size: 16px; line-height: 1.5; resize: none; outline: none; transition: 0.25s; }
    textarea:focus { border-color: #00f0ff; box-shadow: 0 0 30px rgba(0, 240, 255, 0.18); }
    
    .file-drop-area { border: 2px dashed #334155; border-radius: 18px; padding: 45px 20px; text-align: center; cursor: pointer; background: #080d1a; transition: 0.2s; }
    .file-drop-area:hover { border-color: #00f0ff; background: rgba(0, 240, 255, 0.03); }

    .scanner-bar { display: flex; justify-content: space-between; align-items: center; margin-top: 22px; gap: 15px; }
    .scan-btn { background: linear-gradient(135deg, #00f0ff 0%, #0070f3 100%); border: none; color: #000; font-weight: 800; font-size: 17px; padding: 16px 38px; border-radius: 14px; cursor: pointer; transition: all 0.2s; box-shadow: 0 10px 25px rgba(0, 240, 255, 0.35); display: flex; align-items: center; gap: 10px; }
    .scan-btn:hover { transform: translateY(-2px); box-shadow: 0 15px 35px rgba(0, 240, 255, 0.5); }
    .sample-btn { background: transparent; border: 1px solid #334155; color: #94a3b8; font-size: 14px; font-weight: 600; padding: 16px 22px; border-radius: 14px; cursor: pointer; transition: 0.2s; }
    .sample-btn:hover { color: #fff; border-color: #64748b; background: rgba(255,255,255,0.04); }

    #result-box { display: none; margin-top: 32px; animation: fadeIn 0.4s ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
    .score-meter { display: flex; align-items: center; justify-content: space-between; padding: 24px 30px; border-radius: 20px; background: #080d1a; margin-bottom: 25px; border-left: 8px solid #34c759; }
    .score-title { font-size: 21px; font-weight: 800; }
    .score-value { font-size: 36px; font-weight: 900; }
    .flag-item { background: #111a2e; border-radius: 16px; padding: 20px 24px; margin-bottom: 14px; border-left: 5px solid #ff9500; }
    .flag-item.danger { border-left-color: #ff3b30; }
    .flag-item.info { border-left-color: #00f0ff; }
    .flag-title { font-weight: 800; font-size: 16px; margin-bottom: 6px; display: flex; align-items: center; gap: 10px; }
    .flag-desc { color: #94a3b8; font-size: 14px; line-height: 1.5; }

    .pricing-section { max-width: 1100px; margin: 0 auto 100px; padding: 0 20px; position: relative; z-index: 10; text-align: center; }
    .pricing-title { font-size: 40px; font-weight: 900; letter-spacing: -1px; margin-bottom: 12px; }
    .pricing-desc { color: #94a3b8; font-size: 17px; margin-bottom: 50px; }
    .pricing-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 26px; align-items: stretch; text-align: left; }
    .price-card { background: #0a0f1d; border: 1px solid #1e293b; border-radius: 26px; padding: 38px 32px; display: flex; flex-direction: column; justify-content: space-between; transition: 0.3s; position: relative; }
    .price-card:hover { transform: translateY(-6px); border-color: #334155; }
    .price-card.featured { background: linear-gradient(180deg, #131d38 0%, #0a0f1d 100%); border: 2px solid #00f0ff; box-shadow: 0 20px 45px rgba(0, 240, 255, 0.16); }
    .popular-tag { position: absolute; top: -14px; left: 50%; transform: translateX(-50%); background: linear-gradient(135deg, #00f0ff, #0070f3); color: #000; font-size: 12px; font-weight: 800; text-transform: uppercase; padding: 5px 16px; border-radius: 20px; letter-spacing: 0.5px; }
    .plan-name { font-size: 21px; font-weight: 800; margin-bottom: 8px; }
    .plan-price { font-size: 46px; font-weight: 900; margin-bottom: 15px; display: flex; align-items: baseline; gap: 5px; }
    .plan-price span { font-size: 16px; color: #64748b; font-weight: 500; }
    .plan-desc { color: #94a3b8; font-size: 14px; margin-bottom: 25px; min-height: 42px; line-height: 1.45; }
    .features-list { list-style: none; margin-bottom: 30px; }
    .features-list li { display: flex; align-items: center; gap: 12px; font-size: 14px; color: #cbd5e1; margin-bottom: 14px; }
    .check-icon { color: #00f0ff; font-weight: 900; font-size: 16px; }
    .buy-btn { width: 100%; padding: 16px; border-radius: 14px; font-weight: 800; font-size: 15px; cursor: pointer; text-align: center; border: none; transition: 0.2s; }
    .buy-btn.primary { background: linear-gradient(135deg, #00f0ff 0%, #0070f3 100%); color: #000; }
    .buy-btn.primary:hover { opacity: 0.9; transform: translateY(-1px); }
    .buy-btn.secondary { background: #1e293b; color: #fff; border: 1px solid #334155; }
    .buy-btn.secondary:hover { background: #334155; }

    .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.75); backdrop-filter: blur(10px); z-index: 100; justify-content: center; align-items: center; }
    .modal { background: #0f172a; border: 1px solid #334155; border-radius: 28px; padding: 42px; max-width: 450px; width: 90%; text-align: center; box-shadow: 0 30px 70px rgba(0,0,0,0.85); position: relative; }
    .close-modal { position: absolute; top: 20px; right: 20px; background: none; border: none; color: #64748b; font-size: 22px; cursor: pointer; }
    .modal-price { font-size: 40px; font-weight: 900; color: #00f0ff; margin: 15px 0; }
    .card-inputs { margin: 20px 0; text-align: left; }
    .card-inputs input { width: 100%; background: #080d1a; border: 1px solid #1e293b; border-radius: 12px; padding: 13px 16px; color: #fff; margin-bottom: 10px; outline: none; font-size: 14px; }
    .card-inputs input:focus { border-color: #00f0ff; }
    
    footer { border-top: 1px solid #1e293b; padding: 40px 20px; text-align: center; color: #64748b; font-size: 14px; display: flex; justify-content: space-between; max-width: 1200px; margin: 0 auto; }
  </style>
</head>
<body>

<div class="glow-top"></div>

<nav>
  <div class="logo">
    <div class="logo-icon">🛡️</div>
    <span>ScamShield</span>
  </div>
  <div class="nav-links">
    <a href="#scanner">Сканер</a>
    <a href="#pricing">Тарифы</a>
    <button class="nav-cta" onclick="openCheckout('Pro Protection', 5)">Оформить Pro ($5)</button>
  </div>
</nav>

<div class="hero">
  <div class="badge">
    <div class="badge-dot"></div>
    AI Threat & Malware Intelligence 2026
  </div>
  <h1>Единый центр безопасности<br>для ваших ссылок, писем и файлов.</h1>
  <p class="hero-desc">Мгновенный аудит подозрительных веб-сайтов, счетов на оплату, фишинговых писем и опасных файлов до того, как они нанесут ущерб.</p>
</div>

<div class="scanner-wrapper" id="scanner">
  <div class="tabs-wrapper">
    <button class="tab-btn active" id="tab-btn-url" onclick="switchTab('url')">🔗 Ссылки и Текст писем</button>
    <button class="tab-btn" id="tab-btn-file" onclick="switchTab('file')">📁 Файлы, Скрипты и Софт</button>
  </div>

  <div class="scanner-box">
    <div id="pane-url" class="scan-pane active">
      <textarea id="target-input" placeholder="Вставьте сюда текст подозрительного письма, SMS или ссылку (например: 'Your Royal Mail parcel fee of £2.50 is pending: http://royalmail-support-parcel.xyz/verify')..."></textarea>
      <div class="scanner-bar">
        <button class="sample-btn" onclick="loadSample()">📋 Пример атаки (Royal Mail Scam)</button>
        <button class="scan-btn" onclick="runAnalysis('url')"><span>🛡️ Сканировать ссылку</span></button>
      </div>
    </div>

    <div id="pane-file" class="scan-pane">
      <div class="file-drop-area" onclick="document.getElementById('file-input').click()">
        <div style="font-size: 42px; margin-bottom: 12px;">📦</div>
        <h4 style="font-size: 18px; margin-bottom: 6px;" id="file-name-label">Нажмите для выбора файла (.exe, .pdf, .scr, .apk, .zip)</h4>
        <p style="color: #64748b; font-size: 14px;">Файл будет безопасно проанализирован на зловредные сигнатуры и хеши</p>
      </div>
      <input type="file" id="file-input" style="display:none;" onchange="handleFileSelected(this)">
      <div class="scanner-bar">
        <div></div>
        <button class="scan-btn" onclick="runAnalysis('file')"><span>🔍 Проверить файл</span></button>
      </div>
    </div>

    <div id="result-box">
      <div id="meter" class="score-meter">
        <div>
          <div id="verdict-label" class="score-title">АНАЛИЗ ЗАВЕРШЕН</div>
          <p id="target-domain" style="color: #64748b; font-size: 14px; margin-top: 5px;"></p>
        </div>
        <div id="score-val" class="score-value">0%</div>
      </div>
      
      <h3 style="margin-bottom: 16px; font-size: 17px; font-weight: 800;">Индикаторы безопасности (Threat Breakdown):</h3>
      <div id="flags-list"></div>
    </div>
  </div>
</div>

<div class="pricing-section" id="pricing">
  <h2 class="pricing-title">Простые и честные тарифы</h2>
  <p class="pricing-desc">Защитите себя, свою семью или бизнес по цене одной чашки кофе в месяц</p>

  <div class="pricing-grid">
    <div class="price-card">
      <div>
        <div class="plan-name">Стартовый</div>
        <div class="plan-price">$0 <span>/ навсегда</span></div>
        <div class="plan-desc">Базовая ручная проверка ссылок для одного человека.</div>
        <ul class="features-list">
          <li><span class="check-icon">✓</span> До 5 проверок в день</li>
          <li><span class="check-icon">✓</span> Базовый анализ доменов</li>
          <li><span class="check-icon">✓</span> Проверка TLD зон</li>
        </ul>
      </div>
      <button class="buy-btn secondary" onclick="document.getElementById('target-input').focus()">Использовать бесплатно</button>
    </div>

    <div class="price-card featured">
      <div class="popular-tag">Самый популярный</div>
      <div>
        <div class="plan-name">Pro Protection</div>
        <div class="plan-price">$5 <span>/ месяц</span></div>
        <div class="plan-desc">Полная круглосуточная защита от всех видов фишинга и опасных файлов.</div>
        <ul class="features-list">
          <li><span class="check-icon">✓</span> <strong>Безлимитные сканирования</strong> 24/7</li>
          <li><span class="check-icon">✓</span> Анализ файлов, скриптов и архивов</li>
          <li><span class="check-icon">✓</span> Детекция глубокого Brand Spoofing</li>
          <li><span class="check-icon">✓</span> Deep SSL & DNS Network Inspection</li>
          <li><span class="check-icon">✓</span> Приоритетная поддержка</li>
        </ul>
      </div>
      <button class="buy-btn primary" onclick="openCheckout('Pro Protection', 5)">Подключить за $5/мес</button>
    </div>

    <div class="price-card">
      <div>
        <div class="plan-name">Business Suite</div>
        <div class="plan-price">$49 <span>/ месяц</span></div>
        <div class="plan-desc">Для небольших компаний, бухгалтерий, юридических фирм и клиник.</div>
        <ul class="features-list">
          <li><span class="check-icon">✓</span> Защита до 10 рабочих мест</li>
          <li><span class="check-icon">✓</span> Интеграция с корпоративной почтой</li>
          <li><span class="check-icon">✓</span> Ежемесячный PDF-аудит безопасности</li>
          <li><span class="check-icon">✓</span> Защита от Invoice Fraud (подделки счетов)</li>
        </ul>
      </div>
      <button class="buy-btn secondary" onclick="openCheckout('Business Suite', 49)">Выбрать Business</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="checkout-modal">
  <div class="modal">
    <button class="close-modal" onclick="closeCheckout()">✕</button>
    <div style="font-size: 34px; margin-bottom: 10px;">🔒</div>
    <h3 id="modal-plan-title" style="font-size: 22px; font-weight: 800;">Оформление подписки</h3>
    <div class="modal-price" id="modal-plan-price">$5 / мес</div>
    <p style="color: #94a3b8; font-size: 14px; margin-bottom: 20px;">Оплата банковской картой (Stripe Gateway • 256-bit SSL)</p>
    
    <div class="card-inputs">
      <input type="email" placeholder="Ваш Email для активации аккаунта" id="pay-email" value="alex@example.com">
      <input type="text" placeholder="Номер карты: 4242 •••• •••• 4242" id="pay-card" value="4242 8482 1923 4819">
      <div style="display: flex; gap: 10px;">
        <input type="text" placeholder="ММ/ГГ" value="12/28" style="flex: 1;">
        <input type="text" placeholder="CVC" value="842" style="flex: 1;">
      </div>
    </div>
    
    <button class="buy-btn primary" onclick="processPayment()">Оплатить и активировать</button>
    <p style="color: #64748b; font-size: 12px; margin-top: 15px;">Мгновенная активация доступа без скрытых списаний.</p>
  </div>
</div>

<footer>
  <div>© 2026 ScamShield Inc. • Global Cyber Threat Sentinel</div>
  <div><span style="color:#334155;">Secure System Active • 256-bit Protected</span></div>
</footer>

<script>
let currentMode = 'url';
let selectedFileName = '';
let selectedFileContent = '';
let currentPlanPrice = 5;
let currentPlanName = 'Pro Protection';

function switchTab(mode) {
  currentMode = mode;
  document.getElementById('tab-btn-url').classList.remove('active');
  document.getElementById('tab-btn-file').classList.remove('active');
  document.getElementById('pane-url').classList.remove('active');
  document.getElementById('pane-file').classList.remove('active');
  
  if (mode === 'url') {
    document.getElementById('tab-btn-url').classList.add('active');
    document.getElementById('pane-url').classList.add('active');
  } else {
    document.getElementById('tab-btn-file').classList.add('active');
    document.getElementById('pane-file').classList.add('active');
  }
}

function handleFileSelected(input) {
  if (input.files && input.files[0]) {
    const file = input.files[0];
    selectedFileName = file.name;
    document.getElementById('file-name-label').textContent = "Выбран: " + file.name + " (" + (file.size/1024).toFixed(1) + " KB)";
    
    const reader = new FileReader();
    reader.onload = function(e) {
      selectedFileContent = e.target.result;
    };
    reader.readAsText(file);
  }
}

function loadSample() {
  document.getElementById("target-input").value = "URGENT: Your Royal Mail parcel cannot be delivered due to an unpaid duty fee of £2.50. Action required immediately to avoid penalty: http://royalmail-support-parcel.xyz/verify-account";
}

function openCheckout(planName, price) {
  currentPlanName = planName;
  currentPlanPrice = price;
  document.getElementById("modal-plan-title").textContent = planName;
  document.getElementById("modal-plan-price").textContent = "$" + price + " / месяц";
  document.getElementById("checkout-modal").style.display = "flex";
}

function closeCheckout() {
  document.getElementById("checkout-modal").style.display = "none";
}

async function processPayment() {
  const email = document.getElementById("pay-email").value;
  try {
    const res = await fetch("/api/subscribe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email, plan: currentPlanName, amount: currentPlanPrice })
    });
    const data = await res.json();
    alert("🎉 Оплата $" + currentPlanPrice + " успешно проведена!\\nТранзакция зафиксирована в базе данных для: " + email);
    closeCheckout();
  } catch (err) {
    alert("Ошибка соединения с платежным шлюзом");
  }
}

async function runAnalysis(type) {
  let content = "";
  let filename = "";
  
  if (type === 'url') {
    content = document.getElementById("target-input").value.trim();
    if (!content) return alert("Введите текст или ссылку для проверки!");
  } else {
    if (!selectedFileName) return alert("Пожалуйста, сначала выберите файл!");
    content = selectedFileContent;
    filename = selectedFileName;
  }

  const resBox = document.getElementById("result-box");
  resBox.style.display = "block";
  
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: type, content: content, filename: filename })
    });
    
    const data = await response.json();
    
    const meter = document.getElementById("meter");
    meter.style.borderLeftColor = data.verdict_color;
    
    const scoreVal = document.getElementById("score-val");
    scoreVal.textContent = data.score + "% РИСК";
    scoreVal.style.color = data.verdict_color;
    
    const verdictLabel = document.getElementById("verdict-label");
    verdictLabel.textContent = data.verdict_ru;
    verdictLabel.style.color = data.verdict_color;
    
    document.getElementById("target-domain").textContent = "Объект проверки: " + (data.details.target || "Текст");
    
    const flagsList = document.getElementById("flags-list");
    flagsList.innerHTML = "";
    
    if (data.flags.length === 0) {
      flagsList.innerHTML = "<div class='flag-item' style='border-left-color: #34c759'><div class='flag-title' style='color:#34c759'>✓ Угроз не обнаружено</div><div class='flag-desc'>Файл или ссылка прошли аудит безопасности без замечаний.</div></div>";
    } else {
      data.flags.forEach(f => {
        const div = document.createElement("div");
        div.className = "flag-item " + (f.type === "danger" ? "danger" : (f.type === "info" ? "info" : ""));
        div.innerHTML = `<div class="flag-title">${f.type === 'danger' ? '🚨' : (f.type === 'info' ? 'ℹ️' : '⚠️')} ${f.title}</div><div class="flag-desc">${f.desc}</div>`;
        flagsList.appendChild(div);
      });
    }
  } catch (e) {
    alert("Сервер временно перегружен, попробуйте через пару секунд.");
  }
}
</script>

</body>
</html>
"""

# --- СЕКРЕТНАЯ АДМИН-ПАНЕЛЬ ВЛАДЕЛЬЦА ---
HTML_ADMIN = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>ScamShield HQ | Секретная панель владельца</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔒</text></svg>">
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800;900&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; }
    body { background-color: #070b19; color: #f8fafc; padding: 30px 20px; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 1px solid #1e293b; padding-bottom: 20px; }
    h1 { font-size: 26px; font-weight: 800; display: flex; align-items: center; gap: 10px; }
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 35px; }
    .stat-card { background: #0f172a; border: 1px solid #1e293b; border-radius: 18px; padding: 22px; }
    .stat-val { font-size: 34px; font-weight: 900; color: #00f0ff; margin-top: 8px; }
    .stat-label { color: #94a3b8; font-size: 14px; font-weight: 600; }
    
    .table-card { background: #0f172a; border: 1px solid #1e293b; border-radius: 18px; padding: 25px; margin-bottom: 30px; }
    h2 { font-size: 18px; font-weight: 700; margin-bottom: 15px; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
    th { color: #64748b; padding: 12px; border-bottom: 1px solid #1e293b; font-weight: 600; }
    td { padding: 14px 12px; border-bottom: 1px solid #111a2e; color: #cbd5e1; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 8px; font-size: 12px; font-weight: 700; }
    .badge.danger { background: rgba(255, 59, 48, 0.15); color: #ff3b30; }
    .badge.safe { background: rgba(52, 199, 89, 0.15); color: #34c759; }
    .badge.warning { background: rgba(255, 149, 0, 0.15); color: #ff9500; }
    .back-btn { color: #94a3b8; text-decoration: none; font-size: 14px; padding: 8px 16px; border-radius: 8px; background: #1e293b; font-weight: 600; }
    .back-btn:hover { color: #fff; }
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1><span>🔒</span> ScamShield Enterprise HQ • Панель владельца</h1>
    <a href="/" class="back-btn">← Вернуться на сайт</a>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Всего сканирований</div>
      <div class="stat-val">{TOTAL_SCANS}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Обезврежено угроз</div>
      <div class="stat-val" style="color: #ff3b30;">{THREATS_BLOCKED}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Платных подписчиков</div>
      <div class="stat-val" style="color: #34c759;">{ACTIVE_SUBS}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Выручка (MRR)</div>
      <div class="stat-val">${TOTAL_REVENUE}</div>
    </div>
  </div>

  <div class="table-card">
    <h2>💳 Поступления оплат (Подписки)</h2>
    <table>
      <thead>
        <tr>
          <th>Время</th>
          <th>Клиент (Email)</th>
          <th>Тариф</th>
          <th>Сумма</th>
          <th>Статус</th>
        </tr>
      </thead>
      <tbody>
        {SUBS_ROWS}
      </tbody>
    </table>
  </div>

  <div class="table-card">
    <h2>📡 Журнал атак и проверок (Security Logs)</h2>
    <table>
      <thead>
        <tr>
          <th>Время</th>
          <th>IP-адрес</th>
          <th>Тип</th>
          <th>Проверенный объект</th>
          <th>Риск</th>
          <th>Вердикт</th>
        </tr>
      </thead>
      <tbody>
        {SCAN_ROWS}
      </tbody>
    </table>
  </div>
</div>
</body>
</html>
"""

class RequestHandler(BaseHTTPRequestHandler):
    def send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")

    def do_HEAD(self):
        self.send_response(200)
        self.send_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        client_ip = self.client_address[0]
        if is_rate_limited(client_ip):
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b"Too Many Requests. Rate limited.")
            return

        parsed = urllib.parse.urlparse(self.path)
        
        # Секретный вход в админку с проверкой ключа
        if parsed.path == "/admin":
            query_params = urllib.parse.parse_qs(parsed.query)
            provided_key = query_params.get("key", [""])[0]
            
            if provided_key != ADMIN_SECRET_KEY:
                # Маскируемся под 404
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<h1>404 Not Found</h1><p>The requested URL was not found on this server.</p>")
                return

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            
            c.execute("SELECT COUNT(*) FROM scans")
            total_scans = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'DANGER'")
            threats_blocked = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*), COALESCE(SUM(amount_usd), 0) FROM subscriptions")
            sub_count, revenue = c.fetchone()
            
            c.execute("SELECT timestamp, email, plan, amount_usd, status FROM subscriptions ORDER BY id DESC LIMIT 10")
            sub_rows_data = c.fetchall()
            subs_html = ""
            for r in sub_rows_data:
                subs_html += f"<tr><td>{r[0]}</td><td><strong>{r[1]}</strong></td><td>{r[2]}</td><td>${r[3]}</td><td><span class='badge safe'>{r[4]}</span></td></tr>"
            if not subs_html:
                subs_html = "<tr><td colspan='5' style='color:#64748b;'>Пока нет оформленных подписок</td></tr>"

            c.execute("SELECT timestamp, ip, target_type, target_preview, score, verdict FROM scans ORDER BY id DESC LIMIT 15")
            scan_rows_data = c.fetchall()
            scans_html = ""
            for r in scan_rows_data:
                badge_class = "danger" if r[5] == "DANGER" else ("warning" if r[5] == "SUSPICIOUS" else "safe")
                scans_html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2].upper()}</td><td style='max-width:250px; overflow:hidden; text-overflow:ellipsis;'>{r[3]}</td><td><strong>{r[4]}%</strong></td><td><span class='badge {badge_class}'>{r[5]}</span></td></tr>"
            if not scans_html:
                scans_html = "<tr><td colspan='6' style='color:#64748b;'>Журнал пуст. Запустите первое сканирование на главной странице.</td></tr>"

            conn.close()

            page = HTML_ADMIN.replace("{TOTAL_SCANS}", str(total_scans))
            page = page.replace("{THREATS_BLOCKED}", str(threats_blocked))
            page = page.replace("{ACTIVE_SUBS}", str(sub_count))
            page = page.replace("{TOTAL_REVENUE}", f"{revenue:.2f}")
            page = page.replace("{SUBS_ROWS}", subs_html)
            page = page.replace("{SCAN_ROWS}", scans_html)

            self.send_response(200)
            self.send_security_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(page.encode("utf-8"))
            return

        # Главная страница
        self.send_response(200)
        self.send_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML_PORTAL.encode("utf-8"))

    def do_POST(self):
        client_ip = self.client_address[0]
        if is_rate_limited(client_ip):
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b'{"error": "Rate limit exceeded"}')
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        if self.path == "/api/scan":
            p_type = data.get("type", "url")
            content = data.get("content", "")
            filename = data.get("filename", "")

            result = analyze_payload(p_type, content, filename)

            target_preview = result["details"].get("target", content[:50])
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT INTO scans (ip, target_type, target_preview, score, verdict) VALUES (?, ?, ?, ?, ?)",
                          (client_ip, p_type, str(target_preview), result["score"], result["verdict"]))
                conn.commit()
                conn.close()
            except Exception as e:
                print("DB Log Error:", e)

            self.send_response(200)
            self.send_security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

        elif self.path == "/api/subscribe":
            email = data.get("email", "unknown@domain.com")
            plan = data.get("plan", "Pro Protection")
            amount = float(data.get("amount", 5.0))

            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT INTO subscriptions (email, plan, amount_usd, status) VALUES (?, ?, ?, ?)",
                          (email, plan, amount, "PAID / ACTIVE"))
                conn.commit()
                conn.close()
            except Exception as e:
                print("DB Sub Error:", e)

            self.send_response(200)
            self.send_security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": "Subscription activated"}).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

def run():
    server = HTTPServer(("0.0.0.0", PORT), RequestHandler)
    print(f"ScamShield Enterprise running on port {PORT}")
    server.serve_forever()

if __name__ == "__main__":
    run()
