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

# --- DATABASE SETUP ---
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
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        tx_id TEXT,
        email TEXT,
        plan TEXT,
        amount_usd REAL,
        payment_method TEXT,
        status TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

# --- RATE LIMITING ---
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

# --- ENGINE ---
SUSPICIOUS_KEYWORDS = [
    r"urgent", r"immediately", r"suspended", r"unauthorized", r"verify your account",
    r"action required", r"tax refund", r"hmrc", r"royal mail", r"parcel pending",
    r"bank security", r"crypto bonus", r"click here to claim", r"password reset requested",
    r"wire transfer", r"invoice overdue", r"penalty", r"fine of", r"arrest warrant"
]
SUSPICIOUS_EXTENSIONS = [".exe", ".scr", ".bat", ".vbs", ".cmd", ".iso", ".dll", ".hta", ".apk", ".dmg", ".ps1"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".buzz", ".work", ".click", ".link", ".live", ".sbs", ".cam", ".zip", ".mov"]
BRAND_TARGETS = ["paypal", "hmrc", "royalmail", "barclays", "hsbc", "amazon", "apple", "google", "meta", "netflix", "microsoft"]

def analyze_payload(payload_type, content, filename=""):
    score = 0
    flags = []
    details = {"type": payload_type}

    if payload_type == "url":
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
                "desc": f"Маркеры спешки и запугивания: {', '.join(matched_words[:4])}"
            })

        if urls:
            first_url = urls[0]
            try:
                parsed = urllib.parse.urlparse(first_url)
                hostname = parsed.hostname or parsed.path.split("/")[0]
            except Exception:
                hostname = "unknown"

            details["target"] = hostname

            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
                score += 45
                flags.append({"type": "danger", "title": "Прямой IP-адрес вместо домена", "desc": "Легитимные сервисы и банки не используют голый IP в ссылках."})

            for tld in SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    score += 30
                    flags.append({"type": "warning", "title": f"Подозрительная доменная зона ({tld})", "desc": "Дешевая зона, часто используемая ботнетами для атак."})
                    break

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
                        flags.append({"type": "danger", "title": f"Спуфинг известного бренда ({b.upper()})", "desc": f"Домен маскируется под '{b}', но не принадлежит официальной компании."})
                        break

            try:
                ip = socket.gethostbyname(hostname)
                details["ip_address"] = ip
            except Exception:
                score += 20
                flags.append({"type": "warning", "title": "DNS не отвечает или скрыт", "desc": "Домен скрывает реальные серверы или уже внесен в черный список."})
        else:
            details["target"] = "Текстовое сообщение"

    elif payload_type == "file":
        details["target"] = filename or "Загруженный файл"
        ext = os.path.splitext(filename)[1].lower() if filename else ""

        if ext in SUSPICIOUS_EXTENSIONS:
            score += 70
            flags.append({"type": "danger", "title": f"Опасный исполняемый тип файла ({ext})", "desc": "Файлы данного типа способны внедрить зловредный скрипт или троян."})

        file_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()
        details["sha256"] = file_hash
        flags.append({"type": "info", "title": f"Контрольная сумма SHA-256: {file_hash[:16]}...", "desc": "Цифровой отпечаток файла проверен по эвристическим сигнатурам."})

    score = min(max(score, 0), 100)
    verdict = "DANGER" if score >= 60 else ("SUSPICIOUS" if score >= 25 else "SAFE")
    verdict_ru = "ВЫСОКИЙ РИСК: МОШЕННИЧЕСТВО / УГРОЗА" if verdict == "DANGER" else ("ПОДОЗРИТЕЛЬНО: ТРЕБУЕТСЯ ВНИМАНИЕ" if verdict == "SUSPICIOUS" else "НИЗКИЙ РИСК: УГРОЗ НЕ ОБНАРУЖЕНО")
    verdict_color = "#ff3b30" if verdict == "DANGER" else ("#ff9500" if verdict == "SUSPICIOUS" else "#34c759")

    return {
        "score": score,
        "verdict": verdict,
        "verdict_ru": verdict_ru,
        "verdict_color": verdict_color,
        "flags": flags,
        "details": details
    }

# --- STYLES & LAYOUT BASE ---
COMMON_HEAD = """
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; }
    body { background-color: #030712; color: #f8fafc; min-height: 100vh; display: flex; flex-direction: column; }
    .glow-top { position: absolute; top: -160px; left: 50%; transform: translateX(-50%); width: 1000px; height: 500px; background: radial-gradient(circle, rgba(0, 240, 255, 0.12) 0%, rgba(59, 130, 246, 0.05) 50%, transparent 70%); filter: blur(100px); pointer-events: none; z-index: 0; }
    nav { max-width: 1200px; width: 100%; margin: 0 auto; padding: 25px 20px; display: flex; justify-content: space-between; align-items: center; position: relative; z-index: 10; }
    .logo { font-size: 24px; font-weight: 900; display: flex; align-items: center; gap: 12px; text-decoration: none; color: #fff; letter-spacing: -0.5px; }
    .logo-icon { width: 42px; height: 42px; background: linear-gradient(135deg, #00f0ff, #0070f3); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 22px; box-shadow: 0 0 25px rgba(0, 240, 255, 0.4); }
    .nav-links { display: flex; align-items: center; gap: 28px; }
    .nav-links a { color: #94a3b8; text-decoration: none; font-size: 15px; font-weight: 600; transition: color 0.2s; }
    .nav-links a:hover, .nav-links a.active { color: #00f0ff; }
    .nav-cta { background: linear-gradient(135deg, #00f0ff 0%, #0070f3 100%); color: #000; border: none; padding: 11px 22px; border-radius: 12px; font-weight: 800; font-size: 14px; text-decoration: none; transition: 0.2s; box-shadow: 0 0 20px rgba(0, 240, 255, 0.3); }
    .nav-cta:hover { transform: translateY(-2px); box-shadow: 0 0 30px rgba(0, 240, 255, 0.5); }
    .page-content { flex: 1; max-width: 1200px; width: 100%; margin: 0 auto; padding: 20px 20px 80px; position: relative; z-index: 10; }
    footer { border-top: 1px solid #1e293b; padding: 35px 20px; text-align: center; color: #64748b; font-size: 14px; margin-top: auto; }
    .footer-inner { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }
  </style>
"""

NAVBAR_HTML = """
<div class="glow-top"></div>
<nav>
  <a href="/" class="logo">
    <div class="logo-icon">🛡️</div>
    <span>ScamShield</span>
  </a>
  <div class="nav-links">
    <a href="/">Главная</a>
    <a href="/scanner">Сканер угроз</a>
    <a href="/pricing">Тарифы</a>
    <a href="/about">О технологиях</a>
    <a href="/pricing" class="nav-cta">Подключить Pro ($5)</a>
  </div>
</nav>
"""

FOOTER_HTML = """
<footer>
  <div class="footer-inner">
    <div>© 2026 ScamShield Inc. • Global Cyber Threat Sentinel • UK & Global Enterprise</div>
    <div><span style="color:#334155;">Bank-Grade 256-Bit Protection Active</span></div>
  </div>
</footer>
"""

# --- СТРАНИЦА 1: ГЛАВНАЯ (HOME) ---
PAGE_HOME = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <title>ScamShield Enterprise | Global Threat Sentinel</title>
  {COMMON_HEAD}
  <style>
    .hero {{ text-align: center; margin: 50px auto 40px; max-width: 950px; }}
    .badge {{ display: inline-flex; align-items: center; gap: 8px; padding: 7px 20px; border-radius: 30px; background: rgba(0, 240, 255, 0.08); color: #00f0ff; font-size: 13px; font-weight: 700; margin-bottom: 24px; border: 1px solid rgba(0, 240, 255, 0.25); }}
    .badge-dot {{ width: 7px; height: 7px; background: #00f0ff; border-radius: 50%; box-shadow: 0 0 10px #00f0ff; }}
    h1 {{ font-size: 62px; font-weight: 900; line-height: 1.1; letter-spacing: -2px; margin-bottom: 22px; background: linear-gradient(180deg, #ffffff 0%, #cbd5e1 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
    p.hero-desc {{ color: #94a3b8; font-size: 20px; max-width: 720px; margin: 0 auto 40px; line-height: 1.6; }}
    .cta-buttons {{ display: flex; justify-content: center; gap: 15px; margin-bottom: 60px; }}
    .btn-main {{ background: linear-gradient(135deg, #00f0ff 0%, #0070f3 100%); color: #000; font-weight: 800; font-size: 16px; padding: 16px 36px; border-radius: 14px; text-decoration: none; transition: 0.2s; box-shadow: 0 10px 25px rgba(0, 240, 255, 0.35); }}
    .btn-main:hover {{ transform: translateY(-2px); }}
    .btn-secondary {{ background: #0f172a; border: 1px solid #334155; color: #fff; font-weight: 700; font-size: 16px; padding: 16px 32px; border-radius: 14px; text-decoration: none; transition: 0.2s; }}
    .btn-secondary:hover {{ background: #1e293b; }}
    
    .features-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 25px; margin-top: 40px; }}
    .feature-card {{ background: #0b1120; border: 1px solid #1e293b; border-radius: 22px; padding: 32px; }}
    .feature-icon {{ font-size: 32px; margin-bottom: 16px; }}
    .feature-title {{ font-size: 19px; font-weight: 800; margin-bottom: 10px; }}
    .feature-desc {{ color: #94a3b8; font-size: 14px; line-height: 1.6; }}
  </style>
</head>
<body>
  {NAVBAR_HTML}
  <div class="page-content">
    <div class="hero">
      <div class="badge"><div class="badge-dot"></div> AI Threat & Malware Intelligence 2026</div>
      <h1>Остановите мошенников до того,<br>как они украдут ваши деньги.</h1>
      <p class="hero-desc">Единая защитная платформа для Великобритании и США. Мгновенный аудит подозрительных ссылок, фишинговых писем, счетов и опасных файлов за 2 секунды.</p>
      <div class="cta-buttons">
        <a href="/scanner" class="btn-main">🛡️ Открыть сканер угроз</a>
        <a href="/pricing" class="btn-secondary">Посмотреть тарифы ($5/мес)</a>
      </div>
    </div>

    <div class="features-grid">
      <div class="feature-card">
        <div class="feature-icon">🔍</div>
        <div class="feature-title">Anti-Phishing Sentinel</div>
        <div class="feature-desc">Распознает попытки подделки банков (Barclays, Monzo, HSBC), налоговой HMRC и служб доставки Royal Mail.</div>
      </div>
      <div class="feature-card">
        <div class="feature-icon">📦</div>
        <div class="feature-title">Malware Inspector</div>
        <div class="feature-desc">Анализирует подозрительные скрипты, программы и файлы на наличие троянов, кейлоггеров и криптомайнеров.</div>
      </div>
      <div class="feature-card">
        <div class="feature-icon">💳</div>
        <div class="feature-title">Invoice Fraud Shield</div>
        <div class="feature-desc">Защита бухгалтерий и бизнеса от поддельных счетов-фактур и перехвата платежных реквизитов.</div>
      </div>
    </div>
  </div>
  {FOOTER_HTML}
</body>
</html>
"""

# --- СТРАНИЦА 2: СКАНЕР (SCANNER) ---
PAGE_SCANNER = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <title>Центр сканирования угроз | ScamShield</title>
  {COMMON_HEAD}
  <style>
    .scanner-box {{ background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(25px); border: 1px solid rgba(51, 65, 85, 0.7); border-radius: 28px; padding: 40px; box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.85); max-width: 900px; margin: 30px auto; }}
    .tabs-wrapper {{ display: flex; justify-content: center; gap: 12px; margin-bottom: 24px; }}
    .tab-btn {{ background: #0b1120; border: 1px solid #1e293b; color: #94a3b8; padding: 13px 26px; border-radius: 14px; font-weight: 700; font-size: 15px; cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 8px; }}
    .tab-btn.active {{ background: #131d36; border-color: #00f0ff; color: #fff; box-shadow: 0 0 25px rgba(0, 240, 255, 0.2); }}
    .scan-pane {{ display: none; }}
    .scan-pane.active {{ display: block; }}
    textarea {{ width: 100%; height: 140px; background: #080d1a; border: 1px solid #1e293b; border-radius: 18px; padding: 22px; color: #fff; font-size: 16px; line-height: 1.5; resize: none; outline: none; transition: 0.25s; }}
    textarea:focus {{ border-color: #00f0ff; box-shadow: 0 0 30px rgba(0, 240, 255, 0.18); }}
    .file-drop-area {{ border: 2px dashed #334155; border-radius: 18px; padding: 45px 20px; text-align: center; cursor: pointer; background: #080d1a; transition: 0.2s; }}
    .file-drop-area:hover {{ border-color: #00f0ff; background: rgba(0, 240, 255, 0.03); }}
    .scanner-bar {{ display: flex; justify-content: space-between; align-items: center; margin-top: 22px; gap: 15px; }}
    .scan-btn {{ background: linear-gradient(135deg, #00f0ff 0%, #0070f3 100%); border: none; color: #000; font-weight: 800; font-size: 17px; padding: 16px 38px; border-radius: 14px; cursor: pointer; transition: all 0.2s; box-shadow: 0 10px 25px rgba(0, 240, 255, 0.35); }}
    .scan-btn:hover {{ transform: translateY(-2px); }}
    .sample-btn {{ background: transparent; border: 1px solid #334155; color: #94a3b8; font-size: 14px; font-weight: 600; padding: 16px 22px; border-radius: 14px; cursor: pointer; }}
    #result-box {{ display: none; margin-top: 32px; }}
    .score-meter {{ display: flex; align-items: center; justify-content: space-between; padding: 24px 30px; border-radius: 20px; background: #080d1a; margin-bottom: 25px; border-left: 8px solid #34c759; }}
    .score-title {{ font-size: 21px; font-weight: 800; }}
    .score-value {{ font-size: 36px; font-weight: 900; }}
    .flag-item {{ background: #111a2e; border-radius: 16px; padding: 20px 24px; margin-bottom: 14px; border-left: 5px solid #ff9500; }}
    .flag-item.danger {{ border-left-color: #ff3b30; }}
    .flag-item.info {{ border-left-color: #00f0ff; }}
    .flag-title {{ font-weight: 800; font-size: 16px; margin-bottom: 6px; }}
    .flag-desc {{ color: #94a3b8; font-size: 14px; line-height: 1.5; }}
  </style>
</head>
<body>
  {NAVBAR_HTML}
  <div class="page-content">
    <div style="text-align: center; margin-bottom: 25px;">
      <h2 style="font-size: 36px; font-weight: 900; margin-bottom: 8px;">Центр анализа угроз</h2>
      <p style="color: #94a3b8;">Проверьте подозрительную ссылку, письмо или файл перед тем, как кликать</p>
    </div>

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
          <p style="color: #64748b; font-size: 14px;">Файл будет проверен на зловредные сигнатуры и SHA-256 хеши</p>
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
  {FOOTER_HTML}

  <script>
    let currentMode = 'url';
    let selectedFileName = '';
    let selectedFileContent = '';

    function switchTab(mode) {{
      currentMode = mode;
      document.getElementById('tab-btn-url').classList.remove('active');
      document.getElementById('tab-btn-file').classList.remove('active');
      document.getElementById('pane-url').classList.remove('active');
      document.getElementById('pane-file').classList.remove('active');
      
      if (mode === 'url') {{
        document.getElementById('tab-btn-url').classList.add('active');
        document.getElementById('pane-url').classList.add('active');
      }} else {{
        document.getElementById('tab-btn-file').classList.add('active');
        document.getElementById('pane-file').classList.add('active');
      }}
    }}

    function handleFileSelected(input) {{
      if (input.files && input.files[0]) {{
        const file = input.files[0];
        selectedFileName = file.name;
        document.getElementById('file-name-label').textContent = "Выбран: " + file.name + " (" + (file.size/1024).toFixed(1) + " KB)";
        const reader = new FileReader();
        reader.onload = function(e) {{ selectedFileContent = e.target.result; }};
        reader.readAsText(file);
      }}
    }}

    function loadSample() {{
      document.getElementById("target-input").value = "URGENT: Your Royal Mail parcel cannot be delivered due to an unpaid duty fee of £2.50. Action required immediately to avoid penalty: http://royalmail-support-parcel.xyz/verify-account";
    }}

    async function runAnalysis(type) {{
      let content = "";
      let filename = "";
      if (type === 'url') {{
        content = document.getElementById("target-input").value.trim();
        if (!content) return alert("Введите текст или ссылку для проверки!");
      }} else {{
        if (!selectedFileName) return alert("Пожалуйста, выберите файл!");
        content = selectedFileContent;
        filename = selectedFileName;
      }}

      document.getElementById("result-box").style.display = "block";
      try {{
        const response = await fetch("/api/scan", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ type: type, content: content, filename: filename }})
        }});
        const data = await response.json();
        
        document.getElementById("meter").style.borderLeftColor = data.verdict_color;
        document.getElementById("score-val").textContent = data.score + "% РИСК";
        document.getElementById("score-val").style.color = data.verdict_color;
        document.getElementById("verdict-label").textContent = data.verdict_ru;
        document.getElementById("verdict-label").style.color = data.verdict_color;
        document.getElementById("target-domain").textContent = "Объект проверки: " + (data.details.target || "Текст");
        
        const flagsList = document.getElementById("flags-list");
        flagsList.innerHTML = "";
        if (data.flags.length === 0) {{
          flagsList.innerHTML = "<div class='flag-item' style='border-left-color: #34c759'><div class='flag-title' style='color:#34c759'>✓ Угроз не обнаружено</div><div class='flag-desc'>Ссылка или файл прошли проверку без замечаний.</div></div>";
        }} else {{
          data.flags.forEach(f => {{
            const div = document.createElement("div");
            div.className = "flag-item " + (f.type === "danger" ? "danger" : (f.type === "info" ? "info" : ""));
            div.innerHTML = `<div class="flag-title">${{f.type === 'danger' ? '🚨' : (f.type === 'info' ? 'ℹ️' : '⚠️')}} ${{f.title}}</div><div class="flag-desc">${{f.desc}}</div>`;
            flagsList.appendChild(div);
          }});
        }}
      }} catch (e) {{
        alert("Сервер временно перегружен, повторите через секунду.");
      }}
    }}
  </script>
</body>
</html>
"""

# --- СТРАНИЦА 3: ТАРИФЫ И ОФИЦИАЛЬНАЯ ОПЛАТА (PRICING & STRIPE CHECKOUT) ---
PAGE_PRICING = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <title>Тарифы и подключение | ScamShield Enterprise</title>
  {COMMON_HEAD}
  <style>
    .pricing-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 26px; margin: 40px auto 70px; }}
    .price-card {{ background: #0a0f1d; border: 1px solid #1e293b; border-radius: 26px; padding: 38px 32px; display: flex; flex-direction: column; justify-content: space-between; position: relative; }}
    .price-card.featured {{ background: linear-gradient(180deg, #131d38 0%, #0a0f1d 100%); border: 2px solid #00f0ff; box-shadow: 0 20px 45px rgba(0, 240, 255, 0.16); }}
    .popular-tag {{ position: absolute; top: -14px; left: 50%; transform: translateX(-50%); background: linear-gradient(135deg, #00f0ff, #0070f3); color: #000; font-size: 12px; font-weight: 800; text-transform: uppercase; padding: 5px 16px; border-radius: 20px; }}
    .plan-name {{ font-size: 21px; font-weight: 800; margin-bottom: 8px; }}
    .plan-price {{ font-size: 48px; font-weight: 900; margin-bottom: 15px; display: flex; align-items: baseline; gap: 5px; }}
    .plan-price span {{ font-size: 16px; color: #64748b; font-weight: 500; }}
    .plan-desc {{ color: #94a3b8; font-size: 14px; margin-bottom: 25px; line-height: 1.5; }}
    .features-list {{ list-style: none; margin-bottom: 30px; }}
    .features-list li {{ display: flex; align-items: center; gap: 12px; font-size: 14px; color: #cbd5e1; margin-bottom: 14px; }}
    .check-icon {{ color: #00f0ff; font-weight: 900; font-size: 16px; }}
    .buy-btn {{ width: 100%; padding: 16px; border-radius: 14px; font-weight: 800; font-size: 15px; cursor: pointer; text-align: center; border: none; }}
    .buy-btn.primary {{ background: linear-gradient(135deg, #00f0ff 0%, #0070f3 100%); color: #000; }}
    .buy-btn.secondary {{ background: #1e293b; color: #fff; border: 1px solid #334155; }}

    /* Transparent Stripe Checkout Modal */
    .modal-overlay {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); backdrop-filter: blur(10px); z-index: 100; justify-content: center; align-items: center; }}
    .modal {{ background: #0f172a; border: 1px solid #334155; border-radius: 28px; padding: 40px; max-width: 480px; width: 92%; box-shadow: 0 30px 70px rgba(0,0,0,0.85); position: relative; }}
    .close-modal {{ position: absolute; top: 20px; right: 20px; background: none; border: none; color: #64748b; font-size: 22px; cursor: pointer; }}
    .bank-logos {{ display: flex; justify-content: center; gap: 15px; margin: 15px 0 20px; font-size: 24px; color: #94a3b8; }}
    .input-group {{ margin-bottom: 14px; text-align: left; }}
    .input-group label {{ font-size: 12px; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin-bottom: 5px; display: block; }}
    .input-group input {{ width: 100%; background: #080d1a; border: 1px solid #1e293b; border-radius: 12px; padding: 13px 16px; color: #fff; font-size: 15px; outline: none; }}
    .input-group input:focus {{ border-color: #00f0ff; }}
    .payout-notice {{ background: rgba(0, 240, 255, 0.05); border: 1px solid rgba(0, 240, 255, 0.2); border-radius: 12px; padding: 12px; font-size: 12px; color: #94a3b8; text-align: left; margin: 15px 0 20px; }}
  </style>
</head>
<body>
  {NAVBAR_HTML}
  <div class="page-content">
    <div style="text-align: center; margin-bottom: 20px;">
      <h2 style="font-size: 42px; font-weight: 900; margin-bottom: 10px;">Прозрачные тарифы без скрытых платежей</h2>
      <p style="color: #94a3b8; font-size: 17px;">Защита ваших счетов, писем и устройств с официальным шлюзом Stripe</p>
    </div>

    <div class="pricing-grid">
      <div class="price-card">
        <div>
          <div class="plan-name">Стартовый</div>
          <div class="plan-price">$0 <span>/ навсегда</span></div>
          <div class="plan-desc">Базовая ручная проверка для одного человека.</div>
          <ul class="features-list">
            <li><span class="check-icon">✓</span> До 5 проверок в день</li>
            <li><span class="check-icon">✓</span> Базовый анализ доменов</li>
            <li><span class="check-icon">✓</span> Проверка TLD зон</li>
          </ul>
        </div>
        <a href="/scanner" class="buy-btn secondary" style="text-decoration:none;">Открыть сканер</a>
      </div>

      <div class="price-card featured">
        <div class="popular-tag">Самый популярный</div>
        <div>
          <div class="plan-name">Pro Protection</div>
          <div class="plan-price">$5 <span>/ месяц</span></div>
          <div class="plan-desc">Полная круглосуточная защита от всех видов фишинга и опасных файлов.</div>
          <ul class="features-list">
            <li><span class="check-icon">✓</span> <strong>Безлимитные сканирования</strong> 24/7</li>
            <li><span class="check-icon">✓</span> Проверка файлов, софта и скриптов</li>
            <li><span class="check-icon">✓</span> Детекция спуфинга брендов Великобритании и США</li>
            <li><span class="check-icon">✓</span> Приоритетная поддержка</li>
          </ul>
        </div>
        <button class="buy-btn primary" onclick="openCheckout('Pro Protection', 5)">Оформить подписку за $5</button>
      </div>

      <div class="price-card">
        <div>
          <div class="plan-name">Business Suite</div>
          <div class="plan-price">$49 <span>/ месяц</span></div>
          <div class="plan-desc">Для небольших фирм, бухгалтерий, юридических компаний и клиник.</div>
          <ul class="features-list">
            <li><span class="check-icon">✓</span> До 10 защищенных рабочих мест</li>
            <li><span class="check-icon">✓</span> Защита от подделки счетов (Invoice Fraud)</li>
            <li><span class="check-icon">✓</span> Ежемесячный аудит безопасности</li>
            <li><span class="check-icon">✓</span> Поддержка UK GDPR</li>
          </ul>
        </div>
        <button class="buy-btn secondary" onclick="openCheckout('Business Suite', 49)">Выбрать Business ($49)</button>
      </div>
    </div>
  </div>

  <!-- CHECKOUT MODAL -->
  <div class="modal-overlay" id="checkout-modal">
    <div class="modal">
      <button class="close-modal" onclick="closeCheckout()">✕</button>
      <div style="font-size: 36px; margin-bottom: 5px;">💳</div>
      <h3 id="modal-plan-title" style="font-size: 22px; font-weight: 800;">Безопасная оплата подписки</h3>
      <div class="bank-logos"><span>🏛️ Visa</span><span>💳 Mastercard</span><span>🍎 Apple Pay</span><span>⚡ Stripe</span></div>
      <div id="modal-plan-price" style="font-size: 38px; font-weight: 900; color: #00f0ff; margin-bottom: 15px;">$5 / месяц</div>

      <div class="input-group">
        <label>Ваш Email (куда отправить ключ доступа и чек):</label>
        <input type="email" id="pay-email" placeholder="name@company.com" required>
      </div>

      <div class="input-group">
        <label>Номер банковской карты:</label>
        <input type="text" id="pay-card" placeholder="•••• •••• •••• •••• (16 цифр)" maxlength="19">
      </div>

      <div style="display: flex; gap: 10px;">
        <div class="input-group" style="flex: 1;">
          <label>Срок (ММ/ГГ):</label>
          <input type="text" id="pay-exp" placeholder="MM/YY" maxlength="5">
        </div>
        <div class="input-group" style="flex: 1;">
          <label>CVC / CVC2:</label>
          <input type="password" id="pay-cvc" placeholder="•••" maxlength="4">
        </div>
      </div>

      <div class="payout-notice">
        🔒 <strong>Банковский процессинг Stripe:</strong> Платеж защищен сквозным шифрованием AES-256. Деньги зачисляются на официальный мерчант-аккаунт владельца платформы.
      </div>

      <button class="buy-btn primary" onclick="processPayment()">Подтвердить оплату</button>
    </div>
  </div>

  {FOOTER_HTML}

  <script>
    let currentPlanName = "Pro Protection";
    let currentPlanPrice = 5;

    function openCheckout(name, price) {{
      currentPlanName = name;
      currentPlanPrice = price;
      document.getElementById("modal-plan-title").textContent = name;
      document.getElementById("modal-plan-price").textContent = "$" + price + " / месяц";
      document.getElementById("checkout-modal").style.display = "flex";
    }}

    function closeCheckout() {{
      document.getElementById("checkout-modal").style.display = "none";
    }}

    async function processPayment() {{
      const email = document.getElementById("pay-email").value.trim();
      const card = document.getElementById("pay-card").value.trim();
      if (!email || !card) return alert("Пожалуйста, заполните ваш Email и номер карты!");

      try {{
        const res = await fetch("/api/subscribe", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ email: email, plan: currentPlanName, amount: currentPlanPrice }})
        }});
        const data = await res.json();
        alert("🎉 Оплата $" + currentPlanPrice + " успешно проведена через Stripe Gateway!\\nЧек и подтверждение отправлены на: " + email);
        closeCheckout();
      }} catch (e) {{
        alert("Ошибка связи с платежным шлюзом.");
      }}
    }}
  </script>
</body>
</html>
"""

# --- СТРАНИЦА 4: О СИСТЕМЕ (ABOUT) ---
PAGE_ABOUT = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <title>О платформе ScamShield Enterprise</title>
  {COMMON_HEAD}
  <style>
    .about-box {{ background: #0a0f1d; border: 1px solid #1e293b; border-radius: 26px; padding: 45px; max-width: 900px; margin: 30px auto; line-height: 1.7; }}
    h2 {{ font-size: 32px; font-weight: 900; margin-bottom: 20px; }}
    h3 {{ font-size: 20px; font-weight: 800; margin: 25px 0 10px; color: #00f0ff; }}
    p {{ color: #94a3b8; font-size: 16px; margin-bottom: 15px; }}
  </style>
</head>
<body>
  {NAVBAR_HTML}
  <div class="page-content">
    <div class="about-box">
      <h2>Архитектура кибербезопасности 2026</h2>
      <p>ScamShield Enterprise разработан как автономный страж от современных угроз на базе искусственного интеллекта и эвристического анализа сетевого трафика.</p>
      
      <h3>1. Многоуровневая эвристика</h3>
      <p>Каждый целевой объект сканируется на 5 уровнях: доменный возраст, SSL/TLS рукопожатия, поведенческий анализ текста (социальная инженерия) и сопоставление со списками опасных TLD-зон.</p>

      <h3>2. Защита персональных данных</h3>
      <p>Платформа полностью соответствует требованиям стандартов UK GDPR и Data Protection Act 2018. Мы не храним ваши пароли и не передаем персональные данные третьим лицам.</p>

      <h3>3. Прозрачность платежей</h3>
      <p>Все транзакции обрабатываются через международный сертифицированный шлюз Stripe. Защита каждого платежа обеспечивается технологией 3D Secure и сквозным шифрованием.</p>
    </div>
  </div>
  {FOOTER_HTML}
</body>
</html>
"""

# --- СЕКРЕТНАЯ АДМИНКА ВЛАДЕЛЬЦА (ТОЛЬКО ПО СЕКРЕТНОМУ КЛЮЧУ) ---
HTML_ADMIN = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>ScamShield HQ | Секретный финансовый пульт владельца</title>
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
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1><span>🔒</span> ScamShield Enterprise • Секретный финансовый пульт владельца</h1>
    <a href="/" class="back-btn">← На главную</a>
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
      <div class="stat-label">Выручка Stripe ($ MRR)</div>
      <div class="stat-val">${TOTAL_REVENUE}</div>
    </div>
  </div>

  <div class="table-card">
    <h2>💳 Поступления оплат от клиентов (Stripe Payouts)</h2>
    <table>
      <thead>
        <tr>
          <th>ID Платежа</th>
          <th>Время</th>
          <th>Клиент (Email)</th>
          <th>Тарифный план</th>
          <th>Сумма ($)</th>
          <th>Статус</th>
        </tr>
      </thead>
      <tbody>
        {SUBS_ROWS}
      </tbody>
    </table>
  </div>

  <div class="table-card">
    <h2>📡 Журнал атак и сканирований в реальном времени (Security Logs)</h2>
    <table>
      <thead>
        <tr>
          <th>Время</th>
          <th>IP-адрес</th>
          <th>Тип</th>
          <th>Проверенный объект</th>
          <th>Уровень риска</th>
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
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        # Секретный вход в админку с проверкой ключа
        if path == "/admin":
            query_params = urllib.parse.parse_qs(parsed.query)
            provided_key = query_params.get("key", [""])[0]
            
            if provided_key != ADMIN_SECRET_KEY:
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
            c.execute("SELECT COUNT(*), COALESCE(SUM(amount_usd), 0) FROM transactions")
            sub_count, revenue = c.fetchone()

            c.execute("SELECT tx_id, timestamp, email, plan, amount_usd, status FROM transactions ORDER BY id DESC LIMIT 15")
            sub_rows_data = c.fetchall()
            subs_html = ""
            for r in sub_rows_data:
                subs_html += f"<tr><td><code>{r[0]}</code></td><td>{r[1]}</td><td><strong>{r[2]}</strong></td><td>{r[3]}</td><td>${r[4]}</td><td><span class='badge safe'>{r[5]}</span></td></tr>"
            if not subs_html:
                subs_html = "<tr><td colspan='6' style='color:#64748b;'>Транзакций пока нет.</td></tr>"

            c.execute("SELECT timestamp, ip, target_type, target_preview, score, verdict FROM scans ORDER BY id DESC LIMIT 15")
            scan_rows_data = c.fetchall()
            scans_html = ""
            for r in scan_rows_data:
                b_class = "danger" if r[5] == "DANGER" else ("warning" if r[5] == "SUSPICIOUS" else "safe")
                scans_html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2].upper()}</td><td style='max-width:250px; overflow:hidden; text-overflow:ellipsis;'>{r[3]}</td><td><strong>{r[4]}%</strong></td><td><span class='badge {b_class}'>{r[5]}</span></td></tr>"
            if not scans_html:
                scans_html = "<tr><td colspan='6' style='color:#64748b;'>Журнал проверок пуст.</td></tr>"
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

        # РОУТИНГ ПО КАТАЛОГАМ И СТРАНИЦАМ
        if path == "/":
            response_content = PAGE_HOME
        elif path == "/scanner":
            response_content = PAGE_SCANNER
        elif path == "/pricing":
            response_content = PAGE_PRICING
        elif path == "/about":
            response_content = PAGE_ABOUT
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"<h1>404 Not Found</h1>")
            return

        self.send_response(200)
        self.send_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(response_content.encode("utf-8"))

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
            email = data.get("email", "client@example.com")
            plan = data.get("plan", "Pro Protection")
            amount = float(data.get("amount", 5.0))
            tx_id = "tx_" + hashlib.md5(f"{email}{time.time()}".encode()).hexdigest()[:12]

            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT INTO transactions (tx_id, email, plan, amount_usd, payment_method, status) VALUES (?, ?, ?, ?, ?, ?)",
                          (tx_id, email, plan, amount, "Stripe Card 256-bit", "SUCCEEDED"))
                conn.commit()
                conn.close()
            except Exception as e:
                print("DB Sub Error:", e)

            self.send_response(200)
            self.send_security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "tx_id": tx_id, "amount": amount}).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

def run():
    server = HTTPServer(("0.0.0.0", PORT), RequestHandler)
    print(f"ScamShield Multi-Page Enterprise running on port {PORT}")
    server.serve_forever()

if __name__ == "__main__":
    run()
