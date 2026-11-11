import json
import re
import socket
import ssl
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8080

SUSPICIOUS_KEYWORDS = [
    r"urgent", r"immediately", r"suspended", r"unauthorized", r"verify your account",
    r"action required", r"tax refund", r"hmrc", r"royal mail", r"parcel pending",
    r"bank security", r"crypto bonus", r"click here to claim", r"password reset requested",
    r"wire transfer", r"invoice overdue", r"penalty", r"fine of", r"arrest warrant"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".buzz", ".work", ".click", ".link", ".live", ".sbs", ".cam"]

def analyze_target(text_input):
    results = {
        "score": 0,
        "verdict": "SAFE",
        "flags": [],
        "details": {}
    }
    
    score = 0
    flags = []
    
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text_input)
    if not urls:
        potential_domain = text_input.strip().split()[0] if text_input.strip() else ""
        if "." in potential_domain and " " not in potential_domain:
            urls = ["http://" + potential_domain]
            
    matched_words = []
    for pattern in SUSPICIOUS_KEYWORDS:
        if re.search(pattern, text_input, re.IGNORECASE):
            matched_words.append(pattern.replace(r"\b", ""))
            
    if matched_words:
        added = len(matched_words) * 15
        score += min(added, 45)
        flags.append({
            "type": "warning",
            "title": "Психологическое давление и социальная инженерия",
            "desc": f"Обнаружены маркеры спешки и запугивания: {', '.join(matched_words[:4])}"
        })
        
    if urls:
        first_url = urls[0]
        parsed = urllib.parse.urlparse(first_url)
        hostname = parsed.hostname or parsed.path.split("/")[0]
        results["details"]["target_domain"] = hostname
        
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            score += 40
            flags.append({
                "type": "danger",
                "title": "Прямой IP-адрес вместо доменного имени",
                "desc": "Легитимные сервисы и банки никогда не используют «голый» IP в ссылках."
            })
            
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                score += 30
                flags.append({
                    "type": "warning",
                    "title": f"Высокорисковая доменная зона ({tld})",
                    "desc": "Зоны .xyz, .top, .buzz часто используются ботнетами для кратковременных атак."
                })
                break
                
        brands = ["paypal", "hmrc", "royalmail", "barclays", "hsbc", "amazon", "apple", "google", "meta"]
        for b in brands:
            if b in hostname.lower() and not hostname.lower().endswith(f"{b}.com") and not hostname.lower().endswith(f"{b}.co.uk"):
                score += 50
                flags.append({
                    "type": "danger",
                    "title": f"Попытка спуфинга бренда ({b.upper()})",
                    "desc": f"Домен маскируется под '{b}', но не принадлежит официальной компании. 99% фишинг!"
                })
                break
                
        try:
            ip = socket.gethostbyname(hostname)
            results["details"]["ip_address"] = ip
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        results["details"]["ssl_issuer"] = dict(x[0] for x in cert.get("issuer", []))
        except Exception:
            score += 20
            flags.append({
                "type": "warning",
                "title": "Домен скрывает DNS или недоступен",
                "desc": "Не удалось установить прямое защищенное SSL-соединение."
            })
    else:
        results["details"]["target_domain"] = "Текстовое сообщение"

    score = min(max(score, 0), 100)
    results["score"] = score
    
    if score >= 60:
        results["verdict"] = "DANGER"
        results["verdict_ru"] = "ВЫСОКИЙ РИСК: МОШЕННИЧЕСТВО"
        results["verdict_color"] = "#ff3b30"
    elif score >= 25:
        results["verdict"] = "SUSPICIOUS"
        results["verdict_ru"] = "ПОДОЗРИТЕЛЬНО: ТРЕБУЕТСЯ ВНИМАНИЕ"
        results["verdict_color"] = "#ff9500"
    else:
        results["verdict"] = "SAFE"
        results["verdict_ru"] = "НИЗКИЙ РИСК: УГРОЗ НЕ ОБНАРУЖЕНО"
        results["verdict_color"] = "#34c759"
        
    results["flags"] = flags
    return results

HTML_PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>ScamShield Enterprise | AI Cyber Sentinel</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', -apple-system, sans-serif; }
    body { background-color: #060913; color: #f8fafc; min-height: 100vh; overflow-x: hidden; }
    
    .glow-top { position: absolute; top: -150px; left: 50%; transform: translateX(-50%); width: 800px; height: 500px; background: radial-gradient(circle, rgba(0, 240, 255, 0.12) 0%, rgba(59, 130, 246, 0.05) 50%, transparent 70%); filter: blur(80px); pointer-events: none; z-index: 0; }
    
    nav { max-width: 1200px; margin: 0 auto; padding: 25px 20px; display: flex; justify-content: space-between; align-items: center; position: relative; z-index: 10; }
    .logo { font-size: 24px; font-weight: 800; display: flex; align-items: center; gap: 10px; letter-spacing: -0.5px; }
    .logo-icon { width: 38px; height: 38px; background: linear-gradient(135deg, #00f0ff, #0070f3); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 20px; box-shadow: 0 0 20px rgba(0, 240, 255, 0.4); }
    .nav-links { display: flex; align-items: center; gap: 30px; }
    .nav-links a { color: #94a3b8; text-decoration: none; font-size: 15px; font-weight: 500; transition: color 0.2s; }
    .nav-links a:hover { color: #fff; }
    .nav-cta { background: #1e293b; color: #fff; border: 1px solid #334155; padding: 9px 18px; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: 0.2s; }
    .nav-cta:hover { background: #334155; }

    .hero { max-width: 1000px; margin: 40px auto 30px; text-align: center; padding: 0 20px; position: relative; z-index: 10; }
    .badge { display: inline-flex; align-items: center; gap: 8px; padding: 6px 16px; border-radius: 30px; background: rgba(0, 240, 255, 0.08); color: #00f0ff; font-size: 13px; font-weight: 700; margin-bottom: 20px; border: 1px solid rgba(0, 240, 255, 0.25); }
    .badge-dot { width: 6px; height: 6px; background: #00f0ff; border-radius: 50%; box-shadow: 0 0 8px #00f0ff; }
    h1 { font-size: 56px; font-weight: 800; line-height: 1.15; letter-spacing: -1.5px; margin-bottom: 18px; background: linear-gradient(180deg, #ffffff 0%, #cbd5e1 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    p.hero-desc { color: #94a3b8; font-size: 18px; max-width: 650px; margin: 0 auto 35px; line-height: 1.6; }

    .scanner-wrapper { max-width: 900px; margin: 0 auto 80px; padding: 0 20px; position: relative; z-index: 10; }
    .scanner-box { background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(20px); border: 1px solid rgba(51, 65, 85, 0.7); border-radius: 24px; padding: 35px; box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.7); }
    textarea { width: 100%; height: 140px; background: #0b1120; border: 1px solid #1e293b; border-radius: 16px; padding: 20px; color: #fff; font-size: 16px; line-height: 1.5; resize: none; outline: none; transition: all 0.25s; }
    textarea:focus { border-color: #00f0ff; box-shadow: 0 0 25px rgba(0, 240, 255, 0.15); }
    .scanner-bar { display: flex; justify-content: space-between; align-items: center; margin-top: 20px; gap: 15px; }
    .scan-btn { background: linear-gradient(135deg, #00f0ff 0%, #0070f3 100%); border: none; color: #000; font-weight: 800; font-size: 17px; padding: 16px 36px; border-radius: 14px; cursor: pointer; transition: all 0.2s; box-shadow: 0 10px 25px rgba(0, 240, 255, 0.3); display: flex; align-items: center; gap: 10px; }
    .scan-btn:hover { transform: translateY(-2px); box-shadow: 0 15px 35px rgba(0, 240, 255, 0.45); }
    .sample-btn { background: transparent; border: 1px solid #334155; color: #94a3b8; font-size: 14px; font-weight: 600; padding: 16px 22px; border-radius: 14px; cursor: pointer; transition: 0.2s; }
    .sample-btn:hover { color: #fff; border-color: #64748b; background: rgba(255,255,255,0.03); }

    #result-box { display: none; margin-top: 30px; animation: fadeIn 0.4s ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    .score-meter { display: flex; align-items: center; justify-content: space-between; padding: 24px 28px; border-radius: 18px; background: #0b1120; margin-bottom: 25px; border-left: 8px solid #34c759; }
    .score-title { font-size: 20px; font-weight: 800; letter-spacing: -0.3px; }
    .score-value { font-size: 34px; font-weight: 900; }
    .flag-item { background: #111a2e; border-radius: 14px; padding: 18px 22px; margin-bottom: 12px; border-left: 5px solid #ff9500; }
    .flag-item.danger { border-left-color: #ff3b30; }
    .flag-title { font-weight: 700; font-size: 16px; margin-bottom: 6px; display: flex; align-items: center; gap: 10px; }
    .flag-desc { color: #94a3b8; font-size: 14px; line-height: 1.5; }

    .pricing-section { max-width: 1100px; margin: 0 auto 100px; padding: 0 20px; position: relative; z-index: 10; text-align: center; }
    .pricing-title { font-size: 38px; font-weight: 800; letter-spacing: -1px; margin-bottom: 12px; }
    .pricing-desc { color: #94a3b8; font-size: 16px; margin-bottom: 50px; }
    .pricing-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 25px; align-items: stretch; text-align: left; }
    
    .price-card { background: #0f172a; border: 1px solid #1e293b; border-radius: 24px; padding: 35px 30px; display: flex; flex-direction: column; justify-content: space-between; transition: 0.3s; position: relative; }
    .price-card:hover { transform: translateY(-5px); border-color: #334155; }
    .price-card.featured { background: linear-gradient(180deg, #131d36 0%, #0f172a 100%); border: 2px solid #00f0ff; box-shadow: 0 20px 40px rgba(0, 240, 255, 0.15); }
    .popular-tag { position: absolute; top: -14px; left: 50%; transform: translateX(-50%); background: linear-gradient(135deg, #00f0ff, #0070f3); color: #000; font-size: 12px; font-weight: 800; text-transform: uppercase; padding: 4px 14px; border-radius: 20px; letter-spacing: 0.5px; }

    .plan-name { font-size: 20px; font-weight: 700; margin-bottom: 8px; }
    .plan-price { font-size: 44px; font-weight: 900; margin-bottom: 15px; display: flex; align-items: baseline; gap: 5px; }
    .plan-price span { font-size: 16px; color: #64748b; font-weight: 500; }
    .plan-desc { color: #94a3b8; font-size: 14px; margin-bottom: 25px; min-height: 42px; line-height: 1.4; }
    
    .features-list { list-style: none; margin-bottom: 30px; }
    .features-list li { display: flex; align-items: center; gap: 12px; font-size: 14px; color: #cbd5e1; margin-bottom: 14px; }
    .check-icon { color: #00f0ff; font-weight: 900; font-size: 16px; }

    .buy-btn { width: 100%; padding: 15px; border-radius: 12px; font-weight: 700; font-size: 15px; cursor: pointer; text-align: center; border: none; transition: 0.2s; }
    .buy-btn.primary { background: linear-gradient(135deg, #00f0ff 0%, #0070f3 100%); color: #000; }
    .buy-btn.primary:hover { opacity: 0.9; }
    .buy-btn.secondary { background: #1e293b; color: #fff; border: 1px solid #334155; }
    .buy-btn.secondary:hover { background: #334155; }

    .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); backdrop-filter: blur(8px); z-index: 100; justify-content: center; align-items: center; }
    .modal { background: #0f172a; border: 1px solid #334155; border-radius: 24px; padding: 40px; max-width: 440px; width: 90%; text-align: center; box-shadow: 0 30px 60px rgba(0,0,0,0.8); position: relative; }
    .close-modal { position: absolute; top: 20px; right: 20px; background: none; border: none; color: #64748b; font-size: 20px; cursor: pointer; }
    .modal-price { font-size: 38px; font-weight: 900; color: #00f0ff; margin: 15px 0; }
    .card-inputs { margin: 20px 0; text-align: left; }
    .card-inputs input { width: 100%; background: #0b1120; border: 1px solid #1e293b; border-radius: 10px; padding: 12px 15px; color: #fff; margin-bottom: 10px; outline: none; font-size: 14px; }
    .card-inputs input:focus { border-color: #00f0ff; }
    
    footer { border-top: 1px solid #1e293b; padding: 40px 20px; text-align: center; color: #64748b; font-size: 14px; }
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
    <a href="#pricing">Enterprise</a>
    <button class="nav-cta" onclick="openCheckout('Pro Protection', '$5')">Оформить Pro</button>
  </div>
</nav>

<div class="hero">
  <div class="badge">
    <div class="badge-dot"></div>
    AI Threat Intelligence 2026
  </div>
  <h1>Остановите мошенников до того,<br>как они украдут ваши деньги.</h1>
  <p class="hero-desc">Интеллектуальная защита от поддельных счетов, фишинга от имени банков, налоговой HMRC и служб доставки. Сканируйте подозрительный контент за 2 секунды.</p>
</div>

<div class="scanner-wrapper" id="scanner">
  <div class="scanner-box">
    <textarea id="target-input" placeholder="Вставьте сюда текст подозрительного письма, SMS или ссылку (например: 'Your Royal Mail parcel fee of £2.50 is pending: http://royalmail-support-parcel.xyz/verify')..."></textarea>
    
    <div class="scanner-bar">
      <button class="sample-btn" onclick="loadSample()">📋 Загрузить пример атаки (Royal Mail Scam)</button>
      <button class="scan-btn" onclick="runAnalysis()">
        <span>🛡️ Проверить на угрозы</span>
      </button>
    </div>

    <div id="result-box">
      <div id="meter" class="score-meter">
        <div>
          <div id="verdict-label" class="score-title">АНАЛИЗ ЗАВЕРШЕН</div>
          <p id="target-domain" style="color: #64748b; font-size: 14px; margin-top: 5px;"></p>
        </div>
        <div id="score-val" class="score-value">0%</div>
      </div>
      
      <h3 style="margin-bottom: 15px; font-size: 17px; font-weight: 700;">Индикаторы компрометации (Threat Breakdown):</h3>
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
        <div class="plan-desc">Базовая ручная проверка подозрительных ссылок для одного человека.</div>
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
        <div class="plan-desc">Полная круглосуточная защита от всех видов фишинга и фальшивых счетов.</div>
        <ul class="features-list">
          <li><span class="check-icon">✓</span> <strong>Безлимитные сканирования</strong> 24/7</li>
          <li><span class="check-icon">✓</span> Детекция глубокого Brand Spoofing</li>
          <li><span class="check-icon">✓</span> Deep SSL & DNS Network Inspection</li>
          <li><span class="check-icon">✓</span> Поддержка Telegram & WhatsApp бота</li>
          <li><span class="check-icon">✓</span> Приоритетные обновления баз угроз</li>
        </ul>
      </div>
      <button class="buy-btn primary" onclick="openCheckout('Pro Protection', '$5')">Подключить за $5/мес</button>
    </div>

    <div class="price-card">
      <div>
        <div class="plan-name">Business Suite</div>
        <div class="plan-price">$49 <span>/ месяц</span></div>
        <div class="plan-desc">Для небольших компаний, бухгалтерий, юридических фирм и клиник.</div>
        <ul class="features-list">
          <li><span class="check-icon">✓</span> Защита до 10 рабочих мест</li>
          <li><span class="check-icon">✓</span> Интеграция с почтой Google/Outlook</li>
          <li><span class="check-icon">✓</span> Ежемесячный PDF-аудит безопасности</li>
          <li><span class="check-icon">✓</span> Гарантия соответствия UK GDPR</li>
        </ul>
      </div>
      <button class="buy-btn secondary" onclick="openCheckout('Business Suite', '$49')">Выбрать Business</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="checkout-modal">
  <div class="modal">
    <button class="close-modal" onclick="closeCheckout()">✕</button>
    <div style="font-size: 32px; margin-bottom: 10px;">🔒</div>
    <h3 id="modal-plan-title" style="font-size: 22px; font-weight: 800;">Оформление подписки</h3>
    <div class="modal-price" id="modal-plan-price">$5 / мес</div>
    <p style="color: #94a3b8; font-size: 14px; margin-bottom: 20px;">Оплата банковской картой (Stripe / Apple Pay защищено 256-bit SSL)</p>
    
    <div class="card-inputs">
      <input type="email" placeholder="Ваш Email для активации аккаунта" id="pay-email" value="user@example.com">
      <input type="text" placeholder="Номер карты: 4242 •••• •••• 4242" id="pay-card">
      <div style="display: flex; gap: 10px;">
        <input type="text" placeholder="ММ/ГГ" style="flex: 1;">
        <input type="text" placeholder="CVC" style="flex: 1;">
      </div>
    </div>
    
    <button class="buy-btn primary" onclick="processPayment()">Оплатить и активировать</button>
    <p style="color: #64748b; font-size: 12px; margin-top: 15px;">Отмена в один клик в любой момент в личном кабинете.</p>
  </div>
</div>

<footer>
  © 2026 ScamShield Inc. • Платформа защиты цифровых активов • Спроектировано для Великобритании и США
</footer>

<script>
function loadSample() {
  document.getElementById("target-input").value = "URGENT: Your Royal Mail parcel cannot be delivered due to an unpaid duty fee of £2.50. Action required immediately to avoid penalty: http://royalmail-support-parcel.xyz/verify-account";
}

function openCheckout(planName, price) {
  document.getElementById("modal-plan-title").textContent = planName;
  document.getElementById("modal-plan-price").textContent = price + " / месяц";
  document.getElementById("checkout-modal").style.display = "flex";
}

function closeCheckout() {
  document.getElementById("checkout-modal").style.display = "none";
}

function processPayment() {
  const email = document.getElementById("pay-email").value;
  alert("🎉 Успешно! Подписка активирована для " + email + "\\n\\nБезлимитный доступ к ScamShield Pro включен.");
  closeCheckout();
}

async function runAnalysis() {
  const text = document.getElementById("target-input").value.trim();
  if (!text) return alert("Пожалуйста, введите текст или ссылку для проверки!");

  const resBox = document.getElementById("result-box");
  resBox.style.display = "block";
  
  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: text })
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
  
  document.getElementById("target-domain").textContent = "Проверенный объект: " + (data.details.target_domain || "Текст");
  
  const flagsList = document.getElementById("flags-list");
  flagsList.innerHTML = "";
  
  if (data.flags.length === 0) {
    flagsList.innerHTML = "<div class='flag-item' style='border-left-color: #34c759'><div class='flag-title' style='color:#34c759'>✓ Прямых признаков атаки не выявлено</div><div class='flag-desc'>Ссылка и текст не содержат известных паттернов фишинга.</div></div>";
  } else {
    data.flags.forEach(f => {
      const div = document.createElement("div");
      div.className = "flag-item " + (f.type === "danger" ? "danger" : "");
      div.innerHTML = `<div class="flag-title">${f.type === 'danger' ? '🚨' : '⚠️'} ${f.title}</div><div class="flag-desc">${f.desc}</div>`;
      flagsList.appendChild(div);
    });
  }
}
</script>

</body>
</html>
"""

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode("utf-8"))

    def do_POST(self):
        if self.path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body) if body else {}
            
            result = analyze_target(data.get("text", ""))
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def run():
    server = HTTPServer(("127.0.0.1", PORT), RequestHandler)
    print(f"ScamShield Server running at http://127.0.0.1:{PORT}")
    server.serve_forever()

if __name__ == "__main__":
    run()
