#!/usr/bin/env python3
import subprocess
import time
import socket
import re

# Набор белых доверенных портов/процессов
WHITELIST_PORTS = {80, 443, 22, 53, 123}

def send_mac_notification(title, message):
    """Выводит нативное системное всплывающее уведомление на экран macOS"""
    script = f'display notification "{message}" with title "{title}" sound name "Basso"'
    subprocess.run(["osascript", "-e", script])

def scan_connections():
    """Анализ активных сетевых соединений на подозрительные входящие подключения"""
    try:
        res = subprocess.run(["netstat", "-anp", "tcp"], capture_output=True, text=True)
        lines = res.stdout.splitlines()
        for line in lines:
            if "ESTABLISHED" in line or "SYN_SENT" in line:
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[3]
                    foreign_addr = parts[4]
                    # Если есть подозрительное нестандартное соединение
                    if ":" in foreign_addr:
                        r_ip, r_port = foreign_addr.rsplit(":", 1)
                        if r_port.isdigit() and int(r_port) not in WHITELIST_PORTS:
                            # Проверяем, не является ли это локальной сетью
                            if not (r_ip.startswith("127.") or r_ip.startswith("192.168.") or r_ip.startswith("10.")):
                                return f"Подозрительный трафик на порт {r_port} ({r_ip})"
    except Exception as e:
        pass
    return None

def main():
    send_mac_notification("🛡️ Mac Sentinel АКТИВЕН", "Система киберзащиты вашего Mac успешно запущена!")
    print("Mac Sentinel Watchdog running...")
    
    last_alert = 0
    while True:
        alert = scan_connections()
        now = time.time()
        if alert and (now - last_alert > 300): # Не спамить чаще раза в 5 минут
            send_mac_notification("🚨 ТРЕВОГА БЕЗОПАСНОСТИ!", f"Зафиксирована попытка несанкционированного подключения: {alert}")
            last_alert = now
        time.sleep(10)

if __name__ == "__main__":
    main()
