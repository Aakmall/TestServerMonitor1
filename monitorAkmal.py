#!/usr/bin/env python3
# =====================================================
# monitorAkmal.py
# Server Intrusion Detection + Auto Blocking + WA Alerts
# (with Gemini AI summary, cooldown, and clean formatting)
# =====================================================

import os
import re
import time
import json
import shutil
import socket
import logging
import requests
import threading
import subprocess
import concurrent.futures
from collections import defaultdict, deque
from datetime import datetime, timezone

# ==================== CONFIGURATION ====================

HOSTNAME = socket.gethostname()

# Admin whitelist (tidak diblok / tidak dikirimi WA)
ADMIN_IP_WHITELIST = {"36.85.218.181"}

# Log path
LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]
WEB_LOG_PATHS = ["/var/log/nginx/access.log", "/var/log/apache2/access.log"]

# Deteksi & notifikasi
FAIL_THRESHOLD = 5
FAIL_WINDOW_SEC = 300
POLL_INTERVAL = 1.0
COOLDOWN_SECONDS = 600  # 10 menit cooldown per IP

# Token & API Keys
FONNTE_TOKEN = "uqMuVhM4YKzujVg38BiB"
FONNTE_TARGETS = ["6281933976553"]
GEMINI_API_KEY = "AIzaSyA6cfTruhVM6xwpRRX_03ZQXyIQCTd4JVE"
GEMINI_MODEL = "gemini-2.5-flash"

# File penyimpanan cooldown
ALERT_LOG_FILE = "/tmp/alert_log.json"

# ==================== REGEX PATTERNS ====================

RE_SUCCESS = re.compile(
    r"Accepted\s+(password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+(\S+)\s+from\s+(\S+)"
)
RE_FAIL = re.compile(r"Failed\s+password\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)")
RE_WEB_ACCESS = re.compile(r'(?P<ip>\S+) \S+ \S+ \[.*?\] "(?P<req>[^"]+)" (?P<status>\d{3})')

SQLI_PATTERNS = [
    r"(?i)(union(\s+all)?\s+select)",
    r"(?i)(or\s+1=1)",
    r"(?i)(' or '1'='1)",
    r"(?i)(sleep\()",
    r"(?i)(information_schema)",
]
XSS_PATTERNS = [r"(?i)<script", r"(?i)onerror=", r"(?i)javascript:"]

# ==================== LOGGING ====================
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")


# ==================== HELPERS ====================
def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_alert_log():
    if os.path.exists(ALERT_LOG_FILE):
        try:
            with open(ALERT_LOG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_alert_log(data):
    try:
        with open(ALERT_LOG_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        logging.warning("Gagal menyimpan alert log: %s", e)


def is_admin_ip(ip):
    return ip in ADMIN_IP_WHITELIST


# ==================== FONNTE NOTIFICATION ====================
def send_fonnte_message(ip, message):
    """
    Kirim WA via Fonnte (dengan cooldown per-IP).
    ip: string key untuk cooldown (mis: 'system' untuk pesan startup)
    """
    alert_log = load_alert_log()
    now = time.time()

    # Cooldown check
    if ip in alert_log and now - alert_log[ip] < COOLDOWN_SECONDS:
        logging.info(f"[SKIP WA] {ip} masih dalam cooldown.")
        return

    for target in FONNTE_TARGETS:
        try:
            resp = requests.post(
                "https://api.fonnte.com/send",
                headers={"Authorization": FONNTE_TOKEN},
                data={"target": target, "message": message},
                timeout=10,
            )
            if resp.status_code == 200:
                alert_log[ip] = now
                save_alert_log(alert_log)
                logging.info(f"[WA SENT] {target} -> {ip}")
            else:
                logging.warning(f"[WA ERROR] {resp.status_code} {resp.text}")
        except Exception as e:
            logging.warning(f"[Fonnte Error] {e}")


# ==================== GEMINI ANALYSIS ====================
def analyze_with_gemini(summary):
    try:
        import google.generativeai as genai

        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        prompt = (
            "Analisis singkat tingkat risiko kejadian keamanan berikut:\n"
            "Gunakan format:\n"
            "Tingkat Risiko: <Low|Medium|High>\n"
            "Alasan: <2 kalimat>\n\n"
            f"Kejadian: {summary}"
        )
        response = model.generate_content(prompt)
        return (getattr(response, "text", "") or "").strip()
    except Exception as e:
        err = str(e)
        if "429" in err or "quota" in err.lower():
            return "AI Gemini: ⚠️ Kuota harian habis, analisis otomatis dinonaktifkan sementara."
        return "AI Gemini tidak tersedia saat ini."


def gemini_insight(summary):
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(analyze_with_gemini, summary)
            return fut.result(timeout=6)
    except Exception:
        return "Tidak ada analisis AI."


# ==================== FORMAT PESAN WA ====================
def format_whatsapp_message(summary, detection=None, analysis=None):
    det_text = ", ".join(detection) if detection else "-"
    return f"""
📡 SERVER  : {HOSTNAME}
🕒 WAKTU   : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

📋 PERISTIWA :
{summary}

🚨 DETEKSI  : {det_text}

🤖 ANALISIS :
{analysis or '-'}
""".strip()


# ==================== FIREWALL ====================
def block_ip(ip):
    if is_admin_ip(ip):
        logging.info(f"[SKIP BLOCK] IP admin {ip}")
        return False

    try:
        if shutil.which("ufw"):
            subprocess.run(["ufw", "deny", "from", ip], check=False)
        elif shutil.which("iptables"):
            subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=False)
        logging.warning(f"[BLOCKED] {ip}")
        return True
    except Exception as e:
        logging.warning(f"[BLOCK ERROR] {e}")
        return False


# ==================== DETECTION ENGINE ====================
def detect_patterns(req):
    found = []
    for p in SQLI_PATTERNS:
        if re.search(p, req):
            found.append("SQLi")
            break
    for p in XSS_PATTERNS:
        if re.search(p, req):
            found.append("XSS")
            break
    return found


def parse_event(line):
    now = utc_now()
    if m := RE_FAIL.search(line):
        return {"type": "login_fail", "ip": m.group(2), "user": m.group(1), "ts": now}
    if m := RE_SUCCESS.search(line):
        return {"type": "login_success", "ip": m.group(3), "user": m.group(2), "ts": now}
    if m := RE_WEB_ACCESS.search(line):
        return {"type": "web_access", "ip": m.group("ip"), "req": m.group("req"), "status": int(m.group("status")), "ts": now}
    return None


# ==================== MAIN LOOP ====================
def main():
    logging.info(f"[BotAkmal] Memantau log di {HOSTNAME}...")
    ip_fail = defaultdict(deque)

    paths = [p for p in LOG_PATHS + WEB_LOG_PATHS if os.path.exists(p)]
    if not paths:
        logging.warning("Tidak ada log ditemukan.")
        return

    # Open files and seek to end (tail -f behavior)
    files = {p: open(p, "r", errors="ignore") for p in paths}
    for f in files.values():
        f.seek(0, os.SEEK_END)

    while True:
        for p, f in files.items():
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue

            evt = parse_event(line)
            if not evt:
                continue

            ip = evt.get("ip")
            if not ip:
                continue

            # IGNORE admin IP entirely
            if is_admin_ip(ip):
                logging.debug("Skip event from admin IP %s", ip)
                continue

            # --- SSH Brute-force detection ---
            if evt["type"] == "login_fail":
                dq = ip_fail[ip]
                dq.append(time.time())
                # remove timestamps outside window
                while dq and dq[0] < time.time() - FAIL_WINDOW_SEC:
                    dq.popleft()

                if len(dq) >= FAIL_THRESHOLD:
                    blocked = block_ip(ip)
                    summary = f"{len(dq)} kali gagal login SSH dari {ip}"
                    analysis = gemini_insight(summary)
                    msg = format_whatsapp_message(summary, ["BruteForce"], analysis)
                    send_fonnte_message(ip, msg)
                    dq.clear()  # reset counter after action

            # --- Web attacks / suspicious accesses ---
            elif evt["type"] == "web_access":
                req = evt.get("req", "")
                status = evt.get("status", 0)
                patterns = detect_patterns(req)

                # If only HTTP error but no pattern, label as HTTP error so DETEKSI isn't '-'
                if not patterns and status >= 400:
                    patterns = [f"HTTP {status} Error"]

                if patterns or status >= 400:
                    summary = f"Permintaan mencurigakan dari {ip}: {req} (status {status})"
                    analysis = gemini_insight(summary)
                    msg = format_whatsapp_message(summary, patterns, analysis)
                    send_fonnte_message(ip, msg)

        time.sleep(POLL_INTERVAL)


# ==================== STARTUP ====================
if __name__ == "__main__":
    logging.info("[BotAkmal] Starting monitor...")
    def _startup():
        msg = f"""
🟢 [BotAkmal] Aktif di {HOSTNAME}
Pemantauan log dimulai.
"""
        # use 'system' key for startup cooldown tracking
        send_fonnte_message("system", msg.strip())

    threading.Thread(target=_startup, daemon=True).start()
    main()
