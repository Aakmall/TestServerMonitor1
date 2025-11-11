#!/usr/bin/env python3
# monitorAkmal.py — Enhanced IDS + Auto Blocking + WA Alert (Clean & Anti-Spam)

import os
import json
import time
import re
import socket
import logging
import requests
import concurrent.futures
import subprocess
import threading
import shutil
from collections import defaultdict, deque
from datetime import datetime, timezone

# ==================== CONFIG ====================
HOSTNAME = socket.gethostname()

# Whitelist IP Admin
ADMIN_IP_WHITELIST = {"36.85.218.181"}

# Log file paths
LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]
WEB_LOG_PATHS = ["/var/log/nginx/access.log", "/var/log/apache2/access.log"]

# Interval konfigurasi
POLL_INTERVAL = 1.0
FAIL_WINDOW_SEC = 300
SHORT_WINDOW_SEC = 60
AGGREGATE_INTERVAL = 60
DEDUP_TTL_SEC = 60
FAIL_THRESHOLD = 5
SPAM_THRESHOLD_PER_MIN = 6

# Token konfigurasi
FONNTE_TOKEN = "uqMuVhM4YKzujVg38BiB"
FONNTE_TARGETS = ["6281933976553"]
GEMINI_API_KEY = "AIzaSyAh0e2NU7wVzYQqe8q5KV0fFaL8CBrfhBI"
GEMINI_MODEL = "gemini-2.5-flash"

# File untuk log anti-spam
ALERT_LOG_FILE = "/tmp/alert_log.json"
COOLDOWN_SECONDS = 600  # 10 menit antar alert per IP

# ==================== LOGGING ====================
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

# ==================== REGEX ====================
RE_SUCCESS = re.compile(
    r"Accepted\s+(?P<method>password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
RE_FAIL = re.compile(
    r"Failed\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
RE_WEB_COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<req>[^"]+)" (?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

SQLI_PATTERNS = [
    re.compile(r"(?i)(union(\s+all)?\s+select)"),
    re.compile(r"(?i)(or\s+1=1)"),
    re.compile(r"(?i)(' or '1'='1)"),
    re.compile(r"(?i)(sleep\()\b"),
    re.compile(r"(?i)(information_schema)"),
    re.compile(r"(?i)(benchmark\()"),
    re.compile(r"(?i)(--\s*$)"),
]
XSS_PATTERNS = [
    re.compile(r"(?i)<script[^>]*>"),
    re.compile(r"(?i)onerror\s*="),
    re.compile(r"(?i)javascript:"),
    re.compile(r"(?i)<img[^>]+src"),
]
CSRF_INDICATORS = [re.compile(r"(?i)csrf_token")]

# ==================== HELPER ====================
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def is_admin_ip(ip: str) -> bool:
    return ip in ADMIN_IP_WHITELIST

# ---- Anti Spam ----
def load_alert_log():
    if os.path.exists(ALERT_LOG_FILE):
        with open(ALERT_LOG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_alert_log(data):
    with open(ALERT_LOG_FILE, "w") as f:
        json.dump(data, f)

def send_fonnte_message(ip: str, message: str):
    alert_log = load_alert_log()
    now = time.time()

    # Skip kirim WA jika IP masih dalam masa cooldown
    if ip in alert_log and now - alert_log[ip] < COOLDOWN_SECONDS:
        logging.info("[SKIP WA] %s masih dalam cooldown", ip)
        return

    for target in FONNTE_TARGETS:
        try:
            r = requests.post(
                "https://api.fonnte.com/send",
                headers={"Authorization": FONNTE_TOKEN},
                data={"target": target, "message": message},
                timeout=10,
            )
            if r.status_code == 200:
                alert_log[ip] = now
                save_alert_log(alert_log)
                logging.info("[WA SENT] ke %s untuk %s", target, ip)
            else:
                logging.warning("[WA ERROR] %s: %s", target, r.text)
        except Exception as e:
            logging.warning("Fonnte error: %s", e)

def analyze_with_gemini(summary: str, timeout_sec: float = 6.0) -> str | None:
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        prompt = (
            "Nama kamu BotAkmal. Analisis singkat & padat peristiwa berikut.\n"
            "Gunakan format:\n"
            "Tingkat Risiko: <Low|Medium|High>\n"
            "Alasan: <1 kalimat>\n\n"
            f"Peristiwa: {summary}"
        )
        resp = model.generate_content(prompt)
        return (getattr(resp, "text", "") or "").strip() or None
    except Exception:
        return None

def gemini_insight(summary: str) -> str:
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(analyze_with_gemini, summary)
            return fut.result(timeout=6)
    except Exception:
        return "Tidak ada analisis AI."

def format_whatsapp_message(summary: str, labels: list | None = None, analysis: str | None = None) -> str:
    """Format pesan WA yang rapi dan mudah dibaca"""
    msg = [
        f"📡 *Server:* {HOSTNAME}",
        f"🕒 *Waktu:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"🧾 *Peristiwa:* {summary}",
    ]
    if labels:
        msg.append(f"🚨 *Deteksi:* {', '.join(labels)}")
    msg.append("")
    msg.append(f"🤖 *Rekomendasi:* {analysis or '-'}")
    return "\n".join(msg)

# ==================== FIREWALL BLOCK ====================
def block_ip(ip: str) -> bool:
    try:
        if shutil.which("ufw"):
            subprocess.run(["ufw", "deny", "from", ip], check=False)
            logging.warning("Blocked %s via ufw", ip)
            return True
        if shutil.which("nft"):
            subprocess.run(["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"], check=False)
            logging.warning("Blocked %s via nft", ip)
            return True
        if shutil.which("iptables"):
            subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=False)
            logging.warning("Blocked %s via iptables", ip)
            return True
    except Exception as e:
        logging.warning("Block failed: %s", e)
    return False

# ==================== EVENT PARSING ====================
def parse_event(line: str):
    now = utc_now_iso()
    for regex, etype in [(RE_SUCCESS, "login_success"), (RE_FAIL, "login_fail")]:
        m = regex.search(line)
        if m:
            return {"ts": now, "type": etype, "ip": m.group("ip"), "user": m.groupdict().get("user", "?"), "raw": line}
    m = RE_WEB_COMBINED.search(line)
    if m:
        return {
            "ts": now,
            "type": "web_access",
            "ip": m.group("ip"),
            "status": int(m.group("status")),
            "req": m.group("req"),
        }
    return None

# ==================== DETECTION ====================
def detect_patterns(text: str) -> list:
    found = []
    for p in SQLI_PATTERNS:
        if p.search(text): found.append("SQLi")
    for p in XSS_PATTERNS:
        if p.search(text): found.append("XSS")
    for p in CSRF_INDICATORS:
        if p.search(text): found.append("CSRF?")
    return found

# ==================== MAIN ====================
def main():
    logging.info("Memulai pemantauan log...")

    ip_last_alert = defaultdict(float)
    ip_fail = defaultdict(deque)
    web_status = defaultdict(lambda: defaultdict(int))
    web_reqs = defaultdict(list)
    ip_events = defaultdict(list)
    recent_conn = defaultdict(deque)
    global_last_agg = 0.0

    # Gabung log
    paths = [p for p in LOG_PATHS + WEB_LOG_PATHS if os.path.exists(p)]
    if not paths:
        logging.warning("Tidak ada log file ditemukan!")
        return

    files = {p: open(p, "r", errors="ignore") for p in paths}
    for f in files.values(): f.seek(0, os.SEEK_END)

    while True:
        now = time.time()
        for p, f in files.items():
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            evt = parse_event(line)
            if not evt: continue
            ip = evt["ip"]

            # Whitelist admin skip
            if is_admin_ip(ip):
                continue

            # === SSH LOGIN FAIL ===
            if evt["type"] == "login_fail":
                dq = ip_fail[ip]
                dq.append(now)
                while dq and dq[0] < now - FAIL_WINDOW_SEC:
                    dq.popleft()

                if len(dq) >= FAIL_THRESHOLD:
                    blocked = block_ip(ip)
                    summary = f"{len(dq)} gagal login SSH dari {ip}"
                    msg = format_whatsapp_message(summary, ["BruteForce"], gemini_insight(summary))
                    send_fonnte_message(ip, msg)
                    ip_last_alert[ip] = now

            # === WEB ACCESS ===
            elif evt["type"] == "web_access":
                req = evt["req"]
                status = evt["status"]
                patterns = detect_patterns(req)
                if patterns or status >= 400:
                    summary = f"Permintaan mencurigakan dari {ip} [{req}] (status {status})"
                    msg = format_whatsapp_message(summary, patterns, gemini_insight(summary))
                    send_fonnte_message(ip, msg)

        time.sleep(0.3)

# ==================== STARTUP ====================
if __name__ == "__main__":
    logging.info("[BotAkmal] Starting on host %s", HOSTNAME)

    def _startup():
        try:
            msg = f"🟢 [BotAkmal] aktif di {HOSTNAME}.\nPemantauan log dimulai ✅"
            send_fonnte_message("system", msg)
        except Exception as e:
            logging.warning("Startup WA gagal: %s", e)

    threading.Thread(target=_startup, daemon=True).start()
    main()
