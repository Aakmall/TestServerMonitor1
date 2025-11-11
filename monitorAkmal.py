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
FONNTE_TOKEN = "iUrpA4Y6qP7AdcNHewBs"
FONNTE_TARGETS = ["6281933976553"]
GEMINI_API_KEY = "AIzaSyBAVnV2udYQWWvPEOyZ2cuAE91WBHcIaKc"
GEMINI_MODEL = "gemini-2.5-flash"



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
            "Nama kamu Akmal. Analisis singkat & padat peristiwa berikut.\n"
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
# --- temporary block 10 minutes ---
BLOCK_DURATION = 600  # 10 menit

_blocked_ips = set()
_blocked_ips_lock = threading.Lock()

def _remove_firewall_rule(ip: str):
    try:
        if shutil.which("ufw"):
            subprocess.run(["ufw", "delete", "deny", "from", ip], check=False)
            logging.warning("Unblocked %s via ufw (temporary)", ip); return True
        if shutil.which("nft"):
            subprocess.run(["nft", "delete", "rule", "inet", "filter", "input",
                            "ip", "saddr", ip, "drop"], check=False)
            logging.warning("Unblocked %s via nft (temporary)"); return True
        if shutil.which("iptables"):
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
            logging.warning("Unblocked %s via iptables (temporary)"); return True
    except Exception as e:
        logging.warning("Unblock failed for %s: %s", ip, e)
    return False

def _schedule_unblock(ip: str, delay: int = BLOCK_DURATION):
    def _worker():
        try:
            logging.info("Will unblock %s after %s seconds", ip, delay)
            time.sleep(delay)
            _remove_firewall_rule(ip)
        finally:
            with _blocked_ips_lock:
                _blocked_ips.discard(ip)
            try:
                msg = format_whatsapp_message(
                    f"IP {ip} otomatis dibuka setelah {delay//60} menit.",
                    labels=["Unblock"], analysis=None
                )
                send_fonnte_message("system", msg)
            except Exception as e:
                logging.warning("Failed to notify unblock for %s: %s", ip, e)
    threading.Thread(target=_worker, daemon=True).start()

def block_ip(ip: str) -> bool:
    with _blocked_ips_lock:
        if ip in _blocked_ips:
            logging.info("IP %s already temporarily blocked", ip)
            return True
        _blocked_ips.add(ip)
    try:
        if shutil.which("ufw"):
            subprocess.run(["ufw", "deny", "from", ip], check=False)
            logging.warning("Temporarily blocked %s via ufw", ip)
        elif shutil.which("nft"):
            subprocess.run(["nft", "add", "rule", "inet", "filter", "input",
                            "ip", "saddr", ip, "drop"], check=False)
            logging.warning("Temporarily blocked %s via nft", ip)
        elif shutil.which("iptables"):
            subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=False)
            logging.warning("Temporarily blocked %s via iptables", ip)
        else:
            logging.warning("No firewall tool found; in-memory block only for %s", ip)

        msg = format_whatsapp_message(
            f"IP {ip} sementara diblokir {BLOCK_DURATION//60} menit karena deteksi ancaman.",
            labels=["Temporary Block"], analysis=None
        )
        send_fonnte_message(ip, msg)

        _schedule_unblock(ip, delay=BLOCK_DURATION)
        return True
    except Exception as e:
        logging.warning("Block failed: %s", e)
        with _blocked_ips_lock:
            _blocked_ips.discard(ip)
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

            # === SSH LOGIN SUCCESS ===
            elif evt["type"] == "login_success":
                if not is_admin_ip(ip):
                    summary = f"Login SSH berhasil untuk user {evt.get('user','?')} dari {ip}"
                    msg = format_whatsapp_message(summary, ["Login Success"], "Pastikan ini aktivitas Anda.")
                    send_fonnte_message(ip, msg)

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
    logging.info("[Akmal] Starting on host %s", HOSTNAME)

    def _startup():
        try:
            msg = f"🟢 [Akmal] aktif di {HOSTNAME}.\nPemantauan log dimulai ✅"
            send_fonnte_message("system", msg)
        except Exception as e:
            logging.warning("Startup WA gagal: %s", e)

    threading.Thread(target=_startup, daemon=True).start()
    main()