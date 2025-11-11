#!/usr/bin/env python3
# Updated monitorAkmal.py — agregasi alert, SQLi/XSS detection, web-log analysis, auto-block
import os
import re
import time
import socket
import logging
import requests
import concurrent.futures
import subprocess
import threading
import shutil
from collections import defaultdict, deque
from datetime import datetime, timezone

# ---------------- Config ----------------
HOSTNAME = socket.gethostname()

# ADMIN WHITELIST: tambahkan IP publik admin di sini
ADMIN_IP_WHITELIST = {"36.85.218.181"}

# Log sources (SSH auth + common web access logs)
LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]
WEB_LOG_PATHS = ["/var/log/nginx/access.log", "/var/log/apache2/access.log"]

POLL_INTERVAL = 1.0

# Windows for counting events
FAIL_WINDOW_SEC = 300
SHORT_WINDOW_SEC = 60
AGGREGATE_INTERVAL = 60       # how often to send aggregated alerts per-IP / global
DEDUP_TTL_SEC = 60.0          # per-type de-dup ttl for immediate alerts

FAIL_THRESHOLD = 5            # auto-block after this many failed logins in FAIL_WINDOW_SEC
SPAM_THRESHOLD_PER_MIN = 6    # if > this many single-event alerts/min then aggregate

# Fonnte / Gemini (existing tokens kept)
FONNTE_TOKEN = "R3JmjUG5sAmGbSEE7gcG"
FONNTE_TARGETS = ["6281933976553"]
GEMINI_API_KEY = "AIzaSyBEs_tXMSn30of1PvGnwn5mwrvogzOk_fo"
GEMINI_MODEL = "gemini-2.5-flash"

# Logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

# Regex for SSH auth parsing (same)
RE_SUCCESS = re.compile(
    r"Accepted\s+(?P<method>password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
RE_FAIL = re.compile(
    r"Failed\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)

# Basic combined log regex (common Apache/Nginx combined log) — will parse IP, request, status
RE_WEB_COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<req>[^"]+)" (?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

# Attack signature regex (common SQLi/XSS patterns)
SQLI_PATTERNS = [
    re.compile(r"(?i)(union(\s+all)?\s+select)"),
    re.compile(r"(?i)(or\s+1=1)"),
    re.compile(r"(?i)(' or '1'='1)"),
    re.compile(r"(?i)(sleep\()\b"),
    re.compile(r"(?i)(information_schema)"),
    re.compile(r"(?i)(benchmark\()"),
    re.compile(r"(?i)(--\s*$)"),
    re.compile(r"(?i)(;--|;|/\*|\*/)")
]
XSS_PATTERNS = [
    re.compile(r"(?i)<script[^>]*>"),
    re.compile(r"(?i)onerror\s*="),
    re.compile(r"(?i)javascript:"),
    re.compile(r"(?i)<img[^>]+src"),
]
CSRF_INDICATORS = [
    re.compile(r"(?i)csrf_token"),
    # We flag possible CSRF if dangerous state-changing GET requests are seen repeatedly
]

# ---------------- Helper functions ----------------

def is_admin_ip(ip: str) -> bool:
    """Return True jika IP ada di whitelist admin"""
    if not ip:
        return False
    return ip in ADMIN_IP_WHITELIST

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def analyze_with_gemini(summary: str, timeout_sec: float = 6.0) -> str | None:
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        prompt = (
            "Nama kamu BotAkmal. Berikan analisis singkat dan padat untuk peristiwa berikut. "
            "Jawab bahasa Indonesia TANPA pendahuluan dengan format dua bagian:\n\n"
            "*Tingkat Risiko:* <Low|Medium|High>\n\n"
            "*Alasan:* <1-2 kalimat>\n\n"
            f"Peristiwa: {summary}"
        )
        resp = model.generate_content(prompt)
        return (getattr(resp, "text", "") or "").strip() or None
    except Exception as e:
        logging.debug("Gemini analyze failed: %s", e)
        return None

def gemini_insight_with_timeout(summary: str, timeout_sec: float = 6.0) -> str | None:
    def _call():
        return analyze_with_gemini(summary, timeout_sec=timeout_sec)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_call)
            return fut.result(timeout=timeout_sec)
    except concurrent.futures.TimeoutError:
        logging.warning("Gemini timeout %.1fs", timeout_sec)
        return None
    except Exception as e:
        logging.warning("Gemini error: %s", e)
        return None

def send_fonnte_message(message: str):
    if not FONNTE_TOKEN or not FONNTE_TARGETS:
        logging.warning("Fonnte not configured, skip WA.")
        return
    for target in FONNTE_TARGETS:
        try:
            r = requests.post(
                "https://api.fonnte.com/send",
                headers={"Authorization": FONNTE_TOKEN},
                data={"target": target, "message": message},
                timeout=10,
            )
            logging.info("Fonnte->%s status=%s", target, r.status_code)
        except Exception as e:
            logging.warning("Fonnte error to %s: %s", target, e)

# Try blocking IP via ufw/iptables/nft — will only run if script has necessary privileges
def block_ip(ip: str) -> bool:
    try:
        # Prefer ufw if present
        if shutil.which("ufw"):
            subprocess.run(["ufw", "deny", "from", ip], check=False)
            logging.warning("Blocked %s via ufw", ip)
            return True
        # Try nft
        if shutil.which("nft"):
            # simple table rule insert (may need adjustment)
            subprocess.run(["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"], check=False)
            logging.warning("Blocked %s via nft", ip)
            return True
        # fallback to iptables
        if shutil.which("iptables"):
            subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=False)
            logging.warning("Blocked %s via iptables", ip)
            return True
    except Exception as e:
        logging.warning("Block ip failed: %s", e)
    return False

# ---------------- Event parsing (SSH + Web) ----------------
def parse_event(line: str):
    now = utc_now_iso()
    m = RE_SUCCESS.search(line)
    if m:
        return {"ts": now, "type": "login_success", "user": m.group("user"), "ip": m.group("ip"),
                "method": m.group("method"), "raw": line.strip()}
    m = RE_FAIL.search(line)
    if m:
        return {"ts": now, "type": "login_fail", "user": m.group("user"), "ip": m.group("ip"), "raw": line.strip()}
    m = RE_WEB_COMBINED.search(line)
    if m:
        ip = m.group("ip")
        status = int(m.group("status"))
        req = m.group("req")
        # request has form "GET /path?query HTTP/1.1"
        try:
            method, path, proto = req.split(" ", 2)
        except Exception:
            method, path = "GET", "/"
        return {"ts": now, "type": "web_access", "ip": ip, "status": status, "req": req, "path": path, "raw": line.strip()}
    return None

# ---------------- Tail generators ----------------
def tail_file(path: str):
    pos = None
    initialized = False
    while True:
        try:
            with open(path, "r", errors="ignore") as f:
                if not initialized:
                    f.seek(0, os.SEEK_END)
                    pos = f.tell()
                    initialized = True
                else:
                    f.seek(pos)
                chunk = f.read()
                if chunk:
                    pos = f.tell()
                    for line in chunk.splitlines():
                        yield line
                else:
                    size = os.path.getsize(path)
                    if size < pos:
                        pos = 0
        except FileNotFoundError:
            pass
        time.sleep(POLL_INTERVAL)
        yield None

def iter_journald_sshd():
    try:
        proc = subprocess.Popen(
            ["journalctl", "-f", "-n", "0", "-o", "cat", "-u", "ssh", "-u", "sshd"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
    except Exception:
        proc = None
    last_yield = time.time()
    while True:
        if proc and proc.stdout:
            line = proc.stdout.readline()
            if line:
                yield line.rstrip("\n")
                last_yield = time.time()
            else:
                if time.time() - last_yield >= POLL_INTERVAL:
                    last_yield = time.time()
                    yield None
                time.sleep(0.1)
        else:
            time.sleep(POLL_INTERVAL)
            yield None

# ---------------- Aggregation / state ----------------
ip_fail = defaultdict(deque)        # ip -> deque[timestamps]
ip_events = defaultdict(list)       # ip -> recent raw events for aggregation
ip_last_alert = defaultdict(float)  # ip -> last alert ts
global_last_aggregate = 0.0

web_status_counts = defaultdict(lambda: defaultdict(int))  # ip -> {4xx: count, 5xx: count}
web_req_lengths = defaultdict(list)  # ip -> list of query lengths to detect heavy queries

# short-term counters for IDS-like detection
recent_conn_counts = defaultdict(deque)  # ip -> deque[timestamps] of any relevant event

# ---------------- Analysis helpers ----------------
def detect_attack_patterns(text: str) -> list:
    labels = []
    for p in SQLI_PATTERNS:
        if p.search(text):
            labels.append("SQLi")
            break
    for p in XSS_PATTERNS:
        if p.search(text):
            labels.append("XSS")
            break
    for p in CSRF_INDICATORS:
        if p.search(text):
            labels.append("CSRF?")
            break
    return labels

def format_whatsapp_message_v2(event_summary: str, labels: list | None = None, gemini_analysis: str | None = None) -> str:
    parts = [f"[Login Monitor] Host: {HOSTNAME}", f"Time: {utc_now_iso()}", "", event_summary]
    if labels:
        parts.append("")
        parts.append("Detected: " + ", ".join(labels))
    parts.append("")
    parts.append("Rekomendasi:")
    if gemini_analysis:
        parts.append(gemini_analysis)
    else:
        parts.append("-")
    return "\n".join(parts)

# --------------- main loop ---------------
def main():
    global global_last_aggregate
    logging.info("Mulai monitor log (enhanced) ...")

    # prepare tails (auth logs + web access logs)
    existing_paths = [p for p in LOG_PATHS if os.path.exists(p)]
    web_existing = [p for p in WEB_LOG_PATHS if os.path.exists(p)]
    tails = []
    if existing_paths:
        tails.extend([(p, tail_file(p)) for p in existing_paths])
    else:
        logging.warning("Tidak menemukan auth logs; akan pakai journald ssh/sshd")
        tails.append(("journald:ssh", iter_journald_sshd()))

    if web_existing:
        tails.extend([(p, tail_file(p)) for p in web_existing])
        for p in web_existing:
            logging.info("Memantau web log: %s", p)
    else:
        logging.info("Tidak menemukan web access logs di %s", ", ".join(WEB_LOG_PATHS))

    while True:
        now = time.time()
        for path, gen in tails:
            try:
                line = next(gen)
            except Exception as e:
                logging.debug("tail gen error: %s", e)
                continue
            if line is None:
                continue
            evt = parse_event(line)
            if not evt:
                continue

            ip = evt.get("ip", "unknown")
            # record for general IDS counters
            dq = recent_conn_counts[ip]
            dq.append(now)
            while dq and dq[0] < now - SHORT_WINDOW_SEC:
                dq.popleft()

            # handle types
            if evt["type"] == "login_fail":
                dq_fail = ip_fail[ip]
                dq_fail.append(now)
                while dq_fail and dq_fail[0] < now - FAIL_WINDOW_SEC:
                    dq_fail.popleft()

                # skip WA alert jika IP admin
                if is_admin_ip(ip):
                    logging.info("Skip login_fail alert for admin IP %s", ip)
                else:
                    # immediate single-fail alert (but deduped & aggregated)
                    ip_events[ip].append(("fail", evt["raw"], now))
                    # auto-block if threshold exceeded
                    if len(dq_fail) >= FAIL_THRESHOLD and ip not in ip_last_alert:
                        blocked = block_ip(ip)
                        note = f"Auto-block applied to {ip}" if blocked else f"Auto-block requested but failed for {ip}"
                        summary = f"{len(dq_fail)} failed SSH logins from {ip} within {FAIL_WINDOW_SEC}s. {note}"
                        labels = ["BruteForce"]
                        analysis = gemini_insight_with_timeout(summary) or ""
                        msg = format_whatsapp_message_v2(summary, labels, analysis)
                        send_fonnte_message(msg)
                        ip_last_alert[ip] = now

            elif evt["type"] == "login_success":
                ip_events[ip].append(("success", evt["raw"], now))
                if is_admin_ip(ip):
                    logging.info("Skip login_success alert for admin IP %s", ip)
                else:
                    # send less-frequently
                    if now - ip_last_alert.get((ip, "success"), 0) > DEDUP_TTL_SEC:
                        summary = f"Successful login user={evt.get('user')} ip={ip} host={HOSTNAME}"
                        analysis = gemini_insight_with_timeout(summary) or ""
                        msg = format_whatsapp_message_v2(summary, ["LoginSuccess"], analysis)
                        send_fonnte_message(msg)
                        ip_last_alert[(ip, "success")] = now

            elif evt["type"] == "web_access":
                status = evt.get("status", 0)
                req = evt.get("req", "")
                path = evt.get("path", "")
                # analyze URL params
                qs_len = 0
                if "?" in path:
                    qs = path.split("?", 1)[1]
                    qs_len = len(qs)
                    param_count = qs.count("&") + 1 if qs else 0
                else:
                    param_count = 0

                if status >= 500:
                    web_status_counts[ip]["5xx"] += 1
                elif 400 <= status < 500:
                    web_status_counts[ip]["4xx"] += 1

                web_req_lengths[ip].append(qs_len)
                # pattern detection
                labels = detect_attack_patterns(req)
                if param_count >= 8 or qs_len > 800:
                    labels.append("ManyParams/LongQuery")

                if labels:
                    summary = f"Suspicious web request from {ip} status={status} req={req}"
                    analysis = gemini_insight_with_timeout(summary) or ""
                    msg = format_whatsapp_message_v2(summary, labels, analysis)
                    # skip WA untuk admin IP
                    if is_admin_ip(ip):
                        logging.info("Skip web alert for admin IP %s", ip)
                    else:
                        # dedupe rapid web alerts per ip
                        if now - ip_last_alert.get((ip, "web_susp"), 0) > AGGREGATE_INTERVAL:
                            send_fonnte_message(msg)
                            ip_last_alert[(ip, "web_susp")] = now
                    ip_events[ip].append(("web", req, now))
                else:
                    # for normal web events, still record for aggregation
                    ip_events[ip].append(("web", req, now))

            # IDS: abnormal spike connections
            if len(recent_conn_counts[ip]) > SPAM_THRESHOLD_PER_MIN:
                summary = f"High rate of connections from {ip}: {len(recent_conn_counts[ip])} events in last {SHORT_WINDOW_SEC}s"
                analysis = gemini_insight_with_timeout(summary) or ""
                if now - ip_last_alert.get((ip, "spike"), 0) > AGGREGATE_INTERVAL:
                    # skip spike alerts for admin IP
                    if is_admin_ip(ip):
                        logging.info("Skip spike alert for admin IP %s", ip)
                    else:
                        send_fonnte_message(format_whatsapp_message_v2(summary, ["Spike"], analysis))
                        ip_last_alert[(ip, "spike")] = now

        # periodic aggregation every AGGREGATE_INTERVAL seconds
        if time.time() - global_last_aggregate >= AGGREGATE_INTERVAL:
            global_last_aggregate = time.time()
            # build aggregated reports per IP
            for ip, events in list(ip_events.items()):
                if not events:
                    continue
                # If only tiny noise, skip immediate alert (to reduce spam)
                if len(events) == 1 and events[0][0] != "web":
                    # keep in events for next round; skip notifying
                    continue

                # create summary
                fail_count = sum(1 for e in events if e[0] == "fail")
                succ_count = sum(1 for e in events if e[0] == "success")
                web_count = sum(1 for e in events if e[0] == "web")
                top_samples = [e[1] for e in events[-3:]]
                labels = []
                if fail_count:
                    labels.append(f"{fail_count}x FAIL")
                if succ_count:
                    labels.append(f"{succ_count}x SUCCESS")
                if web_count:
                    # include status counts if any
                    s4 = web_status_counts[ip].get("4xx", 0)
                    s5 = web_status_counts[ip].get("5xx", 0)
                    if s4 or s5:
                        labels.append(f"4xx={s4},5xx={s5}")
                # detect heavy query patterns
                avg_qs = (sum(web_req_lengths[ip]) / len(web_req_lengths[ip])) if web_req_lengths[ip] else 0
                if avg_qs > 300:
                    labels.append("HeavyQueryAvg")

                summary = f"Aggregate events from {ip}: {', '.join(labels)}. Samples: {' | '.join(top_samples)}"
                # ask Gemini for smart recommendation
                analysis = gemini_insight_with_timeout(summary, timeout_sec=4.0) or "No AI recommendation available."
                msg = format_whatsapp_message_v2(summary, labels, analysis)
                # send aggregated alert (respect last alert to avoid spam)
                if time.time() - ip_last_alert.get((ip, "agg"), 0) > AGGREGATE_INTERVAL:
                    # skip aggregated alerts for admin IP
                    if is_admin_ip(ip):
                        logging.info("Skip aggregated alert for admin IP %s", ip)
                    else:
                        send_fonnte_message(msg)
                        ip_last_alert[(ip, "agg")] = time.time()
                # clear per-ip buffers after reporting
                ip_events[ip].clear()
                web_req_lengths[ip].clear()
                web_status_counts[ip].clear()

        # small sleep to avoid busy loop
        time.sleep(0.1)

if __name__ == "__main__":
    logging.info("[BotAkmal] enhanced monitor start di %s", HOSTNAME)

    def _notify_startup():
        try:
            sources = [p for p in LOG_PATHS + WEB_LOG_PATHS if os.path.exists(p)]
            source_msg = f"files={', '.join(sources)}" if sources else "journald:ssh,sshd"
            summary = f"monitor startup host={HOSTNAME} sources={source_msg}"
            analysis = gemini_insight_with_timeout(summary, timeout_sec=3.0)
            msg = f"[BotAkmal] monitor start di {HOSTNAME}. Sumber log: {source_msg}\n\nAnalisis: {analysis or '-'}"
            # do not send startup WA if only admin whitelist and you prefer silent start:
            send_fonnte_message(msg)
        except Exception as e:
            logging.warning("Startup notify gagal: %s", e)

    threading.Thread(target=_notify_startup, daemon=True).start()
    main()
