#!/usr/bin/env python3
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
from typing import Iterator

# ---------------- Config ----------------
HOSTNAME = socket.gethostname()
LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]
POLL_INTERVAL = 1.0
FAIL_WINDOW_SEC = 300
SUCCESS_WINDOW_SEC = 300
FAIL_THRESHOLD = 5
SUCCESS_THRESHOLD = 2
ALERT_SESSION_OPEN = False  # False supaya session open tidak mengganggu

# Fonnte API (gantikan dengan token dan nomor WA milikmu)
FONNTE_TOKEN = " uqMuVhM4YKzujVg38BiB"
FONNTE_TARGETS = ["6281933976553"]

# Gemini API Key & model (gantikan dengan milikmu)
GEMINI_API_KEY = "AIzaSyA6cfTruhVM6xwpRRX_03ZQXyIQCTd4JVE"
GEMINI_MODEL = "gemini-2.5-flash"

# Logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

# Regex
RE_SUCCESS = re.compile(
    r"Accepted\s+(?P<method>password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
RE_FAIL = re.compile(
    r"Failed\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
RE_SESSION_OPEN = re.compile(
    r"session opened for user\s+(?P<user>[A-Za-z0-9_.@-]+)",
    re.IGNORECASE,
)

# ---------- Functions ----------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def analyze_with_gemini(summary: str) -> str | None:
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        prompt = (
            "Nama kamu BotAkmal. Berikan analisis singkat dan padat untuk peristiwa berikut. "
            "Jawab dalam bahasa Indonesia TANPA pendahuluan apapun dengan format tepat dua bagian berikut:\n\n"
            "*Tingkat Risiko:* <Low|Medium|High>\n\n"
            "*Alasan:* <alasan ringkas, 1-3 kalimat>\n\n"
            f"Peristiwa: {summary}"
        )
        resp = model.generate_content(prompt)
        text = (getattr(resp, 'text', '') or '').strip()
        return text if text else None
    except Exception as e:
        logging.warning("Gemini gagal: %s", e)
        return None


def send_fonnte_message(message: str):
    if not FONNTE_TOKEN or not FONNTE_TARGETS:
        logging.warning("Fonnte tidak dikonfigurasi; lewati kirim WhatsApp.")
        return
    for target in FONNTE_TARGETS:
        try:
            r = requests.post(
                "https://api.fonnte.com/send",
                headers={"Authorization": FONNTE_TOKEN},
                data={"target": target, "message": message},
                timeout=10,
            )
            logging.info("Fonnte ke %s: %s", target, r.status_code)
        except Exception as e:
            logging.warning("Fonnte error ke %s: %s", target, e)


def gemini_insight_with_timeout(summary: str, timeout_sec: float = 6.0) -> str | None:
    def _call():
        return analyze_with_gemini(summary)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_call)
            return fut.result(timeout=timeout_sec)
    except concurrent.futures.TimeoutError:
        logging.warning("Gemini timeout setelah %.1fs", timeout_sec)
        return None
    except Exception as e:
        logging.warning("Gemini error: %s", e)
        return None


def send_with_gemini(message: str, summary: str | None = None):
    insight = gemini_insight_with_timeout(summary or message)
    block = f"\n\nAnalisis BotAkmal (Gemini):\n{insight.strip()}" if (insight and insight.strip()) else "\n\nAnalisis BotAkmal (Gemini): -"
    send_fonnte_message(message + block)


def parse_event(line: str):
    now = utc_now_iso()
    m = RE_SUCCESS.search(line)
    if m:
        return {"ts": now, "type": "login_success", "user": m.group("user"), "ip": m.group("ip"),
                "method": m.group("method"), "raw": line.strip()}
    m = RE_FAIL.search(line)
    if m:
        return {"ts": now, "type": "login_fail", "user": m.group("user"), "ip": m.group("ip"), "raw": line.strip()}
    m = RE_SESSION_OPEN.search(line)
    if m and ALERT_SESSION_OPEN:
        return {"ts": now, "type": "session_open", "user": m.group("user"), "raw": line.strip()}
    return None


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


def iter_journald_sshd() -> Iterator[str | None]:
    try:
        proc = subprocess.Popen(
            [
                "journalctl",
                "-f",
                "-n", "0",
                "-o", "cat",
                "-u", "ssh",
                "-u", "sshd",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except Exception:
        proc = None

    buffer = ""
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


def format_whatsapp_message_v2(event: dict, analysis_text: str | None = None) -> str:
    lines = [
        f"[Login Monitor] Host: {HOSTNAME}",
        f"Time: {event.get('ts', '-')}",
        f"Type: {event.get('type', '-')}",
        f"User: {event.get('user', '-')}",
    ]
    if 'ip' in event:
        lines.append(f"IP: {event.get('ip')}")
    if 'method' in event:
        lines.append(f"Method: {event.get('method')}")

    lines.append("")
    lines.append("Analisis:")
    if analysis_text and analysis_text.strip():
        lines.append(analysis_text.strip())
    else:
        lines.append("*Tingkat Risiko:* -\n\n*Alasan:* -")

    return "\n".join(lines)


def main():
    logging.info("Mulai monitor log SSH...")
    ip_fail: dict[str, deque[float]] = defaultdict(deque)
    blocked_ips: set[str] = set()
    last_sent: dict[tuple, float] = {}
    DEDUP_TTL_SEC = 60.0

    existing_paths = [p for p in LOG_PATHS if os.path.exists(p)]
    tails = []
    if existing_paths:
        tails.extend([(p, tail_file(p)) for p in existing_paths])
        for p in existing_paths:
            logging.info("Membaca log file: %s", p)
    else:
        logging.warning("Tidak menemukan file log di %s; memakai journald ssh/sshd",
                        ", ".join(LOG_PATHS))
        tails.append(("journald:ssh", iter_journald_sshd()))
        logging.info("Membaca log via journald unit ssh/sshd")

    while True:
        for path, gen in tails:
            try:
                line = next(gen)
            except Exception:
                continue
            if line is None:
                continue

            evt = parse_event(line)
            if not evt:
                continue

            now_ts = time.time()
            cutoff_fail = now_ts - FAIL_WINDOW_SEC

            if evt["type"] == "login_fail":
                dq = ip_fail[evt["ip"]]
                dq.append(now_ts)
                while dq and dq[0] < cutoff_fail:
                    dq.popleft()

                key_fail = ("login_fail_single", evt.get("user"), evt.get("ip"))
                if last_sent.get(key_fail, 0) + DEDUP_TTL_SEC <= now_ts:
                    summ_single = f"login_fail user={evt.get('user')} ip={evt.get('ip','-')} host={HOSTNAME}"
                    analysis_single = gemini_insight_with_timeout(summ_single)
                    msg_single = format_whatsapp_message_v2(evt, analysis_single)
                    send_fonnte_message(msg_single)
                    last_sent[key_fail] = now_ts

                if len(dq) >= FAIL_THRESHOLD and evt["ip"] not in blocked_ips:
                    summ = f"{len(dq)} kali gagal login dari {evt['ip']} dalam {FAIL_WINDOW_SEC}s"
                    analysis = gemini_insight_with_timeout(summ)
                    msg = format_whatsapp_message_v2(evt, analysis)
                    send_fonnte_message(msg)
                    blocked_ips.add(evt["ip"])
                    logging.warning("Blokir IP %s", evt["ip"])

            if evt["type"] == "login_success":
                key = (evt["type"], evt.get("user"), evt.get("ip"))
                if last_sent.get(key, 0) + DEDUP_TTL_SEC <= now_ts:
                    summ = f"{evt['type']} user={evt.get('user')} ip={evt.get('ip','-')} host={HOSTNAME}"
                    analysis = gemini_insight_with_timeout(summ)
                    msg = format_whatsapp_message_v2(evt, analysis)
                    send_fonnte_message(msg)
                    last_sent[key] = now_ts

            if ALERT_SESSION_OPEN and evt["type"] == "session_open":
                key = (evt["type"], evt.get("user"))
                if last_sent.get(key, 0) + DEDUP_TTL_SEC <= now_ts:
                    summ = f"{evt['type']} user={evt.get('user')} host={HOSTNAME}"
                    analysis = gemini_insight_with_timeout(summ)
                    msg = format_whatsapp_message_v2(evt, analysis)
                    send_fonnte_message(msg)
                    last_sent[key] = now_ts


if __name__ == "__main__":
    logging.info("[BotAkmal] monitor start di %s", HOSTNAME)

    def _notify_startup():
        try:
            sources = [p for p in LOG_PATHS if os.path.exists(p)]
            source_msg = f"files={', '.join(sources)}" if sources else "journald:ssh,sshd"
            send_with_gemini(
                f"[BotAkmal] monitor start di {HOSTNAME}. Sumber log: {source_msg}",
                summary=f"monitor startup host={HOSTNAME} sources={source_msg}"
            )
        except Exception as e:
            logging.warning("Startup notify gagal: %s", e)

    threading.Thread(target=_notify_startup, daemon=True).start()
    main()
