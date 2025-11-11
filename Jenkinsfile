pipeline {
    agent any
    options { timestamps() }

    triggers {
        // Webhook GitHub
        githubPush()
        // Polling fallback tiap 2 menit
        pollSCM('H/2 * * * *')
    }

    environment {
        SCRIPT_FILE = "monitorAkmal.py"
        FONNTE_TOKEN = "uqMuVhM4YKzujVg38BiB"
        FONNTE_TARGETS = "6281933976553"
        GEMINI_API_KEY = "AIzaSyA6cfTruhVM6xwpRRX_03ZQXyIQCTd4JVE"
        GEMINI_MODEL = "gemini-2.5-flash"
    }

    stages {
        stage('Checkout') {
            steps {
                sh '''#!/bin/bash
echo "[CHECKOUT] Ambil source code dari repo..."
checkout scm
ls -a | grep "$SCRIPT_FILE" || echo "[CHECKOUT] $SCRIPT_FILE tidak ditemukan!"
'''
            }
        }

        stage('Setup Python') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
echo "[SETUP] Membuat virtual environment..."
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
. .venv/bin/activate
pip install --upgrade pip
pip install requests google-generativeai python-dotenv
'''
            }
        }

        stage('Notify WhatsApp CI Start') {
            steps {
                sh '''#!/bin/bash
. .venv/bin/activate
python3 - << 'PY'
import os, socket, datetime, requests
HOSTNAME = socket.gethostname()
ts = datetime.datetime.now().isoformat()
msg = f"[BotAkmal] Jenkins build monitorAkmal.py dimulai di {HOSTNAME} @ {ts}."

# Tes integrasi Gemini
gemini_ok = False
try:
    import google.generativeai as genai
    genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
    model = genai.GenerativeModel(os.getenv('GEMINI_MODEL', 'gemini-2.5-flash'))
    resp = model.generate_content("buatkan 2 kata kalau sekarang sudah gemini yang membalas.")
    if getattr(resp, 'text', ''):
        gemini_ok = True
        msg += "\\nInsight Gemini: " + getattr(resp, 'text', '').strip()
except Exception as e:
    msg += f"\\nAI Gemini gagal: {e}"

# Kirim Fonnte
token = os.getenv("FONNTE_TOKEN")
targets = [t.strip() for t in os.getenv("FONNTE_TARGETS", "").split(',') if t.strip()]
for t in targets:
    try:
        r = requests.post(
            "https://api.fonnte.com/send",
            headers={"Authorization": token},
            data={"target": t, "message": msg},
            timeout=10
        )
        print(f"Fonnte {t} {r.status_code}")
    except Exception as e:
        print("Fonnte error", e)
PY
'''
            }
        }

        stage('Run Monitor') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
LOG_FILE="$(pwd)/monitor.log"
PID_FILE="$(pwd)/monitor.pid"
echo "[RUN] Menjalankan $SCRIPT_FILE..."

# Validasi file skrip
if [ ! -f "$SCRIPT_FILE" ]; then
    echo "[RUN] FAIL: $SCRIPT_FILE tidak ditemukan di $(pwd)"
    ls -la
    exit 1
fi

# Hentikan monitor lama
if [ -f "$PID_FILE" ]; then
    OLD=$(cat "$PID_FILE" || true)
    if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
        echo "[RUN] Menghentikan monitor lama ($OLD)..."
        kill "$OLD" || true
        sleep 1
    fi
fi

# Pastikan Jenkins tidak mematikan proses background
export BUILD_ID=dontKillMe
export JENKINS_NODE_COOKIE=dontKillMe

# Bersihkan proses lama
pkill -f "$SCRIPT_FILE" 2>/dev/null || true
sleep 1

echo "[RUN] Python: $(.venv/bin/python -V)"
RUNNER=".venv/bin/python -u \"$SCRIPT_FILE\""
nohup setsid bash -c "$RUNNER" > "$LOG_FILE" 2>&1 < /dev/null &
echo $! > "$PID_FILE"
sleep 2

if ps -p $(cat "$PID_FILE") >/dev/null 2>&1; then
    echo "[RUN] OK: $SCRIPT_FILE berjalan (PID=$(cat "$PID_FILE"))"
else
    echo "[RUN] FAIL: Gagal menjalankan $SCRIPT_FILE"
    tail -n 200 "$LOG_FILE" || true
    exit 1
fi

# Health check
sleep 5
if ps -p $(cat "$PID_FILE") >/dev/null 2>&1; then
    echo "[RUN] HEALTH: proses masih hidup (PID=$(cat "$PID_FILE"))"
else
    echo "[RUN] HEALTH FAIL: proses mati segera setelah start"
    echo "----- monitor.log (tail 200) -----"
    tail -n 200 "$LOG_FILE" || true
    exit 1
fi
'''
            }
        }
    }

    post {
        always {
            echo "[POST] Arsipkan log & PID file..."
            archiveArtifacts artifacts: 'monitor.log,monitor.pid', allowEmptyArchive: true
        }
        success { echo "[POST] Build sukses." }
        failure { echo "[POST] Build gagal." }
    }
}
