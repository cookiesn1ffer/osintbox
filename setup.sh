#!/bin/bash
# osintbox-setup.sh — run this on the Pi after copying the project files
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$HOME/osint-env"
SERVICE_USER="$(whoami)"

echo "[*] Installing system dependencies..."
sudo apt update
sudo apt install -y python3-venv python3-pip whois dnsutils

echo "[*] Creating Python venv at $VENV_DIR..."
python3 -m venv --clear "$VENV_DIR"

if [ ! -x "$VENV_DIR/bin/python" ]; then
    echo "[!] venv creation failed — $VENV_DIR/bin/python not found." >&2
    echo "[!] Check that python3-venv installed correctly (see apt output above)." >&2
    exit 1
fi

echo "[*] Installing Flask..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install flask

ENV_FILE="$PROJECT_DIR/.env"
if [ -f "$ENV_FILE" ] && grep -q '^GROQ_API_KEY=' "$ENV_FILE"; then
    echo "[*] Existing GROQ_API_KEY found in .env, keeping it."
elif [ -t 0 ]; then
    echo "[*] Optional: Groq API key enables the AI tab (dossiers, query parsing)."
    echo "    Get a free one at https://console.groq.com/keys — leave blank to skip."
    read -rp "    GROQ_API_KEY: " GROQ_KEY
    if [ -n "$GROQ_KEY" ]; then
        echo "GROQ_API_KEY=$GROQ_KEY" > "$ENV_FILE"
        chmod 600 "$ENV_FILE"
        echo "[+] Saved to $ENV_FILE"
    else
        echo "[*] Skipped — add GROQ_API_KEY to $ENV_FILE later to enable AI features."
    fi
else
    echo "[*] No .env and no terminal to prompt — skipping Groq key (AI tab stays disabled)."
fi

echo "[*] Creating systemd service..."
sudo tee /etc/systemd/system/osintbox.service > /dev/null <<EOF
[Unit]
Description=OSINT Box Web UI
After=network.target

[Service]
User=$SERVICE_USER
WorkingDirectory=$PROJECT_DIR
ExecStart=$VENV_DIR/bin/python app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable osintbox
sudo systemctl restart osintbox

echo "[*] Waiting for service to come up..."
sleep 2

if systemctl is-active --quiet osintbox; then
    echo "[+] Done. OSINT Box running at http://$(hostname -I | awk '{print $1}'):5000"
else
    echo "[!] Service failed to start. Run: sudo systemctl status osintbox" >&2
    exit 1
fi
