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
