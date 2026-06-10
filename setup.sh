#!/bin/bash
# osintbox-setup.sh — run this on the Pi after copying the project files
set -e

echo "[*] Installing system dependencies..."
sudo apt install -y python3-venv python3-pip whois dnsutils nmap

echo "[*] Creating Python venv..."
python3 -m venv ~/osint-env
source ~/osint-env/bin/activate

echo "[*] Installing Flask (only pip dep)..."
pip install flask

echo "[*] Creating systemd service..."
sudo tee /etc/systemd/system/osintbox.service > /dev/null <<EOF
[Unit]
Description=OSINT Box Web UI
After=network.target

[Service]
User=pi
WorkingDirectory=/home/pi/osintbox
ExecStart=/home/pi/osint-env/bin/python app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable osintbox
sudo systemctl start osintbox

echo "[+] Done. OSINT Box running at http://$(hostname -I | awk '{print $1}'):80"
