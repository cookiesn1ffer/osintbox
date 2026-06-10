\# OSINT Box



A self-hosted passive recon platform built on a Raspberry Pi Zero WH.

Plug it in, connect to your network, open a browser — full OSINT toolkit with no setup required on the client side.



!\[OSINT Box UI](screenshot.png)



\---



\## Features



\- \*\*Username recon\*\* — searches 19 platforms with content verification (no false positives)

\- \*\*Name search\*\* — generates username variations + Google dork links for LinkedIn, GitHub, and more

\- \*\*IP / Host lookup\*\* — geo, ASN, org, timezone, reverse DNS via ipinfo.io

\- \*\*Domain recon\*\* — WHOIS, DNS records (A/MX/TXT/NS/CNAME), subdomain enumeration via crt.sh

\- \*\*Email analysis\*\* — format validation, MX records, domain age, Gravatar presence

\- \*\*Phone lookup\*\* — number parsing, country detection, Truecaller/Sync.me links

\- \*\*AI analysis\*\* — Groq-powered dossier generation, chain suggestions, natural language queries

\- \*\*Query history\*\* — all results stored in SQLite, clickable to reload

\- \*\*Dark terminal UI\*\* — JetBrains Mono, green/cyan accents, built for the aesthetic



\---



\## Hardware



| Component | Details |

|---|---|

| Board | Raspberry Pi Zero WH |

| OS | Raspberry Pi OS Lite 32-bit (Debian Trixie) |

| Storage | Any microSD (8GB+) |

| Power | Micro USB 5V |

| Network | Onboard WiFi (wlan0) |



\---



\## Stack



\- \*\*Python 3\*\* — stdlib only (`urllib`, `subprocess`, `socket`, `sqlite3`)

\- \*\*Flask\*\* — only pip dependency

\- \*\*SQLite\*\* — local query history

\- \*\*systemd\*\* — auto-start on boot

\- \*\*Groq API\*\* — AI features (optional, free tier)



\---



\## Setup



\### 1. Flash the SD card



Flash Raspberry Pi OS Lite (32-bit) using Raspberry Pi Imager.

Enable SSH and configure WiFi in the Imager customisation settings.



\### 2. Deploy



```bash

\# SSH into the Pi

ssh pi@raspberrypi.local



\# Clone the repo

git clone https://github.com/cookiesn1ffer/osintbox.git

cd osintbox



\# Run setup

chmod +x setup.sh

./setup.sh

```



\### 3. Access



Open a browser on any device on the same network:



```

http://<pi-ip>:5000

```



\### 4. AI features (optional)



Get a free Groq API key at https://console.groq.com



```bash

echo "GROQ\_API\_KEY=your\_key\_here" > \~/osintbox/.env

sudo systemctl restart osintbox

```



\---



\## Project Structure



```

osintbox/

├── app.py        # Flask app — all modules + embedded HTML UI

├── setup.sh      # One-shot install + systemd service setup

├── .gitignore

└── README.md

```



\---



\## Modules



| Module | Method |

|---|---|

| Username | HTTP + content verification per platform |

| Name | Variation generation + Google dork links |

| IP/Host | ipinfo.io API + socket reverse DNS |

| Domain | whois + dig subprocesses + crt.sh API |

| Email | MX/WHOIS + Gravatar hash check |

| Phone | Regex parsing + Truecaller/Sync.me links |

| AI | Groq llama-3.3-70b — dossier + chain suggestions |



\---



\## Author



\*\*Aarush (Cookie) Pradip\*\* — \[@cookiesn1ffer](https://github.com/cookiesn1ffer)  

Cybersecurity student | Offensive security | Pi hacker



\---



\## License



MIT — use it, break it, build on it.



