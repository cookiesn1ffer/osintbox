from flask import Flask, request, jsonify
import sqlite3, subprocess, socket, json, re, urllib.request, urllib.error, urllib.parse, hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

app = Flask(__name__)
DB = os.path.join(os.path.dirname(__file__), 'osint.db')

# ── Groq AI config ───────────────────────────────────────────────────────────
GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions'
GROQ_MODEL = 'openai/gpt-oss-120b'

def load_groq_key():
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if not os.path.exists(env_path):
        return ''
    lines = [l.strip() for l in open(env_path).read().splitlines()
             if l.strip() and not l.strip().startswith('#')]
    for line in lines:
        if '=' in line:
            k, v = line.split('=', 1)
            if k.strip() == 'GROQ_API_KEY':
                return v.strip().strip('"').strip("'")
    # fall back to a bare key with no GROQ_API_KEY= prefix
    if len(lines) == 1 and '=' not in lines[0]:
        return lines[0]
    return ''

GROQ_API_KEY = load_groq_key()

def call_groq(messages, max_tokens=800, temperature=0.3):
    if not GROQ_API_KEY:
        return None, 'GROQ_API_KEY not configured'
    payload = json.dumps({
        'model': GROQ_MODEL,
        'messages': messages,
        'temperature': temperature,
        'max_tokens': max_tokens,
    }).encode('utf-8')
    req = urllib.request.Request(GROQ_API_URL, data=payload, method='POST', headers={
        'Authorization': f'Bearer {GROQ_API_KEY}',
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (X11; Linux armv7l) osintbox/1.0',
    })
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read().decode('utf-8'))
        return data['choices'][0]['message']['content'], None
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode('utf-8', errors='ignore')
        except Exception:
            err_body = ''
        return None, f'Groq API error {e.code}: {err_body[:200]}'
    except Exception as e:
        return None, str(e)

def extract_json_block(text):
    text = text.strip()
    m = re.search(r'```(?:json)?\s*(\{.*\})\s*```', text, re.DOTALL)
    if m:
        return m.group(1)
    start, end = text.find('{'), text.rfind('}')
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]
    return text

# ── Embedded HTML template ──────────────────────────────────────────────
INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Box</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:        #080b08;
    --bg2:       #0f140f;
    --bg3:       #161d16;
    --bg4:       #1d271d;
    --border:    #1e2a1e;
    --green:     #00ff88;
    --cyan:      #00d4ff;
    --red:       #ff4466;
    --yellow:    #ffcc00;
    --muted:     #4a5e4a;
    --text:      #c8dcc8;
    --dim:       #6b826b;
  }

  html, body {
    background:
      radial-gradient(circle, rgba(0,255,136,0.05) 1px, transparent 1.6px) 0 0 / 26px 26px,
      var(--bg);
    background-attachment: fixed;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    min-height: 100vh;
    font-size: 13px;
    line-height: 1.6;
  }

  /* ── Header ── */
  header {
    border-bottom: 1px solid var(--border);
    padding: 18px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--bg2);
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .logo-icon {
    width: 32px; height: 32px;
    border: 1.5px solid var(--green);
    border-radius: 4px;
    display: flex; align-items: center; justify-content: center;
    color: var(--green);
    font-size: 16px;
    font-weight: 700;
  }

  .logo-text { font-size: 15px; font-weight: 700; color: var(--green); letter-spacing: 0.1em; }
  .logo-sub  { font-size: 10px; color: var(--muted); letter-spacing: 0.2em; text-transform: uppercase; }

  .status-pill {
    display: flex; align-items: center; gap: 6px;
    font-size: 11px; color: var(--dim);
  }

  .status-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  /* ── Layout ── */
  main {
    max-width: 900px;
    margin: 0 auto;
    padding: 32px 24px;
  }

  /* ── Search panel ── */
  .search-panel {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 24px;
    margin-bottom: 24px;
  }

  .panel-label {
    font-size: 10px;
    color: var(--muted);
    letter-spacing: 0.2em;
    text-transform: uppercase;
    margin-bottom: 16px;
  }

  /* ── Type tabs ── */
  .type-tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }

  .tab {
    padding: 6px 14px;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 3px;
    color: var(--dim);
    cursor: pointer;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    letter-spacing: 0.05em;
    transition: all 0.15s;
  }

  .tab:hover { border-color: var(--green); color: var(--green); }

  .tab.active {
    background: var(--green);
    border-color: var(--green);
    color: var(--bg);
    font-weight: 700;
  }

  /* ── Input row ── */
  .input-row {
    display: flex;
    gap: 8px;
  }

  .search-input {
    flex: 1;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 14px;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    outline: none;
    transition: border-color 0.15s;
  }

  .search-input:focus { border-color: var(--green); }
  .search-input::placeholder { color: var(--muted); }

  .search-btn {
    padding: 10px 22px;
    background: var(--green);
    border: none;
    border-radius: 4px;
    color: var(--bg);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    letter-spacing: 0.1em;
    transition: opacity 0.15s;
    white-space: nowrap;
  }

  .search-btn:hover { opacity: 0.85; }
  .search-btn:disabled { opacity: 0.4; cursor: not-allowed; }

  .hint { font-size: 10px; color: var(--muted); margin-top: 8px; }

  /* ── Output terminal ── */
  .terminal {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 24px;
    display: none;
  }

  .terminal.visible { display: block; }

  .terminal-bar {
    background: var(--bg3);
    border-bottom: 1px solid var(--border);
    padding: 8px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 11px;
    color: var(--dim);
  }

  .terminal-dots { display: flex; gap: 5px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; }
  .dot-r { background: #ff5f56; }
  .dot-y { background: #ffbd2e; }
  .dot-g { background: #27c93f; }

  .terminal-title { color: var(--dim); font-size: 11px; }

  .terminal-body {
    padding: 20px;
    min-height: 120px;
    max-height: 600px;
    overflow-y: auto;
    font-size: 12px;
    line-height: 1.8;
  }

  /* ── Result types ── */
  .r-header  { color: var(--cyan); font-weight: 700; font-size: 13px; margin-bottom: 12px; }
  .r-section { color: var(--yellow); margin-top: 14px; margin-bottom: 4px; font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; }
  .r-found   { color: var(--green); }
  .r-miss    { color: var(--muted); }
  .r-key     { color: var(--cyan); }
  .r-val     { color: var(--text); }
  .r-link    { color: var(--green); text-decoration: none; }
  .r-link:hover { text-decoration: underline; }
  .r-error   { color: var(--red); }
  .r-info    { color: var(--dim); font-size: 11px; }
  .r-row     { display: flex; gap: 8px; margin-bottom: 2px; }
  .r-badge   { display: inline-block; padding: 1px 7px; border-radius: 2px; font-size: 10px; font-weight: 700; }
  .badge-found { background: rgba(0,255,136,0.12); color: var(--green); border: 1px solid rgba(0,255,136,0.2); }
  .badge-miss  { background: rgba(74,94,74,0.2); color: var(--muted); border: 1px solid var(--border); }

  .dork-btn {
    display: inline-block;
    padding: 6px 12px;
    margin: 4px 6px 4px 0;
    background: rgba(0,255,136,0.12);
    color: var(--green);
    border: 1px solid rgba(0,255,136,0.3);
    border-radius: 3px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-decoration: none;
  }
  .dork-btn:hover { background: rgba(0,255,136,0.25); }

  .chain-btn {
    display: inline-block;
    padding: 6px 12px;
    margin: 4px 6px 4px 0;
    background: rgba(0,255,136,0.12);
    color: var(--green);
    border: 1px solid rgba(0,255,136,0.3);
    border-radius: 3px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
    cursor: pointer;
    font-family: 'JetBrains Mono', monospace;
  }
  .chain-btn:hover { background: rgba(0,255,136,0.25); }

  /* ── Analyze button ── */
  .analyze-btn {
    margin-left: auto;
    padding: 4px 12px;
    background: transparent;
    border: 1px solid var(--cyan);
    border-radius: 3px;
    color: var(--cyan);
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.1em;
    cursor: pointer;
    transition: all 0.15s;
  }
  .analyze-btn:hover { background: rgba(0,212,255,0.12); }
  .analyze-btn:disabled { opacity: 0.4; cursor: not-allowed; }

  /* ── AI analysis panel ── */
  .ai-panel {
    border-top: 1px solid rgba(0,212,255,0.3);
    padding: 16px 20px;
    background: rgba(0,212,255,0.04);
  }
  .ai-panel-label {
    font-size: 10px;
    color: var(--cyan);
    letter-spacing: 0.2em;
    text-transform: uppercase;
    margin-bottom: 10px;
  }
  .ai-panel-body {
    font-size: 12px;
    line-height: 1.8;
    color: var(--text);
    white-space: pre-wrap;
  }

  .spinner {
    display: inline-block;
    width: 12px; height: 12px;
    border: 2px solid var(--border);
    border-top-color: var(--green);
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
    vertical-align: middle;
    margin-right: 6px;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── History ── */
  .history-panel {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }

  .history-header {
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .history-header span { font-size: 10px; color: var(--muted); letter-spacing: 0.15em; text-transform: uppercase; }

  .history-list { max-height: 240px; overflow-y: auto; }

  .history-item {
    padding: 10px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 12px;
    cursor: pointer;
    transition: background 0.1s;
  }

  .history-item:hover { background: var(--bg3); }
  .history-item:last-child { border-bottom: none; }

  .h-type {
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    padding: 2px 7px;
    border-radius: 2px;
    background: rgba(0,212,255,0.1);
    color: var(--cyan);
    border: 1px solid rgba(0,212,255,0.2);
    white-space: nowrap;
  }

  .h-query { color: var(--text); flex: 1; }
  .h-time  { color: var(--muted); font-size: 10px; white-space: nowrap; }

  .empty-history { padding: 24px 20px; color: var(--muted); font-size: 11px; text-align: center; }

  /* ── Dossier card ── */
  .dossier {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 18px;
    margin-bottom: 18px;
  }

  .dossier-head {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 14px;
  }

  .dossier-avatar {
    width: 52px; height: 52px;
    flex: 0 0 52px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg3);
    color: var(--green);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .dossier-avatar svg { width: 28px; height: 28px; }

  .dossier-title { font-size: 15px; font-weight: 700; color: var(--text); }
  .dossier-query {
    font-size: 10px; color: var(--dim);
    letter-spacing: 0.15em; text-transform: uppercase;
    margin-top: 2px;
  }
  .dossier-badges { display: flex; gap: 6px; margin-top: 8px; flex-wrap: wrap; }

  .badge-pill {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 10px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.05em;
    border: 1px solid transparent;
  }
  .pill-green { background: rgba(0,255,136,0.12); color: var(--green); border-color: rgba(0,255,136,0.25); }
  .pill-cyan  { background: rgba(0,212,255,0.12); color: var(--cyan);  border-color: rgba(0,212,255,0.25); }
  .pill-red   { background: rgba(255,68,102,0.12); color: var(--red);  border-color: rgba(255,68,102,0.25); }

  .dossier-table { width: 100%; border-collapse: collapse; border-top: 1px solid var(--border); }
  .dossier-table tr { border-bottom: 1px solid var(--border); }
  .dossier-table tr:last-child { border-bottom: none; }
  .dossier-table td { padding: 7px 4px; font-size: 11px; }
  .dossier-table-key { color: var(--dim); width: 45%; }
  .dossier-table-val { color: var(--text); }

  /* ── Platform results table ── */
  .platform-table-wrap {
    max-height: 340px;
    overflow-y: auto;
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-top: 8px;
  }

  .platform-table { width: 100%; border-collapse: collapse; }

  .platform-table thead th {
    position: sticky;
    top: 0;
    background: rgba(0,212,255,0.1);
    color: var(--cyan);
    text-align: left;
    font-size: 10px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    padding: 8px 12px;
    z-index: 1;
  }

  .platform-row td {
    padding: 7px 12px;
    border-top: 1px solid var(--border);
    border-left: 2px solid transparent;
    font-size: 12px;
    transition: background 0.1s, border-color 0.1s;
  }

  .platform-row:hover td { background: var(--bg4); }
  .platform-row:hover td:first-child { border-left-color: var(--cyan); }

  .platform-cell, .platform-link-cell { vertical-align: middle; }

  .platform-cell-inner { display: flex; align-items: center; gap: 8px; white-space: nowrap; }
  .platform-icon { display: inline-flex; color: var(--dim); }
  .platform-icon svg { width: 18px; height: 18px; display: block; }
  .platform-row:hover .platform-icon { color: var(--cyan); }
  .platform-name { color: var(--text); }

  .platform-link-inner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }

  .platform-link {
    color: var(--green);
    text-decoration: none;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 320px;
  }
  .platform-link:hover { text-decoration: underline; }

  /* ── Summary links panel ── */
  .summary-grid {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 6px 16px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px 18px;
    margin-top: 16px;
  }
  .summary-key { color: var(--dim); font-size: 11px; }
  .summary-val { color: var(--text); font-size: 11px; font-weight: 700; }

  /* ── Dossier summary / donut charts ── */
  .dossier-summary { margin-top: 16px; }

  .donut-row {
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
    margin-top: 8px;
  }

  .donut-block {
    flex: 1 1 160px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px;
    text-align: center;
  }

  .donut-title {
    font-size: 10px; color: var(--dim);
    letter-spacing: 0.1em; text-transform: uppercase;
    margin-bottom: 8px;
  }

  .donut-center-text {
    fill: var(--text);
    font-size: 16px;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
  }

  .donut-legend { margin-top: 10px; text-align: left; display: inline-block; }
  .legend-item { display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--text); margin-bottom: 4px; }
  .legend-swatch { width: 9px; height: 9px; border-radius: 2px; display: inline-block; flex: 0 0 auto; }

  /* scrollbar */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">⬡</div>
    <div>
      <div class="logo-text">OSINT BOX</div>
      <div class="logo-sub">Passive Recon Platform</div>
    </div>
  </div>
  <div class="status-pill">
    <div class="status-dot"></div>
    <span id="status-text">online</span>
  </div>
</header>

<main>

  <!-- Search Panel -->
  <div class="search-panel">
    <div class="panel-label">// target input</div>

    <div class="type-tabs">
      <button class="tab active" data-type="username">username</button>
      <button class="tab" data-type="name">name</button>
      <button class="tab" data-type="ip">ip / host</button>
      <button class="tab" data-type="domain">domain</button>
      <button class="tab" data-type="email">email</button>
      <button class="tab" data-type="phone">phone</button>
      <button class="tab" data-type="ai" id="aiTab" style="display:none">ai</button>
    </div>
    <div class="hint" id="aiDisabledHint" style="display:none">AI features disabled — add GROQ_API_KEY to .env</div>

    <div class="input-row">
      <input class="search-input" id="queryInput" type="text"
             placeholder="enter target..." autocomplete="off" spellcheck="false">
      <button class="search-btn" id="searchBtn" onclick="runSearch()">RECON</button>
    </div>
    <div class="hint" id="hintText">Search 19 platforms for this username</div>
  </div>

  <!-- Terminal Output -->
  <div class="terminal" id="terminal">
    <div class="terminal-bar">
      <div class="terminal-dots">
        <div class="dot dot-r"></div>
        <div class="dot dot-y"></div>
        <div class="dot dot-g"></div>
      </div>
      <span class="terminal-title" id="termTitle">output</span>
      <button class="analyze-btn" id="analyzeBtn" style="display:none" onclick="analyzeResult()">ANALYZE</button>
    </div>
    <div class="terminal-body" id="termBody"></div>
    <div class="ai-panel" id="aiPanel" style="display:none">
      <div class="ai-panel-label">// AI ANALYSIS</div>
      <div class="ai-panel-body" id="aiPanelBody"></div>
    </div>
  </div>

  <!-- History -->
  <div class="history-panel">
    <div class="history-header">
      <span>// query history</span>
      <span id="historyCount">0 queries</span>
    </div>
    <div class="history-list" id="historyList">
      <div class="empty-history">no queries yet</div>
    </div>
  </div>

</main>

<script>
  let activeType = 'username';

  const hints = {
    username: 'Search 19 platforms for this username',
    name:     'Enter full name to search variations + generate dorks',
    ip:       'Geo, ASN, org, reverse DNS lookup',
    domain:   'WHOIS, DNS records, subdomains via crt.sh',
    email:    'Format check, domain MX, Gravatar presence',
    phone:    'Number analysis + search links',
    ai:       'Describe what you want to find in plain English',
  };

  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeType = tab.dataset.type;
      document.getElementById('hintText').textContent = hints[activeType];
      document.getElementById('queryInput').placeholder = `enter ${activeType}...`;
      document.getElementById('queryInput').focus();
    });
  });

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ── Platform icons (monochrome, currentColor) ──────────────────────────
  const ICONS = {
    github: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.58 2 12.25c0 4.53 2.87 8.37 6.84 9.73.5.09.68-.22.68-.48 0-.24-.01-1.04-.01-1.89-2.78.62-3.37-1.21-3.37-1.21-.46-1.18-1.11-1.5-1.11-1.5-.91-.64.07-.62.07-.62 1 .07 1.53 1.05 1.53 1.05.89 1.56 2.34 1.11 2.91.85.09-.66.34-1.11.62-1.36-2.22-.26-4.56-1.13-4.56-5.02 0-1.11.39-2.01 1.03-2.72-.1-.26-.45-1.3.1-2.7 0 0 .84-.27 2.76 1.04a9.4 9.4 0 0 1 5.02 0c1.92-1.32 2.76-1.04 2.76-1.04.55 1.4.2 2.44.1 2.7.64.71 1.03 1.61 1.03 2.72 0 3.9-2.35 4.76-4.58 5.01.36.32.67.94.67 1.9 0 1.37-.01 2.47-.01 2.81 0 .27.18.58.69.48A10.02 10.02 0 0 0 22 12.25C22 6.58 17.52 2 12 2z"/></svg>`,
    instagram: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="18" height="18" rx="5"/><circle cx="12" cy="12" r="4"/><circle cx="17.2" cy="6.8" r="1" fill="currentColor" stroke="none"/></svg>`,
    twitter: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M4 4l16 16M20 4L4 20"/></svg>`,
    reddit: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="13" r="7"/><circle cx="9" cy="13" r="1" fill="currentColor" stroke="none"/><circle cx="15" cy="13" r="1" fill="currentColor" stroke="none"/><path d="M8.5 16.5c1 .8 2.2 1.2 3.5 1.2s2.5-.4 3.5-1.2" stroke-linecap="round"/><circle cx="12" cy="6.5" r="1.2" fill="currentColor" stroke="none"/><path d="M12 7.5v2"/></svg>`,
    facebook: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 8.5h2.5V5.3C16.1 5.1 15 5 13.8 5c-2.5 0-4.2 1.5-4.2 4.3V11H7v3h2.6v7h3.2v-7h2.6l.4-3h-3V9.6c0-.9.3-1.1 1.2-1.1z"/></svg>`,
    linkedin: `<svg viewBox="0 0 24 24" fill="currentColor"><rect x="3" y="3" width="18" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="8" cy="9" r="1.3"/><rect x="6.8" y="11" width="2.4" height="7"/><path d="M12.5 11h2.3v1.2c.5-.8 1.4-1.4 2.6-1.4 2 0 3 1.3 3 3.8V18h-2.4v-3c0-1.1-.4-1.8-1.4-1.8-.8 0-1.3.6-1.5 1.1-.1.2-.1.5-.1.8V18h-2.4z"/></svg>`,
    tiktok: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 3v10.2a3.3 3.3 0 1 1-2-3v-2.1a5.3 5.3 0 1 0 4 5.1V8.6c1 .8 2.2 1.3 3.6 1.3V7.7c-1.6 0-2.9-.7-3.6-1.9-.4-.6-.6-1.3-.6-2.1z"/></svg>`,
    youtube: `<svg viewBox="0 0 24 24" fill="currentColor"><rect x="2.5" y="6" width="19" height="12" rx="3" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10.5 9.5l5 2.5-5 2.5z"/></svg>`,
    telegram: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"><path d="M21 4L3 11.5l5.5 2 1.8 5.8 3-3.7 4.4 3.4z"/><path d="M9.3 14.3L19 7"/></svg>`,
    discord: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8.5 5.5c-1.6.3-3 .8-4.3 1.5C2.7 10 2.3 13.5 2.6 17c1.5 1.1 3 1.8 4.5 2.2l.9-1.5c-.8-.3-1.5-.6-2.2-1.1.2-.1.4-.3.6-.4 3.2 1.5 6.7 1.5 9.9 0 .2.1.4.3.6.4-.7.5-1.4.8-2.2 1.1l.9 1.5c1.5-.4 3-1.1 4.5-2.2.4-4-.4-7.4-2.4-10-1.3-.7-2.7-1.2-4.3-1.5l-.5 1c1.3.2 2.5.6 3.6 1.2-2.6-1.2-5.7-1.2-8.3 0 1.1-.6 2.3-1 3.6-1.2zM9 12.8c-.8 0-1.4.7-1.4 1.6s.6 1.6 1.4 1.6 1.4-.7 1.4-1.6-.6-1.6-1.4-1.6zm6 0c-.8 0-1.4.7-1.4 1.6s.6 1.6 1.4 1.6 1.4-.7 1.4-1.6-.6-1.6-1.4-1.6z"/></svg>`,
    keybase: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="8" cy="9" r="4"/><path d="M11 12l9 9M16 17l2-2M18.5 19.5l2-2"/></svg>`,
    pinterest: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a10 10 0 0 0-3.6 19.3c-.1-.8-.2-2 .1-2.9l1.3-5.5s-.3-.6-.3-1.6c0-1.5.9-2.6 2-2.6.9 0 1.4.7 1.4 1.6 0 1-.6 2.4-.9 3.7-.3 1.1.5 2 1.6 2 1.9 0 3.2-2.4 3.2-5.3 0-2.2-1.5-3.8-4.2-3.8-3 0-4.9 2.2-4.9 4.7 0 .9.3 1.5.6 2 .2.2.2.3.1.5l-.3 1.1c-.1.3-.3.4-.6.3-1.2-.5-1.9-2-1.9-3.6 0-2.9 2.4-6.3 7.2-6.3 3.8 0 6.3 2.7 6.3 5.7 0 3.9-2.2 6.9-5.4 6.9-1.1 0-2.1-.6-2.4-1.3 0 0-.6 2.2-.7 2.7-.2.7-.6 1.5-.9 2.1A10 10 0 1 0 12 2z"/></svg>`,
    snapchat: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 3c-3 0-4.8 2.2-4.8 5 0 1 .1 1.8.2 2.4-.7.3-1.6.5-2.1 1-.3.3-.2.8.3 1 .4.2 1 .3 1.2.6.2.3-.1.6-.4 1-.5.6-1 1.2-.4 1.8.4.4 1.2.4 1.7.5.4.1.5.3.6.7.2.7.6 1.5 2 1.5.9 0 1.5-.3 1.9-.3s1 .3 1.9.3c1.4 0 1.8-.8 2-1.5.1-.4.2-.6.6-.7.5-.1 1.3-.1 1.7-.5.6-.6.1-1.2-.4-1.8-.3-.4-.6-.7-.4-1 .2-.3.8-.4 1.2-.6.5-.2.6-.7.3-1-.5-.5-1.4-.7-2.1-1 .1-.6.2-1.4.2-2.4 0-2.8-1.8-5-4.8-5z"/></svg>`,
    twitch: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 2L2.5 5.5v14H7V22l3-2.5h3.5L19 14V2H4zm13 11l-2.5 2.5h-3.5L8.5 18v-2.5H5V4h12v9z"/><path d="M14.5 6.5h2v5h-2zM9.5 6.5h2v5h-2z"/></svg>`,
    steam: `<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="15.5" cy="8.5" r="2.3"/><circle cx="8.5" cy="15" r="2"/><path d="M10.2 13.5l3-3" stroke="currentColor" stroke-width="1.4"/></svg>`,
    default: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 4 6 4 9s-1.5 6.3-4 9c-2.5-2.7-4-6-4-9s1.5-6.3 4-9z"/></svg>`,
  };

  function getPlatformIcon(site) {
    const low = (site || '').toLowerCase();
    if (low === 'x' || low.includes('twitter')) return ICONS.twitter;
    for (const key in ICONS) {
      if (key !== 'default' && low.includes(key)) return ICONS[key];
    }
    return ICONS.default;
  }

  const PERSON_ICON = `<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4.42 3.58-8 8-8s8 3.58 8 8H4z"/></svg>`;

  // ── Dossier card: avatar + title + pill badges + key/value table ──────
  function buildDossierCard(type, query, badges, rows) {
    let html = `<div class="dossier">`;
    html += `<div class="dossier-head">`;
    html += `<div class="dossier-avatar">${PERSON_ICON}</div>`;
    html += `<div class="dossier-info">`;
    html += `<div class="dossier-title">${escapeHtml(query)}</div>`;
    html += `<div class="dossier-query">${escapeHtml(type.toUpperCase())} RECON</div>`;
    html += `<div class="dossier-badges">` + badges.map(b =>
      `<span class="badge-pill pill-${b.variant}">${escapeHtml(b.text)}</span>`
    ).join('') + `</div>`;
    html += `</div>`; // dossier-info
    html += `</div>`; // dossier-head
    if (rows && rows.length) {
      html += `<table class="dossier-table">` + rows.map(([k, v]) =>
        `<tr><td class="dossier-table-key">${escapeHtml(k)}</td><td class="dossier-table-val">${escapeHtml(String(v))}</td></tr>`
      ).join('') + `</table>`;
    }
    html += `</div>`; // dossier
    return html;
  }

  // ── Platform results table (used for username `found` + per-variation found lists) ──
  function buildPlatformTable(pairs) {
    if (!pairs || pairs.length === 0) {
      return '<div class="r-miss">no accounts found</div>';
    }
    let html = `<div class="platform-table-wrap"><table class="platform-table">
      <thead><tr><th>Platform</th><th>Link</th></tr></thead><tbody>`;
    pairs.forEach(([site, url]) => {
      html += `<tr class="platform-row">
        <td class="platform-cell">
          <div class="platform-cell-inner">
            <span class="platform-icon">${getPlatformIcon(site)}</span>
            <span class="platform-name">${escapeHtml(site)}</span>
          </div>
        </td>
        <td class="platform-link-cell">
          <div class="platform-link-inner">
            <a class="platform-link" href="${url}" target="_blank">${escapeHtml(url)}</a>
            <span class="badge-pill pill-green">FOUND</span>
          </div>
        </td>
      </tr>`;
    });
    html += `</tbody></table></div>`;
    return html;
  }

  // ── Summary links panel: two-column key/value grid ─────────────────────
  function buildSummaryGrid(rows) {
    return `<div class="summary-grid">` + rows.map(([k, v]) =>
      `<div class="summary-key">${escapeHtml(k)}</div><div class="summary-val">${escapeHtml(String(v))}</div>`
    ).join('') + `</div>`;
  }

  // ── Donut chart (pure SVG, stroke-dasharray segments) ───────────────────
  function donutSvg(segments, centerText, size) {
    size = size || 110;
    const r = size / 2 - 12;
    const c = 2 * Math.PI * r;
    const cx = size / 2, cy = size / 2;
    let cum = 0;
    const arcs = segments.map(seg => {
      const len = Math.max(0, (seg.pct / 100) * c);
      const dasharray = `${len.toFixed(2)} ${(c - len).toFixed(2)}`;
      const dashoffset = -cum;
      cum += len;
      return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke-width="12"
        style="stroke:${seg.color}" stroke-dasharray="${dasharray}" stroke-dashoffset="${dashoffset}"
        transform="rotate(-90 ${cx} ${cy})"/>`;
    }).join('');
    return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      ${arcs}
      <text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="central" class="donut-center-text">${escapeHtml(String(centerText))}</text>
    </svg>`;
  }

  function buildDonutBlock(title, segments, centerText, legendItems) {
    return `<div class="donut-block">
      <div class="donut-title">${escapeHtml(title)}</div>
      ${donutSvg(segments, centerText)}
      <div class="donut-legend">${legendItems.map(li =>
        `<div class="legend-item"><span class="legend-swatch" style="background:${li.color}"></span>${escapeHtml(li.label)} (${li.count})</div>`
      ).join('')}</div>
    </div>`;
  }

  // foundCount/checkedCount drive the hit-rate donut; foundPairs (site,url list) drives
  // the category-breakdown donut — both are real counts already present in the result data.
  function buildDossierSummary(foundCount, checkedCount, foundPairs) {
    const hitRate = checkedCount > 0 ? (foundCount / checkedCount * 100) : 0;
    const segA = [
      { pct: hitRate, color: 'var(--green)' },
      { pct: 100 - hitRate, color: 'var(--border)' },
    ];

    const devKeys = ['github', 'gitlab', 'keybase'];
    const socialKeys = ['instagram', 'twitter', 'facebook', 'tiktok', 'reddit', 'snapchat'];
    const cats = { Dev: 0, Social: 0, Other: 0 };
    foundPairs.forEach(([site]) => {
      const low = site.toLowerCase();
      if (devKeys.some(k => low.includes(k))) cats.Dev++;
      else if (socialKeys.some(k => low.includes(k))) cats.Social++;
      else cats.Other++;
    });
    const totalFound = foundPairs.length;
    const catColors = { Dev: 'var(--green)', Social: 'var(--cyan)', Other: 'var(--yellow)' };
    const segB = totalFound > 0
      ? Object.keys(cats).filter(k => cats[k] > 0).map(k => ({ pct: cats[k] / totalFound * 100, color: catColors[k] }))
      : [{ pct: 100, color: 'var(--border)' }];

    return `<div class="dossier-summary">
      <div class="r-section">dossier summary</div>
      <div class="donut-row">
        ${buildDonutBlock('Found vs Not Found', segA, hitRate.toFixed(1) + '%', [
          { color: 'var(--green)', label: 'Found', count: foundCount },
          { color: 'var(--border)', label: 'Not Found', count: checkedCount - foundCount },
        ])}
        ${buildDonutBlock('Platform Categories', segB, totalFound, Object.keys(cats).map(k =>
          ({ color: catColors[k], label: k, count: cats[k] })
        ))}
      </div>
    </div>`;
  }

  // Show/hide the AI tab based on whether GROQ_API_KEY is configured
  async function checkAiStatus() {
    try {
      const res  = await fetch('/ai/status');
      const data = await res.json();
      if (data.enabled) {
        document.getElementById('aiTab').style.display = '';
      } else {
        document.getElementById('aiDisabledHint').style.display = '';
      }
    } catch (e) {}
  }
  checkAiStatus();

  // Enter key
  document.getElementById('queryInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') runSearch();
  });

  let lastSearchData = null;

  async function runSearch() {
    const query = document.getElementById('queryInput').value.trim();
    if (!query) return;

    const btn  = document.getElementById('searchBtn');
    const term = document.getElementById('terminal');
    const body = document.getElementById('termBody');
    const title= document.getElementById('termTitle');
    const analyzeBtn = document.getElementById('analyzeBtn');

    btn.disabled = true;
    btn.textContent = 'SCANNING...';
    term.classList.add('visible');
    title.textContent = `${activeType} :: ${query}`;
    body.innerHTML = `<span class="spinner"></span><span class="r-info">running recon on <span class="r-key">${query}</span>...</span>`;
    analyzeBtn.style.display = 'none';
    hideAiPanel();
    lastSearchData = null;

    try {
      if (activeType === 'ai') {
        const fd = new FormData();
        fd.append('query', query);

        const res  = await fetch('/ai/parse', { method: 'POST', body: fd });
        const data = await res.json();
        renderAiResults(data, body);
      } else {
        const fd = new FormData();
        fd.append('type', activeType);
        fd.append('query', query);

        const res  = await fetch('/search', { method: 'POST', body: fd });
        const data = await res.json();

        renderResult(data, body);
        if (data.result) {
          lastSearchData = data;
          analyzeBtn.style.display = '';
        }
      }
      loadHistory();
    } catch (e) {
      body.innerHTML = `<span class="r-error">Error: ${e.message}</span>`;
    } finally {
      btn.disabled = false;
      btn.textContent = 'RECON';
    }
  }

  function renderResult(data, container) {
    container.innerHTML = buildResultHtml(data);
  }

  function renderAiResults(data, container) {
    if (data.error) {
      container.innerHTML = `<span class="r-error">${escapeHtml(data.error)}</span>`;
      return;
    }

    const results = data.results || [];
    let html = `<div class="r-header">▶ AI :: ${escapeHtml(data.query)}</div>`;
    html += `<div class="r-info">${results.length} target(s) identified</div>`;

    if (results.length === 0) {
      html += `<div class="r-miss">no recognizable targets found in query</div>`;
    } else {
      results.forEach(item => {
        html += `<div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--border)">`;
        html += buildResultHtml(item);
        html += `</div>`;
      });
    }

    container.innerHTML = html;
  }

  function buildResultHtml(data) {
    if (!data.result) {
      return '<span class="r-error">No result returned.</span>';
    }

    const r = data.result;
    let html = `<div class="r-header">▶ ${data.type.toUpperCase()} :: ${data.query}</div>`;

    if (data.type === 'username') {
      const found = r.found || [];
      const miss  = r.not_found || [];
      const checked = found.length + miss.length;
      const hitRate = checked > 0 ? (found.length / checked * 100) : 0;

      html += buildDossierCard('username', data.query, [
        { text: 'USERNAME', variant: 'cyan' },
        { text: `${found.length} FOUND`, variant: 'green' },
        { text: `${miss.length} NOT FOUND`, variant: 'red' },
      ], [
        ['Query', data.query],
        ['Platforms Checked', checked],
      ]);

      html += `<div class="r-section">found (${found.length})</div>`;
      html += buildPlatformTable(found);

      html += `<div class="r-section">not found (${miss.length})</div>`;
      html += `<div class="r-miss">${miss.join(' · ') || 'none'}</div>`;

      html += buildSummaryGrid([
        ['Query', data.query],
        ['Platforms Checked', checked],
        ['Found', found.length],
        ['Not Found', miss.length],
        ['Hit Rate %', hitRate.toFixed(1) + '%'],
      ]);

      html += buildDossierSummary(found.length, checked, found);

    } else if (data.type === 'name') {
      const variations = r.variations_results || {};
      const dorks       = r.dork_links || [];
      const allKeys     = Object.keys(variations);
      const hits        = allKeys.filter(k => (variations[k] || []).length > 0);
      const allFoundPairs = [];
      allKeys.forEach(k => (variations[k] || []).forEach(pair => allFoundPairs.push(pair)));
      const hitRate = allKeys.length > 0 ? (hits.length / allKeys.length * 100) : 0;

      html += buildDossierCard('name', data.query, [
        { text: 'NAME', variant: 'cyan' },
        { text: `${hits.length} VARIATIONS W/ HITS`, variant: 'green' },
        { text: `${allKeys.length - hits.length} NO HITS`, variant: 'red' },
      ], [
        ['Query', data.query],
        ['Variations Searched', allKeys.length],
      ]);

      html += `<div class="r-info">${allKeys.length} variations searched, ${hits.length} had hits</div>`;

      html += `<div class="r-section">google dorks</div>`;
      html += `<div>` + dorks.map(d =>
        `<a class="dork-btn" href="${d.url}" target="_blank">${d.label}</a>`
      ).join('') + `</div>`;

      html += `<div class="r-section">username variations (${hits.length} with hits)</div>`;
      if (hits.length === 0) {
        html += `<div class="r-miss">no variations returned hits</div>`;
      } else {
        hits.forEach(variation => {
          html += `<div class="r-key" style="margin-top:10px">${variation}</div>`;
          html += buildPlatformTable(variations[variation]);
        });
      }

      html += buildSummaryGrid([
        ['Query', data.query],
        ['Variations Searched', allKeys.length],
        ['Variations w/ Hits', hits.length],
        ['Dork Queries', dorks.length],
        ['Hit Rate %', hitRate.toFixed(1) + '%'],
      ]);

      html += buildDossierSummary(hits.length, allKeys.length, allFoundPairs);

    } else if (data.type === 'ip') {
      const info = r.ipinfo || {};
      html += row('IP',          r.resolved_ip);
      html += row('Hostname',    r.reverse_dns);
      html += row('City',        info.city);
      html += row('Region',      info.region);
      html += row('Country',     info.country);
      html += row('Org/ASN',     info.org);
      html += row('Timezone',    info.timezone);
      html += row('Postal',      info.postal);
      if (info.loc) {
        html += row('Coords', `<a class="r-link" href="https://maps.google.com/?q=${info.loc}" target="_blank">${info.loc}</a>`);
      }

    } else if (data.type === 'domain') {
      html += `<div class="r-section">whois</div>`;
      html += `<pre style="color:var(--text);font-size:11px;white-space:pre-wrap">${r.whois || 'N/A'}</pre>`;
      html += `<div class="r-section">dns records</div>`;
      ['A','MX','TXT','NS','CNAME'].forEach(t => {
        html += row(`DNS ${t}`, r[`dns_${t}`]);
      });
      html += `<div class="r-section">subdomains via crt.sh (${(r.subdomains||[]).length})</div>`;
      if (r.subdomains && r.subdomains.length > 0) {
        html += r.subdomains.map(s =>
          `<div class="r-found">· ${s}</div>`
        ).join('');
      } else {
        html += `<div class="r-miss">none found</div>`;
      }

    } else if (data.type === 'email') {
      html += row('Valid format',    r.valid_format ? '✓ yes' : '✗ no');
      html += row('Domain MX',      r.domain_mx);
      html += row('Domain created', r.domain_created || 'N/A');
      html += row('Gravatar',       r.gravatar_found
        ? `<a class="r-link" href="${r.gravatar}" target="_blank">${r.gravatar}</a>`
        : 'not found');
      html += `<div class="r-info" style="margin-top:10px">${r.hibp_note}</div>`;

    } else if (data.type === 'phone') {
      html += row('Cleaned',   r.cleaned);
      html += row('Length',    r.length);
      html += row('Country',   r.country);
      html += row('Number',    r.number);
      html += `<div class="r-section">search links</div>`;
      html += `<div><a class="r-link" href="${r.truecaller_link}" target="_blank">→ Truecaller</a></div>`;
      html += `<div><a class="r-link" href="${r.sync_me_link}" target="_blank">→ Sync.me</a></div>`;
    }

    return html;
  }

  function row(label, val) {
    if (!val) return '';
    return `<div class="r-row"><span class="r-key" style="min-width:140px">${label}</span><span class="r-val">${val}</span></div>`;
  }

  function hideAiPanel() {
    document.getElementById('aiPanel').style.display = 'none';
    document.getElementById('aiPanelBody').innerHTML = '';
  }

  // Tab type returned by Groq -> the matching type-tab
  const aiTypeToTab = {
    username: 'username', name: 'name', ip: 'ip',
    domain: 'domain', email: 'email', phone: 'phone',
  };

  function selectChainTarget(type, value) {
    const tab = document.querySelector(`.tab[data-type="${aiTypeToTab[type] || type}"]`);
    if (tab) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeType = tab.dataset.type;
      document.getElementById('hintText').textContent = hints[activeType];
      document.getElementById('queryInput').placeholder = `enter ${activeType}...`;
    }
    const input = document.getElementById('queryInput');
    input.value = value;
    input.focus();
  }

  function parseNextTargets(text) {
    const idx = text.search(/NEXT TARGETS:?/i);
    if (idx === -1) return { main: text, targets: [] };

    const main = text.slice(0, idx).trim();
    const section = text.slice(idx);
    const targets = [];

    const lineRe = /\\[(\\w+)\\]\\s*([^\\n—\\-]+?)\\s*[—\\-]\\s*(.+)/g;
    let m;
    while ((m = lineRe.exec(section)) !== null) {
      targets.push({ type: m[1].trim().toLowerCase(), value: m[2].trim(), reason: m[3].trim() });
    }

    return { main, targets };
  }

  async function analyzeResult() {
    if (!lastSearchData) return;

    const analyzeBtn = document.getElementById('analyzeBtn');
    const panel = document.getElementById('aiPanel');
    const body  = document.getElementById('aiPanelBody');

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = 'ANALYZING...';
    panel.style.display = '';
    body.innerHTML = `<span class="spinner"></span><span class="r-info">generating dossier...</span>`;

    try {
      const res = await fetch('/ai/dossier', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: lastSearchData.type,
          query: lastSearchData.query,
          result: lastSearchData.result,
        }),
      });
      const data = await res.json();

      if (data.error) {
        body.innerHTML = `<span class="r-error">${escapeHtml(data.error)}</span>`;
        return;
      }

      const { main, targets } = parseNextTargets(data.dossier || '');

      body.innerHTML = '';
      const mainDiv = document.createElement('div');
      mainDiv.textContent = main;
      body.appendChild(mainDiv);

      if (targets.length > 0) {
        const sectionLabel = document.createElement('div');
        sectionLabel.className = 'r-section';
        sectionLabel.style.marginTop = '14px';
        sectionLabel.textContent = 'next targets';
        body.appendChild(sectionLabel);

        const wrap = document.createElement('div');
        targets.forEach(t => {
          const chainBtn = document.createElement('button');
          chainBtn.className = 'chain-btn';
          chainBtn.textContent = `[${t.type}] ${t.value}`;
          chainBtn.title = t.reason;
          chainBtn.addEventListener('click', () => selectChainTarget(t.type, t.value));
          wrap.appendChild(chainBtn);
        });
        body.appendChild(wrap);
      }
    } catch (e) {
      body.innerHTML = `<span class="r-error">AI analysis unavailable: ${escapeHtml(e.message)}</span>`;
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = 'ANALYZE';
    }
  }

  async function loadHistory() {
    try {
      const res  = await fetch('/history');
      const data = await res.json();
      const list = document.getElementById('historyList');
      const count= document.getElementById('historyCount');

      count.textContent = `${data.length} queries`;

      if (data.length === 0) {
        list.innerHTML = '<div class="empty-history">no queries yet</div>';
        return;
      }

      list.innerHTML = data.map(q => `
        <div class="history-item" onclick="loadHistoryDetail(${q.id})">
          <span class="h-type">${q.type}</span>
          <span class="h-query">${q.query}</span>
          <span class="h-time">${q.time}</span>
        </div>
      `).join('');
    } catch(e) {}
  }

  async function loadHistoryDetail(id) {
    try {
      const res  = await fetch(`/history/${id}`);
      const data = await res.json();
      const body = document.getElementById('termBody');
      const term = document.getElementById('terminal');
      const title= document.getElementById('termTitle');

      term.classList.add('visible');
      title.textContent = `${data.type} :: ${data.query} [history]`;
      renderResult(data, body);
      window.scrollTo({ top: 200, behavior: 'smooth' });
    } catch(e) {}
  }

  // Init
  loadHistory();
  setInterval(loadHistory, 30000);
</script>
</body>
</html>
"""

# ── DB setup ──────────────────────────────────────────────────────────────────
def init_db():
    with sqlite3.connect(DB) as c:
        c.execute('''CREATE TABLE IF NOT EXISTS queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT, query TEXT, result TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )''')
init_db()

def save_result(qtype, query, result):
    with sqlite3.connect(DB) as c:
        c.execute('INSERT INTO queries (type,query,result) VALUES (?,?,?)',
                  (qtype, query, result))

# ── OSINT modules ─────────────────────────────────────────────────────────────

def check_username(username, capture_bodies=False):
    def find_og_title(body):
        # attribute order varies (some sites render content="..." before property="og:title")
        m = re.search(r'<meta[^>]*?property=["\']og:title["\'][^>]*?content=["\']([^"\']*)["\']',
                       body, re.IGNORECASE)
        if not m:
            m = re.search(r'<meta[^>]*?content=["\']([^"\']*)["\'][^>]*?property=["\']og:title["\']',
                           body, re.IGNORECASE)
        return m.group(1) if m else None

    def og_title_has_username(body, uname):
        title = find_og_title(body)
        return bool(title) and uname.lower() in title.lower()

    def instagram_check(body, uname):
        if '"edge_owner_to_timeline_media"' in body:
            return True
        if '"userNotFound":true' in body or 'Page Not Found' in body:
            return False
        # Real profiles carry an og:title meta tag ending in this suffix;
        # the generic shell served for nonexistent users has no og:title at all.
        return 'Instagram photos and videos' in body

    def tiktok_check(body, uname):
        low = body.lower()
        markers = ("couldn't find this account", "couldn’t find this account",
                   "couldnt find this account")
        return not any(m in low for m in markers)

    def twitch_check(body, uname):
        title = find_og_title(body)
        if not title:
            return False
        # Nonexistent users get a generic og:title of just "Twitch";
        # real channels get "{username} - Twitch".
        return title.strip().lower() != 'twitch' and '"statusCode":404' not in body

    def linkedin_check(uname):
        url = f"https://www.linkedin.com/in/{uname}"
        headers = {
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'),
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        try:
            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=8)
            final_url = resp.geturl()
            if '/login' in final_url or 'authwall' in final_url:
                return ("LinkedIn", False, url, None)
            body = resp.read(500000).decode('utf-8', errors='ignore')
            ok = ('linkedin.com/in/' in final_url or '"vanityName"' in body
                  or 'public-profile-hero-image' in body
                  or ('authwall' not in body and resp.status == 200))
            return ("LinkedIn", ok, url, body if ok else None)
        except Exception:
            return ("LinkedIn", False, url, None)

    # site -> (fetch_url, display_url, content_check)
    # content_check is None for a plain status==200 check
    sites = {
        "GitHub":     (f"https://github.com/{username}", None,
                        lambda b, u: 'itemprop="name"' in b or og_title_has_username(b, u)),
        "Instagram":  (f"https://www.instagram.com/{username}", None, instagram_check),
        "Reddit":     (f"https://www.reddit.com/user/{username}", None,
                        lambda b, u: '"is_employee"' in b or '"icon_img"' in b),
        "TikTok":     (f"https://www.tiktok.com/@{username}", None, tiktok_check),
        "Pinterest":  (f"https://www.pinterest.com/{username}", None,
                        lambda b, u: 'og:type" content="profile"' in b),
        "Twitch":     (f"https://www.twitch.tv/{username}", None, twitch_check),
        "Telegram":   (f"https://t.me/{username}", None,
                        lambda b, u: 'tgme_page_title' in b),
        "Snapchat":   (f"https://www.snapchat.com/add/{username}", None,
                        lambda b, u: 'userHandle' in b or u in b),
        "Medium":     (f"https://medium.com/@{username}", None,
                        lambda b, u: 'page-not-found' not in b),
        "Dev.to":     (f"https://dev.to/{username}", None,
                        lambda b, u: 'crayons-avatar' in b or 'profile-header' in b),
        "Gitlab":     (f"https://gitlab.com/{username}", None,
                        lambda b, u: 'class="user-info"' in b),
        "HackerNews": (f"https://news.ycombinator.com/user?id={username}", None,
                        lambda b, u: '<tr class="athing">' in b or 'karma' in b),
        "Keybase":    (f"https://keybase.io/_/api/1.0/user/lookup.json?username={username}",
                        f"https://keybase.io/{username}",
                        lambda b, u: '"them":{' in b),
        "Steam":      (f"https://steamcommunity.com/id/{username}", None,
                        lambda b, u: 'class="actual_persona_name"' in b),
        "Pastebin":   (f"https://pastebin.com/u/{username}", None,
                        lambda b, u: 'Pastebin.com - Page Not Found' not in b),
        "Gravatar":   (f"https://gravatar.com/{username}", None, None),
        "About.me":   (f"https://about.me/{username}", None,
                        lambda b, u: 'aboutme_prod:page' in b),
        "Quora":      (f"https://www.quora.com/profile/{username}", None,
                        lambda b, u: 'ProfilePagedListFeed' in b),
    }

    def check_site(site, fetch_url, display_url, check):
        url = display_url or fetch_url
        try:
            req = urllib.request.Request(fetch_url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=8)
            if resp.status != 200:
                return (site, False, url, None)
            if check is None:
                return (site, True, url, None)
            body = resp.read(500000).decode('utf-8', errors='ignore')
            ok = check(body, username)
            return (site, ok, url, body if ok else None)
        except Exception:
            return (site, False, url, None)

    # Checks are independent network I/O, so run them concurrently instead of
    # one-by-one — sequential checks of ~19 sites (each up to several seconds)
    # made username/name searches take minutes.
    order = {site: i for i, site in enumerate(list(sites.keys()) + ["LinkedIn"])}
    found, not_found, bodies = [], [], {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(check_site, site, fetch_url, display_url, check)
                   for site, (fetch_url, display_url, check) in sites.items()]
        # LinkedIn needs custom headers/timeout/redirect handling, so it's a separate task
        futures.append(ex.submit(linkedin_check, username))
        for fut in as_completed(futures):
            site, ok, url, body = fut.result()
            if ok:
                found.append((site, url))
                if body:
                    bodies[site] = body
            else:
                not_found.append(site)

    found.sort(key=lambda pair: order.get(pair[0], 999))
    not_found.sort(key=lambda site: order.get(site, 999))

    if capture_bodies:
        return found, not_found, bodies
    return found, not_found

def generate_username_variations(full_name):
    parts = full_name.strip().split()
    first = parts[0] if parts else ''
    last = parts[-1] if len(parts) > 1 else ''

    f, l = first.lower(), last.lower()
    fc, lc = first.capitalize(), last.capitalize()

    variations = []
    if last:
        variations.append(fc + lc)             # AarushPradip
        variations.append(f + '_' + l)         # aarush_pradip
        variations.append(f + '.' + l)         # aarush.pradip
        variations.append(l + fc)              # pradipAarush
        variations.append(f + l[0].upper())    # aarushP
        variations.append(f[0] + lc)           # aPradip
    variations.append(f)                       # aarush
    variations.append(f + '1')
    variations.append(f + '123')
    variations.append(f + '007')

    seen, result = set(), []
    for v in variations:
        if v and v not in seen:
            seen.add(v)
            result.append(v)
    return result

def generate_dork_links(full_name):
    title_name = ' '.join(p.capitalize() for p in full_name.strip().split())
    name_q = f'"{title_name}"'

    def search_url(query):
        return "https://www.google.com/search?q=" + urllib.parse.quote(query)

    return [
        {"label": "LinkedIn",   "url": search_url(f'site:linkedin.com/in {name_q}')},
        {"label": "GitHub",     "url": search_url(f'site:github.com {name_q}')},
        {"label": "Instagram",  "url": search_url(f'site:instagram.com {name_q}')},
        {"label": "Twitter/X",  "url": search_url(f'site:twitter.com {name_q}')},
        {"label": "India",      "url": search_url(f'{name_q} India')},
        {"label": "Email",      "url": search_url(f'{name_q} email')},
        {"label": "Phone",      "url": search_url(f'{name_q} phone')},
    ]

def name_matches_body(body, full_name):
    # A bare username match (e.g. "aneek") is often a coincidental handle taken
    # by an unrelated account on a billion-user platform, not the actual target.
    # Require every part of the target's name to appear in the fetched profile
    # page (display name / bio / JSON-LD) before counting it as a real hit.
    # If we have no body to check (e.g. Gravatar, which is a plain 200 check
    # with no page content captured), we can't verify — keep it as-is.
    if body is None:
        return True
    parts = [p.lower() for p in full_name.strip().split() if p]
    if not parts:
        return True
    low = body.lower()
    return all(p in low for p in parts)

def name_recon(full_name):
    variations_results = {}
    for variation in generate_username_variations(full_name):
        found, _, bodies = check_username(variation, capture_bodies=True)
        verified = [(site, url) for site, url in found
                    if name_matches_body(bodies.get(site), full_name)]
        variations_results[variation] = verified

    return {
        'variations_results': variations_results,
        'dork_links': generate_dork_links(full_name),
    }

def ip_lookup(target):
    results = {}
    # Resolve hostname if needed
    try:
        ip = socket.gethostbyname(target)
        results['resolved_ip'] = ip
    except Exception:
        ip = target
        results['resolved_ip'] = target

    # ipinfo.io
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        data = json.loads(urllib.request.urlopen(req, timeout=5).read())
        results['ipinfo'] = data
    except Exception as e:
        results['ipinfo_error'] = str(e)

    # Reverse DNS
    try:
        results['reverse_dns'] = socket.gethostbyaddr(ip)[0]
    except Exception:
        results['reverse_dns'] = 'N/A'

    return results

def domain_recon(domain):
    results = {}
    # WHOIS via subprocess
    try:
        out = subprocess.check_output(['whois', domain], timeout=10, stderr=subprocess.DEVNULL)
        # Extract key lines only
        lines = out.decode(errors='ignore').splitlines()
        key_fields = ['Registrar:', 'Registrant', 'Creation Date', 'Updated Date',
                      'Expiry Date', 'Expiration Date', 'Name Server', 'DNSSEC',
                      'Registry Domain', 'Organisation:', 'Admin Email']
        filtered = [l for l in lines if any(f.lower() in l.lower() for f in key_fields)]
        results['whois'] = '\n'.join(filtered[:30]) if filtered else 'No key fields found'
    except Exception as e:
        results['whois'] = f'Error: {e}'

    # DNS records
    for rtype in ['A', 'MX', 'TXT', 'NS', 'CNAME']:
        try:
            out = subprocess.check_output(['dig', '+short', rtype, domain],
                                          timeout=5, stderr=subprocess.DEVNULL)
            val = out.decode(errors='ignore').strip()
            results[f'dns_{rtype}'] = val if val else 'None'
        except Exception:
            results[f'dns_{rtype}'] = 'Error'

    # crt.sh cert transparency
    try:
        url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        data = json.loads(urllib.request.urlopen(req, timeout=8).read())
        subdomains = sorted(set(
            entry['name_value'].replace('*.', '')
            for entry in data
            if 'name_value' in entry
        ))[:30]
        results['subdomains'] = subdomains
    except Exception as e:
        results['subdomains'] = [f'Error: {e}']

    return results

def email_recon(email):
    results = {}
    domain = email.split('@')[-1] if '@' in email else ''

    # Basic validation
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    results['valid_format'] = bool(re.match(pattern, email))

    # Check if domain has MX records (can receive mail)
    if domain:
        try:
            out = subprocess.check_output(['dig', '+short', 'MX', domain],
                                          timeout=5, stderr=subprocess.DEVNULL)
            results['domain_mx'] = out.decode().strip() or 'No MX records'
        except Exception:
            results['domain_mx'] = 'Error'

        # Check domain age via whois
        try:
            out = subprocess.check_output(['whois', domain], timeout=8,
                                          stderr=subprocess.DEVNULL)
            lines = out.decode(errors='ignore').splitlines()
            for line in lines:
                if 'creation date' in line.lower() or 'created:' in line.lower():
                    results['domain_created'] = line.strip()
                    break
        except Exception:
            pass

    # Gravatar check
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    try:
        req = urllib.request.Request(gravatar_url, headers={'User-Agent': 'Mozilla/5.0'})
        urllib.request.urlopen(req, timeout=5)
        results['gravatar'] = f"https://www.gravatar.com/avatar/{email_hash}"
        results['gravatar_found'] = True
    except Exception:
        results['gravatar_found'] = False

    results['hibp_note'] = 'HaveIBeenPwned requires API key — add in settings'

    return results

def phone_lookup(phone):
    results = {}
    # Basic formatting analysis
    clean = re.sub(r'[\s\-\(\)\+]', '', phone)
    results['cleaned'] = clean
    results['length'] = len(clean)

    if clean.startswith('91') and len(clean) == 12:
        results['country'] = 'India (+91)'
        results['number'] = clean[2:]
    elif len(clean) == 10 and clean[0] in '6789':
        results['country'] = 'India (no country code)'
        results['number'] = clean
    else:
        results['country'] = 'Unknown / International'
        results['number'] = clean

    # Truecaller search link (manual)
    results['truecaller_link'] = f"https://www.truecaller.com/search/in/{clean}"
    results['sync_me_link'] = f"https://sync.me/search/?number={urllib.parse.quote(phone)}"

    return results

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return INDEX_HTML

def run_osint_module(search_type, query):
    if search_type == 'username':
        found, not_found = check_username(query)
        return {'found': found, 'not_found': not_found}
    elif search_type == 'ip':
        return ip_lookup(query)
    elif search_type == 'domain':
        return domain_recon(query)
    elif search_type == 'email':
        return email_recon(query)
    elif search_type == 'phone':
        return phone_lookup(query)
    elif search_type == 'name':
        return name_recon(query)
    return None

@app.route('/search', methods=['POST'])
def search():
    search_type = request.form.get('type')
    query = request.form.get('query', '').strip()
    if not query:
        return jsonify({'error': 'Empty query'})

    result = run_osint_module(search_type, query) or {}

    save_result(search_type, query, json.dumps(result))
    return jsonify({'type': search_type, 'query': query, 'result': result})

@app.route('/ai/status')
def ai_status():
    return jsonify({'enabled': bool(GROQ_API_KEY)})

@app.route('/ai/parse', methods=['POST'])
def ai_parse():
    if not GROQ_API_KEY:
        return jsonify({'error': 'AI features disabled — add GROQ_API_KEY to .env'})

    query = request.form.get('query', '').strip()
    if not query:
        return jsonify({'error': 'Empty query'})

    system_prompt = (
        "You are an OSINT query parser. Extract search targets from the user's "
        "query and return ONLY valid JSON in this format:\n"
        "{\n"
        '  "targets": [\n'
        '    {"type": "username", "value": "cookiesn1ffer"},\n'
        '    {"type": "name", "value": "Aarush Pradip"},\n'
        '    {"type": "ip", "value": "8.8.8.8"},\n'
        '    {"type": "email", "value": "x@gmail.com"},\n'
        '    {"type": "domain", "value": "example.com"},\n'
        '    {"type": "phone", "value": "+919876543210"}\n'
        "  ]\n"
        "}\n"
        "Only include types you are confident about. Return only JSON, no explanation."
    )

    content, error = call_groq([
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': query},
    ])
    if error:
        return jsonify({'error': f'AI analysis unavailable: {error}'})

    try:
        targets = json.loads(extract_json_block(content)).get('targets', [])
    except Exception as e:
        return jsonify({'error': f'AI analysis unavailable: failed to parse response ({e})'})

    results = []
    for target in targets:
        ttype = target.get('type')
        value = (target.get('value') or '').strip()
        if not value:
            continue
        result = run_osint_module(ttype, value)
        if result is None:
            continue
        save_result(ttype, value, json.dumps(result))
        results.append({'type': ttype, 'query': value, 'result': result})

    return jsonify({'query': query, 'targets': targets, 'results': results})

@app.route('/ai/dossier', methods=['POST'])
def ai_dossier():
    if not GROQ_API_KEY:
        return jsonify({'error': 'AI features disabled — add GROQ_API_KEY to .env'})

    data = request.get_json(silent=True) or {}
    qtype = data.get('type', '')
    query = data.get('query', '')
    result = data.get('result', {})

    system_prompt = (
        "You are an OSINT analyst. Given recon data about a target, write a "
        "concise intelligence dossier. Include: identity assessment, digital "
        "footprint summary, key findings, data gaps, and 3 specific recommended "
        "next search actions. Be factual, concise, professional. Max 300 words.\n\n"
        "End your response with a section called NEXT TARGETS: listing specific "
        "values to search next (emails, usernames, IPs found in the data). "
        "Format each as: [type] value — reason\n"
        "Example: [email] aarush@gmail.com — found in GitHub commit history"
    )

    user_content = json.dumps({'type': qtype, 'query': query, 'result': result})[:8000]

    content, error = call_groq([
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': user_content},
    ], max_tokens=1000)

    if error:
        return jsonify({'error': f'AI analysis unavailable: {error}'})

    return jsonify({'dossier': content})

@app.route('/history')
def history():
    with sqlite3.connect(DB) as c:
        rows = c.execute(
            'SELECT id, type, query, created_at FROM queries ORDER BY id DESC LIMIT 50'
        ).fetchall()
    return jsonify([{'id': r[0], 'type': r[1], 'query': r[2], 'time': r[3]} for r in rows])

@app.route('/history/<int:qid>')
def history_detail(qid):
    with sqlite3.connect(DB) as c:
        row = c.execute('SELECT * FROM queries WHERE id=?', (qid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'})
    return jsonify({'id': row[0], 'type': row[1], 'query': row[2],
                    'result': json.loads(row[3]), 'time': row[4]})

@app.route('/status')
def status():
    with sqlite3.connect(DB) as c:
        count = c.execute('SELECT COUNT(*) FROM queries').fetchone()[0]
    return jsonify({'status': 'online', 'total_queries': count,
                    'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
