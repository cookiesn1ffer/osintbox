from flask import Flask, request, jsonify
import sqlite3, subprocess, socket, json, re, urllib.request, urllib.error, urllib.parse, hashlib
from datetime import datetime
import os

app = Flask(__name__)
DB = os.path.join(os.path.dirname(__file__), 'osint.db')

# ── Groq AI config ───────────────────────────────────────────────────────────
GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions'
GROQ_MODEL = 'llama-3.3-70b-versatile'

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
    background: var(--bg);
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
      html += `<div class="r-section">found (${found.length})</div>`;
      if (found.length === 0) {
        html += `<div class="r-miss">no accounts found</div>`;
      } else {
        found.forEach(([site, url]) => {
          html += `<div class="r-row">
            <span class="r-badge badge-found">FOUND</span>
            <span class="r-key">${site}</span>
            <a class="r-link" href="${url}" target="_blank">${url}</a>
          </div>`;
        });
      }
      html += `<div class="r-section">not found (${miss.length})</div>`;
      html += `<div class="r-miss">${miss.join(' · ') || 'none'}</div>`;

    } else if (data.type === 'name') {
      const variations = r.variations_results || {};
      const dorks       = r.dork_links || [];
      const allKeys     = Object.keys(variations);
      const hits        = allKeys.filter(k => (variations[k] || []).length > 0);

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
          variations[variation].forEach(([site, url]) => {
            html += `<div class="r-row">
              <span class="r-badge badge-found">FOUND</span>
              <span class="r-key">${site}</span>
              <a class="r-link" href="${url}" target="_blank">${url}</a>
            </div>`;
          });
        });
      }

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

def check_username(username):
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

    def linkedin_found(uname):
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
                return False
            body = resp.read(500000).decode('utf-8', errors='ignore')
            if 'linkedin.com/in/' in final_url:
                return True
            if '"vanityName"' in body:
                return True
            if 'public-profile-hero-image' in body:
                return True
            if 'authwall' not in body and resp.status == 200:
                return True
            return False
        except Exception:
            return False

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

    found, not_found = [], []
    for site, (fetch_url, display_url, check) in sites.items():
        url = display_url or fetch_url
        try:
            req = urllib.request.Request(fetch_url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.status != 200:
                not_found.append(site)
                continue
            if check is None:
                found.append((site, url))
                continue
            body = resp.read(500000).decode('utf-8', errors='ignore')
            if check(body, username):
                found.append((site, url))
            else:
                not_found.append(site)
        except Exception:
            not_found.append(site)

    # LinkedIn needs custom headers/timeout/redirect handling, so it's checked separately
    if linkedin_found(username):
        found.append(("LinkedIn", f"https://www.linkedin.com/in/{username}"))
    else:
        not_found.append("LinkedIn")

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

def name_recon(full_name):
    variations_results = {}
    for variation in generate_username_variations(full_name):
        found, _ = check_username(variation)
        variations_results[variation] = found

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
