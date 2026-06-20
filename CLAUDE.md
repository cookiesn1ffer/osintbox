# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

OSINTBox is a self-hosted OSINT (open-source intelligence) recon toolkit: a single-file Flask
app with six passive recon modules (username, name, IP/host, domain, email, phone), a dark
terminal-style web UI, local SQLite query history, and an optional Groq-powered AI layer for
natural-language query parsing and dossier generation.

This is a dual-use security tool intended for legitimate OSINT/recon use (pentesting,
investigations, personal footprint audits). Treat it accordingly per standard security-tool
guidelines — it does not perform any intrusive/active exploitation, only passive lookups against
public data sources.

## Architecture

**Everything lives in `app.py` (~1400 lines).** There is no separate frontend build, no
templates directory, no static assets folder. The entire HTML/CSS/JS frontend is an embedded
Python triple-quoted string (`INDEX_HTML`) served directly by the `/` route. When making UI
changes, edit the string in place — there's no compilation step.

Within `app.py`, the structure is:

1. **Groq AI config & helpers** (`load_groq_key`, `call_groq`, `extract_json_block`) — reads
   `GROQ_API_KEY` from a `.env` file next to `app.py` (simple hand-rolled parser, not
   `python-dotenv`). If no key is present, `GROQ_API_KEY` is `''` and all AI routes short-circuit
   with a disabled message. The frontend hides the AI tab based on a live `/ai/status` check.
2. **`INDEX_HTML`** — the full embedded frontend. Dark terminal aesthetic (JetBrains Mono,
   CSS vars `--bg`/`--bg2`/`--bg3`/`--bg4`/`--green`/`--cyan`/`--red`/`--yellow`/`--muted`/`--text`/`--dim`).
   Client-side JS drives tab switching, search submission, result rendering
   (`buildResultHtml`, branches per search type), AI dossier rendering and "next targets"
   chaining, and history list/detail population — all via `fetch()` against the Flask routes
   below. No frontend framework or build step; everything is vanilla JS template literals.
   The `username`/`name` branches build a small dashboard via dedicated helpers:
   `buildDossierCard` (identity card + `.badge-pill` status pills), `buildPlatformTable`
   (per-site rows with icons from the `ICONS` lookup / `getPlatformIcon`, matched by
   case-insensitive substring), `buildSummaryGrid` (computed stats — never fabricated, only
   derived from the actual result payload), and `buildDossierSummary` (two pure-SVG donut
   charts via `donutSvg`'s stroke-dasharray segments). Keep flex/grid layout on wrapper
   `<div>`s inside `<td>`s, not on the `<td>` itself — `display:flex` directly on a table
   cell breaks table layout in Chromium (rows stack instead of forming columns).
3. **DB setup** (`init_db`, `save_result`) — single SQLite table `queries` (id, type, query,
   result JSON, created_at), created on import at `osint.db` next to `app.py`.
4. **OSINT modules** — one function per recon type, called via the `run_osint_module` dispatcher:
   - `check_username` — probes ~19 sites by fetching each profile URL and applying a per-site
     content-check lambda (HTML markers / JSON fragments) to disambiguate real profiles from
     generic "not found" shells. LinkedIn is handled separately (`linkedin_found`) because it
     needs custom headers and redirect/authwall detection.
   - `generate_username_variations` / `generate_dork_links` / `name_recon` — for the "name" tab,
     derives username permutations from a full name and re-runs `check_username` on each,
     plus generates Google dork search URLs.
   - `ip_lookup` — resolves hostname, queries ipinfo.io, reverse DNS.
   - `domain_recon` — shells out to `whois` and `dig` (system binaries — **must be installed**,
     see Raspberry Pi setup below), plus crt.sh for subdomain enumeration via cert transparency.
   - `email_recon` — format regex check, MX lookup via `dig`, domain creation date via `whois`,
     Gravatar existence check.
   - `phone_lookup` — pure string/regex formatting, no external calls; generates Truecaller/
     Sync.me search links.
5. **Routes** — `/` (serves UI), `/search` (dispatches to a module, persists to SQLite),
   `/ai/status`, `/ai/parse` (Groq parses free text into typed targets, then runs each through
   `run_osint_module`), `/ai/dossier` (Groq writes a prose dossier + a `NEXT TARGETS:` section
   the frontend parses into clickable chain buttons), `/history`, `/history/<id>`, `/status`.

Adding a new recon module means: write the module function, add a branch in
`run_osint_module`, and add a rendering branch in the frontend's `buildResultHtml()` JS — all
three live in this one file.

## Running locally

```bash
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux
pip install flask
python app.py
```

App serves on `http://localhost:5000` (binds `0.0.0.0:5000`). No other build/lint/test tooling
exists in this repo — there is no test suite, linter config, or package.json.

To enable the AI tab and ANALYZE feature, create a `.env` file next to `app.py`:
```
GROQ_API_KEY=your_key_here
```

`domain_recon` and `email_recon` shell out to `whois` and `dig`; without those binaries on
PATH those fields will show as errors but the rest of the app still works.

## Raspberry Pi deployment (`setup.sh`)

`setup.sh` is the production install path (built/tested on a Pi Zero WH): installs
`whois`/`dnsutils` system deps, creates a venv at `~/osint-env`, optionally prompts for a Groq
key (skipped if one already exists in `.env`), and installs/starts a systemd service
(`osintbox.service`, auto-restart on crash/boot). It's idempotent — safe to re-run after a
`git pull` to pick up changes. After editing `app.py` on a deployed Pi, the service must be
restarted (`sudo systemctl restart osintbox`); editing the file alone doesn't reload it.

## Conventions to follow

- Keep the frontend inline in `INDEX_HTML` — don't split it into separate template/static
  files unless explicitly asked to restructure the project.
- Match the existing dark-terminal visual language (CSS vars, JetBrains Mono, `.r-*` class
  naming for result rendering, badge/pill styling) when adding UI.
- AI features must degrade gracefully with no key configured — never make a feature hard-depend
  on `GROQ_API_KEY` being set without a disabled/fallback state.
- Per-site username checks are heuristic content-sniffs against live pages (site markup
  changes over time); when one stops working, prefer adjusting its check lambda over removing
  the site.
