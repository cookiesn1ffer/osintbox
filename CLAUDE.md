# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

OSINTBox is a self-hosted OSINT (open-source intelligence) recon toolkit: a single-file Flask
app with six passive recon modules (username, name, IP/host, domain, email, phone), a dark
terminal-style web UI, local SQLite query history, downloadable findings reports (txt/PDF), and
an optional Groq-powered AI layer for natural-language query parsing and dossier generation.

This is a dual-use security tool intended for legitimate OSINT/recon use (pentesting,
investigations, personal footprint audits). Treat it accordingly per standard security-tool
guidelines — it does not perform any intrusive/active exploitation, only passive lookups against
public data sources.

## Architecture

**Everything lives in `app.py` (~2400 lines).** There is no separate frontend build, no
templates directory, no static assets folder. The entire HTML/CSS/JS frontend is an embedded
Python triple-quoted string (`INDEX_HTML`) served directly by the `/` route. When making UI
changes, edit the string in place — there's no compilation step.

Within `app.py`, the structure is:

1. **Optional API keys & AI helpers** (`load_env_file`, `call_groq`, `extract_json_block`) —
   `load_env_file` is a generic `.env` parser (simple hand-rolled, not `python-dotenv`) returning
   a dict; `GROQ_API_KEY`, `HIBP_API_KEY`, `VT_API_KEY`, `ABUSEIPDB_API_KEY` are all read from it
   at import time. Every key defaults to `''` and every feature gated on one degrades gracefully
   when it's blank (AI routes short-circuit with a disabled message; the optional lookups in
   `ip_lookup`/`domain_recon`/`email_recon` just skip that section). The frontend hides the AI
   tab based on a live `/ai/status` check. Adding a new optional-key integration means: add the
   key to `load_env_file`'s callers, `if KEY:`-gate the lookup in the relevant module, and render
   its result (or its `*_error` sibling) in the matching frontend branch — see the
   AbuseIPDB/VirusTotal handling in `ip_lookup`/`domain_recon` as the template.
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
     generic "not found" shells. LinkedIn is handled separately (`linkedin_check`) because it
     needs custom headers and redirect/authwall detection. Site checks run concurrently via a
     `ThreadPoolExecutor` (max 10 workers) — this is reused by both the username tab and
     `name_recon`, so keep new per-site checks side-effect-free/thread-safe. Pass
     `capture_bodies=True` to get back `(found, not_found, bodies)` where `bodies` maps
     site -> fetched page text for hits, used for identity verification (see below).
   - `generate_username_variations` / `generate_dork_links` / `name_matches_body` / `name_recon` —
     for the "name" tab. `generate_username_variations` builds guesses **only** from the target's
     own name tokens (first/middle(s)/last, several orderings/separators/casings) — no generic
     numeric suffixes — so guesses stay tied to the actual name. Each guess is checked via
     `check_username(..., capture_bodies=True)`, then `name_matches_body` filters hits down to
     ones where the target's first + last name actually appear in the fetched profile page,
     dropping coincidental handle collisions (middle name is intentionally excluded from this
     check since real bios often omit it). `name_recon` runs variations through a small
     `ThreadPoolExecutor` (max 3 workers) — kept low since each variation already fans out its
     own ~20-way `check_username` thread pool underneath.
   - `ip_lookup` — resolves hostname, queries ipinfo.io, reverse DNS, ASN/netblock via Team
     Cymru's whois ASN-lookup service (`whois -h whois.cymru.com`, free, no key), and RDAP
     (`rdap.org`) for org name/country and a best-effort abuse-contact email (RDAP entity
     structure varies a lot by RIR, so absence isn't a bug). Optionally adds AbuseIPDB
     (`abuseipdb`/`abuseipdb_error`) and VirusTotal (`virustotal`/`virustotal_error`) reputation
     when their keys are set.
   - `domain_recon` — shells out to `whois` and `dig` (system binaries — **must be installed**,
     see Raspberry Pi setup below). Subdomains come from two merged sources: crt.sh cert
     transparency, and a dictionary brute force against the `COMMON_SUBDOMAINS` wordlist (~70
     common prefixes) resolved concurrently via `dig +short A`. Also checks the Wayback Machine
     availability API (free, no key) for the earliest/closest archived snapshot, and optionally
     VirusTotal domain reputation when `VT_API_KEY` is set.
   - `email_recon` — format regex check, MX lookup via `dig`, domain creation date via `whois`,
     Gravatar existence check, PGP keyserver lookup (`keys.openpgp.org`, free, no key — a 404
     just means no key registered there, not an error), and optionally a HaveIBeenPwned breach
     check when `HIBP_API_KEY` is set (HIBP's account-lookup endpoint has been paid-only since
     2019 — there's no free tier to fall back to).
   - `phone_lookup` — uses the `phonenumbers` library (Google's libphonenumber port) for parsing,
     validation, region, carrier, and line-type (mobile/landline/VoIP/...) detection — all
     offline lookups against bundled prefix data, no external API call. Carrier data is sparse
     for number-portability countries (e.g. US), so an empty carrier on a valid number is
     expected there, not a bug. Also generates Truecaller/Sync.me search links. There is
     intentionally no reverse phone-number-from-name lookup (no legitimate free API exists for
     that) — `generate_dork_links` covers that gap with targeted Google dorks instead.
5. **Findings report** (`METHODOLOGY_REFERENCE`, `format_findings_text`, `build_report`,
   `render_report_txt`, `render_report_pdf`) — every saved query can be exported as a report
   combining its actual automated findings with the full 10-category OSINT methodology checklist
   (domains/IPs/emails/usernames/social media/people/companies/phones/images/documents) as
   manual-follow-up reference for whatever isn't automated. `format_findings_text(qtype, query,
   result)` is the one place that needs a new branch when a module's result shape changes or a
   new search type is added — it mirrors (but doesn't share code with) the frontend's
   `buildResultHtml()`. PDF rendering uses `fpdf2`; its core fonts are latin-1 only and
   `multi_cell`'s default `new_x=XPos.RIGHT` leaves the cursor at the right margin (so a
   follow-up `w=0` call sees ~zero width and throws) — `_pdf_safe()` handles the character-set
   sanitizing + hard-wrapping of overlong unbroken tokens (long whois/DNS values), and every
   `multi_cell` call in `render_report_pdf` explicitly passes `new_x=XPos.LMARGIN,
   new_y=YPos.NEXT` to reset the cursor. Don't drop either safeguard when editing this function.
6. **Routes** — `/` (serves UI), `/search` (dispatches to a module, persists to SQLite, returns
   the new row's `id`), `/ai/status`, `/ai/parse` (Groq parses free text into typed targets, runs
   each through `run_osint_module`), `/ai/dossier` (Groq writes a prose dossier + a `NEXT
   TARGETS:` section the frontend parses into clickable chain buttons), `/history`,
   `/history/<id>`, `/report/<id>.txt`, `/report/<id>.pdf`, `/status`.

Adding a new recon module means: write the module function, add a branch in
`run_osint_module`, and add a rendering branch in the frontend's `buildResultHtml()` JS — all
three live in this one file.

## Running locally

```bash
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux
pip install flask phonenumbers fpdf2
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
