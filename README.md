# AutoRemediate AI

**Project 7: Autonomous Vulnerability Remediation Plan & Incident Response Hub**

DEPI Cyber Security Incident Response Analyst Capstone — Team 3

---

## Team & Evaluator

| Role | Name |
|------|------|
| Team Lead | Marc Wael |
| Developer | Mohey Elden Mostafa |
| Developer | Jerome Arsany |
| Developer | Noureen Elsayed |
| Developer | Hassan Ibrahim |
| Developer | Philopater Helmy |
| **Evaluator** | **Eng. Ahmed Attia** |

---

## What It Does

AutoRemediate AI is a fully autonomous vulnerability remediation pipeline that:

1. **Scans** — Calls the live Nessus Professional API to create and launch a Basic Network Scan against Metasploitable2.
2. **Parses** — Normalises all Nessus plugin results (CVE, port, severity, exploit data) into structured findings.
3. **Prioritises** — Scores every finding with a multi-factor algorithm (severity + exploit status + auth + port reachability) and sorts Critical/High findings for review.
4. **Recommends** — Applies a 5-rung preference ladder (Patch → Stop → Harden → iptables → Monitor) per finding, with a hard safety rule that SSH (port 22) is never stopped or blocked.
5. **Approves (HUMAN-IN-THE-LOOP)** — Displays a Decision Card per finding and **blocks on operator input** before any change reaches the target. There is no silent auto-fire path.
6. **Remediates** — Executes approved commands over Paramiko SSH using Upstart-safe `sudo service X stop` commands (NOT systemctl — Metasploitable2 runs Ubuntu 8.04).
7. **Verifies** — Two independent checks: (i) on-target service status + netstat, (ii) external TCP socket probe from the engine host.
8. **Logs** — Every decision (Approve / Alternative / Reject / Skipped) is written to Supabase with timestamp and operator decision text.
9. **Reports** — Generates nine formatted `.docx` documents and a Mermaid architecture doc.

---

## Architecture

```
Ingestion Layer         Orchestration Layer       Remediation Transport    Persistence
─────────────────       ───────────────────       ────────────────────     ───────────
NessusClient ──────────▶ Engine ◀──▶ Recommender ──▶ Remediator ─SSH──▶ Metasploitable2
(scanner_client.py)     (engine.py)  (recommender.py) (remediator.py)
       │                     │                              │
       ▼                     ▼                              ▼
  NessusParser          DB (psycopg2)               Supabase PostgreSQL
  (parser.py)           (db.py)
```

---

## Folder Structure

```
C:\DEPI_Capstone_Project\
├── backend\
│   ├── engine.py          ← Main CLI entry point
│   ├── core.py            ← Shared execution logic (CLI + web)
│   ├── app.py             ← Flask web console (127.0.0.1:5000)
│   ├── templates\
│   │   └── index.html     ← Dark security-console single-page UI
│   ├── scanner_client.py  ← Live Nessus API client
│   ├── parser.py          ← Nessus result normaliser
│   ├── recommender.py     ← Priority scorer + preference ladder
│   ├── remediator.py      ← Paramiko SSH executor + verifier
│   ├── db.py              ← Supabase/PostgreSQL operations
│   ├── generate_docs.py   ← .docx document generator
│   ├── config.json        ← NEVER committed (gitignored)
│   ├── config.example.json← Committed — placeholders only
│   └── requirements.txt
├── tests\
│   ├── test_parser.py
│   ├── test_recommender.py
│   ├── test_remediator.py
│   ├── test_engine_menu.py
│   ├── test_suggestions.py
│   └── test_api.py        ← Web console tests (mocked SSH/DB)
├── docs\
│   ├── System_Analysis_Design.md          ← Mermaid diagrams
│   ├── Tool_Configuration_Documentation.docx
│   ├── Assessment_Scope_Document.docx
│   ├── Vulnerability_Scan_Report.docx
│   ├── Initial_Analysis_Document.docx
│   ├── Prioritization_Report.docx
│   ├── Remediation_Plan.docx
│   ├── Verification_Report.docx
│   └── Final_Remediation_Report.docx
├── sql\
│   └── schema.sql
├── .gitignore
├── README.md
└── PROJECT_CONTEXT.md
```

---

## Setup from Zero

### Prerequisites

- Anaconda / Miniconda
- Access to Nessus Professional at `https://192.168.244.129:8834`
- Metasploitable2 reachable at `192.168.244.128`
- Supabase project connection string

### 1. Activate the environment

```bash
conda activate autoremediate
```

### 2. Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 3. Create config.json

```bash
cp backend/config.example.json backend/config.json
# Edit backend/config.json — fill in real credentials
```

### 4. Set up database

```bash
python backend/engine.py --setup-db
```

### 5. Launch a Nessus scan (takes 15–40 min)

```bash
python backend/engine.py --launch-scan
# Note the printed scan_id
```

### 6a. Run the remediation loop (terminal)

```bash
python backend/engine.py --run --scan-id <SCAN_ID>
# Optional: --dry-run to preview without touching the target
```

### 6b. Run the SOC Dashboard (browser UI)

```bash
python backend/app.py
# Open http://127.0.0.1:5000 in a browser on the same machine.
# The server listens on 127.0.0.1 only — not accessible from other hosts.
```

The web console shows every Critical/High finding as a card. Click an option
button to open a two-step confirmation panel showing the exact command, then
click **Execute — I Confirm** to run it. One action executes per click.
The terminal CLI (step 6a) and the web console share the same execution and
DB-logging logic via `backend/core.py`.

---

## Dashboard

The browser UI at `http://127.0.0.1:5000` is a dark SOC command-center dashboard
with animated real-time visualizations — all driven by live backend data, never
fabricated.

| Widget | Description |
|--------|-------------|
| **Header** | Pulsing status beacon (green = DB connected), live clock, posture ring (% of Critical/High findings remediated, animates in real time) |
| **Counter strip** | Total Findings / Critical+High / Remediated / Failed / Skipped — each animates with a count-up effect and updates after every action |
| **Severity donut** | Animated Chart.js doughnut of all findings by severity (Critical / High / Medium / Low) with hover tooltips |
| **Priority bar chart** | Horizontal Chart.js bar of Critical+High findings by port/service, color-coded by severity, with CVE + plugin tooltips |
| **Operations metrics** | Success rate %, total actions, average time between remediations (MTTR), DB status |
| **Attack surface chips** | One pill per Critical/High port — red (open) flips to green (secured) with an animation after each successful remediation |
| **Priority queue** | Interactive approval cards — one card per finding, sorted by priority score. Each card shows the PREFERRED option first, then SYSTEM-SUGGESTED, then ALTERNATIVES, then MONITOR ONLY. Click → two-step confirm → Execute. No approve-all button exists. |
| **Live activity feed** | Slide-in timeline entry for every log row returned by `/api/logs`; shows timestamp, plugin, command, and animated status badge |

**New read-only API endpoints** added for the dashboard:

| Endpoint | Returns |
|----------|---------|
| `GET /api/metrics` | total_actions, success, failed, skipped, success_rate, mttr_seconds |
| `GET /api/severity-breakdown` | count of all findings by severity (from scan JSON) |
| `GET /api/ports` | Critical+High findings with port, service, severity, priority_score |

All secrets (SSH / Nessus / Supabase credentials) remain server-side; the browser
receives only finding metadata, labels, commands, statuses, and aggregate metrics.

### 7. Post-remediation verification scan

```bash
python backend/engine.py --verify-scan <BASELINE_SCAN_ID>
```

### 8. Generate documentation

```bash
python backend/generate_docs.py --scan-id <SCAN_ID>
```

### 9. Run unit tests

```bash
cd tests
python -m pytest -v
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [System_Analysis_Design.md](docs/System_Analysis_Design.md) | Mermaid architecture, data-flow, ER, sequence diagrams |
| [Tool_Configuration_Documentation.docx](docs/Tool_Configuration_Documentation.docx) | Tools, credentials strategy, Upstart note |
| [Assessment_Scope_Document.docx](docs/Assessment_Scope_Document.docx) | Scope, rules of engagement |
| [Vulnerability_Scan_Report.docx](docs/Vulnerability_Scan_Report.docx) | Live scan findings table |
| [Initial_Analysis_Document.docx](docs/Initial_Analysis_Document.docx) | Attack surface analysis |
| [Prioritization_Report.docx](docs/Prioritization_Report.docx) | Ranked findings with priority scores |
| [Remediation_Plan.docx](docs/Remediation_Plan.docx) | Preference ladder + approval workflow |
| [Verification_Report.docx](docs/Verification_Report.docx) | Before/after diff + audit log |
| [Final_Remediation_Report.docx](docs/Final_Remediation_Report.docx) | Totals, MTTR, lessons learned |

---

## Security Notes

- `config.json` is **gitignored** — never contains real credentials in the repository.
- SSH (port 22) is **never stopped or blocked** — enforced in code by `assert_not_ssh_kill()`.
- All remediations require **explicit operator approval** — no auto-fire path exists.
- Upstart-safe commands only: `sudo service X stop` (not `systemctl`).
