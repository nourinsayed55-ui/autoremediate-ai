# PROJECT_CONTEXT.md — AutoRemediate AI Persistent Session Memory

Re-read this at the start of any new Claude session for this project.
Last updated: 2026-06-27

---

## Project Identity

- **Title:** AutoRemediate AI — Autonomous Vulnerability Remediation Plan & Incident Response Hub
- **Type:** DEPI Capstone Project 7 — Cyber Security Incident Response Analyst
- **Evaluator:** Eng. Ahmed Attia
- **GitHub:** https://github.com/nourinsayed55-ui/autoremediate-ai
- **Local path:** C:\DEPI_Capstone_Project\

## Team (DEPI Team 3)

| Name | Role |
|------|------|
| Marc Wael | Team Lead |
| Mohey Elden Mostafa | Developer |
| Jerome Arsany | Developer |
| Noureen Elsayed | Developer |
| Hassan Ibrahim | Developer |
| Philopater Helmy | Developer |

---

## Infrastructure

| Asset | Details |
|-------|---------|
| Kali Linux (engine host) | 192.168.244.129 SSH: noureen/noureen |
| Metasploitable2 (target) | 192.168.244.128 SSH: msfadmin/msfadmin |
| Nessus Professional URL | https://192.168.244.129:8834 |
| Nessus API Access Key | 3aae9e16069466a9adfb80e65da4f0aab97b8149531f90b916ef5b820eaecc10 |
| Nessus API Secret Key | d6eab8dde74ccc231c12f0665cdb08659bf621270ddd7d08f8c5724bdb9abc03 |
| Supabase connection | postgresql://postgres.ezmzethdxnhyxfnrxoky:Noureen.1234@aws-1-eu-west-2.pooler.supabase.com:5432/postgres |
| Supabase URL | https://ezmzethdxnhyxfnrxoky.supabase.co |
| Supabase anon key | eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV6bXpldGhkeG5oeXhmbnJ4b2t5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI1NTg2MjUsImV4cCI6MjA5ODEzNDYyNX0.TZC1azBASeen8swa_6yKj0WJYTLgEYUw1qqkofG6UeU |
| Python env | conda activate autoremediate (Python 3.11) |

Credentials live ONLY in backend/config.json which is gitignored. config.example.json has placeholders.

---

## Database Schema (Supabase / PostgreSQL)

```sql
CREATE TABLE "Vulnerabilities" (
    vuln_id        SERIAL PRIMARY KEY,
    cve_reference  TEXT,
    plugin_name    TEXT,
    severity_level TEXT CHECK (severity_level IN ('Critical','High','Medium','Low')),
    target_port    INTEGER
);

CREATE TABLE "Remediation_Activity_Logs" (
    log_id              SERIAL PRIMARY KEY,
    vuln_id             INTEGER REFERENCES "Vulnerabilities"(vuln_id),
    "timestamp"         TIMESTAMPTZ DEFAULT NOW(),
    command_dispatched  TEXT,
    operator_decision   TEXT,
    execution_status    TEXT CHECK (execution_status IN ('Success','Failed','Retrying','Skipped'))
);
```

Tables use quoted names ("Vulnerabilities", "Remediation_Activity_Logs") — always quote them in SQL.
Set up with: `python backend/engine.py --setup-db`

---

## Critical Design Decisions

### 1. Upstart NOT systemctl on Metasploitable2
Metasploitable2 runs Ubuntu 8.04 (Hardy Heron) with Upstart init.
- Use: `sudo service <name> stop` / `sudo service <name> start` / `sudo service <name> status`
- NEVER: `systemctl` — it fails silently and is not installed
- This is enforced throughout remediator.py

### 2. SSH Safety — Hard Code Rule
SSH (port 22 / service ssh/sshd) must NEVER be stopped or have its port blocked.
- Enforced by `assert_not_ssh_kill()` in recommender.py AND called in remediator.execute()
- Preferred action for SSH findings: Rung 3 Harden (PermitRootLogin no + restart)
- This prevents severing the control channel to the target

### 3. Human-in-the-Loop — No Auto-Fire Path
- engine.py ALWAYS blocks on input() for each Critical/High finding
- Even if `require_manual_approval: false` in config, a typed YES is required first
- Every decision is logged to Remediation_Activity_Logs (Approve, Alternative, Reject, Skipped)
- Decision card shows: plugin name, severity, CVE, score, recommended action + rationale, alternatives

### 4. Two-Factor Verification
After executing a stop command, BOTH checks must pass to declare Success:
- (i) On-target: `service <name> status` shows "stop/waiting" AND `netstat -tlnp | grep :<port>` is empty
- (ii) External: TCP socket from engine host to target:port returns connection refused
- If either fails → Retrying (up to retry_attempts=3) → Failed

### 5. Priority Scoring Formula
Critical=100, High=70, Medium=40, Low=10
+40 if known backdoor / Metasploit module / actively exploited
+20 if public PoC (not weaponised)
+15 if no auth required
+15 if port confirmed listening (port > 0)
Tie-break: lower port, then CVE desc

### 6. Preference Ladder (remediation rungs)
1 Patch/upgrade — infeasible on Metasploitable2 (no real patches for intentionally vulnerable packages)
2 Stop/disable — for backdoored/abandoned services
3 Harden/reconfigure — when service must stay up
4 iptables DROP — network containment; standing alternative
5 Monitor only — log, no change; safe fallback; always shown
SSH override: always Rung 3 (harden), never 2 or 4

### 7. Nessus API Authentication
Header: `X-ApiKeys: accessKey=<key>; secretKey=<key>`
SSL: verify=False (self-signed cert on port 8834)
Template: dynamically fetch UUID for "basic" via GET /editor/scan/templates

### 8. Git History — Clean Weekly Commits
Week 1: "Week 1: Environment setup, Nessus config, scope docs"
Week 2: "Week 2: Vulnerability scan execution and analysis"
Week 3: "Week 3: Remediation logic, prioritization, approval workflow"
Week 4: "Week 4: Remediation execution, verification, final reporting"

---

## Key CLI Commands

```bash
conda activate autoremediate

# Set up DB tables
python backend/engine.py --setup-db

# Launch a new scan (saves scan_id to .scan_state.json)
python backend/engine.py --launch-scan

# Run remediation loop with human approval
python backend/engine.py --run --scan-id <ID>

# Dry run (no actual SSH commands)
python backend/engine.py --run --scan-id <ID> --dry-run

# Post-remediation verification
python backend/engine.py --verify-scan <BASELINE_SCAN_ID>

# Generate all .docx docs
python backend/generate_docs.py --scan-id <ID>

# Run unit tests
cd tests && python -m pytest -v
```

---

## Known Metasploitable2 Services (for reference)

| Port | Service | Severity | Upstart Name | Action |
|------|---------|----------|--------------|--------|
| 21 | vsftpd 2.3.4 (backdoor) | Critical | vsftpd | Stop |
| 22 | OpenSSH | Low | ssh | Harden ONLY |
| 23 | Telnet | High | xinetd | Stop |
| 25 | Postfix SMTP | Low | postfix | Harden |
| 80 | Apache | Medium | apache2 | Harden |
| 111 | rpcbind | Medium | portmap | Harden |
| 139/445 | Samba | Critical | smbd | Stop or Harden |
| 512-514 | r-services | High | xinetd | Stop |
| 1099 | Java RMI | High | rmiregistry | Stop |
| 1524 | Bind shell (backdoor) | Critical | (fuser kill) | Kill process |
| 2049 | NFS | Medium | nfs-kernel-server | Harden |
| 2121 | ProFTPD | Medium | proftpd | Stop |
| 3306 | MySQL | Medium | mysql | Harden |
| 3632 | distccd | High | distcc | Stop |
| 5432 | PostgreSQL | Medium | postgresql | Harden |
| 5900 | VNC | High | vncserver | Stop |
| 6667 | UnrealIRCd (backdoor) | Critical | unrealircd | Stop |
| 8180 | Tomcat | Medium | tomcat5.5 | Harden |

---

## Current Status (Week 1)

- [x] Project structure created
- [x] All backend Python files written (engine.py, scanner_client.py, parser.py, recommender.py, remediator.py, db.py)
- [x] Unit tests written (test_parser.py, test_recommender.py, test_remediator.py)
- [x] SQL schema written (sql/schema.sql)
- [x] Config files created (config.json gitignored, config.example.json committed)
- [x] generate_docs.py written
- [x] docs/System_Analysis_Design.md written (Mermaid diagrams)
- [x] README.md written
- [ ] Packages installed (pip install -r requirements.txt)
- [ ] DB tables created in Supabase (python engine.py --setup-db)
- [ ] Nessus scan launched (python engine.py --launch-scan)
- [ ] .docx files generated (python generate_docs.py)
- [ ] Git commits pushed (Week 1 commit)
- [ ] Week 2: Scan results fetched and parsed
- [ ] Week 3: Remediation loop run
- [ ] Week 4: Verification scan + final docs
