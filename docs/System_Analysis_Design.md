# System Analysis & Design — AutoRemediate AI

**Project 7: Autonomous Vulnerability Remediation Plan & Incident Response Hub**  
**Team 3 | DEPI Capstone | Evaluator: Eng. Ahmed Attia**

---

## 1. Use-Case Diagram

```mermaid
%%{init: {'theme': 'default'}}%%
graph TD
    Operator((Operator))
    Engine[AutoRemediate AI Engine]

    Operator -->|"Run scan"| UC1[Launch Nessus Scan]
    Operator -->|"Review decision card"| UC2[Approve / Reject Remediation]
    Operator -->|"View report"| UC3[Generate Documentation]

    UC1 --> Engine
    UC2 --> Engine
    UC3 --> Engine

    Engine -->|"API calls"| Nessus[(Nessus Professional\n192.168.244.129:8834)]
    Engine -->|"SSH commands"| Target[(Metasploitable2\n192.168.244.128)]
    Engine -->|"Audit writes"| DB[(Supabase\nPostgreSQL)]
```

---

## 2. Architecture Diagram (Four Layers)

```mermaid
%%{init: {'theme': 'default'}}%%
graph LR
    subgraph Ingestion
        SC[scanner_client.py\nNessusClient]
        PA[parser.py\nNessusParser]
        SC -->|"raw JSON"| PA
    end

    subgraph Orchestration
        EN[engine.py\nEngine]
        RC[recommender.py\nRecommender + Scorer]
        PA -->|"findings list"| EN
        EN <-->|"score + recommend"| RC
    end

    subgraph "Remediation Transport"
        RM[remediator.py\nRemediator - Paramiko SSH]
        EN -->|"approved command"| RM
        RM -->|"Upstart: service X stop"| TGT[(Metasploitable2)]
    end

    subgraph "Persistence / Presentation"
        DB2[db.py\npsycopg2 → Supabase]
        CLI[Console\nDecision Cards + Summary]
        EN -->|"log decision"| DB2
        EN --> CLI
    end

    NES[(Nessus API\n:8834)] -->|"X-ApiKeys"| SC
```

---

## 3. Data-Flow Diagram

```mermaid
%%{init: {'theme': 'default'}}%%
sequenceDiagram
    participant Op as Operator
    participant Eng as Engine
    participant Nes as Nessus API
    participant Par as Parser
    participant Rec as Recommender
    participant Rem as Remediator
    participant DB as Supabase DB

    Op->>Eng: python engine.py --launch-scan
    Eng->>Nes: POST /scans (create Basic Network Scan)
    Nes-->>Eng: scan_id
    Eng->>Nes: POST /scans/{id}/launch
    Note over Nes: Scan runs 15–40 min

    Op->>Eng: python engine.py --run --scan-id {id}
    Eng->>Nes: GET /scans/{id} (poll until completed)
    Eng->>Nes: GET /scans/{id}/hosts/{host_id}/plugins/{plugin_id}
    Nes-->>Eng: full plugin details JSON
    Eng->>Par: parse_full_results(raw)
    Par-->>Eng: findings[]

    Eng->>Rec: prioritise_and_recommend(findings)
    Rec-->>Eng: scored + sorted findings[]

    loop For each Critical/High finding
        Eng->>Op: Display Decision Card
        Op->>Eng: [A] Approve / [2] Alt / [R] Reject / [Q] Quit
        alt Approved
            Eng->>Rem: execute(finding, action)
            Rem->>Rem: SSH → sudo service X stop
            Rem->>Rem: verify_on_target() + verify_external()
            Rem-->>Eng: {status: Success/Failed/Retrying}
        else Rejected
            Note over Eng: status = Skipped
        end
        Eng->>DB: insert_vulnerability() + insert_remediation_log()
    end

    Eng->>Op: Final Summary (success/failed/skipped counts)
```

---

## 4. Sequence Diagram — Post-Remediation Verification

```mermaid
%%{init: {'theme': 'default'}}%%
sequenceDiagram
    participant Op as Operator
    participant Eng as Engine
    participant Nes as Nessus API
    participant TGT as Metasploitable2

    Op->>Eng: python engine.py --verify-scan {baseline_id}
    Eng->>Nes: POST /scans (create AutoRemediate_Verification_Scan)
    Eng->>Nes: POST /scans/{id}/launch
    Note over Nes: Verification scan runs

    Eng->>Nes: GET /scans/{id} (poll until completed)
    Eng->>Nes: get_full_results(verify_scan_id)
    Nes-->>Eng: post-remediation findings

    Eng->>Eng: diff(baseline_findings, post_findings)
    Note over Eng: resolved = before - after\nnew = after - before\npersisted = before ∩ after

    Eng->>Op: Print diff summary
    Eng->>Op: Save docs/verification_diff.json
```

---

## 5. Entity-Relationship Diagram

```mermaid
%%{init: {'theme': 'default'}}%%
erDiagram
    Vulnerabilities {
        SERIAL vuln_id PK
        TEXT cve_reference
        TEXT plugin_name
        TEXT severity_level
        INTEGER target_port
    }
    Remediation_Activity_Logs {
        SERIAL log_id PK
        INTEGER vuln_id FK
        TIMESTAMPTZ timestamp
        TEXT command_dispatched
        TEXT operator_decision
        TEXT execution_status
    }
    Vulnerabilities ||--o{ Remediation_Activity_Logs : "has"
```

---

## 6. Priority Scoring Formula

| Factor | Points |
|--------|--------|
| Critical severity | +100 |
| High severity | +70 |
| Medium severity | +40 |
| Low severity | +10 |
| Known backdoor / Metasploit module | +40 |
| Public PoC (not weaponised) | +20 |
| No authentication required | +15 |
| Port confirmed listening | +15 |
| **Max possible** | **170** |

Tie-break: lower port number first; then CVE lexicographic descending.

---

## 7. Preference Ladder

| Rung | Action | Command Pattern | SSH Exception |
|------|--------|-----------------|---------------|
| 1 | Patch/upgrade | `apt-get install --only-upgrade` | N/A (infeasible) |
| 2 | Stop service | `sudo service <name> stop` | **NEVER for port 22** |
| 3 | Harden | config edits + service restart | Default for SSH |
| 4 | iptables DROP | `sudo iptables -I INPUT -p tcp --dport <port> -j DROP` | **NEVER port 22** |
| 5 | Monitor only | *(no command)* | Always available |
