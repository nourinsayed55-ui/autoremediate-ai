-- AutoRemediate AI — Database Schema
-- Project 7: Autonomous Vulnerability Remediation Plan & Incident Response Hub
-- DEPI Capstone Team 3 | Evaluator: Eng. Ahmed Attia

CREATE TABLE IF NOT EXISTS "Vulnerabilities" (
    vuln_id        SERIAL PRIMARY KEY,
    cve_reference  TEXT,
    plugin_name    TEXT,
    severity_level TEXT CHECK (severity_level IN ('Critical','High','Medium','Low')),
    target_port    INTEGER
);

CREATE TABLE IF NOT EXISTS "Remediation_Activity_Logs" (
    log_id              SERIAL PRIMARY KEY,
    vuln_id             INTEGER REFERENCES "Vulnerabilities"(vuln_id),
    "timestamp"         TIMESTAMPTZ DEFAULT NOW(),
    command_dispatched  TEXT,
    operator_decision   TEXT,
    execution_status    TEXT CHECK (execution_status IN ('Success','Failed','Retrying','Skipped'))
);
