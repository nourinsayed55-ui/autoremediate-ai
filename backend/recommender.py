"""Vulnerability prioritisation and remediation recommendation engine.

Priority Score (higher = review first):
  Base:         Critical=100, High=70, Medium=40, Low=10
  +40  known backdoor / public Metasploit module / actively exploited
  +20  public PoC, not fully weaponised
  +15  no authentication required
  +15  service confirmed listening & reachable (port > 0)

Tie-breaking: lower port first, then alphabetically newer CVE (lexicographic desc).

Preference Ladder (first safe & feasible rung = recommended; lower rungs = alternatives):
  1  Patch/upgrade     — root-cause fix; usually infeasible on Metasploitable2
  2  Stop/disable      — preferred for backdoored/abandoned services
  3  Harden/reconfigure — preferred when service must stay up
  4  Network containment (iptables DROP)
  5  Monitor-only

HARD SAFETY RULE (enforced in code):
  SSH (port 22 or service ssh/sshd) must NEVER be stopped or have its port blocked.
  For SSH findings the preferred action is always rung-3 harden.
"""

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_SCORES = {"Critical": 100, "High": 70, "Medium": 40, "Low": 10}

# Services that are safe (and recommended) to stop on Metasploitable2
STOP_SAFE_SERVICES = {
    "vsftpd", "ftp",
    "unrealirc", "ircd", "irc",
    "distcc", "distccd",
    "telnet", "telnetd",
    "bindshell",   # the 1524 backdoor
    "rsh", "rlogin", "rexec",
    "rpcbind",
    "vnc", "vncserver",
}

# Map port numbers to /etc/init.d/ script names on Metasploitable2 (Ubuntu 8.04).
# Ubuntu 8.04 predates the 'service' wrapper (introduced in Ubuntu 9.04).
# Commands must use full path: sudo /etc/init.d/<name> stop|status.
# None means no init.d script exists for this port — iptables DROP is used instead.
# Verified against the live target's /etc/init.d/ listing.
PORT_TO_SERVICE = {
    21:   None,              # vsftpd: no init.d script → iptables
    22:   "ssh",             # never stopped — harden only (see is_ssh_asset)
    23:   "xinetd",          # telnetd runs via xinetd
    25:   "postfix",
    53:   "bind9",
    80:   "apache2",
    111:  "portmap",
    139:  "samba",           # script is 'samba', not 'smbd'
    445:  "samba",           # script is 'samba', not 'smbd'
    512:  "xinetd",          # rexec via xinetd
    513:  "xinetd",          # rlogin via xinetd
    514:  "xinetd",          # rsh via xinetd
    1099: None,              # rmiregistry: no init.d script → iptables
    1524: None,              # bind shell → iptables (no init.d; fuser unreliable over SSH)
    2049: "nfs-kernel-server",
    2121: "proftpd",
    3306: "mysql",
    3632: "distcc",
    5432: "postgresql-8.3",  # actual script name (not 'postgresql')
    5900: None,              # vncserver: no init.d script → iptables
    6000: None,              # xfs: no init.d script → iptables
    6667: None,              # unrealircd: no init.d script → iptables
    8009: "tomcat5.5",
    8180: "tomcat5.5",
}

# Known backdoored / actively-exploited plugin patterns (substring match)
BACKDOOR_KEYWORDS = [
    "backdoor", "smiley", "unrealirc", "vsftpd 2.3.4",
    "distcc", "bind shell", "ingreslock",
]

# Port 22 safety constants
SSH_PORTS = {22}
SSH_SERVICE_NAMES = {"ssh", "sshd", "openssh"}


# ---------------------------------------------------------------------------
# Safety helpers (called from recommender AND remediator)
# ---------------------------------------------------------------------------

def is_ssh_asset(finding: dict) -> bool:
    port = finding.get("port", 0)
    service = finding.get("service", "").lower()
    return port in SSH_PORTS or service in SSH_SERVICE_NAMES


def assert_not_ssh_kill(command: str, finding: dict) -> None:
    """Raise ValueError if the command would stop SSH or block port 22."""
    if not is_ssh_asset(finding):
        return
    cmd_lower = command.lower()
    if any(kw in cmd_lower for kw in ("stop", "disable", "kill")):
        raise ValueError(
            "SAFETY VIOLATION: Refusing to stop SSH — would sever the control channel."
        )
    if "--dport 22" in command or "-p 22" in command:
        raise ValueError(
            "SAFETY VIOLATION: Refusing to add firewall rule blocking port 22."
        )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _is_backdoor(finding: dict) -> bool:
    name = finding.get("plugin_name", "").lower()
    ease = finding.get("exploitability_ease", "").lower()
    return (
        any(kw in name for kw in BACKDOOR_KEYWORDS)
        or finding.get("exploit_available")
        or "exploits are available" in ease
    )


def _is_poc_only(finding: dict) -> bool:
    """Public PoC exists but not fully weaponised."""
    ease = finding.get("exploitability_ease", "").lower()
    return (
        not finding.get("exploit_available")
        and any(kw in ease for kw in ("poc", "proof of concept", "proof-of-concept"))
    )


def _no_auth_required(finding: dict) -> bool:
    name = finding.get("plugin_name", "").lower()
    ease = finding.get("exploitability_ease", "").lower()
    return "no exploit is required" in ease or "unauthenticated" in name


def score_finding(finding: dict) -> int:
    score = SEVERITY_SCORES.get(finding.get("severity", "Low"), 10)
    if _is_backdoor(finding):
        score += 40
    elif _is_poc_only(finding):
        score += 20
    if _no_auth_required(finding):
        score += 15
    if finding.get("port", 0) > 0:
        score += 15
    return score


# ---------------------------------------------------------------------------
# Preference ladder
# ---------------------------------------------------------------------------

def _initd_stop_command(service_name: str) -> str:
    return f"sudo /etc/init.d/{service_name} stop"


def _initd_status_command(service_name: str) -> str:
    return f"sudo /etc/init.d/{service_name} status 2>&1 || true"


def _iptables_drop(port: int, protocol: str = "tcp") -> str:
    return f"sudo iptables -I INPUT -p {protocol} --dport {port} -j DROP"


def _harden_ssh() -> dict:
    return {
        "rung": 3,
        "action": "harden",
        "command": (
            "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config "
            "&& sudo /etc/init.d/ssh restart"
        ),
        "verify_cmd": "sudo grep '^PermitRootLogin no' /etc/ssh/sshd_config",
        "description": "Harden SSH: disable root login, restart daemon",
        "rationale": "Rung 3 — SSH must remain up; hardening only (stopping would sever control channel).",
        "feasible": True,
    }


def get_suggestions(finding: dict) -> list:
    """
    Derive additional lower-priority remediation suggestions from the finding's
    own attributes (port, service, plugin_name, protocol) using deterministic
    if/then rules — no LLM or API call.  Same finding always yields the same list.

    Rules:
      SSH (port 22 / service ssh):  only safe hardening, NEVER stop or DROP.
      SSL/TLS finding on port 25:   disable weak protocol versions in Postfix config.
      Apache on port 80:            disable info/status modules (config-level).
      Tomcat AJP on port 8009:      disable AJP connector in server.xml.
      xinetd-managed ports (23, 512-514): disable specific service in /etc/xinetd.d/
                                          (safer than stopping all of xinetd).
      MySQL (port 3306):            revoke remote root at DB level.
      PostgreSQL (port 5432):       restrict pg_hba.conf remote entries.
      No-init.d backdoor ports:     add iptables LOG rule for forensic audit trail.

    All returned actions have action="harden" so verify() runs the verify_cmd
    (a grep/check confirming the config change took effect) rather than probing
    for a closed port.  Every item carries _is_suggested=True for identification.
    """
    port     = finding.get("port", 0)
    protocol = finding.get("protocol", "tcp")
    plugin   = finding.get("plugin_name", "").lower()
    suggestions: list = []

    # ── SSH: hardening only — NEVER stop or DROP ─────────────────────────────
    if is_ssh_asset(finding):
        suggestions.append({
            "rung": 3, "action": "harden", "_is_suggested": True,
            "command": (
                "sudo bash -c 'grep -q MaxAuthTries /etc/ssh/sshd_config"
                " || echo \"MaxAuthTries 3\" >> /etc/ssh/sshd_config'"
                " && sudo /etc/init.d/ssh restart"
            ),
            "verify_cmd": "sudo grep -q 'MaxAuthTries' /etc/ssh/sshd_config",
            "description": "Limit SSH auth attempts to 3 per connection (brute-force protection)",
            "rationale": (
                "Caps guessing attempts per connection without affecting existing "
                "access method; complements PermitRootLogin hardening."
            ),
            "feasible": True,
        })
        return suggestions  # Hard guard: never add stop/DROP for SSH

    # ── SSL/TLS finding on port 25 (Postfix SMTP) ────────────────────────────
    _ssl_kw = ("ssl", "tls", "weak cipher", "poodle", "beast", "sslv2", "sslv3")
    if port == 25 and any(k in plugin for k in _ssl_kw):
        suggestions.append({
            "rung": 3, "action": "harden", "_is_suggested": True,
            "command": (
                "sudo postconf -e 'smtpd_tls_protocols=!SSLv2,!SSLv3'"
                " && sudo postconf -e 'smtp_tls_protocols=!SSLv2,!SSLv3'"
                " && sudo /etc/init.d/postfix restart"
            ),
            "verify_cmd": "sudo postconf smtpd_tls_protocols | grep -q '!SSLv2'",
            "description": "Disable SSLv2/SSLv3 in Postfix TLS config (keep SMTP running)",
            "rationale": (
                "Config-level fix eliminates weak protocol support without "
                "downtime for the mail service."
            ),
            "feasible": True,
        })

    # ── Web server (Apache on port 80) ───────────────────────────────────────
    if port == 80:
        suggestions.append({
            "rung": 3, "action": "harden", "_is_suggested": True,
            "command": (
                "sudo a2dismod status info"
                " && sudo /etc/init.d/apache2 restart"
            ),
            "verify_cmd": (
                "sudo apache2ctl -M 2>/dev/null"
                " | grep -c 'status_module\\|info_module'"
                " | grep -q '^0'"
            ),
            "description": "Disable Apache info/status modules (server-info, server-status endpoints)",
            "rationale": (
                "Removes information-disclosure endpoints without stopping the "
                "web server; reduces attack surface with minimal service impact."
            ),
            "feasible": True,
        })

    # ── Tomcat AJP connector (port 8009 only — 8180 already in harden_hints) ─
    if port == 8009:
        suggestions.append({
            "rung": 3, "action": "harden", "_is_suggested": True,
            "command": (
                "sudo sed -i"
                " 's/<Connector port=\"8009\"/"
                "<!-- <Connector port=\"8009\"/'"
                " /etc/tomcat5.5/server.xml"
                " && echo '-->' | sudo tee -a /etc/tomcat5.5/server.xml > /dev/null"
                " && sudo /etc/init.d/tomcat5.5 restart"
            ),
            "verify_cmd": (
                "sudo grep -qF"
                " '<!-- <Connector port=\"8009\"'"
                " /etc/tomcat5.5/server.xml"
            ),
            "description": "Disable Tomcat AJP connector (port 8009) in server.xml",
            "rationale": (
                "AJP is only needed for Apache-Tomcat proxying; commenting it out "
                "removes a remote unauthenticated attack vector without stopping Tomcat."
            ),
            "feasible": True,
        })

    # ── xinetd-managed services: disable specific entry, not all of xinetd ───
    # Preferred action (stop xinetd) affects ALL xinetd-managed services; this
    # suggestion targets only the vulnerable service in /etc/xinetd.d/.
    _xinetd_map = {23: "telnet", 512: "rexec", 513: "rlogin", 514: "rsh"}
    if port in _xinetd_map and PORT_TO_SERVICE.get(port) == "xinetd":
        svc = _xinetd_map[port]
        suggestions.append({
            "rung": 3, "action": "harden", "_is_suggested": True,
            "command": (
                f"sudo sed -i 's/disable\\s*=\\s*no/disable = yes/'"
                f" /etc/xinetd.d/{svc}"
                " && sudo /etc/init.d/xinetd restart"
            ),
            "verify_cmd": f"sudo grep -q 'disable.*yes' /etc/xinetd.d/{svc}",
            "description": (
                f"Disable {svc} entry in xinetd config"
                " (targeted — keeps other xinetd services running)"
            ),
            "rationale": (
                f"Stops only the {svc} service via /etc/xinetd.d/ without "
                "affecting other xinetd-managed services (rexec, rlogin, etc.)."
            ),
            "feasible": True,
        })

    # ── MySQL: revoke remote root access at the database level ───────────────
    if port == 3306:
        suggestions.append({
            "rung": 3, "action": "harden", "_is_suggested": True,
            "command": (
                "sudo mysql -u root -e \""
                "DELETE FROM mysql.user"
                " WHERE Host NOT IN ('localhost','127.0.0.1') AND User='root';"
                " FLUSH PRIVILEGES;\""
            ),
            "verify_cmd": (
                "sudo mysql -u root -N -e \""
                "SELECT COUNT(*) FROM mysql.user"
                " WHERE Host NOT IN ('localhost','127.0.0.1') AND User='root';\""
                " | grep -q '^0'"
            ),
            "description": "Revoke remote root access in MySQL at the database level",
            "rationale": (
                "Application-level control complements the network bind-address "
                "restriction; blocks remote root regardless of network config."
            ),
            "feasible": True,
        })

    # ── PostgreSQL: restrict pg_hba.conf remote host-access entries ──────────
    if port == 5432:
        suggestions.append({
            "rung": 3, "action": "harden", "_is_suggested": True,
            "command": (
                "sudo sed -i"
                " 's/^host.*all.*all.*0\\.0\\.0\\.0\\/0.*$/# & # DISABLED/'"
                " /etc/postgresql/8.3/main/pg_hba.conf"
                " && sudo /etc/init.d/postgresql-8.3 restart"
            ),
            "verify_cmd": (
                "sudo grep -c '^host.*all.*all.*0\\.0\\.0\\.0'"
                " /etc/postgresql/8.3/main/pg_hba.conf"
                " | grep -q '^0'"
            ),
            "description": "Restrict PostgreSQL pg_hba.conf: comment out remote host-access rules",
            "rationale": (
                "Removes network-level remote access grants; complements the "
                "listen_addresses=localhost restriction."
            ),
            "feasible": True,
        })

    # ── Backdoor / no-init.d ports: iptables LOG rule for audit trail ─────────
    # These ports already have iptables DROP as preferred or alternative.
    # Adding a LOG rule first creates a forensic record of connection attempts.
    _audit_ports = {21, 1099, 1524, 5900, 6000, 6667}
    if port in _audit_ports:
        suggestions.append({
            "rung": 3, "action": "harden", "_is_suggested": True,
            "command": (
                f"sudo iptables -I INPUT -p {protocol} --dport {port}"
                f" -j LOG --log-prefix 'AUDIT_{port}: ' --log-level 4"
            ),
            "verify_cmd": (
                f"sudo iptables -L INPUT -n 2>/dev/null"
                f" | grep -q 'LOG.*dpt:{port}'"
            ),
            "description": (
                f"Add iptables LOG rule for port {port}/{protocol}"
                " (forensic audit trail of connection attempts)"
            ),
            "rationale": (
                "Captures all connection attempts in the kernel log for incident "
                "forensics; can be added alongside or before the DROP rule."
            ),
            "feasible": True,
        })

    return suggestions


def get_recommendation(finding: dict) -> dict:
    """Return dict with 'preferred' action, 'alternatives' list, and 'suggested' list."""
    port = finding.get("port", 0)
    protocol = finding.get("protocol", "tcp")
    service_name = finding.get("service", "").lower() or PORT_TO_SERVICE.get(port, "")

    # ---- SSH safety: always rung-3 harden ----
    if is_ssh_asset(finding):
        preferred = _harden_ssh()
        alternatives = [
            {
                "rung": 5,
                "action": "monitor",
                "command": "",
                "description": "Monitor only — log SSH activity, no change",
                "rationale": "Rung 5 — fallback; acceptable if hardening not yet approved.",
                "feasible": True,
            }
        ]
        return {"preferred": preferred, "alternatives": alternatives,
                "suggested": get_suggestions(finding)}

    # ---- Build all candidate rungs ----
    rungs = []

    # Rung 1 — Patch/upgrade (almost always infeasible on Metasploitable2)
    rungs.append({
        "rung": 1,
        "action": "patch",
        "command": f"# sudo apt-get update && sudo apt-get install --only-upgrade {service_name or 'PACKAGE'}",
        "description": "Patch/upgrade the affected package",
        "rationale": "Rung 1 — root-cause fix; infeasible on Metasploitable2 (no upstream patches for intentionally vulnerable packages).",
        "feasible": False,
    })

    # Rung 2 — Stop/disable service via /etc/init.d/ (Ubuntu 8.04 has no 'service' wrapper).
    # PORT_TO_SERVICE[port] = "name"  → use that init.d script
    # PORT_TO_SERVICE[port] = None    → no init.d script exists; skip rung-2, prefer iptables
    # Port not in PORT_TO_SERVICE     → fall back to Nessus service name if it looks real
    _GENERIC_LABELS = {"www", "http", "https", "unknown", "?", "general", "tcp", "udp"}
    if port in PORT_TO_SERVICE:
        initd_name = PORT_TO_SERVICE[port] or ""   # None → ""  → rung-2 skipped
    else:
        initd_name = service_name if service_name and service_name not in _GENERIC_LABELS else ""

    if initd_name:
        can_stop = service_name in STOP_SAFE_SERVICES or _is_backdoor(finding)
        stop_cmd = _initd_stop_command(initd_name)
        rungs.append({
            "rung": 2,
            "action": "stop_service",
            "command": stop_cmd,
            "description": f"Stop /etc/init.d/{initd_name}",
            "rationale": (
                "Rung 2 — disable the vulnerable service; "
                + ("backdoored/exploitable service is safe to stop." if can_stop else "service can be temporarily stopped.")
            ),
            "feasible": True,
        })

    # Rung 3 — Harden/reconfigure (using /etc/init.d/ — Ubuntu 8.04 has no 'service' wrapper)
    # Each hint carries a verify_cmd that confirms the config change took effect;
    # verify() runs it after the main command and checks for exit_code == 0.
    harden_hints = {
        139: {
            "command": "sudo bash -c 'echo \"[global]\\nhosts allow = 127.0.0.1\" >> /etc/samba/smb.conf && sudo /etc/init.d/samba restart'",
            "verify_cmd": "sudo grep -q 'hosts allow' /etc/samba/smb.conf",
        },
        445: {
            "command": "sudo bash -c 'echo \"[global]\\nhosts allow = 127.0.0.1\" >> /etc/samba/smb.conf && sudo /etc/init.d/samba restart'",
            "verify_cmd": "sudo grep -q 'hosts allow' /etc/samba/smb.conf",
        },
        2049: {
            "command": "sudo bash -c 'echo \"/tmp 127.0.0.1(rw,no_root_squash)\" > /etc/exports && sudo exportfs -ra'",
            "verify_cmd": "sudo grep -q '127.0.0.1' /etc/exports",
        },
        8180: {
            "command": "sudo bash -c 'sed -i \"s/<Connector port=\\\"8180\\\"/<!-- <Connector port=\\\"8180\\\"/\" /etc/tomcat5.5/server.xml && sudo /etc/init.d/tomcat5.5 restart'",
            "verify_cmd": "sudo grep -qF '<!-- <Connector port=\"8180\"' /etc/tomcat5.5/server.xml",
        },
        3306: {
            "command": "sudo bash -c 'sed -i \"s/^bind-address.*/bind-address = 127.0.0.1/\" /etc/mysql/my.cnf && sudo /etc/init.d/mysql restart'",
            "verify_cmd": "sudo grep -q 'bind-address.*127.0.0.1' /etc/mysql/my.cnf",
        },
        5432: {
            "command": "sudo bash -c 'sed -i \"s/^#listen_addresses.*/listen_addresses = \\x27localhost\\x27/\" /etc/postgresql/8.3/main/postgresql.conf && sudo /etc/init.d/postgresql-8.3 restart'",
            "verify_cmd": "sudo grep -q 'listen_addresses' /etc/postgresql/8.3/main/postgresql.conf",
        },
    }
    if port in harden_hints:
        hint = harden_hints[port]
        rungs.append({
            "rung": 3,
            "action": "harden",
            "command": hint["command"],
            "verify_cmd": hint.get("verify_cmd", ""),
            "description": f"Harden port {port} — restrict access",
            "rationale": "Rung 3 — reconfigure to limit exposure while keeping service available.",
            "feasible": True,
        })

    # Rung 4 — Network containment (iptables)
    if port > 0:
        rungs.append({
            "rung": 4,
            "action": "iptables_drop",
            "command": _iptables_drop(port, protocol),
            "description": f"iptables DROP port {port}/{protocol}",
            "rationale": "Rung 4 — network-layer containment; does not fix root cause.",
            "feasible": True,
        })

    # Rung 5 — Monitor only
    rungs.append({
        "rung": 5,
        "action": "monitor",
        "command": "",
        "description": "Monitor only — log finding, no change",
        "rationale": "Rung 5 — safe fallback; no impact on target.",
        "feasible": True,
    })

    # Select preferred (first feasible rung that is safe)
    feasible_rungs = [r for r in rungs if r["feasible"]]
    preferred = feasible_rungs[0] if feasible_rungs else rungs[-1]
    alternatives = [r for r in feasible_rungs if r is not preferred]

    return {"preferred": preferred, "alternatives": alternatives,
            "suggested": get_suggestions(finding)}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def prioritise_and_recommend(findings: list) -> list:
    """
    Score, sort, and attach recommendations to every finding.
    Returns findings list sorted descending by priority_score.
    Tie-break: lower port first, then CVE lexicographic descending.
    """
    for f in findings:
        f["priority_score"] = score_finding(f)
        f["recommendation"] = get_recommendation(f)

    findings.sort(
        key=lambda f: (
            -f["priority_score"],
            f.get("port", 9999),
            f.get("cve_reference", ""),
        )
    )
    return findings
