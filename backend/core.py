"""Shared remediation logic for the CLI engine and the web console.

Both ``engine.cmd_run`` (terminal) and ``app.py`` (Flask) call into this
module so that execution semantics are identical regardless of the interface.

No SSH/DB connections are made at import time.
"""
import json
import os
import sys
import threading

_BACKEND_DIR = os.path.dirname(__file__)
sys.path.insert(0, _BACKEND_DIR)

# One SSH session at a time — prevents two concurrent commands reaching the target.
_EXEC_LOCK = threading.Lock()

_DOCS_DIR = os.path.join(_BACKEND_DIR, "..", "docs")


def _scan_json_path(scan_id: int) -> str:
    return os.path.join(_DOCS_DIR, f"scan_{scan_id}_results.json")


def _load_config() -> dict:
    with open(os.path.join(_BACKEND_DIR, "config.json")) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Public query helpers
# ---------------------------------------------------------------------------

def get_decision_items(scan_id: int) -> list:
    """Load the scan JSON, prioritise, and return only Critical+High findings.

    Each finding gets two extra keys injected:
      ``_id``      – stable identifier ``"<plugin_id>_<port>"``
      ``_options`` – ordered list of option dicts ready for the web UI

    Raises FileNotFoundError if the scan JSON does not exist yet.
    """
    from parser import load_from_json_file
    from recommender import prioritise_and_recommend
    from engine import build_menu

    json_path = _scan_json_path(scan_id)
    if not os.path.exists(json_path):
        raise FileNotFoundError(
            f"Scan {scan_id} results not found at {json_path}. "
            "Run --launch-scan first or place the JSON there manually."
        )

    all_findings = load_from_json_file(json_path)
    ranked = prioritise_and_recommend(all_findings)
    actionable = [f for f in ranked if f["severity"] in ("Critical", "High")]

    for f in actionable:
        f["_id"] = f"{f.get('plugin_id', 'unknown')}_{f['port']}"
        f["_options"] = _build_options(f, build_menu(f))

    return actionable


def get_all_findings_count(scan_id: int) -> int:
    """Return the total count of non-Info findings in the scan JSON."""
    from parser import load_from_json_file
    json_path = _scan_json_path(scan_id)
    if not os.path.exists(json_path):
        return 0
    return len(load_from_json_file(json_path))


def get_all_findings(scan_id: int) -> list:
    """Return ALL non-Info findings (all severities) without recommendations.

    Used by read-only dashboard endpoints — no SSH, no DB.
    Returns empty list if scan JSON does not exist yet.
    """
    from parser import load_from_json_file
    json_path = _scan_json_path(scan_id)
    if not os.path.exists(json_path):
        return []
    return load_from_json_file(json_path)


# ---------------------------------------------------------------------------
# Option-key helpers (CLI ↔ web bridge)
# ---------------------------------------------------------------------------

def _build_options(finding: dict, menu: dict) -> list:
    """Convert a build_menu() result into a stable, ordered option list.

    Stable keys:  "preferred"  "alt_0" … "alt_N"  "sug_0" … "sug_N"  "monitor"
    """
    options = []

    p = menu["preferred"]
    options.append({
        "key": "preferred",
        "label": f"RECOMMENDED (Rung {p['rung']}): {p['description']}",
        "rung": p["rung"],
        "action": p.get("action", ""),
        "command": p.get("command", ""),
        "rationale": p.get("rationale", ""),
        "tier": "preferred",
    })

    for i, (_, alt) in enumerate(menu["alt_slots"]):
        options.append({
            "key": f"alt_{i}",
            "label": f"ALTERNATIVE (Rung {alt['rung']}): {alt['description']}",
            "rung": alt["rung"],
            "action": alt.get("action", ""),
            "command": alt.get("command", ""),
            "rationale": alt.get("rationale", ""),
            "tier": "alternative",
        })

    for i, (_, sug) in enumerate(menu["suggested_slots"]):
        options.append({
            "key": f"sug_{i}",
            "label": f"SUGGESTED (Rung {sug['rung']}): {sug['description']}",
            "rung": sug["rung"],
            "action": sug.get("action", ""),
            "command": sug.get("command", ""),
            "rationale": sug.get("rationale", ""),
            "tier": "suggested",
        })

    mon = menu["monitor"]
    options.append({
        "key": "monitor",
        "label": "MONITOR ONLY — log finding, no change to target",
        "rung": 5,
        "action": "monitor",
        "command": "",
        "rationale": mon.get("rationale", "Rung 5 — safe fallback; no impact on target."),
        "tier": "monitor",
    })

    return options


def _key_to_action(finding: dict, option_key: str) -> dict:
    """Map a stable option key to its action dict.

    Raises ValueError for unknown keys.
    """
    from engine import build_menu
    menu = build_menu(finding)

    if option_key == "preferred":
        return menu["preferred"]

    if option_key == "monitor":
        return menu["monitor"]

    if option_key.startswith("alt_"):
        idx = int(option_key.split("_", 1)[1])
        if 0 <= idx < len(menu["alt_slots"]):
            return menu["alt_slots"][idx][1]

    if option_key.startswith("sug_"):
        idx = int(option_key.split("_", 1)[1])
        if 0 <= idx < len(menu["suggested_slots"]):
            return menu["suggested_slots"][idx][1]

    raise ValueError(f"Unknown option key: {option_key!r}")


def decision_to_option_key(finding: dict, decision: dict, menu: dict) -> str:
    """Map a get_human_decision() raw choice ('A', '2', …) to a stable option key.

    Used by cmd_run to translate the CLI decision into the key that
    execute_action() expects.
    """
    choice = decision["choice"]

    if choice == "A":
        return "preferred"

    if choice == menu["monitor_key"]:
        return "monitor"

    for i, (k, _) in enumerate(menu["alt_slots"]):
        if choice == k:
            return f"alt_{i}"

    for i, (k, _) in enumerate(menu["suggested_slots"]):
        if choice == k:
            return f"sug_{i}"

    raise ValueError(f"Cannot map decision choice {choice!r} to a stable option key")


# ---------------------------------------------------------------------------
# Execution (single shared path for CLI + web)
# ---------------------------------------------------------------------------

def execute_action(finding_id: str, option_key: str, operator: str,
                   scan_id: int = 12, dry_run: bool = False) -> dict:
    """Execute one remediation action and write the result to the database.

    CALLER MUST have obtained explicit human approval before invoking this.
    There is no silent auto-fire path in this function.

    Thread-safe: _EXEC_LOCK prevents concurrent SSH sessions.
    Returns a result dict with at minimum: status, command, attempts, finding_id, option_key.
    """
    import db
    from remediator import Remediator

    cfg = _load_config()
    target = cfg["target_node"]

    findings = get_decision_items(scan_id)
    finding = next((f for f in findings if f["_id"] == finding_id), None)
    if finding is None:
        raise ValueError(f"Finding '{finding_id}' not found in scan {scan_id}")

    action = _key_to_action(finding, option_key)

    with _EXEC_LOCK:
        rem = Remediator(
            host=target["host_ip"],
            user=target["ssh_user"],
            password=target["ssh_pass"],
            dry_run=dry_run,
            retry_attempts=cfg["automation_rules"].get("retry_attempts", 3),
        )
        result = rem.execute(finding, action)

    log_status = result.get("status", "Failed")
    if log_status not in ("Success", "Failed", "Retrying", "Skipped"):
        log_status = "Failed"

    try:
        vuln_id = db.insert_vulnerability(
            finding.get("cve_reference", ""),
            finding.get("plugin_name", ""),
            finding.get("severity", ""),
            finding.get("port", 0),
        )
        op_label = (
            f"WEB-APPROVED by {operator} "
            f"(Rung {action['rung']}): {action['description']}"
        )
        db.insert_remediation_log(
            vuln_id=vuln_id,
            command_dispatched=result.get("command", ""),
            operator_decision=op_label,
            execution_status=log_status,
        )
        result["vuln_id"] = vuln_id
    except Exception as exc:
        result["db_error"] = str(exc)

    result["finding_id"] = finding_id
    result["option_key"] = option_key
    result["operator"] = operator
    return result
