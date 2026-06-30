"""AutoRemediate AI — Local web console (Flask, 127.0.0.1:5000 only).

SECURITY CONSTRAINTS (enforced here):
- Bound to 127.0.0.1 ONLY — the server must never listen on 0.0.0.0.
- No 'approve-all' or 'run-all' endpoint; /api/remediate accepts exactly
  one finding_id + one option_key per POST, enforced at the HTTP layer.
- All config.json secrets (SSH password, Nessus keys, Supabase DSN) are
  loaded only inside backend functions and are never serialised to JSON
  or sent to the browser.
- One SSH session at a time (threading.Lock inside core.execute_action).

Run:
    conda activate autoremediate
    python backend/app.py
Then open http://127.0.0.1:5000 in a browser on the same machine.
"""
import os
import sys
from datetime import datetime as _dt

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, jsonify, render_template, request
import core
import db

app = Flask(__name__, template_folder="templates")

SCAN_ID = 12  # hard-coded for the demo; single scan target


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/findings")
def api_findings():
    """Return all Critical+High findings with their option lists.

    Secrets (SSH/Nessus/Supabase credentials) are never included.
    """
    try:
        findings = core.get_decision_items(SCAN_ID)
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 503
    except Exception as exc:
        return jsonify({"error": f"Unexpected error loading findings: {exc}"}), 500

    safe = []
    for f in findings:
        safe.append({
            "_id": f["_id"],
            "plugin_name": f.get("plugin_name", ""),
            "severity": f.get("severity", ""),
            "port": f.get("port", 0),
            "protocol": f.get("protocol", "tcp"),
            "service": f.get("service", ""),
            "cve_reference": f.get("cve_reference", ""),
            "cvss_base_score": f.get("cvss_base_score", ""),
            "priority_score": f.get("priority_score", 0),
            "host": f.get("host", ""),
            "_options": f["_options"],
        })
    return jsonify({"findings": safe})


@app.route("/api/remediate", methods=["POST"])
def api_remediate():
    """Execute exactly one action for exactly one finding per explicit operator click.

    Requires JSON body: { "finding_id": "...", "option_key": "..." }
    Any request without both fields returns HTTP 400 — no batch paths exist.
    """
    data = request.get_json(silent=True) or {}
    finding_id = data.get("finding_id")
    option_key = data.get("option_key")
    operator = str(data.get("operator", "web-operator"))[:64]

    if not finding_id or not option_key:
        return jsonify({"error": "finding_id and option_key are both required"}), 400

    try:
        result = core.execute_action(
            finding_id=str(finding_id),
            option_key=str(option_key),
            operator=operator,
            scan_id=SCAN_ID,
            dry_run=False,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Execution error: {exc}"}), 500

    # Return only safe fields — never SSH password, Nessus keys, or DSN
    safe_result = {
        "finding_id": result.get("finding_id"),
        "option_key": result.get("option_key"),
        "operator": result.get("operator"),
        "status": result.get("status"),
        "command": result.get("command", ""),
        "attempts": result.get("attempts"),
        "message": result.get("message", ""),
    }
    if "db_error" in result:
        safe_result["db_error"] = result["db_error"]
    return jsonify(safe_result)


@app.route("/api/logs")
def api_logs():
    """Return the 50 most recent activity log rows from the database."""
    try:
        logs = db.get_recent_logs(limit=50)
        for row in logs:
            ts = row.get("timestamp")
            if ts is not None and hasattr(ts, "isoformat"):
                row["timestamp"] = ts.isoformat()
        return jsonify({"logs": logs})
    except Exception as exc:
        return jsonify({"error": str(exc), "logs": []}), 500


@app.route("/api/status")
def api_status():
    """Return aggregate counters for the dashboard header."""
    total = 0
    try:
        total = core.get_all_findings_count(SCAN_ID)
    except Exception:
        pass

    critical_high = 0
    try:
        critical_high = len(core.get_decision_items(SCAN_ID))
    except Exception:
        pass

    remediated_success = 0
    db_connected = False
    try:
        logs = db.get_recent_logs(limit=500)
        remediated_success = sum(
            1 for row in logs if row.get("execution_status") == "Success"
        )
        db_connected = True
    except Exception:
        pass

    return jsonify({
        "total_findings": total,
        "critical_high": critical_high,
        "remediated_success": remediated_success,
        "db_connected": db_connected,
    })


# ---------------------------------------------------------------------------
# Read-only dashboard endpoints (no remediation actions)
# ---------------------------------------------------------------------------

@app.route("/api/metrics")
def api_metrics():
    """Aggregate performance metrics from the remediation log.

    Returns: total_actions, success, failed, skipped, success_rate, mttr_seconds.
    """
    def _parse_ts(ts):
        if ts is None:
            return None
        if hasattr(ts, "timestamp"):
            return ts
        try:
            return _dt.fromisoformat(str(ts).replace("Z", ""))
        except Exception:
            return None

    payload = {
        "total_actions": 0, "success": 0, "failed": 0, "skipped": 0,
        "success_rate": 0.0, "mttr_seconds": None,
    }
    try:
        logs = db.get_recent_logs(limit=500)
        payload["total_actions"] = len(logs)
        payload["success"] = sum(1 for l in logs if l.get("execution_status") == "Success")
        payload["failed"]  = sum(1 for l in logs if l.get("execution_status") == "Failed")
        payload["skipped"] = sum(1 for l in logs if l.get("execution_status") in ("Skipped", "Retrying"))
        if payload["total_actions"] > 0:
            payload["success_rate"] = round(
                100 * payload["success"] / payload["total_actions"], 1
            )
        success_logs = [
            l for l in logs
            if l.get("execution_status") == "Success" and l.get("timestamp")
        ]
        if len(success_logs) >= 2:
            # logs are newest-first; sort ascending for time-span math
            times = sorted(
                [_parse_ts(l["timestamp"]) for l in success_logs if _parse_ts(l["timestamp"])]
            )
            if len(times) >= 2:
                span = (times[-1] - times[0]).total_seconds()
                payload["mttr_seconds"] = round(span / (len(times) - 1), 1)
    except Exception as exc:
        payload["error"] = str(exc)
    return jsonify(payload)


@app.route("/api/severity-breakdown")
def api_severity_breakdown():
    """Count of all scan findings by severity (read from JSON, not DB)."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    try:
        findings = core.get_all_findings(SCAN_ID)
        for f in findings:
            sev = f.get("severity", "")
            if sev in counts:
                counts[sev] += 1
    except Exception as exc:
        return jsonify({"error": str(exc), **counts}), 500
    return jsonify(counts)


@app.route("/api/ports")
def api_ports():
    """Critical+High findings grouped by port for the bar chart and port chips."""
    try:
        findings = core.get_decision_items(SCAN_ID)
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc), "ports": []}), 503
    except Exception as exc:
        return jsonify({"error": str(exc), "ports": []}), 500

    ports = []
    for f in findings:
        ports.append({
            "_id":           f["_id"],
            "port":          f.get("port", 0),
            "protocol":      f.get("protocol", "tcp"),
            "service":       f.get("service", ""),
            "severity":      f.get("severity", ""),
            "plugin_name":   f.get("plugin_name", ""),
            "cve_reference": f.get("cve_reference", ""),
            "priority_score": f.get("priority_score", 0),
        })
    ports.sort(key=lambda x: x["priority_score"], reverse=True)
    return jsonify({"ports": ports})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  AutoRemediate AI — Web Console")
    print("  http://127.0.0.1:5000/")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    # NEVER change host to '0.0.0.0' — local-only is a security constraint.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
