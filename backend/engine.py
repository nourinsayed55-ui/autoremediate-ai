"""AutoRemediate AI — Main Orchestrator Engine.

Usage:
  python engine.py --setup-db
  python engine.py --launch-scan
  python engine.py --run [--scan-id SCAN_ID] [--dry-run]
  python engine.py --verify-scan BASELINE_SCAN_ID
  python engine.py --generate-docs [--scan-id SCAN_ID]

Requirements:
  - config.json must be present in the same directory.
  - conda activate autoremediate (Python 3.11)
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

# ── local modules ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
import db
from scanner_client import NessusClient
from parser import parse_full_results, load_from_json_file
from recommender import prioritise_and_recommend
from remediator import Remediator


# ── helpers ────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(cfg_path) as f:
        return json.load(f)


def make_nessus_client(cfg: dict) -> NessusClient:
    n = cfg["nessus_api"]
    return NessusClient(n["base_url"], n["access_key"], n["secret_key"])


def severity_banner(sev: str) -> str:
    colors = {"Critical": "\033[91m", "High": "\033[31m",
               "Medium": "\033[33m", "Low": "\033[36m"}
    reset = "\033[0m"
    return f"{colors.get(sev, '')}{sev.upper()}{reset}"


# ── human-in-the-loop decision card ───────────────────────────────────────────

APPROVAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════╗
║  ⚠  require_manual_approval is FALSE in config — this is UNSAFE.  ║
║  You must still type an explicit confirmation before anything runs. ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def build_menu(finding: dict) -> dict:
    """
    Build a consistent, per-finding menu structure from its recommendation.

    Both show_decision_card() and get_human_decision() derive everything from
    this single source of truth, so printed options and accepted inputs can
    never drift apart.

    Returns:
      preferred    — the recommended action dict
      alt_slots    — list of (key_str, action_dict) for non-monitor alternatives,
                     numbered consecutively from "2"
      monitor_key  — the input key for the monitor-only option (one past alt_slots)
      monitor      — the monitor action dict
      valid_keys   — ordered list of every accepted key, e.g. ["A","2","3","R","Q"]
    """
    rec = finding["recommendation"]
    preferred = rec["preferred"]

    # Separate monitor (rung 5 / action==monitor) from numbered alternatives
    non_monitor = [
        a for a in rec["alternatives"]
        if a.get("action") != "monitor" and a.get("rung", 0) != 5
    ]
    monitor = next(
        (a for a in rec["alternatives"]
         if a.get("action") == "monitor" or a.get("rung", 0) == 5),
        {"rung": 5, "action": "monitor", "command": "",
         "description": "Monitor only — log finding, no change to target",
         "rationale": "Rung 5 — safe fallback; no impact on target.",
         "feasible": True},
    )

    # Assign keys "2", "3", … to non-monitor alternatives (at most 3)
    alt_slots = [(str(i + 2), non_monitor[i]) for i in range(min(3, len(non_monitor)))]

    # System-suggested options (new key; empty list for findings without suggestions)
    suggested_raw = rec.get("suggested", [])
    sug_start = len(alt_slots) + 2
    suggested_slots = [(str(sug_start + i), suggested_raw[i])
                       for i in range(len(suggested_raw))]

    # Monitor key follows all alt_slots AND suggested_slots
    monitor_key = str(len(alt_slots) + len(suggested_slots) + 2)

    valid_keys = (
        ["A"]
        + [k for k, _ in alt_slots]
        + [k for k, _ in suggested_slots]
        + [monitor_key, "R", "Q"]
    )

    return {
        "preferred": preferred,
        "alt_slots": alt_slots,
        "suggested_slots": suggested_slots,
        "monitor_key": monitor_key,
        "monitor": monitor,
        "valid_keys": valid_keys,
    }


def show_decision_card(finding: dict, idx: int, total: int) -> None:
    menu = build_menu(finding)
    preferred = menu["preferred"]

    border = "═" * 72
    print(f"\n{border}")
    print(f"  DECISION REQUIRED  [{idx}/{total}]")
    print(border)
    print(f"  Plugin:    {finding['plugin_name']}")
    print(f"  Severity:  {severity_banner(finding['severity'])}"
          f"   Port: {finding['port']}/{finding['protocol']}"
          f"   Service: {finding.get('service','?')}")
    print(f"  CVE:       {finding.get('cve_reference','N/A')}")
    print(f"  CVSS:      {finding.get('cvss_base_score','N/A')}")
    print(f"  Score:     {finding['priority_score']}")
    print(f"  Host:      {finding.get('host','?')}")
    print("─" * 72)
    print(f"  [A] RECOMMENDED (Rung {preferred['rung']}): {preferred['description']}")
    print(f"      Command:   {preferred['command'] or '(no command)'}")
    print(f"      Rationale: {preferred['rationale']}")
    print()
    for key, alt in menu["alt_slots"]:
        print(f"  [{key}] ALTERNATIVE (Rung {alt['rung']}): {alt['description']}")
        print(f"       Command: {alt['command'] or '(no command)'}")
    if menu["suggested_slots"]:
        print(f"  {'─' * 66}")
        print("  ADDITIONAL SYSTEM-SUGGESTED OPTIONS (lower priority)")
        for key, sug in menu["suggested_slots"]:
            print(f"  [{key}] SUGGESTED (Rung {sug['rung']}): {sug['description']}")
            print(f"       Command:   {sug['command'] or '(no command)'}")
            print(f"       Rationale: {sug.get('rationale', '')}")
    print(f"  [{menu['monitor_key']}] MONITOR ONLY — log finding, no change to target")
    print()
    print("  [R] REJECT / SKIP  (you will be asked for a reason)")
    print("  [Q] QUIT this run cleanly")
    valid_str = " / ".join(menu["valid_keys"])
    print(f"  Accepted: {valid_str}")
    print(border)


def get_human_decision(finding: dict, cfg: dict) -> dict:
    """
    Block on stdin until the operator chooses an action.
    NOTHING runs without an explicit keystroke.
    Returns dict: {choice, action, reason}

    The menu options and accepted inputs are derived from the same build_menu()
    call, so they can never drift apart — every printed option is valid.
    """
    require_approval = cfg["automation_rules"].get("require_manual_approval", True)
    if not require_approval:
        print(APPROVAL_WARNING)
        confirm = input(
            "  require_manual_approval is off — type YES to proceed: "
        ).strip()
        if confirm.upper() != "YES":
            print("  Confirmation not received. Skipping finding.")
            return {"choice": "R", "action": None,
                    "reason": "auto-approval disabled but not confirmed"}

    menu = build_menu(finding)
    valid_str = " / ".join(menu["valid_keys"])

    while True:
        raw = input(f"\n  Your decision [{valid_str}]: ").strip().upper()

        if raw == "A":
            return {"choice": "A", "action": menu["preferred"],
                    "reason": "operator approved recommended action"}

        for key, alt in menu["alt_slots"]:
            if raw == key:
                return {"choice": raw, "action": alt,
                        "reason": f"operator chose alternative (rung {alt['rung']})"}

        for key, sug in menu["suggested_slots"]:
            if raw == key:
                return {"choice": raw, "action": sug,
                        "reason": f"operator chose system-suggested option (rung {sug['rung']})"}

        if raw == menu["monitor_key"]:
            return {"choice": raw, "action": menu["monitor"],
                    "reason": "operator chose monitor-only"}

        if raw == "R":
            reason = input("  Reason for rejection: ").strip() or "no reason given"
            return {"choice": "R", "action": None, "reason": reason}

        if raw == "Q":
            return {"choice": "Q", "action": None, "reason": "operator quit run"}

        print(f"  Invalid input — please enter one of: {valid_str}")


# ── sub-commands ───────────────────────────────────────────────────────────────

def cmd_setup_db():
    print("[Engine] Creating database schema …")
    db.create_schema()
    tables = db.verify_tables()
    print(f"[Engine] Tables confirmed in Supabase: {tables}")


def cmd_launch_scan(cfg: dict) -> int:
    client = make_nessus_client(cfg)
    target = cfg["target_node"]["host_ip"]
    scan_id = client.create_scan(target)
    client.launch_scan(scan_id)
    print(f"[Engine] Scan {scan_id} is running. Poll with: python engine.py --run --scan-id {scan_id}")
    # Save scan_id for future reference
    state_path = os.path.join(os.path.dirname(__file__), ".scan_state.json")
    with open(state_path, "w") as f:
        json.dump({"scan_id": scan_id, "launched_at": datetime.utcnow().isoformat()}, f)
    return scan_id


def _load_scan_id(cfg: dict, given_id: int = None) -> int:
    if given_id:
        return given_id
    state_path = os.path.join(os.path.dirname(__file__), ".scan_state.json")
    if os.path.exists(state_path):
        with open(state_path) as f:
            state = json.load(f)
        return state["scan_id"]
    raise RuntimeError("No scan_id provided and no .scan_state.json found. Run --launch-scan first.")


def _fetch_and_save_results(client: NessusClient, scan_id: int, cfg: dict) -> list:
    """Wait for scan completion, fetch all results, save to docs/, return findings list."""
    client.wait_for_completion(scan_id, poll_seconds=60)

    docs_dir = os.path.join(os.path.dirname(__file__), "..", "docs")
    os.makedirs(docs_dir, exist_ok=True)

    json_path = os.path.join(docs_dir, f"scan_{scan_id}_results.json")
    csv_path = os.path.join(docs_dir, f"scan_{scan_id}_results.csv")

    print("[Engine] Fetching full results via API …")
    raw = client.get_full_results(scan_id)
    client.save_json_results(raw, json_path)

    try:
        client.export_csv(scan_id, csv_path)
    except Exception as exc:
        print(f"[Engine] CSV export failed (non-critical): {exc}")

    findings = parse_full_results(raw)
    print(f"[Engine] Parsed {len(findings)} non-Info findings.")
    return findings


def cmd_run(cfg: dict, scan_id: int = None, dry_run: bool = False):
    """Main remediation loop with human-in-the-loop approval."""
    import core  # lazy — avoids circular import (core imports engine.build_menu)

    client = make_nessus_client(cfg)
    scan_id = _load_scan_id(cfg, scan_id)

    # Ensure scan JSON exists; fetch from Nessus if not yet cached
    json_path = os.path.join(os.path.dirname(__file__), "..", "docs",
                             f"scan_{scan_id}_results.json")
    if os.path.exists(json_path):
        print(f"[Engine] Loading cached results from {json_path}")
    else:
        _fetch_and_save_results(client, scan_id, cfg)

    # Load, score, prioritise via the shared core module
    actionable = core.get_decision_items(scan_id)
    all_count = core.get_all_findings_count(scan_id)
    informational_count = all_count - len(actionable)

    print(f"\n{'='*72}")
    print(f"  AutoRemediate AI — Remediation Run")
    print(f"  Scan ID: {scan_id} | Mode: {'DRY-RUN' if dry_run else 'LIVE'}")
    print(f"  Critical+High: {len(actionable)} | Medium+Low: {informational_count}")
    print(f"{'='*72}\n")

    summary = {"approved": 0, "rejected": 0, "skipped": 0, "failed": 0, "success": 0}

    for idx, finding in enumerate(actionable, 1):
        show_decision_card(finding, idx, len(actionable))
        decision = get_human_decision(finding, cfg)

        if decision["choice"] == "Q":
            print("\n[Engine] Operator quit. Stopping run.")
            break

        if decision["choice"] == "R" or decision["action"] is None:
            summary["rejected"] += 1
            try:
                vuln_id = db.insert_vulnerability(
                    finding.get("cve_reference", ""),
                    finding.get("plugin_name", ""),
                    finding.get("severity", ""),
                    finding.get("port", 0),
                )
                db.insert_remediation_log(
                    vuln_id=vuln_id,
                    command_dispatched="(none — rejected)",
                    operator_decision=f"REJECTED: {decision['reason']}",
                    execution_status="Skipped",
                )
                print(f"  [DB] Rejection logged for vuln_id={vuln_id}")
            except Exception as exc:
                print(f"  [DB] Log error: {exc}")
            continue

        # Map the raw CLI choice ('A', '2', …) to a stable option key, then
        # delegate execution + DB logging to the shared core path.
        menu = build_menu(finding)
        option_key = core.decision_to_option_key(finding, decision, menu)

        print(f"\n  [Engine] Executing: {decision['action']['command']}")
        result = core.execute_action(
            finding_id=finding["_id"],
            option_key=option_key,
            operator="cli-operator",
            scan_id=scan_id,
            dry_run=dry_run,
        )
        print(f"  [Engine] Result: {result['status']} (attempts={result['attempts']})")
        if "db_error" in result:
            print(f"  [DB] Log error: {result['db_error']}")
        else:
            print(f"  [DB] Logged, status={result['status']}")

        if result["status"] == "Success":
            summary["success"] += 1
        elif result["status"] == "Failed":
            summary["failed"] += 1
        else:
            summary["skipped"] += 1

    # Final summary
    print(f"\n{'='*72}")
    print(f"  RUN COMPLETE — Summary")
    print(f"  Approved & Succeeded: {summary['success']}")
    print(f"  Approved & Failed:    {summary['failed']}")
    print(f"  Rejected/Skipped:     {summary['rejected'] + summary['skipped']}")
    print(f"  Medium/Low (not actioned): {informational_count}")
    print(f"{'='*72}\n")


def cmd_verify_scan(cfg: dict, baseline_scan_id: int):
    """Launch a post-remediation scan and diff against the baseline."""
    client = make_nessus_client(cfg)
    target = cfg["target_node"]["host_ip"]

    print(f"[Engine] Launching post-remediation verification scan against {target} …")
    verify_scan_id = client.create_scan(target, name="AutoRemediate_Verification_Scan")
    client.launch_scan(verify_scan_id)

    findings_after = _fetch_and_save_results(client, verify_scan_id, cfg)
    findings_after_set = {
        (f["plugin_id"], f["port"]) for f in findings_after
    }

    # Load baseline
    baseline_json = os.path.join(os.path.dirname(__file__), "..", "docs",
                                 f"scan_{baseline_scan_id}_results.json")
    findings_before = load_from_json_file(baseline_json) if os.path.exists(baseline_json) else []
    findings_before_set = {(f["plugin_id"], f["port"]) for f in findings_before}

    resolved = findings_before_set - findings_after_set
    new_findings = findings_after_set - findings_before_set
    persisted = findings_before_set & findings_after_set

    print(f"\n[Verification] Baseline scan: {baseline_scan_id}")
    print(f"[Verification] Post-scan:      {verify_scan_id}")
    print(f"[Verification] Resolved:       {len(resolved)}")
    print(f"[Verification] New findings:   {len(new_findings)}")
    print(f"[Verification] Persisted:      {len(persisted)}")

    diff = {
        "baseline_scan_id": baseline_scan_id,
        "verify_scan_id": verify_scan_id,
        "resolved": list(resolved),
        "new_findings": list(new_findings),
        "persisted": list(persisted),
    }
    import json as _json
    out_path = os.path.join(os.path.dirname(__file__), "..", "docs", "verification_diff.json")
    with open(out_path, "w") as f:
        _json.dump(diff, f, indent=2)
    print(f"[Verification] Diff saved → {out_path}")
    return diff


def cmd_generate_docs(cfg: dict, scan_id: int = None):
    """Generate all .docx documentation files."""
    try:
        from generate_docs import generate_all
        generate_all(cfg, scan_id)
    except ImportError:
        print("[Engine] generate_docs.py not found. Run from backend/ directory.")
    except Exception as exc:
        print(f"[Engine] Doc generation error: {exc}")
        raise


# ── CLI entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AutoRemediate AI — Autonomous Vulnerability Remediation Engine"
    )
    parser.add_argument("--setup-db", action="store_true",
                        help="Create/verify database schema in Supabase")
    parser.add_argument("--launch-scan", action="store_true",
                        help="Create and launch a new Nessus scan")
    parser.add_argument("--run", action="store_true",
                        help="Run the remediation loop (requires completed scan)")
    parser.add_argument("--scan-id", type=int, default=None,
                        help="Nessus scan ID to use (optional; reads .scan_state.json if omitted)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what WOULD happen without connecting to target")
    parser.add_argument("--verify-scan", type=int, default=None, metavar="BASELINE_SCAN_ID",
                        help="Launch a post-remediation scan and diff against baseline")
    parser.add_argument("--generate-docs", action="store_true",
                        help="Generate all .docx documentation files")
    args = parser.parse_args()

    cfg = load_config()

    if args.setup_db:
        cmd_setup_db()

    if args.launch_scan:
        cmd_launch_scan(cfg)

    if args.run:
        cmd_run(cfg, scan_id=args.scan_id, dry_run=args.dry_run)

    if args.verify_scan:
        cmd_verify_scan(cfg, baseline_scan_id=args.verify_scan)

    if args.generate_docs:
        cmd_generate_docs(cfg, scan_id=args.scan_id)

    if not any([args.setup_db, args.launch_scan, args.run,
                args.verify_scan, args.generate_docs]):
        parser.print_help()


if __name__ == "__main__":
    main()
