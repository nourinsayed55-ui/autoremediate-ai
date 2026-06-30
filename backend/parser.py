"""Parse raw Nessus API results into a normalised list of Finding dicts.

Each Finding contains:
  plugin_id, plugin_name, severity (Critical/High/Medium/Low),
  severity_num (4/3/2/1), port, protocol, service,
  cve_reference, exploit_available, exploitability_ease,
  synopsis, solution, description, host
"""

SEVERITY_MAP = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}


def _extract_cve(attrs: dict) -> str:
    """Pull the first CVE ref from pluginattributes ref_information."""
    try:
        refs = attrs.get("ref_information", {}).get("ref", [])
        for ref in refs:
            if ref.get("name", "").upper() == "CVE":
                vals = ref.get("values", [])
                return vals[0] if vals else ""
    except Exception:
        pass
    return ""


def _extract_port_protocol_service(details: dict) -> tuple:
    """Parse port/protocol/service from plugin outputs -> ports key."""
    try:
        outputs = details.get("outputs", [])
        if outputs:
            ports_dict = outputs[0].get("ports", {})
            for port_str in ports_dict.keys():
                # Format: "21 / tcp / ftp" or "0 / tcp"
                parts = [p.strip() for p in port_str.split("/")]
                port_num = int(parts[0]) if parts[0].isdigit() else 0
                protocol = parts[1] if len(parts) > 1 else "tcp"
                service = parts[2] if len(parts) > 2 else ""
                return port_num, protocol, service
    except Exception:
        pass
    return 0, "tcp", ""


def parse_full_results(raw: dict) -> list:
    """Convert NessusClient.get_full_results() output into normalised Finding list."""
    findings = []
    for host in raw.get("hosts", []):
        hostname = host.get("hostname", "unknown")
        for vuln in host.get("vulnerabilities", []):
            sev_num = vuln.get("severity", 0)
            if sev_num == 0:
                continue  # skip Info

            details = vuln.get("_details", {})
            plugin_info = details.get("info", {})
            attrs = plugin_info.get("pluginattributes", {})

            exploit_info = attrs.get("exploit_information", {})
            risk_info = attrs.get("risk_information", {})
            vuln_info = attrs.get("vuln_information", {})

            exploit_available = (
                exploit_info.get("exploit_available", "false").lower() == "true"
                or vuln_info.get("exploit_available", "false").lower() == "true"
            )
            exploitability_ease = (
                exploit_info.get("exploitability_ease", "")
                or vuln_info.get("exploitability_ease", "")
            )

            port, protocol, service = _extract_port_protocol_service(details)

            finding = {
                "host": hostname,
                "plugin_id": vuln.get("plugin_id"),
                "plugin_name": vuln.get("plugin_name", ""),
                "plugin_family": vuln.get("plugin_family", ""),
                "severity": SEVERITY_MAP.get(sev_num, "Low"),
                "severity_num": sev_num,
                "port": port,
                "protocol": protocol,
                "service": service,
                "cve_reference": _extract_cve(attrs),
                "exploit_available": exploit_available,
                "exploitability_ease": exploitability_ease,
                "synopsis": attrs.get("synopsis", ""),
                "solution": attrs.get("solution", ""),
                "description": attrs.get("description", ""),
                "cvss_base_score": risk_info.get("cvss_base_score", ""),
            }
            findings.append(finding)

    return findings


def load_from_json_file(path: str) -> list:
    """Load a saved JSON results file and parse it."""
    import json
    with open(path) as f:
        raw = json.load(f)
    return parse_full_results(raw)
