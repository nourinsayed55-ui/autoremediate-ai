"""Live Nessus API client — no file-based or mock fallback.

Authentication uses X-ApiKeys header:
  accessKey=<key>; secretKey=<key>

All network calls are wrapped in try/except for Fail-Safe Error Resilience.
SSL certificate verification is disabled (verify=False) because Nessus uses
a self-signed certificate; InsecureRequestWarning is suppressed.
"""
import json
import os
import ssl
import time
import urllib3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

urllib3.disable_warnings()  # suppress all urllib3 warnings including InsecureRequestWarning


class _PermissiveTLSAdapter(HTTPAdapter):
    """Mount this on the session to fully disable cert verification at the TLS layer."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Allow older TLS and cipher suites that Nessus may use
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["ssl_context"] = create_urllib3_context()
        proxy_kwargs["ssl_context"].check_hostname = False
        proxy_kwargs["ssl_context"].verify_mode = ssl.CERT_NONE
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class NessusClient:
    def __init__(self, base_url: str, access_key: str, secret_key: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json",
        })
        # Disable certificate verification at both session and adapter level
        self.session.verify = False
        self.session.mount("https://", _PermissiveTLSAdapter())
        self.session.mount("http://", _PermissiveTLSAdapter())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path, **kw):
        kw.setdefault("verify", False)
        kw.setdefault("timeout", 30)
        try:
            r = self.session.get(f"{self.base_url}{path}", **kw)
            r.raise_for_status()
            return r
        except requests.RequestException as exc:
            print(f"[Nessus] GET {path} failed: {exc}")
            raise

    def _post(self, path, **kw):
        kw.setdefault("verify", False)
        kw.setdefault("timeout", 30)
        try:
            r = self.session.post(f"{self.base_url}{path}", **kw)
            r.raise_for_status()
            return r
        except requests.RequestException as exc:
            print(f"[Nessus] POST {path} failed: {exc}")
            raise

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------

    def get_basic_template_uuid(self) -> str:
        """Return the UUID of the 'basic' (Basic Network Scan) template."""
        r = self._get("/editor/scan/templates")
        templates = r.json().get("templates", [])
        for t in templates:
            if t.get("name") == "basic":
                return t["uuid"]
        raise ValueError("Could not find 'basic' scan template in Nessus.")

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def create_scan(self, target_ip: str, name: str = "AutoRemediate_Baseline_Scan") -> int:
        """Create a Basic Network Scan against target_ip, return scan_id."""
        uuid = self.get_basic_template_uuid()
        payload = {
            "uuid": uuid,
            "settings": {
                "name": name,
                "description": "Baseline vulnerability scan — AutoRemediate AI Capstone",
                "enabled": True,
                "text_targets": target_ip,
            },
        }
        r = self._post("/scans", json=payload)
        scan_id = r.json()["scan"]["id"]
        print(f"[Nessus] Scan created. ID={scan_id}  Target={target_ip}")
        return scan_id

    def launch_scan(self, scan_id: int) -> str:
        """Launch an existing scan, return scan_uuid."""
        r = self._post(f"/scans/{scan_id}/launch")
        scan_uuid = r.json().get("scan_uuid", "")
        print(f"[Nessus] Scan {scan_id} launched. UUID={scan_uuid}")
        return scan_uuid

    def get_scan_status(self, scan_id: int) -> str:
        """Return the current status string for a scan."""
        r = self._get(f"/scans/{scan_id}")
        return r.json()["info"]["status"]

    def wait_for_completion(self, scan_id: int, poll_seconds: int = 60) -> None:
        """Block (with periodic prints) until the scan status is 'completed'."""
        terminal_states = {"completed", "canceled", "aborted", "imported"}
        print(f"[Nessus] Polling scan {scan_id} every {poll_seconds}s …")
        while True:
            try:
                status = self.get_scan_status(scan_id)
                print(f"[Nessus] Scan {scan_id} status: {status}")
                if status in terminal_states:
                    if status != "completed":
                        raise RuntimeError(f"Scan ended with status '{status}', not 'completed'.")
                    break
            except Exception as exc:
                print(f"[Nessus] Poll error (will retry): {exc}")
            time.sleep(poll_seconds)

    # ------------------------------------------------------------------
    # Results retrieval
    # ------------------------------------------------------------------

    def get_hosts(self, scan_id: int) -> list:
        """Return list of host dicts from the completed scan."""
        r = self._get(f"/scans/{scan_id}")
        return r.json().get("hosts", [])

    def get_host_vulnerabilities(self, scan_id: int, host_id: int) -> list:
        """Return list of vulnerability dicts for a specific host."""
        r = self._get(f"/scans/{scan_id}/hosts/{host_id}")
        return r.json().get("vulnerabilities", [])

    def get_plugin_details(self, scan_id: int, host_id: int, plugin_id: int) -> dict:
        """Return full plugin details dict including CVE, exploit info, port, outputs."""
        r = self._get(f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}")
        return r.json()

    def get_full_results(self, scan_id: int) -> dict:
        """Collect all hosts + all plugin details into a single structured dict."""
        hosts = self.get_hosts(scan_id)
        result = {"scan_id": scan_id, "hosts": []}
        for host in hosts:
            host_id = host["host_id"]
            vulns = self.get_host_vulnerabilities(scan_id, host_id)
            detailed_vulns = []
            for v in vulns:
                if v.get("severity", 0) == 0:
                    continue  # skip informational
                try:
                    details = self.get_plugin_details(scan_id, host_id, v["plugin_id"])
                    v["_details"] = details
                except Exception as exc:
                    print(f"[Nessus] Could not fetch plugin {v['plugin_id']} details: {exc}")
                    v["_details"] = {}
                detailed_vulns.append(v)
            host["vulnerabilities"] = detailed_vulns
            result["hosts"].append(host)
            print(f"[Nessus] Host {host.get('hostname')} — {len(detailed_vulns)} findings fetched.")
        return result

    # ------------------------------------------------------------------
    # Export for documentation evidence
    # ------------------------------------------------------------------

    def export_csv(self, scan_id: int, out_path: str) -> str:
        """Export scan results as CSV; save to out_path. Returns out_path."""
        r = self._post(f"/scans/{scan_id}/export", json={"format": "csv"})
        file_id = r.json()["file"]
        print(f"[Nessus] Export requested. file_id={file_id} — waiting for ready …")
        while True:
            try:
                sr = self._get(f"/scans/{scan_id}/export/{file_id}/status")
                if sr.json().get("status") == "ready":
                    break
            except Exception as exc:
                print(f"[Nessus] Export status error: {exc}")
            time.sleep(10)
        dr = self._get(f"/scans/{scan_id}/export/{file_id}/download", stream=True)
        with open(out_path, "wb") as f:
            for chunk in dr.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[Nessus] CSV export saved → {out_path}")
        return out_path

    def save_json_results(self, results: dict, out_path: str) -> str:
        """Save the structured full_results dict to a JSON file."""
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[Nessus] JSON results saved → {out_path}")
        return out_path
