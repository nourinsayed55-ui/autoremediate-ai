"""Unit tests for parser.py — runs without a live scan."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from parser import parse_full_results, _extract_cve, _extract_port_protocol_service

# ── sample API response data ──────────────────────────────────────────────────

SAMPLE_RAW = {
    "scan_id": 1,
    "hosts": [
        {
            "host_id": 1,
            "hostname": "192.168.244.128",
            "vulnerabilities": [
                {
                    "plugin_id": 51988,
                    "plugin_name": "vsftpd Smiley Face Backdoor",
                    "plugin_family": "Backdoors",
                    "severity": 4,  # Critical
                    "vuln_index": 1,
                    "_details": {
                        "info": {
                            "pluginattributes": {
                                "synopsis": "The remote FTP server has a backdoor.",
                                "description": "vsftpd 2.3.4 contains a backdoor.",
                                "solution": "Remove vsftpd 2.3.4.",
                                "risk_information": {
                                    "cvss_base_score": "10.0",
                                    "risk_factor": "Critical"
                                },
                                "exploit_information": {
                                    "exploit_available": "true",
                                    "exploitability_ease": "Exploits are available"
                                },
                                "ref_information": {
                                    "ref": [
                                        {"name": "CVE", "values": ["CVE-2011-2523"]},
                                        {"name": "BID", "values": ["48539"]}
                                    ]
                                }
                            }
                        },
                        "outputs": [
                            {
                                "ports": {
                                    "21 / tcp / ftp": [
                                        {"plugin_output": "Port 21 is open."}
                                    ]
                                }
                            }
                        ]
                    }
                },
                {
                    # Informational — should be filtered out
                    "plugin_id": 10114,
                    "plugin_name": "ICMP Timestamp Request Remote Date Disclosure",
                    "plugin_family": "General",
                    "severity": 0,
                    "vuln_index": 2,
                    "_details": {}
                },
                {
                    "plugin_id": 46882,
                    "plugin_name": "UnrealIRCd Backdoor Detection",
                    "plugin_family": "Backdoors",
                    "severity": 3,  # High
                    "vuln_index": 3,
                    "_details": {
                        "info": {
                            "pluginattributes": {
                                "synopsis": "UnrealIRCd with backdoor.",
                                "description": "",
                                "solution": "Upgrade UnrealIRCd.",
                                "risk_information": {"cvss_base_score": "10.0"},
                                "exploit_information": {
                                    "exploit_available": "true",
                                    "exploitability_ease": "Exploits are available"
                                },
                                "ref_information": {
                                    "ref": [{"name": "CVE", "values": ["CVE-2010-2075"]}]
                                }
                            }
                        },
                        "outputs": [
                            {"ports": {"6667 / tcp / ircd": []}}
                        ]
                    }
                }
            ]
        }
    ]
}


# ── tests ─────────────────────────────────────────────────────────────────────

class TestParseFullResults:
    def setup_method(self):
        self.findings = parse_full_results(SAMPLE_RAW)

    def test_info_filtered_out(self):
        plugin_ids = [f["plugin_id"] for f in self.findings]
        assert 10114 not in plugin_ids, "Severity-0 (Info) findings must be filtered"

    def test_critical_parsed(self):
        critical = [f for f in self.findings if f["severity"] == "Critical"]
        assert len(critical) == 1
        assert critical[0]["plugin_id"] == 51988

    def test_high_parsed(self):
        high = [f for f in self.findings if f["severity"] == "High"]
        assert len(high) == 1
        assert high[0]["plugin_id"] == 46882

    def test_cve_extracted(self):
        vsftpd = next(f for f in self.findings if f["plugin_id"] == 51988)
        assert vsftpd["cve_reference"] == "CVE-2011-2523"

    def test_port_extracted(self):
        vsftpd = next(f for f in self.findings if f["plugin_id"] == 51988)
        assert vsftpd["port"] == 21
        assert vsftpd["protocol"] == "tcp"
        assert vsftpd["service"] == "ftp"

    def test_exploit_available(self):
        vsftpd = next(f for f in self.findings if f["plugin_id"] == 51988)
        assert vsftpd["exploit_available"] is True

    def test_host_assigned(self):
        for f in self.findings:
            assert f["host"] == "192.168.244.128"

    def test_unrealirc_port(self):
        irc = next(f for f in self.findings if f["plugin_id"] == 46882)
        assert irc["port"] == 6667
        assert irc["service"] == "ircd"


class TestExtractCve:
    def test_normal_cve(self):
        attrs = {"ref_information": {"ref": [{"name": "CVE", "values": ["CVE-2011-2523"]}]}}
        assert _extract_cve(attrs) == "CVE-2011-2523"

    def test_no_cve(self):
        attrs = {"ref_information": {"ref": [{"name": "BID", "values": ["48539"]}]}}
        assert _extract_cve(attrs) == ""

    def test_empty_attrs(self):
        assert _extract_cve({}) == ""


class TestExtractPortProtocol:
    def test_normal_format(self):
        details = {"outputs": [{"ports": {"21 / tcp / ftp": []}}]}
        port, proto, svc = _extract_port_protocol_service(details)
        assert port == 21
        assert proto == "tcp"
        assert svc == "ftp"

    def test_no_service(self):
        details = {"outputs": [{"ports": {"443 / tcp": []}}]}
        port, proto, svc = _extract_port_protocol_service(details)
        assert port == 443
        assert proto == "tcp"
        assert svc == ""

    def test_empty_outputs(self):
        port, proto, svc = _extract_port_protocol_service({})
        assert port == 0

    def test_udp_protocol(self):
        details = {"outputs": [{"ports": {"53 / udp / dns": []}}]}
        port, proto, svc = _extract_port_protocol_service(details)
        assert port == 53
        assert proto == "udp"
        assert svc == "dns"
