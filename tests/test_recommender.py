"""Unit tests for recommender.py — runs without a live target or scan."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from recommender import (
    score_finding, get_recommendation, prioritise_and_recommend,
    is_ssh_asset, assert_not_ssh_kill,
)

# ── fixtures ──────────────────────────────────────────────────────────────────

VSFTPD_BACKDOOR = {
    "plugin_id": 51988,
    "plugin_name": "vsftpd Smiley Face Backdoor",
    "severity": "Critical",
    "severity_num": 4,
    "port": 21,
    "protocol": "tcp",
    "service": "ftp",
    "cve_reference": "CVE-2011-2523",
    "exploit_available": True,
    "exploitability_ease": "Exploits are available",
    "synopsis": "The remote FTP server has a backdoor.",
    "solution": "Remove vsftpd 2.3.4.",
    "description": "",
    "cvss_base_score": "10.0",
    "host": "192.168.244.128",
}

UNREALIRC_BACKDOOR = {
    "plugin_id": 46882,
    "plugin_name": "UnrealIRCd Backdoor Detection",
    "severity": "Critical",
    "severity_num": 4,
    "port": 6667,
    "protocol": "tcp",
    "service": "ircd",
    "cve_reference": "CVE-2010-2075",
    "exploit_available": True,
    "exploitability_ease": "Exploits are available",
    "synopsis": "Remote code execution via IRC backdoor.",
    "solution": "Upgrade UnrealIRCd.",
    "description": "",
    "cvss_base_score": "10.0",
    "host": "192.168.244.128",
}

SSH_FINDING = {
    "plugin_id": 10881,
    "plugin_name": "SSH Protocol Version 1 Session Key Retrieval",
    "severity": "High",
    "severity_num": 3,
    "port": 22,
    "protocol": "tcp",
    "service": "ssh",
    "cve_reference": "CVE-2001-0361",
    "exploit_available": False,
    "exploitability_ease": "No known exploits are available",
    "synopsis": "An issue with SSHv1.",
    "solution": "Disable SSHv1.",
    "description": "",
    "cvss_base_score": "7.1",
    "host": "192.168.244.128",
}

MEDIUM_FINDING = {
    "plugin_id": 99999,
    "plugin_name": "Apache httpd Information Disclosure",
    "severity": "Medium",
    "severity_num": 2,
    "port": 80,
    "protocol": "tcp",
    "service": "http",
    "cve_reference": "",
    "exploit_available": False,
    "exploitability_ease": "",
    "synopsis": "",
    "solution": "",
    "description": "",
    "cvss_base_score": "5.0",
    "host": "192.168.244.128",
}


# ── scoring tests ─────────────────────────────────────────────────────────────

class TestScoring:
    def test_critical_base_score(self):
        f = {**VSFTPD_BACKDOOR, "exploit_available": False, "exploitability_ease": ""}
        score = score_finding(f)
        assert score >= 100, "Critical base must be ≥100"

    def test_backdoor_bonus(self):
        score = score_finding(VSFTPD_BACKDOOR)
        assert score >= 140, "Critical + backdoor + port bonus should be ≥140"

    def test_high_lower_than_critical(self):
        high = {**VSFTPD_BACKDOOR, "severity": "High"}
        assert score_finding(high) < score_finding(VSFTPD_BACKDOOR)

    def test_medium_lower_than_high(self):
        assert score_finding(MEDIUM_FINDING) < score_finding(SSH_FINDING)

    def test_port_bonus_applied(self):
        with_port = {**MEDIUM_FINDING, "port": 80}
        without_port = {**MEDIUM_FINDING, "port": 0}
        assert score_finding(with_port) > score_finding(without_port)


# ── SSH safety tests ──────────────────────────────────────────────────────────

class TestSSHSafety:
    def test_ssh_is_ssh_asset(self):
        assert is_ssh_asset(SSH_FINDING)

    def test_port_22_is_ssh_asset(self):
        assert is_ssh_asset({"port": 22, "service": "other"})

    def test_service_name_ssh(self):
        assert is_ssh_asset({"port": 0, "service": "ssh"})

    def test_non_ssh_not_asset(self):
        assert not is_ssh_asset(VSFTPD_BACKDOOR)

    def test_ssh_recommendation_is_not_stop(self):
        rec = get_recommendation(SSH_FINDING)
        preferred = rec["preferred"]
        assert preferred["action"] != "stop_service", (
            "Preferred action for SSH must not be stop_service"
        )
        assert "stop" not in preferred.get("command", "").lower(), (
            "SSH preferred command must not contain 'stop'"
        )

    def test_ssh_preferred_is_harden(self):
        rec = get_recommendation(SSH_FINDING)
        assert rec["preferred"]["action"] == "harden"

    def test_ssh_no_iptables_drop_22(self):
        rec = get_recommendation(SSH_FINDING)
        all_actions = [rec["preferred"]] + rec["alternatives"]
        for action in all_actions:
            cmd = action.get("command", "")
            assert "--dport 22" not in cmd, (
                f"No action should contain '--dport 22': {cmd}"
            )

    def test_assert_not_ssh_kill_raises_for_stop(self):
        with pytest.raises(ValueError, match="SAFETY"):
            assert_not_ssh_kill("sudo service ssh stop", SSH_FINDING)

    def test_assert_not_ssh_kill_raises_for_iptables(self):
        with pytest.raises(ValueError, match="SAFETY"):
            assert_not_ssh_kill("iptables -A INPUT -p tcp --dport 22 -j DROP", SSH_FINDING)

    def test_assert_not_ssh_kill_ok_for_harden(self):
        # Should not raise
        assert_not_ssh_kill("sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config", SSH_FINDING)

    def test_assert_not_ssh_kill_ok_for_non_ssh(self):
        # Should never raise for non-SSH finding
        assert_not_ssh_kill("sudo service vsftpd stop", VSFTPD_BACKDOOR)


# ── preference ladder tests ───────────────────────────────────────────────────

class TestPreferenceLadder:
    def test_vsftpd_preferred_iptables(self):
        # vsftpd has no /etc/init.d/ script on Metasploitable2; iptables is preferred
        rec = get_recommendation(VSFTPD_BACKDOOR)
        assert rec["preferred"]["rung"] == 4, (
            f"Expected rung 4 (iptables) for vsftpd (no init.d script), got {rec['preferred']['rung']}"
        )
        assert "iptables" in rec["preferred"]["command"]
        assert "21" in rec["preferred"]["command"]

    def test_unrealirc_preferred_iptables(self):
        # unrealircd has no /etc/init.d/ script on Metasploitable2; iptables is preferred
        rec = get_recommendation(UNREALIRC_BACKDOOR)
        assert rec["preferred"]["rung"] == 4, (
            f"Expected rung 4 (iptables) for unrealircd (no init.d script), got {rec['preferred']['rung']}"
        )

    def test_iptables_is_preferred_for_no_initd_ports(self):
        # Ports with PORT_TO_SERVICE[port] = None get iptables as preferred, not in alternatives
        rec = get_recommendation(VSFTPD_BACKDOOR)
        assert rec["preferred"]["action"] == "iptables_drop"

    def test_monitor_available(self):
        rec = get_recommendation(VSFTPD_BACKDOOR)
        all_rungs = [a["rung"] for a in rec["alternatives"]]
        assert 5 in all_rungs, "Monitor-only (rung 5) must always be in alternatives"


# ── prioritise_and_recommend ──────────────────────────────────────────────────

class TestPrioritisation:
    def test_sorted_critical_before_medium(self):
        findings = [MEDIUM_FINDING, VSFTPD_BACKDOOR]
        result = prioritise_and_recommend(findings)
        assert result[0]["severity"] == "Critical"
        assert result[-1]["severity"] == "Medium"

    def test_priority_score_attached(self):
        findings = prioritise_and_recommend([VSFTPD_BACKDOOR.copy()])
        assert "priority_score" in findings[0]

    def test_recommendation_attached(self):
        findings = prioritise_and_recommend([VSFTPD_BACKDOOR.copy()])
        assert "recommendation" in findings[0]

    def test_tie_break_lower_port_first(self):
        a = {**VSFTPD_BACKDOOR, "port": 21}
        b = {**VSFTPD_BACKDOOR, "port": 6667}
        result = prioritise_and_recommend([b, a])
        assert result[0]["port"] == 21
