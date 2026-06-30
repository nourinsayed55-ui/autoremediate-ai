"""
Tests for the deterministic system-suggested remediation options:

  1. TestGetSuggestions         — get_suggestions() returns correct items per finding type
  2. TestSSHSuggestionSafety    — SSH suggestions never contain stop/drop/block-22
  3. TestPreferredAlwaysFirst   — preferred option is always in preferred, not in suggested
  4. TestBuildMenuWithSuggested — build_menu() slots suggested items between alts and monitor
  5. TestCardAndInputWithSugg   — show_decision_card() renders suggested; input parser accepts them
  6. TestVerifyRouting          — every suggested action type routes to the correct verify() path
"""

import sys
import os
import re
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from recommender import get_suggestions, get_recommendation, is_ssh_asset
from engine import build_menu, show_decision_card, get_human_decision


# ---------------------------------------------------------------------------
# Shared finding factories
# ---------------------------------------------------------------------------

def _f(port, protocol="tcp", service="", plugin_name="Generic Vulnerability",
       severity="High", exploit=False, exploitability=""):
    return {
        "plugin_id": 99000 + port,
        "plugin_name": plugin_name,
        "severity": severity,
        "severity_num": 3,
        "port": port,
        "protocol": protocol,
        "service": service,
        "cve_reference": "CVE-2024-0001",
        "exploit_available": exploit,
        "exploitability_ease": exploitability,
        "synopsis": "",
        "solution": "",
        "description": "",
        "cvss_base_score": "7.5",
        "host": "192.168.244.128",
    }


SSH_FINDING   = _f(22, service="ssh",   plugin_name="SSH Protocol Weakness")
APACHE_FINDING = _f(80, service="http",  plugin_name="Apache httpd Information Disclosure")
XINETD_TELNET = _f(23, service="telnet", plugin_name="Telnet Plaintext Protocol")
XINETD_REXEC  = _f(512, service="rexec", plugin_name="rexec Service Detection")
XINETD_RLOGIN = _f(513, service="rlogin", plugin_name="rlogin Service Detection")
XINETD_RSH    = _f(514, service="rsh",   plugin_name="rsh Service Detection")
TOMCAT_AJP    = _f(8009, service="ajp", plugin_name="Tomcat AJP Connector Exposure")
POSTFIX_SSL   = _f(25, service="smtp",  plugin_name="SSLv2 Supported on SMTP Port")
POSTFIX_PLAIN = _f(25, service="smtp",  plugin_name="Postfix Banner Information Disclosure")
MYSQL_FINDING = _f(3306, service="mysql", plugin_name="MySQL Remote Root Login")
PGSQL_FINDING = _f(5432, service="postgresql", plugin_name="PostgreSQL Remote Access")
VSFTPD_FINDING = _f(21, service="ftp", plugin_name="vsftpd Smiley Face Backdoor",
                    exploit=True, exploitability="Exploits are available")
BINDSHELL     = _f(1524, service="", plugin_name="Metasploitable Ingreslock Backdoor")
UNREALIRCD    = _f(6667, service="ircd", plugin_name="UnrealIRCd Backdoor Detection")
RMI_FINDING   = _f(1099, service="java-rmi", plugin_name="Java RMI Remote Code Execution")
VNC_FINDING   = _f(5900, service="vnc", plugin_name="VNC Server Security Bypass")
XFS_FINDING   = _f(6000, service="X11", plugin_name="X Font Server Buffer Overflow")
UNKNOWN_PORT  = _f(9999, service="unknown", plugin_name="Generic Service Finding")


# ---------------------------------------------------------------------------
# 1. TestGetSuggestions — correct items per finding type
# ---------------------------------------------------------------------------

class TestGetSuggestions:

    # Required fields that every suggestion must carry
    _REQUIRED = {"action", "command", "description", "rationale", "feasible", "_is_suggested"}

    def _assert_fields(self, items):
        for item in items:
            for field in self._REQUIRED:
                assert field in item, f"Suggestion missing field '{field}': {item}"
            assert item["_is_suggested"] is True
            assert item["feasible"] is True
            assert item["action"] in {"harden", "stop_service", "iptables_drop", "monitor"}

    # -- SSH ------------------------------------------------------------------

    def test_ssh_returns_suggestions(self):
        sug = get_suggestions(SSH_FINDING)
        assert len(sug) >= 1

    def test_ssh_suggestions_have_required_fields(self):
        self._assert_fields(get_suggestions(SSH_FINDING))

    def test_ssh_suggestions_all_harden_type(self):
        for s in get_suggestions(SSH_FINDING):
            assert s["action"] == "harden", (
                f"SSH suggestion must never be stop/drop, got: {s['action']}"
            )

    def test_ssh_no_stop_in_command(self):
        for s in get_suggestions(SSH_FINDING):
            assert "stop" not in s["command"].lower(), (
                f"SSH suggestion command must not contain 'stop': {s['command']}"
            )

    def test_ssh_no_dport_22_in_command(self):
        for s in get_suggestions(SSH_FINDING):
            assert "--dport 22" not in s["command"], (
                f"SSH suggestion must not block port 22: {s['command']}"
            )

    def test_ssh_all_have_verify_cmd(self):
        for s in get_suggestions(SSH_FINDING):
            assert s.get("verify_cmd", ""), "SSH harden suggestion needs a verify_cmd"

    # -- Apache 80 ------------------------------------------------------------

    def test_apache_has_suggestion(self):
        sug = get_suggestions(APACHE_FINDING)
        assert len(sug) >= 1

    def test_apache_suggestion_describes_modules(self):
        sug = get_suggestions(APACHE_FINDING)
        descriptions = " ".join(s["description"].lower() for s in sug)
        assert "apache" in descriptions or "module" in descriptions or "status" in descriptions

    def test_apache_suggestion_has_verify_cmd(self):
        for s in get_suggestions(APACHE_FINDING):
            assert s.get("verify_cmd", "")

    def test_apache_fields(self):
        self._assert_fields(get_suggestions(APACHE_FINDING))

    # -- xinetd-managed services (telnet / rexec / rlogin / rsh) -------------

    def test_telnet_has_xinetd_suggestion(self):
        sug = get_suggestions(XINETD_TELNET)
        assert any("telnet" in s["description"].lower() or "xinetd" in s["command"]
                   for s in sug), f"Expected xinetd suggestion for port 23: {sug}"

    def test_rexec_has_xinetd_suggestion(self):
        sug = get_suggestions(XINETD_REXEC)
        assert any("rexec" in s["description"].lower() for s in sug)

    def test_rlogin_has_xinetd_suggestion(self):
        sug = get_suggestions(XINETD_RLOGIN)
        assert any("rlogin" in s["description"].lower() for s in sug)

    def test_rsh_has_xinetd_suggestion(self):
        sug = get_suggestions(XINETD_RSH)
        assert any("rsh" in s["description"].lower() for s in sug)

    def test_xinetd_suggestion_is_harden(self):
        for finding in [XINETD_TELNET, XINETD_REXEC, XINETD_RLOGIN, XINETD_RSH]:
            for s in get_suggestions(finding):
                assert s["action"] == "harden"

    def test_xinetd_suggestion_fields(self):
        for finding in [XINETD_TELNET, XINETD_REXEC, XINETD_RLOGIN, XINETD_RSH]:
            self._assert_fields(get_suggestions(finding))

    # -- Tomcat AJP (port 8009) -----------------------------------------------

    def test_tomcat_ajp_has_suggestion(self):
        sug = get_suggestions(TOMCAT_AJP)
        assert len(sug) >= 1

    def test_tomcat_ajp_describes_connector(self):
        sug = get_suggestions(TOMCAT_AJP)
        text = " ".join(s["description"].lower() for s in sug)
        assert "ajp" in text or "connector" in text or "8009" in text

    def test_tomcat_ajp_fields(self):
        self._assert_fields(get_suggestions(TOMCAT_AJP))

    # -- Postfix SSL finding --------------------------------------------------

    def test_postfix_ssl_has_tls_suggestion(self):
        sug = get_suggestions(POSTFIX_SSL)
        assert any("ssl" in s["description"].lower() or "tls" in s["description"].lower()
                   for s in sug), f"Expected TLS suggestion for SSLv2 finding on port 25: {sug}"

    def test_postfix_plain_no_ssl_suggestion(self):
        """A non-SSL postfix finding should NOT get the TLS config suggestion."""
        sug = get_suggestions(POSTFIX_PLAIN)
        for s in sug:
            assert "ssl" not in s["description"].lower() and "tls" not in s["description"].lower(), (
                f"Non-SSL postfix finding should not get SSL suggestion: {s['description']}"
            )

    def test_postfix_ssl_fields(self):
        self._assert_fields(get_suggestions(POSTFIX_SSL))

    # -- MySQL ----------------------------------------------------------------

    def test_mysql_has_suggestion(self):
        sug = get_suggestions(MYSQL_FINDING)
        assert len(sug) >= 1

    def test_mysql_suggestion_is_harden(self):
        for s in get_suggestions(MYSQL_FINDING):
            assert s["action"] == "harden"

    def test_mysql_suggestion_mentions_root_or_revoke(self):
        sug = get_suggestions(MYSQL_FINDING)
        text = " ".join(s["description"].lower() + " " + s["command"].lower() for s in sug)
        assert "root" in text or "revoke" in text or "remote" in text

    def test_mysql_fields(self):
        self._assert_fields(get_suggestions(MYSQL_FINDING))

    # -- PostgreSQL -----------------------------------------------------------

    def test_pgsql_has_suggestion(self):
        sug = get_suggestions(PGSQL_FINDING)
        assert len(sug) >= 1

    def test_pgsql_suggestion_is_harden(self):
        for s in get_suggestions(PGSQL_FINDING):
            assert s["action"] == "harden"

    def test_pgsql_suggestion_mentions_hba(self):
        sug = get_suggestions(PGSQL_FINDING)
        text = " ".join(s["description"].lower() + " " + s["command"].lower() for s in sug)
        assert "pg_hba" in text or "remote" in text

    def test_pgsql_fields(self):
        self._assert_fields(get_suggestions(PGSQL_FINDING))

    # -- Backdoor / no-init.d audit log suggestions ---------------------------

    def test_vsftpd_audit_log_suggestion(self):
        sug = get_suggestions(VSFTPD_FINDING)
        assert any("log" in s["description"].lower() or "audit" in s["description"].lower()
                   for s in sug), f"Port 21 should have audit LOG suggestion: {sug}"

    def test_bindshell_audit_log_suggestion(self):
        sug = get_suggestions(BINDSHELL)
        assert any("log" in s["description"].lower() or "audit" in s["description"].lower()
                   for s in sug)

    def test_unrealircd_audit_log_suggestion(self):
        sug = get_suggestions(UNREALIRCD)
        assert any("log" in s["description"].lower() or "audit" in s["description"].lower()
                   for s in sug)

    def test_rmi_audit_log_suggestion(self):
        sug = get_suggestions(RMI_FINDING)
        assert any("log" in s["description"].lower() or "audit" in s["description"].lower()
                   for s in sug)

    def test_audit_log_suggestions_are_harden_type(self):
        for finding in [VSFTPD_FINDING, BINDSHELL, UNREALIRCD, RMI_FINDING,
                        VNC_FINDING, XFS_FINDING]:
            for s in get_suggestions(finding):
                assert s["action"] == "harden", (
                    f"Audit LOG suggestion should use action='harden' (not block); got {s['action']}"
                )

    def test_audit_log_suggestions_have_verify_cmd(self):
        for finding in [VSFTPD_FINDING, BINDSHELL, UNREALIRCD]:
            for s in get_suggestions(finding):
                assert s.get("verify_cmd", ""), (
                    f"Audit LOG suggestion needs verify_cmd to confirm LOG rule was added"
                )

    # -- Determinism ----------------------------------------------------------

    def test_same_finding_same_suggestions(self):
        """Calling get_suggestions() twice on the same finding returns identical results."""
        sug1 = get_suggestions(APACHE_FINDING)
        sug2 = get_suggestions(APACHE_FINDING)
        assert sug1 == sug2

    def test_unknown_port_returns_empty(self):
        sug = get_suggestions(UNKNOWN_PORT)
        assert isinstance(sug, list)
        # Port 9999 matches no rule — should return empty (or contain nothing inappropriate)
        for s in sug:
            assert s.get("feasible") is True


# ---------------------------------------------------------------------------
# 2. TestSSHSuggestionSafety — exhaustive SSH safety checks
# ---------------------------------------------------------------------------

class TestSSHSuggestionSafety:
    """Belt-and-suspenders: verify that SSH suggestion constraints hold even
    for edge-case SSH findings (different plugin names, service labels)."""

    _SSH_FINDINGS = [
        SSH_FINDING,
        _f(22, service="sshd",    plugin_name="OpenSSH Vulnerability"),
        _f(22, service="openssh", plugin_name="SSH Key Weakness"),
        _f(0,  service="ssh",     plugin_name="SSH Service Finding"),   # service-only detection
    ]

    def test_no_stop_in_any_ssh_suggestion(self):
        for finding in self._SSH_FINDINGS:
            for s in get_suggestions(finding):
                cmd = s.get("command", "").lower()
                assert "stop" not in cmd, (
                    f"SSH suggestion must not contain 'stop': {cmd}"
                )

    def test_no_dport_22_in_any_ssh_suggestion(self):
        for finding in self._SSH_FINDINGS:
            for s in get_suggestions(finding):
                cmd = s.get("command", "")
                assert "--dport 22" not in cmd, (
                    f"SSH suggestion must not block port 22: {cmd}"
                )
                assert "-p 22" not in cmd

    def test_no_kill_in_any_ssh_suggestion(self):
        for finding in self._SSH_FINDINGS:
            for s in get_suggestions(finding):
                cmd = s.get("command", "").lower()
                assert "kill" not in cmd

    def test_ssh_suggestions_never_iptables_drop(self):
        for finding in self._SSH_FINDINGS:
            for s in get_suggestions(finding):
                assert s["action"] != "iptables_drop", (
                    "SSH suggestion action must never be iptables_drop"
                )

    def test_ssh_suggestions_never_stop_service(self):
        for finding in self._SSH_FINDINGS:
            for s in get_suggestions(finding):
                assert s["action"] != "stop_service"


# ---------------------------------------------------------------------------
# 3. TestPreferredAlwaysFirst
# ---------------------------------------------------------------------------

class TestPreferredAlwaysFirst:
    """preferred is always in recommendation['preferred'], never only in suggested."""

    def _rec(self, finding):
        return get_recommendation(finding)

    def test_ssh_preferred_is_harden(self):
        rec = self._rec(SSH_FINDING)
        assert rec["preferred"]["action"] == "harden"

    def test_ssh_preferred_not_in_suggested(self):
        rec = self._rec(SSH_FINDING)
        preferred_cmd = rec["preferred"]["command"]
        for s in rec.get("suggested", []):
            assert s["command"] != preferred_cmd, (
                "The preferred action must not be duplicated in suggested"
            )

    def test_apache_preferred_is_stop(self):
        rec = self._rec(APACHE_FINDING)
        assert rec["preferred"]["action"] == "stop_service"

    def test_apache_suggested_do_not_include_stop(self):
        rec = self._rec(APACHE_FINDING)
        for s in rec.get("suggested", []):
            assert s["action"] != "stop_service", (
                "Apache suggested options should not duplicate the preferred stop action"
            )

    def test_vsftpd_preferred_is_iptables_drop(self):
        rec = self._rec(VSFTPD_FINDING)
        assert rec["preferred"]["action"] == "iptables_drop"

    def test_bindshell_preferred_is_iptables_drop(self):
        rec = self._rec(BINDSHELL)
        assert rec["preferred"]["action"] == "iptables_drop"

    def test_suggested_key_present_in_all_recommendations(self):
        for finding in [SSH_FINDING, APACHE_FINDING, VSFTPD_FINDING,
                        BINDSHELL, MYSQL_FINDING, TOMCAT_AJP]:
            rec = self._rec(finding)
            assert "suggested" in rec, (
                f"recommendation must always have a 'suggested' key (port {finding['port']})"
            )

    def test_preferred_rung_always_lower_or_equal_to_suggested_rungs(self):
        """Preferred rung ≤ first suggested rung (lower rung number = higher preference)."""
        for finding in [SSH_FINDING, APACHE_FINDING, MYSQL_FINDING]:
            rec = self._rec(finding)
            preferred_rung = rec["preferred"]["rung"]
            for s in rec.get("suggested", []):
                assert preferred_rung <= s["rung"], (
                    f"Preferred rung {preferred_rung} must be ≤ suggestion rung {s['rung']}"
                )

    def test_alternatives_rung_always_below_preferred(self):
        """Alternatives start at a rung ≥ preferred rung (same preference level or lower)."""
        rec = self._rec(APACHE_FINDING)
        preferred_rung = rec["preferred"]["rung"]
        for alt in rec["alternatives"]:
            assert alt["rung"] >= preferred_rung


# ---------------------------------------------------------------------------
# 4. TestBuildMenuWithSuggested
# ---------------------------------------------------------------------------

class TestBuildMenuWithSuggested:
    """build_menu() slots suggested items between alt_slots and monitor."""

    def _menu(self, finding):
        finding = {**finding, "priority_score": 140}
        rec = get_recommendation(finding)
        finding["recommendation"] = rec
        return build_menu(finding)

    def test_ssh_has_suggested_slots(self):
        menu = self._menu(SSH_FINDING)
        assert len(menu["suggested_slots"]) >= 1

    def test_apache_has_suggested_slots(self):
        menu = self._menu(APACHE_FINDING)
        assert len(menu["suggested_slots"]) >= 1

    def test_suggested_slots_come_after_alt_slots(self):
        menu = self._menu(APACHE_FINDING)
        if menu["alt_slots"] and menu["suggested_slots"]:
            last_alt_key = int(menu["alt_slots"][-1][0])
            first_sug_key = int(menu["suggested_slots"][0][0])
            assert first_sug_key == last_alt_key + 1, (
                f"Suggested slots must immediately follow alt_slots: "
                f"last alt={last_alt_key}, first sug={first_sug_key}"
            )

    def test_monitor_key_after_all_suggested(self):
        menu = self._menu(APACHE_FINDING)
        if menu["suggested_slots"]:
            last_sug_key = int(menu["suggested_slots"][-1][0])
            assert int(menu["monitor_key"]) == last_sug_key + 1

    def test_suggested_slot_keys_in_valid_keys(self):
        for finding in [SSH_FINDING, APACHE_FINDING, BINDSHELL, MYSQL_FINDING]:
            menu = self._menu(finding)
            for key, _ in menu["suggested_slots"]:
                assert key in menu["valid_keys"], (
                    f"Suggested slot key '{key}' missing from valid_keys"
                )

    def test_no_duplicate_valid_keys_with_suggestions(self):
        for finding in [SSH_FINDING, APACHE_FINDING, BINDSHELL,
                        MYSQL_FINDING, PGSQL_FINDING, TOMCAT_AJP]:
            menu = self._menu(finding)
            assert len(menu["valid_keys"]) == len(set(menu["valid_keys"])), (
                f"Duplicate valid_keys for port {finding['port']}: {menu['valid_keys']}"
            )

    def test_suggested_slots_carry_is_suggested_marker(self):
        menu = self._menu(APACHE_FINDING)
        for _, sug in menu["suggested_slots"]:
            assert sug.get("_is_suggested") is True

    def test_suggested_slots_all_harden_action(self):
        for finding in [SSH_FINDING, APACHE_FINDING, BINDSHELL, MYSQL_FINDING,
                        PGSQL_FINDING, TOMCAT_AJP, XINETD_TELNET]:
            menu = self._menu(finding)
            for _, sug in menu["suggested_slots"]:
                assert sug["action"] == "harden", (
                    f"All suggested slots must use action='harden' for correct verify() routing; "
                    f"got '{sug['action']}' for port {finding['port']}"
                )

    def test_finding_without_suggestions_has_empty_slots(self):
        """A port with no matching suggestion rule → suggested_slots = [] → monitor_key unchanged."""
        menu = self._menu(UNKNOWN_PORT)
        assert menu["suggested_slots"] == []
        # monitor_key must still be consistent (no dead slots)
        assert int(menu["monitor_key"]) == len(menu["alt_slots"]) + 2


# ---------------------------------------------------------------------------
# 5. TestCardAndInputWithSuggested
# ---------------------------------------------------------------------------

CFG_ON = {"automation_rules": {"require_manual_approval": True}}


def _real_finding(base_finding):
    """Attach a real recommendation (including suggested) to a copy of a finding."""
    f = {**base_finding, "priority_score": 140}
    f["recommendation"] = get_recommendation(f)
    return f


class TestCardAndInputWithSuggested:

    def _capture(self, finding):
        lines = []
        with patch("builtins.print",
                   side_effect=lambda *a, **kw: lines.append(str(a[0]) if a else "")):
            show_decision_card(finding, idx=1, total=5)
        return "\n".join(lines)

    def _bracket_keys(self, output):
        return set(re.findall(r"\[([A-Z0-9]+)\]", output))

    def _decide(self, finding, inputs):
        with patch("builtins.input", side_effect=inputs):
            return get_human_decision(finding, CFG_ON)

    # -- card rendering -------------------------------------------------------

    def test_card_shows_additional_options_header(self):
        finding = _real_finding(APACHE_FINDING)
        output = self._capture(finding)
        assert "ADDITIONAL SYSTEM-SUGGESTED OPTIONS" in output

    def test_card_no_suggested_section_when_no_suggestions(self):
        finding = _real_finding(UNKNOWN_PORT)
        # Only show suggested section if there are suggestions
        menu = build_menu(finding)
        output = self._capture(finding)
        if not menu["suggested_slots"]:
            assert "ADDITIONAL SYSTEM-SUGGESTED OPTIONS" not in output

    def test_card_suggested_keys_all_printed(self):
        finding = _real_finding(APACHE_FINDING)
        menu = build_menu(finding)
        output = self._capture(finding)
        for key, _ in menu["suggested_slots"]:
            assert f"[{key}]" in output, (
                f"Suggested slot key [{key}] not printed on card"
            )

    def test_card_rationale_printed_for_suggested(self):
        finding = _real_finding(APACHE_FINDING)
        output = self._capture(finding)
        assert "Rationale:" in output

    def test_card_keys_equal_valid_keys_with_suggestions(self):
        """Card bracket tokens == valid_keys for real findings with suggestions."""
        for finding_base in [SSH_FINDING, APACHE_FINDING, BINDSHELL,
                             MYSQL_FINDING, PGSQL_FINDING]:
            finding = _real_finding(finding_base)
            card_keys = self._bracket_keys(self._capture(finding))
            valid_keys = set(build_menu(finding)["valid_keys"])
            assert card_keys == valid_keys, (
                f"Card/input mismatch for port {finding['port']}: "
                f"card={sorted(card_keys)} valid={sorted(valid_keys)}"
            )

    def test_card_no_dead_numbers_with_suggestions(self):
        """No [N] appears in card that isn't in valid_keys."""
        for finding_base in [SSH_FINDING, APACHE_FINDING, BINDSHELL, TOMCAT_AJP]:
            finding = _real_finding(finding_base)
            menu = build_menu(finding)
            output = self._capture(finding)
            highest = int(menu["monitor_key"])
            for n in range(highest + 1, highest + 5):
                assert f"[{n}]" not in output, (
                    f"Dead slot [{n}] printed for port {finding['port']} — not in valid_keys"
                )

    # -- input parser ---------------------------------------------------------

    def test_suggested_slot_key_accepted(self):
        """Typing the suggested slot key returns the correct action."""
        finding = _real_finding(APACHE_FINDING)
        menu = build_menu(finding)
        assert menu["suggested_slots"], "Apache finding should have suggested slots"
        sug_key, sug_action = menu["suggested_slots"][0]
        result = self._decide(finding, [sug_key])
        assert result["choice"] == sug_key
        assert result["action"] == sug_action

    def test_suggested_slot_returns_harden_action(self):
        finding = _real_finding(APACHE_FINDING)
        menu = build_menu(finding)
        sug_key, _ = menu["suggested_slots"][0]
        result = self._decide(finding, [sug_key])
        assert result["action"]["action"] == "harden"

    def test_suggested_reason_mentions_system_suggested(self):
        finding = _real_finding(APACHE_FINDING)
        menu = build_menu(finding)
        sug_key, _ = menu["suggested_slots"][0]
        result = self._decide(finding, [sug_key])
        assert "system-suggested" in result["reason"]

    def test_ssh_suggested_slot_accepted(self):
        finding = _real_finding(SSH_FINDING)
        menu = build_menu(finding)
        assert menu["suggested_slots"]
        sug_key, _ = menu["suggested_slots"][0]
        result = self._decide(finding, [sug_key])
        assert result["choice"] == sug_key
        assert result["action"]["action"] == "harden"

    def test_monitor_still_works_with_suggestions(self):
        finding = _real_finding(APACHE_FINDING)
        menu = build_menu(finding)
        result = self._decide(finding, [menu["monitor_key"]])
        assert result["action"]["action"] == "monitor"

    def test_suggested_lowercase_accepted(self):
        """Slot keys are digits — digits are invariant under .upper(), so lowercase is fine."""
        finding = _real_finding(APACHE_FINDING)
        menu = build_menu(finding)
        sug_key, _ = menu["suggested_slots"][0]
        # digit keys are the same in upper/lower; test that strip() still works
        result = self._decide(finding, [f"  {sug_key}  "])
        assert result["choice"] == sug_key

    def test_dead_slot_above_monitor_still_invalid(self):
        finding = _real_finding(APACHE_FINDING)
        menu = build_menu(finding)
        dead = str(int(menu["monitor_key"]) + 1)
        result = self._decide(finding, [dead, "Q"])
        assert result["choice"] == "Q"

    def test_invalid_reprompts_with_suggestions(self):
        finding = _real_finding(BINDSHELL)
        result = self._decide(finding, ["X", "99", "!", "A"])
        assert result["choice"] == "A"


# ---------------------------------------------------------------------------
# 6. TestVerifyRouting — verify() picks the right path for suggested actions
# ---------------------------------------------------------------------------

class TestVerifyRouting:
    """
    All suggested actions use action='harden', so verify() must route to
    the verify_cmd path (not port-unreachable external probe).
    We check this by inspecting the action dicts themselves, and by verifying
    that the verify() method calls _run_remote for harden actions.
    """

    def test_all_suggested_have_harden_action(self):
        """Any suggested item that reaches verify() must use action='harden'."""
        for finding_base in [SSH_FINDING, APACHE_FINDING, BINDSHELL,
                             MYSQL_FINDING, PGSQL_FINDING, TOMCAT_AJP,
                             XINETD_TELNET, VSFTPD_FINDING, UNREALIRCD]:
            rec = get_recommendation({**finding_base, "priority_score": 140})
            for s in rec.get("suggested", []):
                assert s["action"] == "harden", (
                    f"Suggested action for port {finding_base['port']} "
                    f"must be 'harden'; got '{s['action']}'"
                )

    def test_all_suggested_have_verify_cmd(self):
        """Every harden suggestion needs a verify_cmd so verify() has a check to run."""
        for finding_base in [SSH_FINDING, APACHE_FINDING, BINDSHELL,
                             MYSQL_FINDING, PGSQL_FINDING, TOMCAT_AJP,
                             XINETD_TELNET, VSFTPD_FINDING, UNREALIRCD]:
            rec = get_recommendation({**finding_base, "priority_score": 140})
            for s in rec.get("suggested", []):
                assert s.get("verify_cmd", ""), (
                    f"Suggested harden action for port {finding_base['port']} "
                    f"must have a non-empty verify_cmd: {s['description']}"
                )

    def test_verify_routes_harden_to_verify_cmd(self):
        """verify() with action_type='harden' calls _run_remote for verify_cmd."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
        from remediator import Remediator
        r = Remediator("192.168.244.128", "msfadmin", "msfadmin")

        # Simulate verify_cmd succeeding (exit_code 0) → verify returns True
        with patch.object(r, "_run_remote", return_value=("found", "", 0)) as mock_run:
            result = r.verify(
                service_name="apache2",
                port=80,
                action_type="harden",
                action={"verify_cmd": "sudo apache2ctl -M | grep -c 'status_module'"},
            )
        assert result is True
        mock_run.assert_called_once()  # confirm it ran the verify_cmd

    def test_verify_routes_harden_no_verify_cmd_returns_true(self):
        """If a harden action has no verify_cmd, verify() accepts it (trusts execute())."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
        from remediator import Remediator
        r = Remediator("192.168.244.128", "msfadmin", "msfadmin")
        result = r.verify(
            service_name="apache2",
            port=80,
            action_type="harden",
            action={"verify_cmd": ""},  # empty → no SSH call
        )
        assert result is True

    def test_verify_harden_failing_cmd_returns_false(self):
        """If verify_cmd exits non-zero, verify() returns False (config change not confirmed)."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
        from remediator import Remediator
        r = Remediator("192.168.244.128", "msfadmin", "msfadmin")
        with patch.object(r, "_run_remote", return_value=("", "", 1)):
            result = r.verify(
                service_name="apache2",
                port=80,
                action_type="harden",
                action={"verify_cmd": "sudo grep -q 'disabled' /etc/apache2/mods-enabled/status.load"},
            )
        assert result is False

    def test_monitor_action_skipped_not_failed(self):
        """Monitor-only suggested action → execute() returns Skipped, never Failed."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
        from remediator import Remediator
        r = Remediator("192.168.244.128", "msfadmin", "msfadmin")
        monitor_action = {
            "rung": 5, "action": "monitor", "command": "",
            "description": "Monitor only", "rationale": "Safe fallback", "feasible": True,
        }
        result = r.execute(SSH_FINDING, monitor_action)
        assert result["status"] == "Skipped"
