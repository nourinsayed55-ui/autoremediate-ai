"""
Tests for engine.py decision-menu: build_menu(), show_decision_card(),
and get_human_decision().

All option numbers printed on the card are exactly the keys accepted by
get_human_decision() — verified by deriving both from build_menu().
"""

import sys
import os
import io
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from engine import build_menu, show_decision_card, get_human_decision


# ---------------------------------------------------------------------------
# Fixtures — synthetic findings for common recommendation shapes
# ---------------------------------------------------------------------------

def _finding(preferred, alternatives, extra=None):
    """Build a minimal finding dict for menu tests."""
    f = {
        "plugin_name": "Test Plugin",
        "severity": "High",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "cve_reference": "CVE-2024-0001",
        "cvss_base_score": "9.8",
        "priority_score": 140,
        "host": "192.168.244.128",
        "recommendation": {
            "preferred": preferred,
            "alternatives": alternatives,
        },
    }
    if extra:
        f.update(extra)
    return f


def _action(rung, action_type, description="desc", command="cmd"):
    return {
        "rung": rung,
        "action": action_type,
        "command": command,
        "description": description,
        "rationale": f"Rung {rung} rationale",
        "feasible": True,
    }


# Preferred stop + one iptables alternative + monitor
FINDING_STOP_IPTABLES = _finding(
    preferred=_action(2, "stop_service", "Stop apache2", "sudo /etc/init.d/apache2 stop"),
    alternatives=[
        _action(4, "iptables_drop", "iptables DROP 80/tcp", "sudo iptables -I INPUT -p tcp --dport 80 -j DROP"),
        _action(5, "monitor", "Monitor only", ""),
    ],
)

# Preferred iptables (no init.d) + monitor only
FINDING_IPTABLES_ONLY = _finding(
    preferred=_action(4, "iptables_drop", "iptables DROP 6667/tcp", "sudo iptables -I INPUT -p tcp --dport 6667 -j DROP"),
    alternatives=[
        _action(5, "monitor", "Monitor only", ""),
    ],
    extra={"port": 6667},
)

# Preferred harden + monitor only (SSH pattern)
FINDING_HARDEN = _finding(
    preferred={
        "rung": 3, "action": "harden",
        "command": "sudo sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo /etc/init.d/ssh restart",
        "verify_cmd": "sudo grep '^PermitRootLogin no' /etc/ssh/sshd_config",
        "description": "Harden SSH: disable root login",
        "rationale": "Rung 3 — SSH must stay up.",
        "feasible": True,
    },
    alternatives=[
        _action(5, "monitor", "Monitor only", ""),
    ],
    extra={"port": 22, "service": "ssh"},
)

# Preferred stop + 3 alternatives (stop, iptables, harden) + monitor — tests 3-alt cap
FINDING_THREE_ALTS = _finding(
    preferred=_action(2, "stop_service", "Stop service", "sudo /etc/init.d/samba stop"),
    alternatives=[
        _action(3, "harden", "Harden samba", "sudo bash -c '...'"),
        _action(4, "iptables_drop", "iptables DROP 139/tcp", "sudo iptables -I INPUT -p tcp --dport 139 -j DROP"),
        _action(5, "monitor", "Monitor only", ""),
    ],
    extra={"port": 139},
)


# ---------------------------------------------------------------------------
# TestBuildMenu
# ---------------------------------------------------------------------------

class TestBuildMenu:
    def test_stop_iptables_structure(self):
        menu = build_menu(FINDING_STOP_IPTABLES)
        assert menu["preferred"]["action"] == "stop_service"
        assert len(menu["alt_slots"]) == 1
        key, alt = menu["alt_slots"][0]
        assert key == "2"
        assert alt["action"] == "iptables_drop"
        assert menu["monitor_key"] == "3"
        assert menu["monitor"]["action"] == "monitor"

    def test_iptables_only_structure(self):
        menu = build_menu(FINDING_IPTABLES_ONLY)
        assert menu["preferred"]["action"] == "iptables_drop"
        assert menu["alt_slots"] == []
        assert menu["monitor_key"] == "2"
        assert menu["monitor"]["rung"] == 5

    def test_harden_structure(self):
        menu = build_menu(FINDING_HARDEN)
        assert menu["preferred"]["action"] == "harden"
        assert menu["alt_slots"] == []
        assert menu["monitor_key"] == "2"

    def test_three_alts_capped_at_three(self):
        """Alternatives list ≤ 3 numbered slots (monitor excluded)."""
        menu = build_menu(FINDING_THREE_ALTS)
        # non-monitor alternatives: harden(3) and iptables(4)
        assert len(menu["alt_slots"]) == 2
        assert menu["alt_slots"][0] == ("2", FINDING_THREE_ALTS["recommendation"]["alternatives"][0])
        assert menu["alt_slots"][1] == ("3", FINDING_THREE_ALTS["recommendation"]["alternatives"][1])
        assert menu["monitor_key"] == "4"

    def test_valid_keys_always_include_A_R_Q(self):
        for finding in [FINDING_STOP_IPTABLES, FINDING_IPTABLES_ONLY, FINDING_HARDEN]:
            menu = build_menu(finding)
            assert "A" in menu["valid_keys"]
            assert "R" in menu["valid_keys"]
            assert "Q" in menu["valid_keys"]

    def test_valid_keys_include_all_alt_slots_and_monitor(self):
        menu = build_menu(FINDING_STOP_IPTABLES)
        assert "2" in menu["valid_keys"]   # iptables alt
        assert "3" in menu["valid_keys"]   # monitor

    def test_valid_keys_ordered(self):
        menu = build_menu(FINDING_THREE_ALTS)
        assert menu["valid_keys"] == ["A", "2", "3", "4", "R", "Q"]

    def test_monitor_fallback_synthesized_when_absent(self):
        """If alternatives has no rung-5/monitor entry, build_menu synthesizes one."""
        finding = _finding(
            preferred=_action(4, "iptables_drop"),
            alternatives=[],  # no monitor entry at all
        )
        menu = build_menu(finding)
        assert menu["monitor"]["action"] == "monitor"
        assert menu["monitor"]["rung"] == 5

    def test_monitor_key_is_not_in_alt_slots(self):
        for finding in [FINDING_STOP_IPTABLES, FINDING_IPTABLES_ONLY,
                        FINDING_HARDEN, FINDING_THREE_ALTS]:
            menu = build_menu(finding)
            alt_keys = [k for k, _ in menu["alt_slots"]]
            assert menu["monitor_key"] not in alt_keys

    def test_no_duplicate_valid_keys(self):
        for finding in [FINDING_STOP_IPTABLES, FINDING_IPTABLES_ONLY,
                        FINDING_HARDEN, FINDING_THREE_ALTS]:
            menu = build_menu(finding)
            assert len(menu["valid_keys"]) == len(set(menu["valid_keys"]))


# ---------------------------------------------------------------------------
# TestShowDecisionCard
# ---------------------------------------------------------------------------

class TestShowDecisionCard:
    def _capture(self, finding):
        with patch("builtins.print") as mock_print:
            show_decision_card(finding, idx=1, total=5)
            lines = "\n".join(str(call.args[0]) for call in mock_print.call_args_list
                              if call.args)
        return lines

    def test_all_valid_keys_printed(self):
        for finding in [FINDING_STOP_IPTABLES, FINDING_IPTABLES_ONLY,
                        FINDING_HARDEN, FINDING_THREE_ALTS]:
            menu = build_menu(finding)
            output = self._capture(finding)
            for key in menu["valid_keys"]:
                assert key in output, f"Key '{key}' missing from card output"

    def test_no_dead_extra_slot(self):
        """The card must not print a slot number that build_menu doesn't accept."""
        for finding in [FINDING_STOP_IPTABLES, FINDING_IPTABLES_ONLY,
                        FINDING_HARDEN, FINDING_THREE_ALTS]:
            menu = build_menu(finding)
            output = self._capture(finding)
            all_numeric_keys = {k for k in menu["valid_keys"] if k.isdigit()}
            # The highest numeric key in the card should match highest in build_menu
            # No number higher than monitor_key should appear in a [N] slot
            highest = int(menu["monitor_key"])
            for n in range(highest + 1, highest + 5):
                assert f"[{n}]" not in output, \
                    f"Dead slot [{n}] printed on card but not accepted by get_human_decision"

    def test_preferred_action_shown_as_A(self):
        output = self._capture(FINDING_STOP_IPTABLES)
        assert "[A]" in output
        assert "RECOMMENDED" in output

    def test_monitor_key_is_monitor_only(self):
        menu = build_menu(FINDING_STOP_IPTABLES)
        output = self._capture(FINDING_STOP_IPTABLES)
        assert f"[{menu['monitor_key']}] MONITOR ONLY" in output

    def test_accepted_line_shows_valid_keys(self):
        menu = build_menu(FINDING_STOP_IPTABLES)
        output = self._capture(FINDING_STOP_IPTABLES)
        for key in menu["valid_keys"]:
            assert key in output


# ---------------------------------------------------------------------------
# TestGetHumanDecision
# ---------------------------------------------------------------------------

CFG_APPROVAL_ON = {"automation_rules": {"require_manual_approval": True}}
CFG_APPROVAL_OFF = {"automation_rules": {"require_manual_approval": False}}


class TestGetHumanDecision:
    """All inputs verified case-insensitively, after strip()."""

    def _decide(self, finding, inputs):
        with patch("builtins.input", side_effect=inputs):
            return get_human_decision(finding, CFG_APPROVAL_ON)

    # -- A / a / " A " -------------------------------------------------------

    def test_A_uppercase(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["A"])
        assert result["choice"] == "A"
        assert result["action"]["action"] == "stop_service"

    def test_a_lowercase(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["a"])
        assert result["choice"] == "A"

    def test_A_with_whitespace(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["  A  "])
        assert result["choice"] == "A"

    # -- numbered alt slots --------------------------------------------------

    def test_slot_2_iptables(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["2"])
        assert result["choice"] == "2"
        assert result["action"]["action"] == "iptables_drop"

    def test_slot_2_three_alts_is_harden(self):
        result = self._decide(FINDING_THREE_ALTS, ["2"])
        assert result["action"]["action"] == "harden"

    def test_slot_3_three_alts_is_iptables(self):
        result = self._decide(FINDING_THREE_ALTS, ["3"])
        assert result["action"]["action"] == "iptables_drop"

    def test_slot_returns_correct_action_dict(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["2"])
        assert result["action"]["rung"] == 4

    # -- monitor slot --------------------------------------------------------

    def test_monitor_slot_stop_iptables(self):
        """FINDING_STOP_IPTABLES has 1 alt → monitor_key='3'."""
        result = self._decide(FINDING_STOP_IPTABLES, ["3"])
        assert result["action"]["action"] == "monitor"

    def test_monitor_slot_iptables_only(self):
        """FINDING_IPTABLES_ONLY has 0 alts → monitor_key='2'."""
        result = self._decide(FINDING_IPTABLES_ONLY, ["2"])
        assert result["action"]["action"] == "monitor"

    def test_monitor_slot_three_alts(self):
        """FINDING_THREE_ALTS has 2 alts → monitor_key='4'."""
        result = self._decide(FINDING_THREE_ALTS, ["4"])
        assert result["action"]["action"] == "monitor"

    # -- R reject ------------------------------------------------------------

    def test_R_uppercase(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["R", "too risky"])
        assert result["choice"] == "R"
        assert result["action"] is None
        assert result["reason"] == "too risky"

    def test_r_lowercase(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["r", "reason here"])
        assert result["choice"] == "R"

    def test_R_empty_reason_defaults(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["R", ""])
        assert result["reason"] == "no reason given"

    # -- Q quit --------------------------------------------------------------

    def test_Q_uppercase(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["Q"])
        assert result["choice"] == "Q"
        assert result["action"] is None

    def test_q_lowercase(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["q"])
        assert result["choice"] == "Q"

    # -- invalid reprompt ----------------------------------------------------

    def test_invalid_then_valid(self):
        """Invalid input must reprompt; does not crash or exit."""
        result = self._decide(FINDING_STOP_IPTABLES, ["X", "9", "!", "A"])
        assert result["choice"] == "A"

    def test_dead_slot_is_invalid(self):
        """A number one above monitor_key is never accepted."""
        menu = build_menu(FINDING_STOP_IPTABLES)
        dead = str(int(menu["monitor_key"]) + 1)  # "4" when monitor_key="3"
        result = self._decide(FINDING_STOP_IPTABLES, [dead, "A"])
        assert result["choice"] == "A"

    def test_empty_input_reprompts(self):
        result = self._decide(FINDING_STOP_IPTABLES, ["", "   ", "A"])
        assert result["choice"] == "A"

    def test_old_hardcoded_4_rejected_for_iptables_only(self):
        """
        The original bug: card showed [2] monitor but parser had monitor_slot='3'.
        Regression: for FINDING_IPTABLES_ONLY monitor_key='2', so '4' must be
        invalid and reprompted.
        """
        result = self._decide(FINDING_IPTABLES_ONLY, ["4", "Q"])
        assert result["choice"] == "Q"

    # -- require_manual_approval=False gate ----------------------------------

    def test_approval_off_yes_proceeds(self):
        with patch("builtins.input", side_effect=["YES", "A"]):
            with patch("builtins.print"):
                result = get_human_decision(FINDING_STOP_IPTABLES, CFG_APPROVAL_OFF)
        assert result["choice"] == "A"

    def test_approval_off_no_skips(self):
        with patch("builtins.input", side_effect=["NO"]):
            with patch("builtins.print"):
                result = get_human_decision(FINDING_STOP_IPTABLES, CFG_APPROVAL_OFF)
        assert result["choice"] == "R"
        assert "not confirmed" in result["reason"]

    def test_approval_off_empty_skips(self):
        with patch("builtins.input", side_effect=[""]):
            with patch("builtins.print"):
                result = get_human_decision(FINDING_STOP_IPTABLES, CFG_APPROVAL_OFF)
        assert result["choice"] == "R"


# ---------------------------------------------------------------------------
# Integration: menu card keys == accepted input keys
# ---------------------------------------------------------------------------

class TestMenuCardAndInputConsistency:
    """
    For every test finding, verify that every key printed by show_decision_card()
    is accepted by get_human_decision(), and that no extra keys exist in either
    direction.
    """

    def _extract_bracket_keys(self, output: str) -> set:
        """Extract all [X] tokens from card output (single char or digit groups)."""
        import re
        return set(re.findall(r"\[([A-Z0-9]+)\]", output))

    def _valid_input_keys(self, finding) -> set:
        return set(build_menu(finding)["valid_keys"])

    def _card_keys(self, finding) -> set:
        printed_lines = []
        with patch("builtins.print", side_effect=lambda *a, **kw: printed_lines.append(str(a[0]) if a else "")):
            show_decision_card(finding, 1, 1)
        output = "\n".join(printed_lines)
        return self._extract_bracket_keys(output)

    def test_stop_iptables_consistency(self):
        card = self._card_keys(FINDING_STOP_IPTABLES)
        valid = self._valid_input_keys(FINDING_STOP_IPTABLES)
        assert card == valid

    def test_iptables_only_consistency(self):
        card = self._card_keys(FINDING_IPTABLES_ONLY)
        valid = self._valid_input_keys(FINDING_IPTABLES_ONLY)
        assert card == valid

    def test_harden_consistency(self):
        card = self._card_keys(FINDING_HARDEN)
        valid = self._valid_input_keys(FINDING_HARDEN)
        assert card == valid

    def test_three_alts_consistency(self):
        card = self._card_keys(FINDING_THREE_ALTS)
        valid = self._valid_input_keys(FINDING_THREE_ALTS)
        assert card == valid
