"""Unit tests for remediator.py — runs without a live target.

Tests cover:
  - Command building logic
  - SSH safety guard (assert_not_ssh_kill)
  - verify() logic via mocking
  - dry_run mode
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from unittest.mock import patch, MagicMock
from remediator import Remediator
from recommender import assert_not_ssh_kill

# ── fixtures ──────────────────────────────────────────────────────────────────

VSFTPD_FINDING = {
    "plugin_id": 51988,
    "plugin_name": "vsftpd Smiley Face Backdoor",
    "severity": "Critical",
    "port": 21,
    "protocol": "tcp",
    "service": "ftp",
    "cve_reference": "CVE-2011-2523",
    "host": "192.168.244.128",
}

STOP_ACTION = {
    "rung": 2,
    "action": "stop_service",
    "command": "sudo service vsftpd stop",
    "description": "Stop vsftpd",
    "rationale": "Rung 2 — backdoored service",
    "feasible": True,
}

MONITOR_ACTION = {
    "rung": 5,
    "action": "monitor",
    "command": "",
    "description": "Monitor only",
    "rationale": "Rung 5 — safe fallback",
    "feasible": True,
}

SSH_FINDING = {
    "plugin_id": 10881,
    "plugin_name": "SSH Protocol Issue",
    "severity": "High",
    "port": 22,
    "protocol": "tcp",
    "service": "ssh",
    "cve_reference": "",
    "host": "192.168.244.128",
}

SSH_STOP_ACTION = {
    "rung": 2,
    "action": "stop_service",
    "command": "sudo service ssh stop",
    "description": "Stop SSH",
    "rationale": "Should never run",
    "feasible": True,
}


# ── dry-run tests ─────────────────────────────────────────────────────────────

class TestDryRun:
    def get_remediator(self):
        return Remediator("192.168.244.128", "msfadmin", "msfadmin", dry_run=True)

    def test_dry_run_returns_success(self):
        r = self.get_remediator()
        result = r.execute(VSFTPD_FINDING, STOP_ACTION)
        assert result["status"] == "Success"

    def test_dry_run_no_ssh_connect(self):
        r = self.get_remediator()
        with patch.object(r, "_connect") as mock_connect:
            r.execute(VSFTPD_FINDING, STOP_ACTION)
            mock_connect.assert_not_called()

    def test_dry_run_records_command(self):
        r = self.get_remediator()
        result = r.execute(VSFTPD_FINDING, STOP_ACTION)
        assert "vsftpd" in result["command"]

    def test_dry_run_monitor_skipped(self):
        r = self.get_remediator()
        result = r.execute(VSFTPD_FINDING, MONITOR_ACTION)
        assert result["status"] == "Skipped"


# ── SSH safety in execute ─────────────────────────────────────────────────────

class TestSSHSafetyInExecute:
    def get_remediator(self, dry_run=False):
        return Remediator("192.168.244.128", "msfadmin", "msfadmin",
                          dry_run=dry_run, retry_attempts=1)

    def test_ssh_stop_returns_skipped(self):
        r = self.get_remediator(dry_run=False)
        result = r.execute(SSH_FINDING, SSH_STOP_ACTION)
        assert result["status"] == "Skipped"
        assert "SAFETY" in result["stderr"].upper()

    def test_iptables_22_returns_skipped(self):
        r = self.get_remediator(dry_run=False)
        action = {**SSH_STOP_ACTION, "command": "iptables -A INPUT -p tcp --dport 22 -j DROP"}
        result = r.execute(SSH_FINDING, action)
        assert result["status"] == "Skipped"

    def test_ssh_dry_run_also_blocked(self):
        r = self.get_remediator(dry_run=True)
        result = r.execute(SSH_FINDING, SSH_STOP_ACTION)
        # Dry-run still hits safety check first
        assert result["status"] == "Skipped"


# ── verification logic (mocked) ───────────────────────────────────────────────

class TestVerification:
    def get_remediator(self):
        return Remediator("192.168.244.128", "msfadmin", "msfadmin",
                          dry_run=False, retry_attempts=1)

    @patch("remediator.Remediator._verify_on_target", return_value=True)
    @patch("remediator.Remediator._verify_external", return_value=True)
    @patch("remediator.Remediator._run_remote", return_value=("", "", 0))
    def test_both_checks_pass_success(self, mock_run, mock_ext, mock_on):
        r = self.get_remediator()
        result = r.execute(VSFTPD_FINDING, STOP_ACTION)
        assert result["status"] == "Success"

    @patch("remediator.Remediator._verify_on_target", return_value=False)
    @patch("remediator.Remediator._verify_external", return_value=False)
    @patch("remediator.Remediator._run_remote", return_value=("", "", 0))
    def test_both_fail_returns_failed(self, mock_run, mock_ext, mock_on):
        r = self.get_remediator()
        result = r.execute(VSFTPD_FINDING, STOP_ACTION)
        assert result["status"] == "Failed"

    @patch("remediator.Remediator._verify_on_target", return_value=True)
    @patch("remediator.Remediator._verify_external", return_value=False)
    @patch("remediator.Remediator._run_remote", return_value=("", "", 0))
    def test_mixed_check_returns_failed(self, mock_run, mock_ext, mock_on):
        r = self.get_remediator()
        result = r.execute(VSFTPD_FINDING, STOP_ACTION)
        assert result["status"] == "Failed"


# ── probe_before ──────────────────────────────────────────────────────────────

class TestProbeBefore:
    @patch("remediator.socket.create_connection")
    def test_port_open(self, mock_create):
        # create_connection succeeds → port is open
        mock_sock = MagicMock()
        mock_create.return_value = mock_sock
        r = Remediator("192.168.244.128", "msfadmin", "msfadmin")
        assert r.probe_before(21) is True

    @patch("remediator.socket.create_connection")
    def test_port_closed(self, mock_create):
        # create_connection raises ConnectionRefusedError → port is closed
        mock_create.side_effect = ConnectionRefusedError
        r = Remediator("192.168.244.128", "msfadmin", "msfadmin")
        assert r.probe_before(21) is False

    @patch("remediator.socket.create_connection")
    def test_port_timeout(self, mock_create):
        # create_connection raises socket.timeout (iptables DROP) → port treated as closed
        import socket as _sock
        mock_create.side_effect = _sock.timeout
        r = Remediator("192.168.244.128", "msfadmin", "msfadmin")
        assert r.probe_before(21) is False

    def test_port_zero_returns_false(self):
        r = Remediator("192.168.244.128", "msfadmin", "msfadmin")
        assert r.probe_before(0) is False
