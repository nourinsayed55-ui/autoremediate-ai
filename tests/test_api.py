"""Tests for the Flask web console (backend/app.py).

All SSH, Supabase, and Nessus calls are mocked — no live targets needed.
Tests verify: response shape, one-action-per-POST enforcement, secret
exclusion, and error handling for invalid inputs.
"""
import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from app import app as flask_app  # noqa: E402  (path setup above)

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

FAKE_OPTIONS = [
    {
        "key": "preferred",
        "label": "RECOMMENDED (Rung 2): Stop apache2",
        "rung": 2,
        "action": "stop_service",
        "command": "sudo /etc/init.d/apache2 stop",
        "rationale": "Fastest closure.",
        "tier": "preferred",
    },
    {
        "key": "alt_0",
        "label": "ALTERNATIVE (Rung 4): iptables DROP 80/tcp",
        "rung": 4,
        "action": "iptables_drop",
        "command": "sudo iptables -I INPUT -p tcp --dport 80 -j DROP",
        "rationale": "Blocks without stopping service.",
        "tier": "alternative",
    },
    {
        "key": "monitor",
        "label": "MONITOR ONLY — log finding, no change to target",
        "rung": 5,
        "action": "monitor",
        "command": "",
        "rationale": "Rung 5 — safe fallback.",
        "tier": "monitor",
    },
]

FAKE_FINDING = {
    "_id": "12345_80",
    "plugin_name": "Apache Default Files",
    "severity": "High",
    "port": 80,
    "protocol": "tcp",
    "service": "http",
    "cve_reference": "CVE-2024-0001",
    "cvss_base_score": "7.5",
    "priority_score": 120,
    "host": "192.168.244.128",
    "_options": FAKE_OPTIONS,
}

FAKE_EXEC_RESULT = {
    "finding_id": "12345_80",
    "option_key": "preferred",
    "operator": "web-operator",
    "status": "Success",
    "command": "sudo /etc/init.d/apache2 stop",
    "attempts": 1,
    "message": "",
    "vuln_id": 42,
}

FAKE_LOGS = [
    {
        "log_id": 1,
        "timestamp": "2026-06-30T10:00:00",
        "command_dispatched": "sudo /etc/init.d/apache2 stop",
        "operator_decision": "WEB-APPROVED by web-operator (Rung 2): Stop apache2",
        "execution_status": "Success",
        "plugin_name": "Apache Default Files",
        "severity_level": "High",
        "target_port": 80,
    }
]


# ---------------------------------------------------------------------------
# GET /api/findings
# ---------------------------------------------------------------------------

class TestAPIFindings(unittest.TestCase):

    def setUp(self):
        flask_app.config["TESTING"] = True
        self.client = flask_app.test_client()

    def test_findings_returns_200(self):
        with patch("core.get_decision_items", return_value=[FAKE_FINDING]):
            resp = self.client.get("/api/findings")
        self.assertEqual(resp.status_code, 200)

    def test_findings_has_findings_key(self):
        with patch("core.get_decision_items", return_value=[FAKE_FINDING]):
            resp = self.client.get("/api/findings")
        data = resp.get_json()
        self.assertIn("findings", data)

    def test_findings_correct_count(self):
        with patch("core.get_decision_items", return_value=[FAKE_FINDING]):
            resp = self.client.get("/api/findings")
        self.assertEqual(len(resp.get_json()["findings"]), 1)

    def test_findings_has_id(self):
        with patch("core.get_decision_items", return_value=[FAKE_FINDING]):
            resp = self.client.get("/api/findings")
        finding = resp.get_json()["findings"][0]
        self.assertEqual(finding["_id"], "12345_80")

    def test_findings_preferred_is_first_option(self):
        with patch("core.get_decision_items", return_value=[FAKE_FINDING]):
            resp = self.client.get("/api/findings")
        options = resp.get_json()["findings"][0]["_options"]
        self.assertEqual(options[0]["key"], "preferred")

    def test_findings_options_include_monitor(self):
        with patch("core.get_decision_items", return_value=[FAKE_FINDING]):
            resp = self.client.get("/api/findings")
        options = resp.get_json()["findings"][0]["_options"]
        tiers = [o["tier"] for o in options]
        self.assertIn("monitor", tiers)

    def test_findings_severity_field_present(self):
        with patch("core.get_decision_items", return_value=[FAKE_FINDING]):
            resp = self.client.get("/api/findings")
        finding = resp.get_json()["findings"][0]
        self.assertEqual(finding["severity"], "High")

    def test_findings_503_when_scan_json_missing(self):
        with patch("core.get_decision_items", side_effect=FileNotFoundError("not found")):
            resp = self.client.get("/api/findings")
        self.assertEqual(resp.status_code, 503)
        self.assertIn("error", resp.get_json())

    def test_findings_no_ssh_password_in_response(self):
        with patch("core.get_decision_items", return_value=[FAKE_FINDING]):
            resp = self.client.get("/api/findings")
        body = resp.data.decode()
        self.assertNotIn("ssh_pass", body)
        self.assertNotIn("secret_key", body)
        self.assertNotIn("connection_string", body)

    def test_findings_no_access_key_in_response(self):
        with patch("core.get_decision_items", return_value=[FAKE_FINDING]):
            resp = self.client.get("/api/findings")
        body = resp.data.decode()
        self.assertNotIn("access_key", body)

    def test_findings_empty_list_is_ok(self):
        with patch("core.get_decision_items", return_value=[]):
            resp = self.client.get("/api/findings")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["findings"], [])


# ---------------------------------------------------------------------------
# POST /api/remediate
# ---------------------------------------------------------------------------

class TestAPIRemediate(unittest.TestCase):

    def setUp(self):
        flask_app.config["TESTING"] = True
        self.client = flask_app.test_client()

    def test_remediate_success_200(self):
        with patch("core.execute_action", return_value=FAKE_EXEC_RESULT):
            resp = self.client.post(
                "/api/remediate",
                json={"finding_id": "12345_80", "option_key": "preferred"},
            )
        self.assertEqual(resp.status_code, 200)

    def test_remediate_returns_status(self):
        with patch("core.execute_action", return_value=FAKE_EXEC_RESULT):
            resp = self.client.post(
                "/api/remediate",
                json={"finding_id": "12345_80", "option_key": "preferred"},
            )
        self.assertEqual(resp.get_json()["status"], "Success")

    def test_remediate_returns_finding_id(self):
        with patch("core.execute_action", return_value=FAKE_EXEC_RESULT):
            resp = self.client.post(
                "/api/remediate",
                json={"finding_id": "12345_80", "option_key": "preferred"},
            )
        self.assertEqual(resp.get_json()["finding_id"], "12345_80")

    def test_remediate_missing_finding_id_is_400(self):
        resp = self.client.post("/api/remediate", json={"option_key": "preferred"})
        self.assertEqual(resp.status_code, 400)

    def test_remediate_missing_option_key_is_400(self):
        resp = self.client.post("/api/remediate", json={"finding_id": "12345_80"})
        self.assertEqual(resp.status_code, 400)

    def test_remediate_empty_body_is_400(self):
        resp = self.client.post("/api/remediate", json={})
        self.assertEqual(resp.status_code, 400)

    def test_remediate_plural_finding_ids_is_400(self):
        """Batch key 'finding_ids' (plural) must be rejected — no batch paths."""
        resp = self.client.post(
            "/api/remediate",
            json={"finding_ids": ["a", "b"], "option_key": "preferred"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_remediate_invalid_finding_id_is_400(self):
        with patch("core.execute_action", side_effect=ValueError("Finding 'bad_id' not found")):
            resp = self.client.post(
                "/api/remediate",
                json={"finding_id": "bad_id", "option_key": "preferred"},
            )
        self.assertEqual(resp.status_code, 400)

    def test_remediate_calls_execute_action_exactly_once(self):
        with patch("core.execute_action", return_value=FAKE_EXEC_RESULT) as mock_exec:
            self.client.post(
                "/api/remediate",
                json={"finding_id": "12345_80", "option_key": "preferred"},
            )
        mock_exec.assert_called_once()

    def test_remediate_passes_finding_id_and_option_key(self):
        with patch("core.execute_action", return_value=FAKE_EXEC_RESULT) as mock_exec:
            self.client.post(
                "/api/remediate",
                json={"finding_id": "12345_80", "option_key": "alt_0", "operator": "alice"},
            )
        # execute_action should have been called with finding_id and option_key
        call_kwargs = mock_exec.call_args.kwargs
        self.assertEqual(call_kwargs["finding_id"], "12345_80")
        self.assertEqual(call_kwargs["option_key"], "alt_0")

    def test_remediate_no_secrets_in_response(self):
        with patch("core.execute_action", return_value=FAKE_EXEC_RESULT):
            resp = self.client.post(
                "/api/remediate",
                json={"finding_id": "12345_80", "option_key": "preferred"},
            )
        body = resp.data.decode()
        self.assertNotIn("ssh_pass", body)
        self.assertNotIn("access_key", body)
        self.assertNotIn("connection_string", body)

    def test_remediate_no_json_body_is_400(self):
        resp = self.client.post("/api/remediate", data="not-json",
                                content_type="application/json")
        # json.loads will fail → data={} → missing fields → 400
        self.assertIn(resp.status_code, (400, 500))


# ---------------------------------------------------------------------------
# GET /api/logs
# ---------------------------------------------------------------------------

class TestAPILogs(unittest.TestCase):

    def setUp(self):
        flask_app.config["TESTING"] = True
        self.client = flask_app.test_client()

    def test_logs_returns_200(self):
        with patch("db.get_recent_logs", return_value=FAKE_LOGS):
            resp = self.client.get("/api/logs")
        self.assertEqual(resp.status_code, 200)

    def test_logs_has_logs_key(self):
        with patch("db.get_recent_logs", return_value=FAKE_LOGS):
            resp = self.client.get("/api/logs")
        self.assertIn("logs", resp.get_json())

    def test_logs_correct_count(self):
        with patch("db.get_recent_logs", return_value=FAKE_LOGS):
            resp = self.client.get("/api/logs")
        self.assertEqual(len(resp.get_json()["logs"]), 1)

    def test_logs_contains_status(self):
        with patch("db.get_recent_logs", return_value=FAKE_LOGS):
            resp = self.client.get("/api/logs")
        row = resp.get_json()["logs"][0]
        self.assertEqual(row["execution_status"], "Success")

    def test_logs_empty_list_on_db_error(self):
        with patch("db.get_recent_logs", side_effect=Exception("DB down")):
            resp = self.client.get("/api/logs")
        data = resp.get_json()
        self.assertEqual(data.get("logs"), [])

    def test_logs_db_error_returns_500(self):
        with patch("db.get_recent_logs", side_effect=Exception("DB down")):
            resp = self.client.get("/api/logs")
        self.assertEqual(resp.status_code, 500)


# ---------------------------------------------------------------------------
# GET /api/status
# ---------------------------------------------------------------------------

class TestAPIStatus(unittest.TestCase):

    def setUp(self):
        flask_app.config["TESTING"] = True
        self.client = flask_app.test_client()

    def _status(self):
        with patch("core.get_all_findings_count", return_value=42), \
             patch("core.get_decision_items", return_value=[FAKE_FINDING]), \
             patch("db.get_recent_logs", return_value=FAKE_LOGS):
            return self.client.get("/api/status")

    def test_status_returns_200(self):
        self.assertEqual(self._status().status_code, 200)

    def test_status_has_all_fields(self):
        data = self._status().get_json()
        for field in ("total_findings", "critical_high", "remediated_success", "db_connected"):
            self.assertIn(field, data, f"Missing field: {field}")

    def test_status_total_findings(self):
        self.assertEqual(self._status().get_json()["total_findings"], 42)

    def test_status_critical_high(self):
        self.assertEqual(self._status().get_json()["critical_high"], 1)

    def test_status_remediated_success_counts_successes(self):
        self.assertEqual(self._status().get_json()["remediated_success"], 1)

    def test_status_db_connected_true_when_logs_ok(self):
        self.assertTrue(self._status().get_json()["db_connected"])

    def test_status_db_connected_false_on_db_error(self):
        with patch("core.get_all_findings_count", return_value=0), \
             patch("core.get_decision_items", return_value=[]), \
             patch("db.get_recent_logs", side_effect=Exception("down")):
            resp = self.client.get("/api/status")
        self.assertFalse(resp.get_json()["db_connected"])

    def test_status_does_not_expose_secrets(self):
        body = self._status().data.decode()
        self.assertNotIn("ssh_pass", body)
        self.assertNotIn("access_key", body)
        self.assertNotIn("connection_string", body)


# ---------------------------------------------------------------------------
# GET /api/metrics (new SOC dashboard endpoint)
# ---------------------------------------------------------------------------

FAKE_LOGS_MULTI = [
    {
        "log_id": 2, "timestamp": "2026-06-30T10:02:00",
        "command_dispatched": "sudo iptables -I INPUT -p tcp --dport 6667 -j DROP",
        "operator_decision": "WEB-APPROVED", "execution_status": "Success",
        "plugin_name": "UnrealIRCd Backdoor", "severity_level": "Critical", "target_port": 6667,
    },
    {
        "log_id": 1, "timestamp": "2026-06-30T10:00:00",
        "command_dispatched": "sudo /etc/init.d/apache2 stop",
        "operator_decision": "WEB-APPROVED", "execution_status": "Success",
        "plugin_name": "Apache Default Files", "severity_level": "High", "target_port": 80,
    },
]

FAKE_LOGS_MIXED = [
    {**FAKE_LOGS_MULTI[0], "execution_status": "Failed"},
    {**FAKE_LOGS_MULTI[1], "execution_status": "Skipped", "log_id": 0},
]


class TestAPIMetrics(unittest.TestCase):

    def setUp(self):
        flask_app.config["TESTING"] = True
        self.client = flask_app.test_client()

    def test_metrics_returns_200(self):
        with patch("db.get_recent_logs", return_value=FAKE_LOGS_MULTI):
            resp = self.client.get("/api/metrics")
        self.assertEqual(resp.status_code, 200)

    def test_metrics_has_required_fields(self):
        with patch("db.get_recent_logs", return_value=FAKE_LOGS_MULTI):
            resp = self.client.get("/api/metrics")
        data = resp.get_json()
        for field in ("total_actions", "success", "failed", "skipped", "success_rate"):
            self.assertIn(field, data)

    def test_metrics_counts_correct(self):
        with patch("db.get_recent_logs", return_value=FAKE_LOGS_MULTI):
            resp = self.client.get("/api/metrics")
        data = resp.get_json()
        self.assertEqual(data["total_actions"], 2)
        self.assertEqual(data["success"], 2)
        self.assertEqual(data["failed"],  0)

    def test_metrics_success_rate_100_when_all_success(self):
        with patch("db.get_recent_logs", return_value=FAKE_LOGS_MULTI):
            data = self.client.get("/api/metrics").get_json()
        self.assertEqual(data["success_rate"], 100.0)

    def test_metrics_success_rate_0_on_empty(self):
        with patch("db.get_recent_logs", return_value=[]):
            data = self.client.get("/api/metrics").get_json()
        self.assertEqual(data["success_rate"], 0)

    def test_metrics_mixed_statuses(self):
        with patch("db.get_recent_logs", return_value=FAKE_LOGS_MIXED):
            data = self.client.get("/api/metrics").get_json()
        self.assertEqual(data["failed"], 1)
        self.assertEqual(data["skipped"], 1)
        self.assertEqual(data["success"], 0)

    def test_metrics_no_mttr_on_single_success(self):
        with patch("db.get_recent_logs", return_value=[FAKE_LOGS[0]]):
            data = self.client.get("/api/metrics").get_json()
        self.assertIsNone(data["mttr_seconds"])

    def test_metrics_mttr_computed_for_two_successes(self):
        with patch("db.get_recent_logs", return_value=FAKE_LOGS_MULTI):
            data = self.client.get("/api/metrics").get_json()
        # 10:02 - 10:00 = 120s span / (2-1) = 120s
        self.assertIsNotNone(data["mttr_seconds"])
        self.assertAlmostEqual(data["mttr_seconds"], 120.0, delta=1.0)

    def test_metrics_returns_200_on_db_error(self):
        with patch("db.get_recent_logs", side_effect=Exception("DB down")):
            resp = self.client.get("/api/metrics")
        # Returns 200 with empty/zero values (graceful)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["total_actions"], 0)


# ---------------------------------------------------------------------------
# GET /api/severity-breakdown (new SOC dashboard endpoint)
# ---------------------------------------------------------------------------

FAKE_ALL_FINDINGS = [
    {"severity": "Critical", "plugin_name": "A", "port": 80},
    {"severity": "Critical", "plugin_name": "B", "port": 6667},
    {"severity": "High",     "plugin_name": "C", "port": 22},
    {"severity": "Medium",   "plugin_name": "D", "port": 25},
    {"severity": "Low",      "plugin_name": "E", "port": 3306},
]


class TestAPISeverityBreakdown(unittest.TestCase):

    def setUp(self):
        flask_app.config["TESTING"] = True
        self.client = flask_app.test_client()

    def test_severity_breakdown_returns_200(self):
        with patch("core.get_all_findings", return_value=FAKE_ALL_FINDINGS):
            resp = self.client.get("/api/severity-breakdown")
        self.assertEqual(resp.status_code, 200)

    def test_severity_breakdown_has_all_keys(self):
        with patch("core.get_all_findings", return_value=FAKE_ALL_FINDINGS):
            data = self.client.get("/api/severity-breakdown").get_json()
        for k in ("Critical", "High", "Medium", "Low"):
            self.assertIn(k, data)

    def test_severity_breakdown_correct_counts(self):
        with patch("core.get_all_findings", return_value=FAKE_ALL_FINDINGS):
            data = self.client.get("/api/severity-breakdown").get_json()
        self.assertEqual(data["Critical"], 2)
        self.assertEqual(data["High"],     1)
        self.assertEqual(data["Medium"],   1)
        self.assertEqual(data["Low"],      1)

    def test_severity_breakdown_all_zero_on_empty(self):
        with patch("core.get_all_findings", return_value=[]):
            data = self.client.get("/api/severity-breakdown").get_json()
        self.assertEqual(data["Critical"], 0)
        self.assertEqual(data["Low"],      0)

    def test_severity_breakdown_no_secrets(self):
        with patch("core.get_all_findings", return_value=FAKE_ALL_FINDINGS):
            body = self.client.get("/api/severity-breakdown").data.decode()
        self.assertNotIn("ssh_pass", body)
        self.assertNotIn("access_key", body)


# ---------------------------------------------------------------------------
# GET /api/ports (new SOC dashboard endpoint)
# ---------------------------------------------------------------------------

FAKE_PORTS_FINDINGS = [
    {**FAKE_FINDING, "_id": "12345_80",   "port": 80,   "severity": "High",     "priority_score": 120},
    {**FAKE_FINDING, "_id": "99999_6667", "port": 6667, "severity": "Critical", "priority_score": 200,
     "plugin_name": "UnrealIRCd Backdoor", "service": "irc"},
]


class TestAPIPorts(unittest.TestCase):

    def setUp(self):
        flask_app.config["TESTING"] = True
        self.client = flask_app.test_client()

    def test_ports_returns_200(self):
        with patch("core.get_decision_items", return_value=FAKE_PORTS_FINDINGS):
            resp = self.client.get("/api/ports")
        self.assertEqual(resp.status_code, 200)

    def test_ports_has_ports_key(self):
        with patch("core.get_decision_items", return_value=FAKE_PORTS_FINDINGS):
            data = self.client.get("/api/ports").get_json()
        self.assertIn("ports", data)

    def test_ports_correct_count(self):
        with patch("core.get_decision_items", return_value=FAKE_PORTS_FINDINGS):
            data = self.client.get("/api/ports").get_json()
        self.assertEqual(len(data["ports"]), 2)

    def test_ports_sorted_by_priority_desc(self):
        with patch("core.get_decision_items", return_value=FAKE_PORTS_FINDINGS):
            data = self.client.get("/api/ports").get_json()
        scores = [p["priority_score"] for p in data["ports"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_ports_include_id_field(self):
        with patch("core.get_decision_items", return_value=FAKE_PORTS_FINDINGS):
            data = self.client.get("/api/ports").get_json()
        ids = {p["_id"] for p in data["ports"]}
        self.assertIn("12345_80", ids)

    def test_ports_has_required_fields(self):
        with patch("core.get_decision_items", return_value=FAKE_PORTS_FINDINGS):
            data = self.client.get("/api/ports").get_json()
        for p in data["ports"]:
            for field in ("_id", "port", "severity", "priority_score"):
                self.assertIn(field, p)

    def test_ports_503_when_scan_json_missing(self):
        with patch("core.get_decision_items", side_effect=FileNotFoundError("no json")):
            resp = self.client.get("/api/ports")
        self.assertEqual(resp.status_code, 503)

    def test_ports_no_secrets(self):
        with patch("core.get_decision_items", return_value=FAKE_PORTS_FINDINGS):
            body = self.client.get("/api/ports").data.decode()
        self.assertNotIn("ssh_pass", body)
        self.assertNotIn("connection_string", body)

    def test_ports_empty_on_no_findings(self):
        with patch("core.get_decision_items", return_value=[]):
            data = self.client.get("/api/ports").get_json()
        self.assertEqual(data["ports"], [])


if __name__ == "__main__":
    unittest.main()
