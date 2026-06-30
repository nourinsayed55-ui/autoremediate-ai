"""Database operations for AutoRemediate AI (Supabase/PostgreSQL via psycopg2)."""
import json
import os
import psycopg2
from psycopg2.extras import RealDictCursor


def _load_conn_string():
    cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(cfg_path) as f:
        cfg = json.load(f)
    return cfg["database"]["connection_string"]


def get_connection():
    return psycopg2.connect(_load_conn_string(), cursor_factory=RealDictCursor)


def create_schema():
    """Execute schema.sql to create tables if they don't already exist."""
    sql_path = os.path.join(os.path.dirname(__file__), "..", "sql", "schema.sql")
    with open(sql_path) as f:
        ddl = f.read()
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute(ddl)
        conn.close()
        print("[DB] Schema applied successfully.")
    except Exception as exc:
        print(f"[DB] Schema creation failed: {exc}")
        raise


def verify_tables():
    """Return list of table names that now exist in the public schema."""
    sql = """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name IN ('Vulnerabilities', 'Remediation_Activity_Logs');
    """
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
        conn.close()
        return [r["table_name"] for r in rows]
    except Exception as exc:
        print(f"[DB] Verify tables failed: {exc}")
        raise


def insert_vulnerability(cve_reference, plugin_name, severity_level, target_port):
    """Insert a vulnerability record and return the new vuln_id."""
    sql = """
        INSERT INTO "Vulnerabilities" (cve_reference, plugin_name, severity_level, target_port)
        VALUES (%s, %s, %s, %s)
        RETURNING vuln_id;
    """
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql, (cve_reference, plugin_name, severity_level, target_port))
                row = cur.fetchone()
        conn.close()
        return row["vuln_id"]
    except Exception as exc:
        print(f"[DB] insert_vulnerability failed: {exc}")
        raise


def insert_remediation_log(vuln_id, command_dispatched, operator_decision, execution_status):
    """Insert a remediation log entry."""
    sql = """
        INSERT INTO "Remediation_Activity_Logs"
            (vuln_id, command_dispatched, operator_decision, execution_status)
        VALUES (%s, %s, %s, %s)
        RETURNING log_id;
    """
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql, (vuln_id, command_dispatched, operator_decision, execution_status))
                row = cur.fetchone()
        conn.close()
        return row["log_id"]
    except Exception as exc:
        print(f"[DB] insert_remediation_log failed: {exc}")
        raise


def fetch_all_logs():
    """Return all remediation log rows joined with vulnerability info."""
    sql = """
        SELECT l.log_id, l.timestamp, l.command_dispatched, l.operator_decision,
               l.execution_status, v.plugin_name, v.severity_level, v.target_port
        FROM "Remediation_Activity_Logs" l
        JOIN "Vulnerabilities" v ON v.vuln_id = l.vuln_id
        ORDER BY l.timestamp DESC;
    """
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as exc:
        print(f"[DB] fetch_all_logs failed: {exc}")
        raise


def get_recent_logs(limit=50):
    """Return the most recent `limit` remediation log rows (newest first)."""
    sql = """
        SELECT l.log_id, l.timestamp, l.command_dispatched, l.operator_decision,
               l.execution_status, v.plugin_name, v.severity_level, v.target_port
        FROM "Remediation_Activity_Logs" l
        JOIN "Vulnerabilities" v ON v.vuln_id = l.vuln_id
        ORDER BY l.timestamp DESC
        LIMIT %s;
    """
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(sql, (limit,))
            rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as exc:
        print(f"[DB] get_recent_logs failed: {exc}")
        raise
