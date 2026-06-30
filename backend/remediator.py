"""SSH-based remediation executor with two-factor post-verification.

Uses Upstart-safe commands (sudo service / sudo stop) on the target.
NEVER uses systemctl — Metasploitable2 runs Ubuntu 8.04 with Upstart.

Two independent verification checks before declaring Success:
  (i)  On-target:  service <name> status / netstat shows port closed
       (skipped for iptables/harden actions — port stays LISTEN after DROP)
  (ii) External:   raw TCP socket from engine host cannot connect to target:port

Sudo handling:
  Commands starting with 'sudo' are converted to 'sudo -S' and the SSH
  password is fed via stdin so sudo does not block on /dev/tty over the
  non-interactive exec_command channel.

Timeouts:
  _CONNECT_TIMEOUT — max seconds for the SSH handshake
  _CMD_TIMEOUT     — max seconds for any single remote command (read phase)
  If a command exceeds _CMD_TIMEOUT the attempt is marked Failed and the
  retry loop continues — the loop can never hang permanently.
"""

import socket
import time
import paramiko
from cryptography.hazmat.primitives import hashes as _crypto_hashes

from recommender import assert_not_ssh_kill

_CONNECT_TIMEOUT = 10   # SSH handshake timeout (seconds)
_CMD_TIMEOUT     = 20   # Per-command hard read timeout (seconds)


class Remediator:
    def __init__(self, host: str, user: str, password: str,
                 dry_run: bool = False, retry_attempts: int = 3):
        self.host = host
        self.user = user
        self.password = password
        self.dry_run = dry_run
        self.retry_attempts = retry_attempts

    # ------------------------------------------------------------------
    # SSH helpers
    # ------------------------------------------------------------------

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Paramiko 5.x removed legacy ssh-rsa (SHA-1) support at three levels:
        #   1. Transport._preferred_keys — 'ssh-rsa' absent → negotiation fails
        #      with "no acceptable host key"
        #   2. Transport._key_info — no 'ssh-rsa' entry → KeyError during verify
        #   3. RSAKey.HASHES — no SHA1 entry → verify_ssh_sig returns False
        # Metasploitable2 (OpenSSH 4.7p1, Ubuntu 8.04) only speaks ssh-rsa, so
        # all three tables are patched for the duration of this connect call and
        # restored in the finally block.
        _orig_pref_keys = paramiko.Transport._preferred_keys
        _added_key_info = "ssh-rsa" not in paramiko.Transport._key_info
        _added_sha1 = "ssh-rsa" not in paramiko.RSAKey.HASHES
        paramiko.Transport._preferred_keys = ("ssh-rsa",) + tuple(
            k for k in _orig_pref_keys if k != "ssh-rsa"
        )
        if _added_key_info:
            paramiko.Transport._key_info["ssh-rsa"] = paramiko.RSAKey
        if _added_sha1:
            paramiko.RSAKey.HASHES["ssh-rsa"] = _crypto_hashes.SHA1
        try:
            client.connect(
                self.host, username=self.user, password=self.password,
                timeout=_CONNECT_TIMEOUT,
                banner_timeout=15, auth_timeout=15,
                look_for_keys=False, allow_agent=False,
            )
            return client
        except Exception as exc:
            print(f"[Remediator] SSH connect to {self.host} failed: {exc}")
            raise
        finally:
            paramiko.Transport._preferred_keys = _orig_pref_keys
            if _added_key_info:
                paramiko.Transport._key_info.pop("ssh-rsa", None)
            if _added_sha1:
                paramiko.RSAKey.HASHES.pop("ssh-rsa", None)

    def _run_remote(self, command: str) -> tuple:
        """
        Run a command over SSH. Returns (stdout_str, stderr_str, exit_code).

        Privileged commands (starting with 'sudo') are automatically converted
        to 'sudo -S' and self.password is written to stdin before reading output,
        so sudo never prompts interactively over the non-TTY exec_command channel.

        A hard _CMD_TIMEOUT prevents any command from blocking forever:
        stdout.read() respects the channel settimeout; if it fires, TimeoutError
        is raised and caught by the execute() retry loop.

        After stdout.read() returns EOF the channel is already closed, so
        recv_exit_status() returns immediately — it is never the blocking call.
        """
        client = self._connect()
        try:
            needs_sudo = command.lstrip().startswith("sudo ")
            if needs_sudo and "sudo -S " not in command:
                actual_cmd = command.replace("sudo ", "sudo -S ", 1)
            else:
                actual_cmd = command

            stdin, stdout, stderr = client.exec_command(actual_cmd)
            stdout.channel.settimeout(_CMD_TIMEOUT)

            if needs_sudo:
                try:
                    stdin.write(f"{self.password}\n")
                    stdin.flush()
                    stdin.channel.shutdown_write()
                except OSError:
                    pass  # channel already closed on fast-exit commands

            try:
                out = stdout.read().decode(errors="replace").strip()
                err = stderr.read().decode(errors="replace").strip()
            except socket.timeout:
                raise TimeoutError(
                    f"Command timed out after {_CMD_TIMEOUT}s "
                    f"(no EOF received): {command!r}"
                )

            # Channel is at EOF here — recv_exit_status() returns instantly
            exit_code = stdout.channel.recv_exit_status()
            return out, err, exit_code

        except Exception as exc:
            print(f"[Remediator] exec_command failed: {exc}")
            raise
        finally:
            client.close()

    # ------------------------------------------------------------------
    # Verification helpers
    # ------------------------------------------------------------------

    def _verify_on_target(self, service_name: str, port: int) -> bool:
        """
        Check (i): on-target service status + netstat.
        Returns True if the service/port is confirmed stopped/closed.
        Only meaningful for service-stop actions; callers skip this for
        iptables/harden where the port stays LISTEN in netstat.
        """
        if not service_name and port <= 0:
            return True  # nothing to verify

        stopped = False
        port_closed = False

        if service_name:
            try:
                # Ubuntu 8.04 has no 'service' wrapper; use /etc/init.d/ directly
                out, _, code = self._run_remote(
                    f"sudo /etc/init.d/{service_name} status 2>&1 || true"
                )
                out_lower = out.lower()
                # init.d status outputs vary; check for common "not running" patterns
                stopped = any(kw in out_lower for kw in
                              ("stop/waiting", "not running", "is not running",
                               "stopped", "unrecognized", "does not exist",
                               "no pid", "command not found"))
                print(f"[Verify-i] /etc/init.d/{service_name} status: {out!r} → stopped={stopped}")
            except Exception as exc:
                print(f"[Verify-i] service status check failed: {exc}")

        if port > 0:
            try:
                out, _, _ = self._run_remote(
                    f"netstat -tlnp 2>/dev/null | grep ':{port} ' || echo 'PORT_CLOSED'"
                )
                port_closed = "PORT_CLOSED" in out or out.strip() == ""
                print(f"[Verify-i] netstat port {port}: {out!r} → closed={port_closed}")
            except Exception as exc:
                print(f"[Verify-i] netstat check failed: {exc}")
                port_closed = False

        # OR: either the service status OR the netstat check is sufficient
        # (inetd-managed services may not show as "stopped" via service status)
        return stopped or port_closed

    def _verify_external(self, port: int, timeout: int = 5) -> bool:
        """
        Check (ii): from engine host, attempt raw TCP connection.
        Returns True if the port is NOT reachable (remediation effective).

        Handles both cases:
          - Service stopped → ConnectionRefusedError (RST)     → verified
          - iptables DROP   → socket.timeout (no SYN+ACK)      → verified
          - Still open      → connect succeeds, returns 0       → NOT verified
        """
        if port <= 0:
            return True
        try:
            sock = socket.create_connection((self.host, port), timeout=timeout)
            sock.close()
            print(f"[Verify-ii] TCP {self.host}:{port} → OPEN (still reachable)")
            return False
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            print(f"[Verify-ii] TCP {self.host}:{port} → unreachable "
                  f"({type(exc).__name__}) → verified")
            return True

    def verify(self, service_name: str, port: int,
               action_type: str = "stop_service", action: dict = None) -> bool:
        """
        Run the appropriate verification check for the given action type.

        harden:
          Run action['verify_cmd'] over SSH and return True iff exit_code == 0.
          This confirms the config change took effect (e.g. grep finds the new
          setting). The port MUST stay open for harden actions — do NOT use a
          port-closed check here.
          If no verify_cmd is set, trust that execute() already confirmed exit_code 0.

        iptables_drop:
          External TCP probe only — port still shows LISTEN in netstat even
          after DROP, so on-target check is misleading.

        stop_service (default):
          Both on-target service-status / netstat AND external TCP probe must agree.
        """
        if action_type == "harden":
            verify_cmd = (action or {}).get("verify_cmd", "")
            if verify_cmd:
                try:
                    _, _, vcode = self._run_remote(verify_cmd)
                    verified = vcode == 0
                    print(f"[Verify-harden] {verify_cmd!r} → exit={vcode} → verified={verified}")
                    return verified
                except Exception as exc:
                    print(f"[Verify-harden] Config check failed: {exc}")
                    return False
            # No verify_cmd: command already returned exit_code 0 in execute()
            print("[Verify-harden] No verify_cmd — accepting exit_code=0 from command")
            return True

        if action_type == "iptables_drop":
            time.sleep(2)
            return self._verify_external(port)

        # stop_service and everything else: both on-target + external
        check_i = self._verify_on_target(service_name, port)
        time.sleep(2)
        check_ii = self._verify_external(port)
        return check_i and check_ii

    # ------------------------------------------------------------------
    # Public execute interface
    # ------------------------------------------------------------------

    def execute(self, finding: dict, action: dict) -> dict:
        """
        Execute action['command'] on the target.

        Returns result dict:
          {
            "status": "Success"|"Failed"|"Retrying"|"Skipped",
            "command": str,
            "stdout": str,
            "stderr": str,
            "exit_code": int,
            "attempts": int,
          }
        """
        command = action.get("command", "")
        action_type = action.get("action", "stop_service")
        service_name = (
            finding.get("service", "").lower()
            or str(action.get("_service_name", ""))
        )
        port = finding.get("port", 0)

        # Infer service name from PORT_TO_SERVICE if blank
        from recommender import PORT_TO_SERVICE
        if not service_name and port in PORT_TO_SERVICE:
            service_name = PORT_TO_SERVICE[port] or ""

        # Hard safety check
        try:
            assert_not_ssh_kill(command, finding)
        except ValueError as exc:
            print(f"\n{'!'*70}\n{exc}\n{'!'*70}\n")
            return {
                "status": "Skipped",
                "command": command,
                "stdout": "",
                "stderr": str(exc),
                "exit_code": -1,
                "attempts": 0,
            }

        # Monitor-only action — always Skipped, even in dry-run
        if action_type == "monitor" or not command:
            return {
                "status": "Skipped",
                "command": "(monitor-only — no command dispatched)",
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
                "attempts": 0,
            }

        if self.dry_run:
            print(f"[DRY-RUN] Would execute: {command}")
            return {
                "status": "Success",
                "command": command,
                "stdout": "[DRY-RUN]",
                "stderr": "",
                "exit_code": 0,
                "attempts": 0,
            }

        attempts = 0
        last_result = {}
        for attempt in range(1, self.retry_attempts + 1):
            attempts = attempt
            print(f"[Remediator] Attempt {attempt}/{self.retry_attempts}: {command}")
            try:
                out, err, code = self._run_remote(command)
                print(f"  stdout: {out!r}")
                print(f"  stderr: {err!r}")
                print(f"  exit_code: {code}")
                time.sleep(3)

                if self.verify(service_name, port, action_type, action=action):
                    return {
                        "status": "Success",
                        "command": command,
                        "stdout": out,
                        "stderr": err,
                        "exit_code": code,
                        "attempts": attempts,
                    }
                else:
                    last_result = {
                        "status": "Retrying" if attempt < self.retry_attempts else "Failed",
                        "command": command,
                        "stdout": out,
                        "stderr": err,
                        "exit_code": code,
                        "attempts": attempts,
                    }
                    if attempt < self.retry_attempts:
                        print(f"[Remediator] Verification failed — retrying …")
                        time.sleep(5)
            except KeyboardInterrupt:
                print("\n[Remediator] Interrupted by operator — marking Failed.")
                return {
                    "status": "Failed",
                    "command": command,
                    "stdout": "",
                    "stderr": "Interrupted by operator",
                    "exit_code": -1,
                    "attempts": attempts,
                }
            except Exception as exc:
                last_result = {
                    "status": "Retrying" if attempt < self.retry_attempts else "Failed",
                    "command": command,
                    "stdout": "",
                    "stderr": str(exc),
                    "exit_code": -1,
                    "attempts": attempts,
                }
                if attempt < self.retry_attempts:
                    print(f"[Remediator] Error on attempt {attempt}: {exc} — retrying …")
                    time.sleep(5)

        last_result["status"] = "Failed"
        return last_result

    def probe_before(self, port: int) -> bool:
        """Return True if port is currently OPEN (pre-remediation check)."""
        if port <= 0:
            return False
        try:
            sock = socket.create_connection((self.host, port), timeout=5)
            sock.close()
            print(f"[Pre-check] TCP {self.host}:{port} → open=True")
            return True
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            print(f"[Pre-check] TCP {self.host}:{port} → open=False ({type(exc).__name__})")
            return False
