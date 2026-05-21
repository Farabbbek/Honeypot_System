import shlex
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any


class BehaviorEngine:
    TACTIC_WEIGHTS = {
        "BRUTE_FORCE": 25,
        "RECONNAISSANCE": 15,
        "MALWARE_DEPLOYMENT": 35,
        "CREDENTIAL_ACCESS": 30,
        "PERSISTENCE": 30,
        "EXFILTRATION": 40,
        "DEFENSE_EVASION": 25,
        "EXECUTION": 30,
        "DISCOVERY": 10,
        "LATERAL_MOVEMENT": 30,
        "INITIAL_ACCESS": 20,
    }

    # Non-command events → MITRE mapping
    EVENT_MITRE: dict[str, tuple[str, str, str]] = {
        "cowrie.session.connect": ("T1046", "Reconnaissance", "Network Service Discovery"),
        "session.connect": ("T1046", "Reconnaissance", "Network Service Discovery"),
        "cowrie.client.version": ("T1082", "Discovery", "System Information Discovery"),
        "client.version": ("T1082", "Discovery", "System Information Discovery"),
        "cowrie.client.kex": ("T1046", "Reconnaissance", "SSH Key Exchange Fingerprinting"),
        "client.kex": ("T1046", "Reconnaissance", "SSH Key Exchange Fingerprinting"),
        "cowrie.client.size": ("T1082", "Discovery", "Terminal Size Discovery"),
        "client.size": ("T1082", "Discovery", "Terminal Size Discovery"),
        "cowrie.client.var": ("T1082", "Discovery", "Environment Variable Discovery"),
        "client.var": ("T1082", "Discovery", "Environment Variable Discovery"),
        "cowrie.login.success": ("T1078", "Initial Access", "Valid Accounts"),
        "login.success": ("T1078", "Initial Access", "Valid Accounts"),
        "cowrie.login.failed": ("T1110.001", "Credential Access", "Password Guessing"),
        "login.failed": ("T1110.001", "Credential Access", "Password Guessing"),
        "cowrie.session.file_download": ("T1105", "Command and Control", "Ingress Tool Transfer"),
        "session.file_download": ("T1105", "Command and Control", "Ingress Tool Transfer"),
        "cowrie.session.file_upload": ("T1041", "Exfiltration", "Exfiltration Over C2 Channel"),
        "session.file_upload": ("T1041", "Exfiltration", "Exfiltration Over C2 Channel"),
        "cowrie.command.failed": ("T1059", "Execution", "Command and Scripting Interpreter"),
        "command.failed": ("T1059", "Execution", "Command and Scripting Interpreter"),
        "cowrie.session.closed": ("T1506", "Defense Evasion", "Session Termination"),
        "session.closed": ("T1506", "Defense Evasion", "Session Termination"),
        "cowrie.log.closed": ("T1562", "Defense Evasion", "Impair Defenses - Log Manipulation"),
        "log.closed": ("T1562", "Defense Evasion", "Impair Defenses - Log Manipulation"),
        "cowrie.direct-tcpip.request": ("T1021", "Lateral Movement", "Remote Services"),
        "direct-tcpip.request": ("T1021", "Lateral Movement", "Remote Services"),
        "cowrie.direct-tcpip.data": ("T1041", "Exfiltration", "Exfiltration Over C2 Channel"),
        "direct-tcpip.data": ("T1041", "Exfiltration", "Exfiltration Over C2 Channel"),
    }

    def classify_command(self, command: str) -> dict[str, str]:
        tokens = self._tokenize(command.strip())
        if not tokens:
            return self._unknown()

        executable = tokens[0]

        if executable in {"wget", "curl"}:
            return self._result("T1105", "Command and Control", "Ingress Tool Transfer")
        if executable == "chmod" and "+x" in tokens[1:]:
            return self._result("T1059.004", "Execution", "Command and Scripting Interpreter")
        if executable == "cat" and any(target in tokens[1:] for target in {"/etc/passwd", "/etc/shadow"}):
            return self._result("T1003", "Credential Access", "OS Credential Dumping")
        if executable in {"useradd", "adduser"}:
            return self._result("T1136", "Persistence", "Create Account")
        if executable in {"whoami", "id", "uname"}:
            return self._result("T1033", "Discovery", "System Owner/User Discovery")
        if executable in {"ps", "top", "netstat"}:
            return self._result("T1057", "Discovery", "Process Discovery")
        if executable == "history":
            return self._result("T1070", "Defense Evasion", "Indicator Removal")
        if executable in {"ssh", "telnet"}:
            return self._result("T1021", "Lateral Movement", "Remote Services")
        if executable in {"python", "perl", "bash"} and "-c" in tokens[1:]:
            return self._result("T1059", "Execution", "Command and Scripting Interpreter")
        if executable in {"rm", "shred"}:
            return self._result("T1485", "Impact", "Data Destruction")
        if executable in {"nmap", "ifconfig", "hostname"}:
            return self._result("T1082", "Discovery", "System Information Discovery")
        if executable in {"crontab"} or "systemctl enable" in command or "~/.bashrc" in command:
            return self._result("T1053", "Persistence", "Scheduled Task/Job")
        if executable in {"tar", "zip", "scp", "rsync"}:
            return self._result("T1041", "Exfiltration", "Exfiltration Over C2 Channel")
        if executable in {"ls", "pwd", "cd", "echo", "mkdir"}:
            return self._result("T1082", "Discovery", "System Information Discovery")
        if executable in {"cat", "head", "tail", "less", "more"}:
            return self._result("T1005", "Collection", "Data from Local System")
        if command.startswith("./"):
            return self._result("T1105", "Command and Control", "Payload Execution After Transfer")

        return self._unknown()

    def classify_event(self, event: dict[str, Any], recent_failed_logins: list[datetime] | None = None) -> dict[str, Any]:
        event_type = event.get("event_type") or event.get("eventid") or ""
        command = event.get("command") or event.get("input") or event.get("raw_command") or ""

        # Check non-command event types first
        if event_type in self.EVENT_MITRE:
            technique_id, tactic, description = self.EVENT_MITRE[event_type]
            return self._result_full(technique_id, tactic, description, self._tactic_weight(tactic))

        # Login events
        if event_type in {"cowrie.login.failed", "login.failed"}:
            if self.is_brute_force(recent_failed_logins or []):
                return self._tactic("BRUTE_FORCE", "T1110.001", "Credential Access", "Password Guessing")
            return self._tactic("LOGIN_FAILED", "T1110.001", "Credential Access", "Failed Login")

        # Command events — use command classification
        if event_type in {"cowrie.command.input", "command.input"}:
            mapping = self.classify_command(command)
            tactic = self.command_to_tactic(command)
            return {
                **mapping,
                "tactic": tactic,
                "risk_score": self.TACTIC_WEIGHTS.get(tactic, 0),
            }

        return self._unknown()

    def command_to_tactic(self, command: str) -> str:
        tokens = self._tokenize(command.strip())
        if not tokens:
            return "UNKNOWN"

        executable = tokens[0]
        if executable in {"nmap", "ifconfig", "netstat", "uname", "hostname", "whoami", "id", "ps", "top", "ls", "pwd", "cd", "echo", "mkdir"}:
            return "RECONNAISSANCE"
        if executable in {"wget", "curl"} or (executable == "chmod" and "+x" in tokens[1:]) or command.startswith("./"):
            return "MALWARE_DEPLOYMENT"
        if executable == "cat" and any(target in tokens[1:] for target in {"/etc/passwd", "/etc/shadow"}):
            return "CREDENTIAL_ACCESS"
        if executable in {"crontab"} or "systemctl enable" in command or "~/.bashrc" in command:
            return "PERSISTENCE"
        if executable in {"tar", "zip", "scp", "rsync"}:
            return "EXFILTRATION"
        if executable in {"python", "perl", "bash"} and "-c" in tokens[1:]:
            return "EXECUTION"
        if executable in {"cat", "head", "tail", "less", "more"}:
            return "DISCOVERY"
        return "UNKNOWN"

    def build_session_profile(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        history = []
        failed_logins = []

        for event in events:
            timestamp = event.get("timestamp") or datetime.now(UTC)
            event_type = event.get("event_type") or event.get("eventid") or ""
            if event_type in {"cowrie.login.failed", "login.failed"}:
                failed_logins.append(timestamp)

            classified = self.classify_event(event, failed_logins)
            tactic = classified.get("tactic")
            if tactic and tactic != "UNKNOWN":
                history.append(
                    {
                        "tactic": tactic,
                        "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp),
                        "mitre_technique_id": classified.get("mitre_technique_id"),
                    }
                )

        tactic_counts = Counter(item["tactic"] for item in history)
        risk_score = min(100, sum(self.TACTIC_WEIGHTS.get(tactic, 0) for tactic in tactic_counts))
        current_tactic = history[-1]["tactic"] if history else None
        return {
            "current_tactic": current_tactic,
            "tactic_history": history,
            "risk_score": risk_score,
            "severity": self.severity_from_score(risk_score),
        }

    def is_brute_force(self, failed_login_times: list[datetime]) -> bool:
        if len(failed_login_times) < 3:
            return False
        latest = max(failed_login_times)
        window_start = latest - timedelta(minutes=1)
        return sum(1 for item in failed_login_times if item >= window_start) > 2

    def severity_from_score(self, risk_score: int) -> str:
        if risk_score >= 85:
            return "CRITICAL"
        if risk_score >= 60:
            return "HIGH"
        if risk_score >= 30:
            return "MEDIUM"
        return "LOW"

    def _tactic_weight(self, tactic: str) -> int:
        return self.TACTIC_WEIGHTS.get(tactic, 0)

    def _tokenize(self, command: str) -> list[str]:
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()

    def _result(self, technique_id: str, tactic: str, description: str) -> dict[str, str]:
        return {
            "mitre_technique_id": technique_id,
            "mitre_tactic": tactic,
            "description": description,
        }

    def _result_full(self, technique_id: str, mitre_tactic: str, description: str, risk_score: int) -> dict[str, Any]:
        return {
            "mitre_technique_id": technique_id,
            "mitre_tactic": mitre_tactic,
            "description": description,
            "tactic": mitre_tactic.upper().replace(" ", "_"),
            "risk_score": risk_score,
        }

    def _tactic(self, tactic: str, technique_id: str, mitre_tactic: str, description: str) -> dict[str, Any]:
        return {
            "tactic": tactic,
            "mitre_technique_id": technique_id,
            "mitre_tactic": mitre_tactic,
            "description": description,
            "risk_score": self.TACTIC_WEIGHTS.get(tactic, 0),
        }

    def _unknown(self) -> dict[str, str]:
        return {
            "mitre_technique_id": "TBD",
            "mitre_tactic": "TBD",
            "description": "event classification pending",
        }