import shlex
from datetime import UTC, datetime, timedelta
from typing import Any


class BehaviorEngine:
    TACTIC_WEIGHTS = {
        "UNKNOWN": 0,
        "LOGIN_FAILED": 0,
        "BRUTE_FORCE": 25,
        "RECONNAISSANCE": 15,
        "DISCOVERY": 10,
        "INITIAL_ACCESS": 20,
        "CREDENTIAL_ACCESS": 30,
        "EXECUTION": 30,
        "PERSISTENCE": 30,
        "DEFENSE_EVASION": 25,
        "LATERAL_MOVEMENT": 30,
        "COMMAND_AND_CONTROL": 25,
        "EXFILTRATION": 40,
        "IMPACT": 35,
        "MALWARE_DEPLOYMENT": 35,
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
        "cowrie.command.success": ("T1059.004", "Execution", "Unix Shell"),
        "command.success": ("T1059.004", "Execution", "Unix Shell"),
        "cowrie.command.failed": ("T1059", "Execution", "Command and Scripting Interpreter"),
        "command.failed": ("T1059", "Execution", "Command and Scripting Interpreter"),
        "cowrie.env.request": ("T1082", "Discovery", "System Information Discovery"),
        "env.request": ("T1082", "Discovery", "System Information Discovery"),
        "cowrie.ttyvars.request": ("T1082", "Discovery", "Terminal/TTY Discovery"),
        "ttyvars.request": ("T1082", "Discovery", "Terminal/TTY Discovery"),
        "cowrie.session.closed": ("T1562", "Defense Evasion", "Impair Defenses"),
        "session.closed": ("T1562", "Defense Evasion", "Impair Defenses"),
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
        if executable == "base64":
            return self._result("T1027", "Defense Evasion", "Obfuscated Files or Information")
        if executable in {"iptables", "ufw"}:
            return self._result("T1562.004", "Defense Evasion", "Disable or Modify System Firewall")
        if executable == "passwd":
            return self._result("T1098", "Persistence", "Account Manipulation")
        if executable in {"nc", "netcat", "ncat"}:
            return self._result("T1059.004", "Command and Control", "Unix Shell Reverse Shell")
        if executable in {"python3", "python"} and "-c" in tokens[1:]:
            return self._result("T1059.006", "Execution", "Python Script Execution")
        if executable in {"export", "env"}:
            return self._result("T1082", "Discovery", "Environment Variable Enumeration")
        if executable in {"kill", "pkill"}:
            return self._result("T1489", "Impact", "Service Stop")
        if executable in {"dd", "mkfs"}:
            return self._result("T1485", "Impact", "Data Destruction")
        if executable == "chmod":
            if "+x" in tokens[1:]:
                return self._result("T1059.004", "Execution", 
                                   "Command and Scripting Interpreter: Unix Shell")
            if "+777" in tokens[1:] or "777" in tokens[1:] or "a+x" in tokens[1:]:
                return self._result("T1222", "Defense Evasion", 
                                   "File and Directory Permissions Modification")
            # Any other chmod
            return self._result("T1222", "Defense Evasion",
                                "File and Directory Permissions Modification")
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
        if executable in {"perl", "bash"} and "-c" in tokens[1:]:
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

        # Login events
        if event_type in {"cowrie.login.failed", "login.failed"}:
            failed_logins = list(recent_failed_logins or [])
            timestamp = event.get("timestamp")
            if timestamp and timestamp not in failed_logins:
                failed_logins.append(timestamp)

            intensity = self.brute_force_intensity(failed_logins)
            if intensity:
                result = self._tactic("CREDENTIAL_ACCESS", "T1110.001", "Credential Access", "Brute Force: Password Guessing")
                result["internal_tactic"] = "CREDENTIAL_ACCESS"
                if intensity == "HEAVY":
                    result["risk_score"] = 35
                result["brute_force_intensity"] = intensity
                return result
            # Even individual failed logins contribute to CREDENTIAL_ACCESS tactic
            return self._tactic("CREDENTIAL_ACCESS", "T1110.001", "Credential Access", "Failed Login Attempt")

        # Check non-command event types after login.failed so brute force can be detected.
        if event_type in self.EVENT_MITRE:
            technique_id, tactic, description = self.EVENT_MITRE[event_type]
            return self._result_full(technique_id, tactic, description, self._tactic_weight(tactic))

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
        if executable in {"nmap", "ifconfig", "netstat"}:
            return "RECONNAISSANCE"
        if executable in {"uname", "hostname", "whoami", "id", "ps", "top", "ls", "pwd", "cd", "echo", "mkdir", "export", "env"}:
            return "DISCOVERY"
        if executable in {"wget", "curl"} or (executable == "chmod" and "+x" in tokens[1:]) or command.startswith("./"):
            return "MALWARE_DEPLOYMENT"
        if executable in {"nc", "netcat", "ncat"}:
            return "COMMAND_AND_CONTROL"
        if executable == "cat" and any(target in tokens[1:] for target in {"/etc/passwd", "/etc/shadow"}):
            return "CREDENTIAL_ACCESS"
        if executable in {"passwd", "crontab"} or "systemctl enable" in command or "~/.bashrc" in command:
            return "PERSISTENCE"
        if executable in {"base64", "iptables", "ufw", "history"}:
            return "DEFENSE_EVASION"
        if executable in {"ssh", "telnet"}:
            return "LATERAL_MOVEMENT"
        if executable in {"tar", "zip", "scp", "rsync"}:
            return "EXFILTRATION"
        if executable in {"python3", "python", "perl", "bash"} and "-c" in tokens[1:]:
            return "EXECUTION"
        if executable in {"cat", "head", "tail", "less", "more"}:
            return "DISCOVERY"
        if executable in {"kill", "pkill", "dd", "mkfs", "rm", "shred"}:
            return "IMPACT"
        return "UNKNOWN"

    def build_session_profile(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        history = []
        failed_logins = []
        risk_by_tactic: dict[str, int] = {}

        for event in events:
            timestamp = event.get("timestamp") or datetime.now(UTC)
            event_type = event.get("event_type") or event.get("eventid") or ""
            if event_type in {"cowrie.login.failed", "login.failed"}:
                failed_logins.append(timestamp)

            classified = self.classify_event(event, failed_logins)
            tactic = classified.get("tactic")
            if tactic and tactic != "UNKNOWN":
                risk_by_tactic[tactic] = max(risk_by_tactic.get(tactic, 0), classified.get("risk_score", 0))
                history.append(
                    {
                        "tactic": tactic,
                        "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp),
                        "mitre_technique_id": classified.get("mitre_technique_id"),
                    }
                )

        risk_score = min(100, sum(risk_by_tactic.values()))
        # Pick the dominant tactic: highest risk_score, ties broken by most recent
        current_tactic = self._dominant_tactic(history, risk_by_tactic)
        return {
            "current_tactic": current_tactic,
            "tactic_history": history,
            "risk_score": risk_score,
            "severity": self.severity_from_score(risk_score),
        }

    @staticmethod
    def _dominant_tactic(history: list[dict], risk_by_tactic: dict[str, int]) -> str | None:
        """Select the dominant tactic from session history.

        Uses highest risk_score; ties broken by most-recent occurrence.
        Returns None if history is empty.
        """
        if not history:
            return None
        # Build recency map: tactic → last timestamp index
        recency: dict[str, int] = {}
        for idx, entry in enumerate(history):
            t = entry.get("tactic")
            if t:
                recency[t] = idx
        # Sort: highest risk first, then most recent for ties
        ranked = sorted(
            risk_by_tactic.keys(),
            key=lambda t: (risk_by_tactic.get(t, 0), recency.get(t, 0)),
            reverse=True,
        )
        return ranked[0] if ranked else None

    def is_brute_force(self, failed_login_times: list[datetime]) -> bool:
        return self.brute_force_intensity(failed_login_times) is not None

    def brute_force_intensity(self, failed_login_times: list[datetime]) -> str | None:
        if len(failed_login_times) < 10:
            return None
        latest = max(failed_login_times)
        window_start = latest - timedelta(minutes=1)
        attempts = sum(1 for item in failed_login_times if item >= window_start)
        if attempts >= 20:
            return "HEAVY"
        if attempts >= 10:
            return "LIGHT"
        return None

    def severity_from_score(self, risk_score: int) -> str:
        if risk_score >= 85:
            return "CRITICAL"
        if risk_score >= 60:
            return "HIGH"
        if risk_score >= 30:
            return "MEDIUM"
        return "LOW"

    def _tactic_weight(self, tactic: str) -> int:
        return self.TACTIC_WEIGHTS.get(self._internal_tactic(tactic), 0)

    def _tokenize(self, command: str) -> list[str]:
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()

    def _result(self, technique_id: str, tactic: str, description: str) -> dict[str, str]:
        internal_tactic = self._internal_tactic(tactic)
        return {
            "mitre_technique_id": technique_id,
            "mitre_tactic": tactic,
            "internal_tactic": internal_tactic,
            "description": description,
        }

    def _result_full(self, technique_id: str, mitre_tactic: str, description: str, risk_score: int) -> dict[str, Any]:
        tactic = self._internal_tactic(mitre_tactic)
        return {
            "mitre_technique_id": technique_id,
            "mitre_tactic": mitre_tactic,
            "description": description,
            "tactic": tactic,
            "internal_tactic": tactic,
            "risk_score": risk_score,
        }

    def _tactic(self, tactic: str, technique_id: str, mitre_tactic: str, description: str) -> dict[str, Any]:
        return {
            "tactic": tactic,
            "internal_tactic": tactic,
            "mitre_technique_id": technique_id,
            "mitre_tactic": mitre_tactic,
            "description": description,
            "risk_score": self.TACTIC_WEIGHTS.get(tactic, 0),
        }

    def _internal_tactic(self, mitre_tactic: str) -> str:
        return mitre_tactic.upper().replace(" ", "_").replace("-", "_")

    def _unknown(self) -> dict[str, str]:
        return {
            "mitre_technique_id": "TBD",
            "mitre_tactic": "TBD",
            "description": "event classification pending",
        }
