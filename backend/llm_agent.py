import json
import os
from typing import Any

try:
    from openai import AsyncOpenAI
except ImportError:  # pragma: no cover
    AsyncOpenAI = None


SYSTEM_PROMPT = """
You are a senior cybersecurity analyst and threat intelligence expert.
Analyze SSH honeypot session logs and return ONLY valid JSON with professional language.
No markdown and no extra commentary. Map detected behaviors to MITRE ATT&CK techniques.
"""

USER_PROMPT = """
Analyze this honeypot session:

Attacker IP: {attacker_ip}
Country: {country} | City: {city}
ASN: {asn} | Org: {org}
AbuseIPDB Score: {abuse_score}%
Session duration: {duration}s
Login attempts: {login_attempts}
Successful login: {successful_login}
Detected tactics: {tactics_list}

Commands executed:
{commands_with_timestamps}

Downloaded files: {downloaded_files}

Return JSON:
{{
  "attack_type": "short attack name",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "mitre_techniques": [{{"id": "T1110.001", "name": "Password Guessing"}}],
  "kill_chain_phase": "Reconnaissance|Weaponization|Delivery|Exploitation|Installation|C2|Exfiltration",
  "attacker_goal": "one sentence",
  "attacker_profile": "human|automated|botnet|apt",
  "summary": "2-3 sentence executive summary",
  "impact": "short paragraph on impact and risk",
  "key_findings": ["bullet 1", "bullet 2"],
  "detection_opportunities": ["log source or rule idea"],
  "recommendations": {{
    "immediate": ["action 1", "action 2"],
    "short_term": ["action 1"],
    "long_term": ["action 1"]
  }},
  "ioc": {{
    "ip": "{attacker_ip}",
    "country": "{country}",
    "city": "{city}",
    "asn": "{asn}",
    "org": "{org}",
    "abuse_score": {abuse_score},
    "usernames_tried": [],
    "passwords_tried": [],
    "tools_detected": [],
    "malware_urls": []
  }},
  "recommendation": "single-sentence priority action",
  "timeline": [
    {{"timestamp": "2026-05-21T11:18:14Z", "event": "cowrie.command.input", "command": "uname -a", "mitre": "T1082"}}
  ],
  "confidence": 0.0
}}
"""


class LLMAgent:
    def __init__(self) -> None:
        self.provider = os.getenv("LLM_PROVIDER", "openai").lower()
        self.model = self._model_name()
        self.client = self._client()

    async def analyze_session(self, session: dict[str, Any], events: list[dict[str, Any]], ip_intel: dict[str, Any] | None) -> dict[str, Any]:
        if not self.client:
            return self.fallback_report(session, events, ip_intel)

        prompt = self.build_prompt(session, events, ip_intel)
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            content = response.choices[0].message.content or "{}"
            report = json.loads(content)
            report["raw_llm_response"] = content
            return report
        except Exception as exc:
            report = self.fallback_report(session, events, ip_intel)
            report["raw_llm_response"] = f"llm_error: {type(exc).__name__}: {exc}"
            return report

    def build_prompt(self, session: dict[str, Any], events: list[dict[str, Any]], ip_intel: dict[str, Any] | None) -> str:
        ip_intel = ip_intel or {}
        commands = self.commands_with_timestamps(events)
        downloaded_files = self.downloaded_files(events)
        tactics = session.get("tactic_history") or []

        return USER_PROMPT.format(
            attacker_ip=session.get("attacker_ip", "unknown"),
            country=ip_intel.get("country_name") or "unknown",
            city=ip_intel.get("city") or "unknown",
            asn=ip_intel.get("asn") or "unknown",
            org=ip_intel.get("org_name") or "unknown",
            abuse_score=ip_intel.get("abuse_confidence_score") or 0,
            duration=session.get("duration_seconds") or 0,
            login_attempts=session.get("login_attempts") or 0,
            successful_login=session.get("successful_login") or False,
            tactics_list=json.dumps(tactics, default=str),
            commands_with_timestamps=commands or "No commands executed.",
            downloaded_files=json.dumps(downloaded_files, default=str),
        )

    def fallback_report(self, session: dict[str, Any], events: list[dict[str, Any]], ip_intel: dict[str, Any] | None) -> dict[str, Any]:
        techniques = [
            {"id": technique_id, "name": self.technique_name(technique_id)}
            for technique_id in sorted(
                {
                    event.get("mitre_technique")
                    for event in events
                    if event.get("mitre_technique") and event.get("mitre_technique") != "unknown"
                }
            )
        ]
        commands = [event.get("raw_command") for event in events if event.get("raw_command")]
        severity = session.get("severity") or "LOW"
        report = {
            "attack_type": "Automated SSH attack activity",
            "severity": severity,
            "mitre_techniques": techniques,
            "kill_chain_phase": "Exploitation",
            "attacker_goal": "Gain unauthorized access and explore the environment",
            "attacker_profile": "Automated scanner or opportunistic bot",
            "summary": "Automated SSH activity observed with reconnaissance and credential access behaviors.",
            "impact": "Likely intent to establish access and collect credentials. Risk depends on exposure of SSH and reuse of credentials.",
            "key_findings": [
                "Credential access behavior detected in session commands.",
                "Multiple discovery and reconnaissance commands executed.",
            ],
            "detection_opportunities": [
                "Alert on sequences of wget/curl followed by chmod and execution.",
                "Correlate repeated failed logins with subsequent successful access.",
            ],
            "recommendations": {
                "immediate": [
                    "Block the source IP and known malicious URLs.",
                    "Review SSH access logs for related activity.",
                ],
                "short_term": [
                    "Disable password authentication and enforce SSH keys.",
                    "Harden SSH with allowlists and MFA where possible.",
                ],
                "long_term": [
                    "Deploy centralized logging and detection rules for SSH abuse.",
                ],
            },
            "ioc": {
                "ip": session.get("attacker_ip"),
                "country": (ip_intel or {}).get("country_name"),
                "city": (ip_intel or {}).get("city"),
                "asn": (ip_intel or {}).get("asn"),
                "org": (ip_intel or {}).get("org_name"),
                "abuse_score": (ip_intel or {}).get("abuse_confidence_score"),
                "usernames_tried": sorted(
                    {
                        event.get("event_data", {}).get("username")
                        for event in events
                        if event.get("event_data", {}).get("username")
                    }
                ),
                "passwords_tried": sorted(
                    {
                        event.get("event_data", {}).get("password")
                        for event in events
                        if event.get("event_data", {}).get("password")
                    }
                ),
                "tools_detected": sorted({cmd.split()[0] for cmd in commands if cmd}),
                "malware_urls": self.downloaded_files(events),
            },
            "recommendation": "Block the source IP, review SSH exposure, enforce key-based auth and monitor for repeated attempts.",
            "timeline": self.build_timeline(events),
            "confidence": 0.75,
        }
        report["raw_llm_response"] = json.dumps(report, default=str)
        return report

    def commands_with_timestamps(self, events: list[dict[str, Any]]) -> str:
        lines = []
        for event in events:
            command = event.get("raw_command")
            if command:
                lines.append(f"{event.get('timestamp')}: {command}")
        return "\n".join(lines)

    def downloaded_files(self, events: list[dict[str, Any]]) -> list[str]:
        downloads = []
        for event in events:
            data = event.get("event_data") or {}
            url = data.get("url") or data.get("outfile") or data.get("shasum")
            if event.get("event_type") in {"cowrie.session.file_download", "cowrie.command.input"} and url:
                downloads.append(str(url))
            command = event.get("raw_command") or ""
            if command.startswith(("wget ", "curl ")):
                downloads.append(command)
        return downloads

    def build_timeline(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        timeline: list[dict[str, Any]] = []
        for event in events:
            entry = {
                "timestamp": event.get("timestamp"),
                "event": event.get("event_type"),
                "command": event.get("raw_command"),
                "mitre": event.get("mitre_technique"),
            }
            if entry["timestamp"] or entry["event"] or entry["command"]:
                timeline.append(entry)
        return timeline

    def technique_name(self, technique_id: str) -> str:
        names = {
            "T1003": "OS Credential Dumping",
            "T1021": "Remote Services",
            "T1033": "System Owner/User Discovery",
            "T1041": "Exfiltration Over C2 Channel",
            "T1053": "Scheduled Task/Job",
            "T1057": "Process Discovery",
            "T1059": "Command and Scripting Interpreter",
            "T1059.004": "Unix Shell",
            "T1070": "Indicator Removal",
            "T1082": "System Information Discovery",
            "T1105": "Ingress Tool Transfer",
            "T1110.001": "Password Guessing",
            "T1136": "Create Account",
            "T1566": "Phishing",
        }
        return names.get(technique_id, "Unknown Technique")

    def _client(self):
        if not AsyncOpenAI:
            return None

        if self.provider == "deepseek":
            api_key = os.getenv("DEEPSEEK_API_KEY")
            if not api_key:
                return None
            return AsyncOpenAI(
                api_key=api_key,
                base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            )

        api_key = os.getenv("OPENAI_API_KEY")
        return AsyncOpenAI(api_key=api_key) if api_key else None

    def _model_name(self) -> str:
        if self.provider == "deepseek":
            return os.getenv("DEEPSEEK_MODEL", "deepseek-v4-pro")
        return os.getenv("OPENAI_MODEL", "gpt-4o-mini")
