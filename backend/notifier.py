import ipaddress
import logging
import os
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class TelegramNotifier:
    def __init__(self) -> None:
        self.token = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip() or None
        self.chat_id = (os.getenv("TELEGRAM_CHAT_ID") or "").strip() or None
        self.dashboard_url = (os.getenv("DASHBOARD_URL") or "http://localhost:3000").strip()
        self._last_sent_by_ip: dict[str, float] = {}
        self.last_error: str | None = None

    async def send_attack_alert(self, report: dict[str, Any]) -> bool:
        self.last_error = None
        if not self.token or not self.chat_id:
            self.last_error = "Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID"
            return False

        ioc = report.get("ioc") or {}
        ip = ioc.get("ip", "unknown")
        now = time.time()
        if now - self._last_sent_by_ip.get(ip, 0) < 60:
            self.last_error = "Notification suppressed by rate limit"
            return False

        text = self.format_alert(report)
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        async with httpx.AsyncClient(timeout=5) as client:
            try:
                response = await client.post(
                    url,
                    json={
                        "chat_id": self.chat_id,
                        "text": text,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True,
                    },
                )
            except httpx.RequestError as exc:
                self.last_error = f"Telegram request failed: {type(exc).__name__}: {exc}"
                logger.warning("Telegram request failed", exc_info=True)
                return False

        if response.status_code >= 400:
            self.last_error = self._extract_telegram_error(response)
            if "parse" in (self.last_error or "").lower():
                # Fallback: send without parse_mode
                async with httpx.AsyncClient(timeout=5) as client:
                    try:
                        response = await client.post(
                            url,
                            json={
                                "chat_id": self.chat_id,
                                "text": text,
                                "disable_web_page_preview": True,
                            },
                        )
                    except httpx.RequestError as exc:
                        self.last_error = f"Telegram request failed: {type(exc).__name__}: {exc}"
                        return False
            else:
                logger.warning("Telegram API error: %s", self.last_error)
                return False

        self._last_sent_by_ip[ip] = now
        return True

    async def diagnose(self) -> dict[str, Any]:
        if not self.token:
            return {"ok": False, "error": "Missing TELEGRAM_BOT_TOKEN"}

        base_url = f"https://api.telegram.org/bot{self.token}"
        async with httpx.AsyncClient(timeout=5) as client:
            try:
                me_response = await client.get(f"{base_url}/getMe")
                me_data = me_response.json()
            except httpx.RequestError as exc:
                return {"ok": False, "error": f"Telegram request failed: {type(exc).__name__}: {exc}"}
            except ValueError:
                return {"ok": False, "error": "Telegram getMe returned invalid JSON"}

            if not me_data.get("ok"):
                return {"ok": False, "error": me_data.get("description", "Telegram getMe failed")}

            try:
                updates_response = await client.get(f"{base_url}/getUpdates")
                updates_data = updates_response.json()
            except httpx.RequestError as exc:
                return {"ok": False, "error": f"Telegram request failed: {type(exc).__name__}: {exc}", "bot": me_data.get("result")}
            except ValueError:
                return {"ok": False, "error": "Telegram getUpdates returned invalid JSON", "bot": me_data.get("result")}

        if not updates_data.get("ok"):
            return {
                "ok": False,
                "error": updates_data.get("description", "Telegram getUpdates failed"),
                "bot": me_data.get("result"),
            }

        chats: list[dict[str, Any]] = []
        seen: set[int] = set()
        for item in updates_data.get("result", []):
            candidate = (
                item.get("message")
                or item.get("edited_message")
                or item.get("channel_post")
                or item.get("my_chat_member")
            )
            if not isinstance(candidate, dict):
                continue
            chat = candidate.get("chat")
            if not isinstance(chat, dict):
                continue
            chat_id = chat.get("id")
            if chat_id is None or chat_id in seen:
                continue
            seen.add(chat_id)
            chats.append(
                {
                    "id": chat_id,
                    "type": chat.get("type"),
                    "title": chat.get("title"),
                    "username": chat.get("username"),
                }
            )

        return {"ok": True, "bot": me_data.get("result"), "chat_candidates": chats}

    def format_alert(self, report: dict[str, Any]) -> str:
        ioc = report.get("ioc") or {}
        ip = ioc.get("ip", "unknown")
        country = ioc.get("country") or "unknown"
        city = ioc.get("city") or ""
        location = self.format_location(city, country, ip)
        abuse_score = ioc.get("abuse_score")
        abuse_label = self.format_abuse_score(abuse_score, ip)
        session_id = report.get("session_id", "unknown")
        severity = (report.get("severity") or "UNKNOWN").upper()
        attack_type = report.get("attack_type") or "Unknown Attack"
        confidence = report.get("confidence")
        conf_label = f"{confidence:.0%}" if isinstance(confidence, (int, float)) else "N/A"

        severity_emoji = {"CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0", "MEDIUM": "\U0001f7e1", "LOW": "\U0001f7e2"}
        emoji = severity_emoji.get(severity, "\u26a0\ufe0f")

        techniques = report.get("mitre_techniques") or []
        tech_lines: list[str] = []
        if isinstance(techniques, list) and techniques and isinstance(techniques[0], dict):
            for t in techniques[:5]:
                tid = t.get("id", "?")
                tname = t.get("name", "?")
                tech_lines.append(f"\u2022 <code>{tid}</code> — {tname}")

        link = f"{self.dashboard_url}/sessions/{session_id}"

        lines = [
            f"{emoji} <b>{severity} ATTACK DETECTED</b> {emoji}",
            "",
            "<b>Attack Type:</b> " + attack_type,
            "<b>Confidence:</b> " + conf_label,
            "",
            "\U0001f310 <b>Attacker Information</b>",
            "<b>IP:</b> <code>" + ip + "</code>",
            "<b>Location:</b> " + location,
            "<b>Abuse Score:</b> " + abuse_label,
        ]

        # Add TOR/VPN if relevant
        if ioc.get("is_tor"):
            lines.append("\U0001f300 TOR Exit Node")
        if ioc.get("is_vpn"):
            lines.append("\U0001f510 VPN/Proxy detected")

        lines.append("")

        if tech_lines:
            lines.append("\U0001f9e0 <b>MITRE ATT&CK Techniques</b>")
            lines.extend(tech_lines)
            lines.append("")

        lines.append("\U0001f4cb <b>Actions</b>")
        lines.append(f"\U0001f517 <a href='{link}'>View Full Report</a>")

        return "\n".join(lines)

    def format_location(self, city: str, country: str, ip: str) -> str:
        if self.is_private_ip(ip):
            return "Private network"
        if city and country and country.lower() != "unknown":
            return f"{city}, {country}"
        if country and country.lower() != "unknown":
            return country
        return "unknown"

    def format_abuse_score(self, abuse_score: Any, ip: str) -> str:
        if self.is_private_ip(ip):
            return "N/A (private IP)"
        if abuse_score is None:
            return "N/A"
        score = int(abuse_score)
        if score >= 80:
            return f"\U0001f534 {score}% (Malicious)"
        if score >= 40:
            return f"\U0001f7e1 {score}% (Suspicious)"
        return f"\U0001f7e2 {score}% (Low)"

    def is_private_ip(self, ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved

    @staticmethod
    def _extract_telegram_error(response: httpx.Response) -> str:
        try:
            data = response.json()
        except ValueError:
            return f"Telegram API error {response.status_code}: invalid JSON"

        description = data.get("description") if isinstance(data, dict) else None
        if description:
            return f"Telegram API error {response.status_code}: {description}"
        return f"Telegram API error {response.status_code}"