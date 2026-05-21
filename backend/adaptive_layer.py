import logging
from pathlib import Path


class AdaptiveResponseLayer:
    def __init__(self, honeyfs_root: str = "/opt/cowrie/honeyfs") -> None:
        self.honeyfs_root = Path(honeyfs_root)
        self.logger = logging.getLogger(__name__)

    def apply(self, tactic: str) -> str:
        handlers = {
            "BRUTE_FORCE": self._allow_login_after_bruteforce,
            "RECONNAISSANCE": self._inject_recon_files,
            "MALWARE_DEPLOYMENT": self._simulate_payload_download,
            "CREDENTIAL_ACCESS": self._inject_fake_shadow,
            "PERSISTENCE": self._enable_fake_persistence,
            "EXFILTRATION": self._add_fake_valuable_files,
        }
        handler = handlers.get(tactic)
        if not handler:
            return "NO_ADAPTATION"
        strategy = handler()
        self.reload_cowrie()
        return strategy

    def reload_cowrie(self) -> None:
        self.logger.info("Cowrie reload requested. Configure COWRIE_API_URL for production reloads.")

    def _write(self, path: str, content: str) -> None:
        target = self.honeyfs_root / path.lstrip("/")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        except OSError as exc:
            self.logger.warning("Cannot write adaptive file %s: %s", target, exc)

    def _allow_login_after_bruteforce(self) -> str:
        return "ALLOW_LOGIN_AFTER_30_ATTEMPTS"

    def _inject_recon_files(self) -> str:
        self._write("/home/admin/.env", "DB_HOST=10.0.2.15\nDB_USER=app\nDB_PASSWORD=fake-prod-password\n")
        self._write("/var/www/config.yml", "api_key: fake_live_api_key_123\nsecret: fake_secret\n")
        return "RICH_FAKE_FILESYSTEM"

    def _simulate_payload_download(self) -> str:
        self._write("/tmp/payload", "#!/bin/sh\necho simulated payload\n")
        self._write("/tmp/kworker", "fake binary placeholder\n")
        return "SIMULATED_MALWARE_DOWNLOAD"

    def _inject_fake_shadow(self) -> str:
        self._write(
            "/etc/shadow",
            "root:$6$fakeSalt$8zQfakehashfakehashfakehash:19700:0:99999:7:::\n"
            "admin:$6$prodSalt$fakefakefakefakefakefakefake:19700:0:99999:7:::\n",
        )
        return "FAKE_SHADOW_EXPOSED"

    def _enable_fake_persistence(self) -> str:
        self._write("/var/spool/cron/crontabs/admin", "# attacker-controlled fake crontab\n")
        return "FAKE_CRONTAB_ENABLED"

    def _add_fake_valuable_files(self) -> str:
        self._write("/home/admin/backups/customer_db.sql", "-- fake database dump\n")
        self._write("/home/admin/backups/payments.zip", "fake archive placeholder\n")
        return "FAKE_EXFILTRATION_TARGETS"
