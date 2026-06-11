import logging
from pathlib import Path


class AdaptiveResponseLayer:
    def __init__(self, honeyfs_root: str = "/opt/cowrie/honeyfs") -> None:
        self.honeyfs_root = Path(honeyfs_root)
        self.logger = logging.getLogger(__name__)

    def apply(self, tactic: str, severity: str = "LOW") -> str:
        """Select and apply an adaptive deception based on the detected tactic
        and the session severity.

        Severity-aware escalation:
            - HIGH / CRITICAL sessions get a more aggressive variant when
              available (e.g. DECEPTIVE_BANNER → FAKE_OPEN_PORTS for
              RECONNAISSANCE).
        """
        handlers = {
            "INITIAL_ACCESS": self._deceptive_banner,
            "BRUTE_FORCE": self._honey_credentials,
            "RECONNAISSANCE": self._deceptive_banner,
            "DISCOVERY": self._inject_discovery_bait,
            "MALWARE_DEPLOYMENT": self._simulate_payload_download,
            "CREDENTIAL_ACCESS": self._honey_credentials,
            "EXECUTION": self._allow_fake_script_execution,
            "PERSISTENCE": self._enable_fake_persistence,
            "DEFENSE_EVASION": self._expose_fake_logs,
            "LATERAL_MOVEMENT": self._expose_fake_network,
            "COMMAND_AND_CONTROL": self._deploy_c2_decoy,
            "EXFILTRATION": self._fake_sensitive_files,
            "IMPACT": self._expose_fake_critical_files,
        }
        handler = handlers.get(tactic)
        if not handler:
            return "NO_ADAPTATION"

        strategy = handler()

        # Severity-based escalation: swap to more aggressive adaptation
        severity_upper = (severity or "LOW").upper()
        if severity_upper in ("HIGH", "CRITICAL"):
            strategy = self._escalate(tactic, strategy)

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

    # ── Tactic → Adaptation handlers ──────────────────────────────────

    def _honey_credentials(self) -> str:
        """Plant honey credentials that look like real admin credentials."""
        self._write(
            "/home/admin/.env",
            "DB_HOST=10.0.2.15\nDB_USER=app\nDB_PASSWORD=fake-prod-password\n"
            "ADMIN_USER=admin\nADMIN_PASS=H0n3yp0t_Trap!\n",
        )
        self._write(
            "/home/admin/.bash_history",
            "ssh admin@10.0.2.15\nmysql -u root -pR00tP@ss! production_db\n"
            "su - admin\ncat /etc/shadow\n",
        )
        return "HONEY_CREDENTIALS"

    def _deceptive_banner(self) -> str:
        """Present a deceptive SSH banner and fake service versions."""
        self._write(
            "/home/admin/.env",
            "DB_HOST=10.0.2.15\nDB_USER=app\nDB_PASSWORD=fake-prod-password\n",
        )
        self._write(
            "/var/www/config.yml",
            "api_key: fake_live_api_key_123\nsecret: fake_secret\n",
        )
        return "DECEPTIVE_BANNER"

    def _fake_open_ports(self) -> str:
        """Expose fake open-port information and internal network hints."""
        self._write(
            "/home/admin/ports.txt",
            "PORT  STATE SERVICE\n22    open  ssh\n80    open  http\n"
            "443   open  https\n3306  open  mysql\n5432  open  postgresql\n",
        )
        self._write(
            "/var/www/config.yml",
            "api_key: fake_live_api_key_123\nsecret: fake_secret\n",
        )
        return "FAKE_OPEN_PORTS"

    def _inject_discovery_bait(self) -> str:
        """Inject files that reward recon behavior to keep attacker exploring."""
        self._write(
            "/etc/os-release",
            'NAME="Ubuntu"\nVERSION="20.04.6 LTS"\nID=ubuntu\n'
            'VERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n',
        )
        self._write(
            "/proc/version",
            "Linux version 5.4.0-182-generic (buildd@lcy02-amd64-020) "
            "(gcc version 9.4.0) #202-Ubuntu SMP Fri Apr 26 12:29:36 UTC 2024\n",
        )
        return "DISCOVERY_BAIT_INJECTED"

    def _simulate_payload_download(self) -> str:
        self._write("/tmp/payload", "#!/bin/sh\necho simulated payload\n")
        self._write("/tmp/kworker", "fake binary placeholder\n")
        return "SIMULATED_MALWARE_DOWNLOAD"

    def _allow_fake_script_execution(self) -> str:
        """Place fake executable scripts to simulate code execution environment."""
        self._write("/tmp/update.sh", "#!/bin/bash\necho 'System update complete'\nexit 0\n")
        self._write(
            "/opt/app/deploy.sh",
            "#!/bin/bash\necho 'Deploying application v2.3.1'\nsleep 2\necho 'Done'\n",
        )
        return "RICH_FAKE_FILESYSTEM"

    def _enable_fake_persistence(self) -> str:
        self._write("/var/spool/cron/crontabs/admin", "# attacker-controlled fake crontab\n")
        return "FAKE_CRONTAB_ENABLED"

    def _expose_fake_logs(self) -> str:
        """Inject manipulatable fake logs to simulate a real system."""
        self._write(
            "/var/log/auth.log",
            "Jun 10 08:01:22 server sshd[1234]: Accepted password for admin from 192.168.1.5 port 51234 ssh2\n"
            "Jun 10 08:05:11 server sudo: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash\n",
        )
        return "FAKE_AUTH_LOGS_INJECTED"

    def _expose_fake_network(self) -> str:
        """Expose fake internal network topology to attract lateral movement."""
        self._write(
            "/etc/hosts",
            "127.0.0.1 localhost\n"
            "10.0.2.10 db-server.internal\n"
            "10.0.2.11 dev-server.internal\n"
            "10.0.2.12 backup.internal\n"
            "10.0.2.15 prod-db.internal\n",
        )
        self._write(
            "/home/admin/.ssh/known_hosts",
            "10.0.2.10 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfake...\n"
            "10.0.2.15 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfake2...\n",
        )
        return "FAKE_NETWORK_TOPOLOGY_EXPOSED"

    def _deploy_c2_decoy(self) -> str:
        """Simulate active C2 channel artifacts to keep attacker engaged."""
        self._write("/tmp/.x", "#!/bin/sh\nwhile true; do sleep 60; done\n")
        self._write("/tmp/.config", "server=10.0.2.99:4444\ntoken=fake_c2_token_abc123\n")
        return "C2_DECOY_DEPLOYED"

    def _fake_sensitive_files(self) -> str:
        """Plant fake sensitive files (db dumps, keys) to bait exfiltration tracking."""
        self._write("/home/admin/backups/customer_db.sql", "-- fake database dump\n")
        self._write("/home/admin/backups/payments.zip", "fake archive placeholder\n")
        return "FAKE_SENSITIVE_FILES"

    def _expose_fake_critical_files(self) -> str:
        """Plant fake critical system files to detect impact-phase activity."""
        self._write("/home/admin/backups/system_backup.tar.gz", "fake archive placeholder\n")
        self._write(
            "/root/encryption_key.pem",
            "-----BEGIN FAKE RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAfake...\n-----END FAKE RSA PRIVATE KEY-----\n",
        )
        return "FAKE_CRITICAL_FILES_EXPOSED"

    # ── Severity escalation ───────────────────────────────────────────

    @staticmethod
    def _escalate(tactic: str, base_strategy: str) -> str:
        """Return a more aggressive adaptation name for high-severity sessions."""
        escalation_map = {
            "RECONNAISSANCE": "FAKE_OPEN_PORTS",
            "CREDENTIAL_ACCESS": "FAKE_SHADOW_EXPOSED",
            "EXECUTION": "FAKE_SCRIPTS_PLANTED",
            "EXFILTRATION": "FAKE_CRITICAL_FILES_EXPOSED",
            "LATERAL_MOVEMENT": "FAKE_NETWORK_TOPOLOGY_EXPOSED",
            "DEFENSE_EVASION": "FAKE_AUTH_LOGS_INJECTED",
            "PERSISTENCE": "FAKE_CRONTAB_ENABLED",
            "COMMAND_AND_CONTROL": "C2_DECOY_DEPLOYED",
            "IMPACT": "FAKE_CRITICAL_FILES_EXPOSED",
        }
        return escalation_map.get(tactic, base_strategy)