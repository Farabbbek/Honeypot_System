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
            "DISCOVERY": self._inject_discovery_bait,
            "MALWARE_DEPLOYMENT": self._simulate_payload_download,
            "CREDENTIAL_ACCESS": self._inject_fake_shadow,
            "EXECUTION": self._allow_fake_script_execution,
            "PERSISTENCE": self._enable_fake_persistence,
            "DEFENSE_EVASION": self._expose_fake_logs,
            "LATERAL_MOVEMENT": self._expose_fake_network,
            "COMMAND_AND_CONTROL": self._deploy_c2_decoy,
            "EXFILTRATION": self._add_fake_valuable_files,
            "IMPACT": self._expose_fake_critical_files,
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
        """Allow fake login after the 10-attempt brute-force threshold."""
        return "ALLOW_LOGIN_AFTER_10_ATTEMPTS"

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

    def _deploy_c2_decoy(self) -> str:
        """Simulate active C2 channel artifacts to keep attacker engaged."""
        self._write("/tmp/.x", "#!/bin/sh\nwhile true; do sleep 60; done\n")
        self._write("/tmp/.config", "server=10.0.2.99:4444\ntoken=fake_c2_token_abc123\n")
        return "C2_DECOY_DEPLOYED"

    def _expose_fake_network(self) -> str:
        """Expose fake internal network topology to attract lateral movement."""
        self._write(
            "/etc/hosts",
            (
                "127.0.0.1 localhost\n"
                "10.0.2.10 db-server.internal\n"
                "10.0.2.11 dev-server.internal\n"
                "10.0.2.12 backup.internal\n"
                "10.0.2.15 prod-db.internal\n"
            ),
        )
        self._write(
            "/home/admin/.ssh/known_hosts",
            (
                "10.0.2.10 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfake...\n"
                "10.0.2.15 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfake2...\n"
            ),
        )
        return "FAKE_NETWORK_TOPOLOGY_EXPOSED"

    def _expose_fake_logs(self) -> str:
        """Inject manipulatable fake logs to simulate a real system."""
        self._write(
            "/var/log/auth.log",
            (
                "Jun 10 08:01:22 server sshd[1234]: Accepted password for admin from 192.168.1.5 port 51234 ssh2\n"
                "Jun 10 08:05:11 server sudo: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash\n"
            ),
        )
        return "FAKE_AUTH_LOGS_INJECTED"

    def _allow_fake_script_execution(self) -> str:
        """Place fake executable scripts to simulate code execution environment."""
        self._write("/tmp/update.sh", "#!/bin/bash\necho 'System update complete'\nexit 0\n")
        self._write(
            "/opt/app/deploy.sh",
            "#!/bin/bash\necho 'Deploying application v2.3.1'\nsleep 2\necho 'Done'\n",
        )
        return "FAKE_SCRIPTS_PLANTED"

    def _expose_fake_critical_files(self) -> str:
        """Plant fake critical system files to detect impact-phase activity."""
        self._write("/home/admin/backups/system_backup.tar.gz", "fake archive placeholder\n")
        self._write(
            "/root/encryption_key.pem",
            "-----BEGIN FAKE RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAfake...\n-----END FAKE RSA PRIVATE KEY-----\n",
        )
        return "FAKE_CRITICAL_FILES_EXPOSED"

    def _inject_discovery_bait(self) -> str:
        """Inject files that reward recon behavior to keep attacker exploring."""
        self._write(
            "/etc/os-release",
            (
                'NAME="Ubuntu"\nVERSION="20.04.6 LTS"\nID=ubuntu\n'
                'VERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n'
            ),
        )
        self._write(
            "/proc/version",
            "Linux version 5.4.0-182-generic (buildd@lcy02-amd64-020) (gcc version 9.4.0) #202-Ubuntu SMP Fri Apr 26 12:29:36 UTC 2024\n",
        )
        return "DISCOVERY_BAIT_INJECTED"
