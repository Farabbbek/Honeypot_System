# 🛡️ Adaptive Honeypot System

Дипломный проект: адаптивный honeypot на базе Cowrie для автоматизированного обнаружения кибератак, классификации по MITRE ATT&CK, генерации LLM-отчётов, Telegram-уведомлений, экспорта PDF и визуализации в дашборде.

---

## Архитектура системы

```
                          ┌─────────────────────────┐
                          │     DigitalOcean VPS     │
                          │     167.71.54.188        │
                          └───────────┬─────────────┘
                                      │
                          ┌───────────▼─────────────┐
                          │   Nginx (port 80/443)   │
                          │   Reverse Proxy         │
                          │   /     → Dashboard     │
                          │   /api/ → Backend API   │
                          │   /ws/  → WebSocket     │
                          │   /docs → Swagger UI    │
                          └──┬──────────────────┬───┘
                             │                  │
              ┌──────────────▼────┐    ┌────────▼──────────┐
              │  Next.js Dashboard│    │  FastAPI Backend  │
              │  (127.0.0.1:3001) │    │  (127.0.0.1:8000) │
              │  React + Leaflet  │    │  REST + WebSocket │
              │  Chart.js + Cobe  │    │  Healthcheck      │
              └──────────────────┘    └────────┬──────────┘
                                               │
                              ┌────────────────┼────────────────┐
                              │                │                │
                   ┌──────────▼───┐  ┌─────────▼────┐  ┌───────▼──────┐
                   │  PostgreSQL  │  │    Redis     │  │  Collector   │
                   │  :5432       │  │   :6379      │  │  (log tail)  │
                   │  sessions,   │  │  event stream│  │  cowrie logs │
                   │  events,     │  │  + cache     │  │  → DB + Redis│
                   │  ip_intel,   │  └──────────────┘  └──────────────┘
                   │  reports     │
                   └──────────────┘
                                              │
                              ┌───────────────▼───────────────┐
                              │   Cowrie SSH Honeypot (2222)  │
                              │   Docker Hub: cowrie/cowrie   │
                              │   Принимает любые пароли      │
                              │   Логирует все команды        │
                              │   Fake filesystem (honeyfs)   │
                              └───────────────────────────────┘
                                              │
                              ┌───────────────▼───────────────┐
                              │        Интернет               │
                              │   Атакующие со всего мира     │
                              └───────────────────────────────┘
```

### Поток данных

```
Атакующий → SSH :2222 → Cowrie → cowrie.json → Collector
                                                    ├→ PostgreSQL (sessions, events)
                                                    ├→ Redis Stream (cowrie:events)
                                                    ├→ Behavior Engine (MITRE ATT&CK)
                                                    ├→ Adaptive Layer (fake filesystem)
                                                    ├→ IP Enrichment (GeoIP + AbuseIPDB)
                                                    ├→ LLM Agent (DeepSeek report)
                                                    ├→ Telegram Notifier
                                                    └→ PDF Exporter

Backend API ← PostgreSQL / Redis ← Dashboard (Next.js)
WebSocket /ws/alerts → Live Feed (real-time)
```

---

## Стек технологий

| Слой | Компонент | Технологии |
|------|-----------|------------|
| **Honeypot** | Cowrie | Python/Twisted, Docker Hub `cowrie/cowrie:latest` |
| **Backend** | FastAPI | Python 3.11, SQLAlchemy, Uvicorn |
| **Database** | PostgreSQL 16 | SQL schema auto-init |
| **Stream** | Redis 7 | `cowrie:events` stream, pub/sub |
| **Frontend** | Next.js 14 | React 18, Leaflet, Chart.js, Cobe globe, TailwindCSS |
| **Reverse Proxy** | Nginx 1.27-alpine | `/` → Dashboard, `/api/` → Backend, `/ws/` → WebSocket |
| **ML/AI** | DeepSeek V4 Pro | LLM threat reports |
| **Deployment** | Docker Compose | 7 контейнеров |
| **Hosting** | DigitalOcean VPS | Ubuntu 24.04, 2 vCPU, 2GB RAM, 60GB SSD |
| **Pipelines** | Git + GitHub | `git push` → `git pull` → `docker compose up -d --build` |

---

## Файловая структура

```
Honeypot_System/
├── .env.example              # шаблон переменных (без секретов)
├── .gitignore                # исключения: .env, node_modules, cowrie/cowrie/, ...
├── docker-compose.yml        # 7 сервисов: postgres, redis, cowrie, backend, collector, frontend, nginx
├── schema.sql                # DDL: sessions, events, ip_intel, threat_reports, password_stats
├── README.md                 # этот файл
├── DEPLOY.md                 # инструкция по деплою на VPS
│
├── backend/
│   ├── Dockerfile            # python:3.11-slim, HEALTHCHECK, EXPOSE 8000
│   ├── .dockerignore         # __pycache__, .venv, *.pyc
│   ├── requirements.txt      # 13 зависимостей
│   ├── main.py               # FastAPI приложение, 15 эндпоинтов + WebSocket
│   ├── collector.py          # читает cowrie.json → PostgreSQL + Redis
│   ├── database.py           # SQLAlchemy session + engine
│   ├── models.py             # ORM: Session, Event, IPIntel, ThreatReport, PasswordStat
│   ├── schemas.py            # Pydantic схемы ответов
│   ├── behavior_engine.py    # MITRE ATT&CK классификация (6 тактик)
│   ├── adaptive_layer.py     # динамическая подмена honeyfs
│   ├── analysis_service.py   # оркестрация: IP-обогащение + LLM + Telegram + PDF
│   ├── ip_enrichment.py      # GeoIP2 + AbuseIPDB
│   ├── llm_agent.py          # DeepSeek/OpenAI промпт → структурированный отчёт
│   ├── notifier.py           # Telegram Bot API
│   ├── pdf_export.py         # WeasyPrint HTML → PDF
│   └── reports/              # сгенерированные PDF + markdown
│
├── frontend/
│   ├── Dockerfile            # Multi-stage: builder + runner, ARG NEXT_PUBLIC_*
│   ├── .dockerignore         # node_modules, .next
│   ├── package.json          # Next.js 14, React 18, Leaflet, Chart.js, Cobe
│   ├── package-lock.json     # lockfile
│   ├── tailwind.config.js    # TailwindCSS 3
│   ├── postcss.config.js     # PostCSS + Autoprefixer
│   ├── styles.css            # Tailwind директивы
│   ├── public/               # статика
│   ├── pages/                # 8 роутов (index, sessions, threats, analytics, map, live-feed, ...)
│   └── components/           # 9 компонентов (KPICard, AttackMap, Globe3D, ThreatFeed, ...)
│
├── cowrie/
│   ├── cowrie.cfg            # конфиг SSH honeypot
│   ├── userdb.txt            # фейковые учётные данные
│   └── honeyfs/              # фейковая файловая система (etc/passwd, etc/shadow, ...)
│
├── nginx/
│   └── nginx.conf            # reverse proxy: / → :3001, /api/ → :8000, /ws/ → WebSocket
│
└── geoip/
    └── .gitkeep              # GeoLite2-City.mmdb + GeoLite2-ASN.mmdb (MaxMind)
```

---

## Полная хронология деплоя (сессия 21-22 мая 2026)

### Этап 1: Подготовка Docker-файлов для production

| Файл | Действие |
|------|----------|
| `backend/Dockerfile` | Обновлён: добавлены `EXPOSE 8000`, `HEALTHCHECK` |
| `backend/requirements.txt` | Добавлен `websockets>=12.0` |
| `backend/.dockerignore` | Создан: исключает `__pycache__`, `.venv`, `*.pyc` |
| `frontend/Dockerfile` | Переписан на multi-stage build: `builder` + `runner`, non-root user `nextjs`, `ARG NEXT_PUBLIC_API_URL` и `NEXT_PUBLIC_WS_URL` передаются на этапе сборки |
| `frontend/.dockerignore` | Создан: исключает `node_modules`, `.next` |

### Этап 2: Production docker-compose.yml

Создан единый Compose-файл с 7 сервисами:

| Сервис | Image/Build | Порт | Примечание |
|--------|-------------|------|------------|
| `postgres` | `postgres:16` | `127.0.0.1:5432` | healthcheck `pg_isready`, volumes для данных + schema auto-init |
| `redis` | `redis:7-alpine` | `127.0.0.1:6379` | healthcheck `redis-cli ping`, append-only |
| `cowrie` | `cowrie/cowrie:latest` | `0.0.0.0:2222` | Docker Hub, volumes: logs + downloads + configs |
| `backend` | build `backend/` | `127.0.0.1:8000` | FastAPI, healthcheck HTTP, depends_on postgres + redis |
| `collector` | build `backend/` | нет | `command: python collector.py`, depends_on postgres + redis + cowrie |
| `frontend` | build `frontend/` | `127.0.0.1:3001` | Next.js, build args для `NEXT_PUBLIC_*`, depends_on backend |
| `nginx` | `nginx:1.27-alpine` | `0.0.0.0:80` | reverse proxy, зависит от frontend + backend |

**Ключевое архитектурное решение**: все сервисы кроме nginx (порт 80) и cowrie (порт 2222) привязаны к `127.0.0.1` — недоступны извне, безопасность на уровне сетевого стека.

### Этап 3: Nginx reverse proxy

`/` → `frontend:3001` (дашборд)  
`/api/` → `backend:8000` (REST API)  
`/ws/` → `backend:8000` (WebSocket с `Upgrade`)  
`/docs` → `backend:8000/docs` (Swagger UI)  
`/openapi.json` → `backend:8000/openapi.json`

### Этап 4: Git-flow и деплой на VPS

1. **Локально**: `git init`, `git add .`, `git commit`, `git push origin main`
2. **На VPS**: `git clone`, добавлен `.env` через `scp` (НЕ в репозитории — `.gitignore`)
3. **Сборка**: `docker compose up -d --build`
4. **UFW**: порты 80, 2222, 443 открыты

### Этап 5: Решённые проблемы

| Проблема | Причина | Решение |
|----------|--------|---------|
| `Module not found: autoprefixer` | `npm ci --omit=dev` исключал devDependencies нужные для сборки Next.js | Убрал `--omit=dev`, используется `npm ci` |
| `COPY /app/public: not found` | Не было папки `public/` в проекте | Создал `frontend/public/.gitkeep` |
| `address already in use :80` | Системный nginx на VPS держал порт 80 | `sudo systemctl stop nginx && sudo systemctl disable nginx` |
| `{"detail":"Not Found"} /api/health` | Backend имел `/health`, nginx проксировал `/api/health` → `/api/health` не существовало | Добавлен `@app.get("/api/health")` в FastAPI |
| CORS `loopback` ошибки в браузере | `NEXT_PUBLIC_API_URL` вшивается на этапе сборки, а не передавался | Добавлен `ARG` + `ENV` в Dockerfile и `args:` в docker-compose.yml → `NEXT_PUBLIC_API_URL=http://167.71.54.188/api` |

### Этап 6: Финальное состояние

**7 контейнеров в статусе Up на VPS `167.71.54.188`:**

```
honeypot-nginx        Up  0.0.0.0:80→80
honeypot-dashboard    Up  127.0.0.1:3001→3001
honeypot-api          Up  127.0.0.1:8000→8000 (healthy)
honeypot-collector    Up  обработка логов
cowrie                Up  0.0.0.0:2222→2222
honeypot-db           Up  127.0.0.1:5432→5432 (healthy)
honeypot-redis        Up  127.0.0.1:6379→6379 (healthy)
```

**Проверка работоспособности:**
```bash
curl http://167.71.54.188/api/health        # → {"status":"ok"}
curl http://167.71.54.188/api/stats         # → {"total_attacks":0,...}
curl http://167.71.54.188/api/sessions      # → [] (пусто до первой атаки)
ssh -p 2222 root@167.71.54.188             # → принимает ЛЮБОЙ пароль
http://167.71.54.188                        # → дашборд
http://167.71.54.188/docs                   # → Swagger UI
http://167.71.54.188/sessions               # → страница сессий
```

---

## Управление системой

```bash
# Деплой после изменений кода
ssh root@167.71.54.188
cd /opt/honeypot-app/Honeypot_System
git pull
docker compose up -d --build

# Логи
docker compose logs -f backend
docker compose logs -f collector
docker compose logs -f cowrie

# Статус
docker compose ps

# Перезапуск одного сервиса
docker compose restart backend

# Полная остановка
docker compose down

# Остановка с удалением данных (⚠️ сброс БД)
docker compose down -v
```

---

## API эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/health` | Healthcheck |
| `GET` | `/api/health` | Healthcheck (через nginx) |
| `GET` | `/api/sessions` | Список сессий (пагинация, фильтры) |
| `GET` | `/api/sessions/{id}` | Детали сессии + события + отчёт + IP intel |
| `GET` | `/api/stats` | Статистика: top IP, страны, тактики, пароли |
| `GET` | `/api/threats` | Список threat reports |
| `POST` | `/api/threats/{session_id}/analyze` | Сгенерировать LLM-отчёт |
| `GET` | `/api/threats/{report_id}/export` | Скачать PDF |
| `POST` | `/api/threats/{report_id}/notify` | Отправить в Telegram |
| `GET` | `/api/map` | Данные для карты (GeoIP координаты) |
| `GET` | `/api/geoip/{ip}` | GeoIP enrichment для одного IP |
| `GET` | `/api/geoip/batch` | Batch GeoIP enrichment |
| `GET` | `/api/telegram/diagnose` | Статус Telegram-бота |
| `WS` | `/ws/alerts` | Real-time WebSocket алерты |

---

## MITRE ATT&CK классификация (Behavior Engine)

| Тактика | Техника | Триггеры |
|---------|---------|----------|
| `RECONNAISSANCE` | T1590 | `uname`, `ifconfig`, `netstat`, `nmap`, `hostname` |
| `BRUTE_FORCE` | T1110.001 | >30 failed logins/min |
| `CREDENTIAL_ACCESS` | T1003 | `cat /etc/shadow`, `cat /etc/passwd`, `whoami`, `id` |
| `MALWARE_DEPLOYMENT` | T1105 | `wget`, `curl`, `chmod +x`, `./payload` |
| `PERSISTENCE` | T1546 | `crontab`, `systemctl enable`, `~/.bashrc` |
| `EXFILTRATION` | T1560 | `tar`, `zip`, `scp`, `rsync` |

---

## Безопасность

- **`.env` в `.gitignore`** — API-ключи и пароли НЕ в репозитории
- **Все сервисы кроме nginx:80 и cowrie:2222** привязаны к `127.0.0.1`
- **Cowrie запущен от непривилегированного пользователя** внутри контейнера
- **Next.js frontend собран с `NODE_ENV=production`**
- **UFW** разрешает только 80/tcp + 2222/tcp + 443/tcp

---

## Требования

- Docker + Docker Compose
- Git
- MaxMind GeoLite2 API key (опционально, для гео-обогащения)
- DeepSeek API key (опционально, для LLM-отчётов)
- AbuseIPDB API key (опционально, для IP-репутации)
- Telegram Bot Token + Chat ID (опционально, для уведомлений)