# 🚀 Adaptive Honeypot System — Deploy to DigitalOcean VPS

## Сервер
- **IP**: 167.71.54.188
- **OS**: Ubuntu 24.04
- **Hardware**: 2 vCPU, 2GB RAM, 60GB SSD
- **Pre-installed**: Docker, Docker Compose, Git

---

## 1. Запушить репозиторий (локально)

```bash
cd /Users/farabi/Honeypot

# Если ещё нет git-репозитория — инициализируй
git init
git add .
git commit -m "Production-ready deploy config"

# Создай репозиторий на GitHub/GitLab и запушь
git remote add origin git@github.com:YOUR_USER/honeypot.git
git branch -M main
git push -u origin main
```

**.env НЕ попадёт в репозиторий** — он в `.gitignore`. Его скопируем отдельно.

---

## 2. Склонировать на VPS

```bash
ssh root@167.71.54.188

cd /opt
git clone git@github.com:YOUR_USER/honeypot.git
cd honeypot

# Скопировать .env с локальной машины (ВЫПОЛНИ С ЛОКАЛЬНОЙ МАШИНЫ):
# scp /Users/farabi/Honeypot/.env root@167.71.54.188:/opt/honeypot/.env

# Проверь что .env на месте
cat /opt/honeypot/.env | head -5
```

---

## 3. Скачать GeoIP базы (на VPS)

```bash
cd /opt/honeypot/geoip

# Зарегистрируйся на https://dev.maxmind.com/geolite2/signup и получи API-ключ
# Затем:
wget -O GeoLite2-City.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz"
wget -O GeoLite2-ASN.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_KEY&suffix=tar.gz"
tar xzf GeoLite2-City.tar.gz --strip-components=1
tar xzf GeoLite2-ASN.tar.gz --strip-components=1
chmod 644 *.mmdb
```

---

## 4. Запуск сервисов

```bash
cd /opt/honeypot

# Разрешить внешний доступ
sudo ufw allow 80/tcp
sudo ufw allow 2222/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# Собрать и запустить
docker compose up -d --build

# Проверить
docker compose ps
curl http://167.71.54.188/api/health
```

---

## 5. Проверка

- Dashboard: http://167.71.54.188
- API docs: http://167.71.54.188/docs
- SSH honeypot: `nc -zv 167.71.54.188 2222`

---

## 6. Обновление после изменений кода

```bash
# Локально
git add . && git commit -m "..." && git push

# На VPS
ssh root@167.71.54.188
cd /opt/honeypot
git pull
docker compose up -d --build
```

---

## Состав сервисов

| Сервис     | Порт                    | Назначение                   |
|------------|-------------------------|------------------------------|
| postgres   | 127.0.0.1:5432         | База данных                  |
| redis      | 127.0.0.1:6379         | Кэш + event-stream           |
| cowrie     | 0.0.0.0:2222           | SSH-honeypot (Docker Hub)    |
| backend    | 127.0.0.1:8000         | FastAPI REST + WebSocket     |
| collector  | нет                     | Логи cowrie → БД + Redis     |
| frontend   | 127.0.0.1:3001         | Next.js Dashboard            |
| nginx      | 0.0.0.0:80             | Reverse proxy                |