# Obelisk — API для бэкенда (базы)

Это контракт между **Кенни-бэкендом (базой)** и узлом **Obelisk**. Бэкенд — единственный,
кто управляет Obelisk по Service API. Он же выдаёт лаунчеру конфиг, по которому **Phantom
на машине игрока** подключается к Obelisk и отдаёт Minecraft (или другую игру) через туннель.

## Схема

```
[Launcher: Phantom]  --config-->  [Obelisk (public node)]  <--X-Service-Key--  [Kennie Backend / DB]
        игрок входит        туннель control/data                     управляет юзерами + портами
```

## Авторизация

Все запросы бэкенда идут по `POST/GET/DELETE` и требуют заголовок:

```
X-Service-Key: <service_api_key>
```

Плюс опциональный IP-allowlist `allow_api_peers` (если задан, IP бэкенда должен быть в списке).
`GET /api/health` — без авторизации (для вачдога). База: `https://<web_bind>:<web_port>`.

---

## 1. Создать пользователя и получить конфиг для Phantom

### `POST /api/service/users`

**Тело:**

```json
{ "user_id": "u-123", "comment": "Друг", "requested_port": 30123 }
```

- `user_id` — **обязательный** стабильный ключ игрока.
- `requested_port` — желаемый постоянный порт (необязательно; если свободен в пуле — займётся).
- Идемпотентен: если `user_id` уже есть, вернётся существующий (`exists:true`) без дубликата.

**Ответ `200`:**

```json
{
  "status": "ok",
  "id": 1234567,
  "client_port": 30123,
  "public_ip": "203.0.113.10",
  "enabled": false,
  "exists": false,
  "config": {
    "CONTROL_PORT": 4455,
    "LOCAL_IP": "127.0.0.1",
    "LOCAL_PORT": "",
    "POOL_SIZE": 10,
    "SERVER_IP": "203.0.113.10",
    "ID_CLIENT": 1234567,
    "CERTIFICATE": "-----BEGIN CERTIFICATE-----...",
    "PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----...",
    "TRUSTED_SERVER_CERTIFICATE": "-----BEGIN CERTIFICATE-----..."
  }
}
```

> **`config` — это и есть файл `server_<id>.json`, отдаётся лаунчеру.** Phantom читает его
> и по `CONTROL_PORT`/`ID_CLIENT`/`CERTIFICATE`/`PRIVATE_KEY`/`TRUSTED_SERVER_CERTIFICATE`
> подключается к Obelisk, а `SERVER_IP`/`LOCAL_PORT` уточняют адрес игры.

**Ошибки:**
- `400` — нет `user_id`: `{"status":"error","message":"user_id is required"}`
- `503` — нет свободных портов / достигнут `max_sessions`: `{"status":"error","message":"cannot provision (no free ports or limit reached)"}`

## 2. Состояние пользователя

### `GET /api/service/users/{user_id}`

**Ответ `200`:**

```json
{
  "id": 1234567,
  "client_port": 30123,
  "public_ip": "203.0.113.10",
  "enabled": false,
  "online": false,
  "active_pairs": 0,
  "total_traffic": 0
}
```

`online:true` — Phantom подключён, `client_port` слушается, друзья могут заходить.
**`404`** — пользователь не найден.

## 3. Разрешить ждать (включить хост)

### `POST /api/service/users/{user_id}/enable`

Гейт `enabled` — без него Phantom **не принимается** даже с верным id+сертификатом.

**Ответ `200`:**

```json
{ "status": "ok", "enabled": true, "public_ip": "203.0.113.10", "client_port": 30123, "config": { "...": "..." } }
```

## 4. Приостановить (выключить хост, порт сохранить)

### `POST /api/service/users/{user_id}/suspend`

`enabled=false` + акцептор закрыт. **`client_port` и запись сохраняются** — после `enable` тот же порт снова слушается.

**Ответ `200`:** `{"status":"ok","enabled":false}`

## 5. Удалить полностью (освободить порт)

### `DELETE /api/service/users/{user_id}`

Удаляет запись + возвращает порт в пул.

**Ответ `200`:** `{"status":"ok","deleted":true}`

> `suspend` ≠ `delete`. Suspend — пауза с сохранением порта; delete — освобождение навсегда.

## 5.2. Статистика узла одним запросом

### `GET /api/service/stats`

Агрегированные метрики всего Obelisk — онлайн, скорость, трафик, пул — в **одном ответе**.
Сюда бэкенд может поллить раз в несколько секунд.

**Ответ `200`:**

```json
{
  "status": "ok",
  "node_id": "obelisk-1",
  "online_servers": 2,
  "active_pairs": 5,
  "speed_in": 1048576,
  "speed_out": 524288,
  "total_traffic": 125829120,
  "free_ports": 8990,
  "uptime_sec": 43200
}
```

| Поле | Что значит |
|---|---|
| `online_servers` | Сколько серверов сейчас с подключённым Phantom |
| `active_pairs` | Активные связи (игрок↔Фантом) |
| `speed_in` / `speed_out` | Скорость (байт/с, суммарно) |
| `total_traffic` | Трафик за всё время |
| `free_ports` | Осталось свободных портов в пуле |
| `uptime_sec` | Аптайм процесса |

## 6. Здоровье узла (для вачдога/рестарта)

### `GET /api/health` — без авторизации

```json
{ "status": "ok", "version": "1.0.0", "uptime_sec": 43200,
  "online_servers": 2, "free_ports": 8990 }
```

Если не отвечает или `status != "ok"` — вачдог перезапускает Obelisk (systemd `Restart`/NSSM).

---

## 7. Жизненный цикл и что персистить в бэкенде

### Своя модель в БД

```sql
users (
  user_id      TEXT PRIMARY KEY, -- ключ игрока (из Obelisk)
  server_id    INT,              -- id из ответа create
  client_port  INT,              -- постоянный порт (сохранить!)
  public_ip    TEXT,             -- IP узла Obelisk
  enabled      BOOL DEFAULT false,
  status       TEXT,             -- 'created'|'enabled'|'suspended'
  created_at   TIMESTAMP,
  updated_at   TIMESTAMP
)
configs -- при желании сохранить server_<id>.json (или выдавать по GET /api/server/config?id=)
```

### Регламент бэкенда

| Шаг | Вызов | Что сохранить/сделать |
|---|---|---|
| Регистрация | `POST /api/service/users` | `client_port`, `public_ip`, `enabled=false`; **отдать `config` лаунчеру** |
| Хост стартует | `POST .../enable` | `enabled=true`; лаунчеру → `host/port` |
| Поллинг статуса | `GET .../{user_id}` | обновить `online`, `active_pairs`, `last_active` |
| Статистика узла | `GET /api/service/stats` | онлайн, скорость, трафик, свободные порты — одним вызовом |
| Здоровье узла | `GET /api/health` | при подъёме — **повторно `enable`** (сессии не остаются выключенными) |
| Плановый стоп | `POST .../suspend` | `enabled=false` (порт жив) |
| Удаление | `DELETE .../{user_id}` | удалить запись, порт освобождён |
| Скачать конфиг | `GET /api/server/config?id={id}` | повторно получить `server_<id>.json` (если потерян) |

### Ответ лаунчеру (от бэкенда)

```json
{ "user_id": "u-123", "host": "203.0.113.10", "port": 30123,
  "enabled": true, "online": true, "active_pairs": 2 }
```

Плюс **файл конфига** `server_<id>.json` (из `config` в ответе `create`) — Phantom читает его и
сам соединяется с Obelisk. Хост и порт игрок вводит/получает автоматически; `online:false` →
лаунчер показывает «сервер офлайн, переподключитесь».

---

## 8. Примеры (curl)

### Создать пользователя + сохранить конфиг

```bash
curl -k -X POST https://127.0.0.1:8000/api/service/users \
  -H "X-Service-Key: $OBELISK_SERVICE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"u-123","comment":"friend","requested_port":30123}'
```

### Включить / приостановить

```bash
curl -k -X POST https://127.0.0.1:8000/api/service/users/u-123/enable   -H "X-Service-Key: $KEY"
curl -k -X POST https://127.0.0.1:8000/api/service/users/u-123/suspend  -H "X-Service-Key: $KEY"
```

### Статус / удаление

```bash
curl -k https://127.0.0.1:8000/api/service/users/u-123 -H "X-Service-Key: $KEY"
curl -k -X DELETE https://127.0.0.1:8000/api/service/users/u-123 -H "X-Service-Key: $KEY"
```
