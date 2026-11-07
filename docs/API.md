# Obelisk HTTP API

Obelisk предоставляет HTTPS-интерфейс для администрирования и программного управления.
Все эндпоинты обслуживаются через `httplib::SSLServer` на **web-порту** (`web_port`), слушающем
`web_bind` (по умолчанию `127.0.0.1`).

База: `https://<web_bind>:<web_port>`. Например `https://127.0.0.1:8000`.

> **Security**: по умолчанию web слушает только localhost. Для внешнего доступа пробрасывайте
> порт через приватную сеть/firewall и не светите админку в интернет.

---

## 1. Авторизация

Три уровня доступа (middleware, по пути запроса):

| Уровень | Пути | Как проходит |
|---|---|---|
| Без авторизации | `/api/health` | Самопроверка для вачдога/supervisor'а. |
| Machine-to-machine | `/api/service/*` | Заголовок `X-Service-Key` (равен `service_api_key`) **и**, если задан `allow_api_peers`, IP клиента должен быть в списке. |
| Админ-панель | всё остальное (в т.ч. `/metrics`, `/api/monitor`, `/api/admin/*`, `/api/server/*`, `/api/ports/*`, `/api/logs`) | HTTP Basic: `Authorization: Basic base64(user:pass)` по `admin_username`/`admin_password`. |

### Ошибка авторизации
- Machine API: `401` + `{"status":"error","message":"service auth failed"}`
- Админ: `401` + заголовок `WWW-Authenticate: Basic realm="Admin Panel"`

### Формат ошибок
Все ошибки отдают HTTP-статус и JSON-тело с `status:"error"` (где уместно). Успех обычно
`{"status":"ok"}` или `{"status":"success"}`.

---

## 2. Общесистемные эндпоинты

### `GET /api/health` — самопроверка узла
Без авторизации. Используется supervisor'ом/вачдогом для рестарта при неответе.

**Ответ `200`:**

```json
{
  "node_id": "obelisk-1",
  "online_servers": 2,
  "active_pairs": 5,
  "speed_in": 1048576,
  "speed_out": 524288,
  "total_traffic": 125829120,
  "free_ports": 8990,
  "uptime_sec": 43200,
  "status": "ok",
  "version": "1.0.0"
}
```

### `GET /api/monitor` — сводные метрики (для вкладки «Мониторинг»)
Basic-авторизация. Тот же объект, что `/api/health`, но без `status`/`version`.

### `GET /metrics` — метрики Prometheus
Basic-авторизация. Текст в формате Prometheus:

```
# HELP obelisk_servers_total Total registered servers
# TYPE obelisk_servers_total gauge
obelisk_servers_total 3

obelisk_server_info{id="1234567",comment="My server"} 1
obelisk_active_pairs{id="1234567"} 2
obelisk_ping_ms{id="1234567"} 12
obelisk_traffic_total{id="1234567"} 104857600
obelisk_speed_in_bytes{id="1234567"} 1048576
obelisk_speed_out_bytes{id="1234567"} 524288
```

### `POST /api/admin/restart` — ручной перезапуск
Basic-авторизация. Отвечает `{"status":"restarting"}` и через 300 мс вызывает `exit(0)`.
Процесс завершается грациозно; сервис-менеджер (systemd/NSSM) поднимает его заново.

---

## 3. Service API (`/api/service/*`) — машина-машина

Предназначен для Кенни-бэкенда. Авторизация: `X-Service-Key` (+ опциональный `allow_api_peers`).

Все запросы (`POST`) принимают JSON-тело. `DELETE` — без тела.

### `POST /api/service/users` — создать пользователя (идемпотентно)

**Тело:**

```json
{ "user_id": "u-123", "comment": "Приглашённый игрок", "requested_port": 30123 }
```

| Поле | Обязательно | Описание |
|---|---|---|
| `user_id` | да | Стабильный внешний ключ игрока. |
| `comment` | нет | Комментарий/описание. По умолчанию = `user_id`. |
| `requested_port` | нет | Желаемый постоянный порт. Если свободен в пуле — используется; иначе берётся первый свободный. |

**Поведение:**
- **Идемпотентность**: если запись с таким `user_id` уже есть — возвращается она (`exists:true`), дубликат не создаётся.
- `requested_port`, занятый или вне пула → `existed` не создаётся, ответ `error`.
- Лимит одновременных сессий (`max_sessions`) исчерпан → `503`.
- Нет свободных портов в пуле → `error`.

**Ответ `200`:**

```json
{
  "status": "ok",
  "id": 1234567,
  "client_port": 30123,
  "public_ip": "203.0.113.10",
  "enabled": false,
  "exists": false,
  "config": { "CONTROL_PORT": 4455, "ID_CLIENT": 1234567, "...": "..." }
}
```

- `public_ip` — внешний IP узла (определяется через api.ipify.org).
- `config` — содержимое файла конфигурации сервера (`server_<id>.json`).

**Ошибки:**
- `400` — `user_id` отсутствует: `{"status":"error","message":"user_id is required"}`
- `503` — нельзя зарезервировать (нет портов / достигнут лимит): `{"status":"error","message":"cannot provision (no free ports or limit reached)"}`

### `GET /api/service/users/{user_id}` — состояние игрока

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

**Ошибки:** `404` — пользователь не найден.

### `POST /api/service/users/{user_id}/enable` — разрешить ждать

Позволяет Phantom подключиться к этому серверу (гейт `enabled`).

**Ответ `200`:**

```json
{
  "status": "ok",
  "enabled": true,
  "public_ip": "203.0.113.10",
  "client_port": 30123,
  "config": { "...": "..." }
}
```

**Ошибки:** `404` — пользователь не найден.

### `POST /api/service/users/{user_id}/suspend` — приостановить

Устанавливает `enabled=false` и выключает сервер (Socket acceptor закрывается). **Порт и запись сохраняются** —
после `enable` порт снова слушается.

**Ответ `200`:**

```json
{ "status": "ok", "enabled": false }
```

**Ошибки:** `404` — пользователь не найден.

### `DELETE /api/service/users/{user_id}` — удалить полностью

Удаляет запись и освобождает порт (возвращает его в пул).

**Ответ `200`:**

```json
{ "status": "ok", "deleted": true }
```

**Ошибки:** `404` — пользователь не найден; `error` при удалении.

> `suspend` ≠ `delete`: suspend сохраняет порт/идентичность, delete освобождает всё.

### `GET /api/service/stats` — статистика узла одним запросом

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

---

## 4. Админ-эндпоинты (`/api/server/*`, `/api/ports/*`, `/api/logs`)

Basic-авторизация.

### `GET /api/servers` — список всех серверов

**Ответ `200`** — JSON-массив:

```json
[
  {
    "id": 1234567,
    "client_port": 30123,
    "comment": "My server",
    "last_seen": 12,
    "active_pairs": 2,
    "online": true,
    "speed_in": 1048576,
    "speed_out": 524288,
    "total_traffic": 104857600
  }
]
```

`last_seen` — задержка ping/Pong (мс). `online` — подключён ли Phantom.

### `POST /api/server/add` — добавить сервер

**Тело:** `{ "comment": "..." }` (обязательное поле `comment`).

**Ответ `200`:** `{"status":"ok"}` / `{"status":"error"}`.

### `POST /api/server/delete` — удалить сервер

**Тело:** `{ "id": 1234567 }` (обязательное поле `id`).

**Ответ `200`:** `{"status":"ok"}` / `{"status":"error"}`.

### `POST /api/server/stop` — остановить сервер

**Тело:** `{ "id": 1234567 }`. Останавливает сервер (закрывает акцептор). Запустить заново напрямую нельзя
(только подключение Phantom заново).

**Ответ `200`:** `{"status":"ok"}` / `{"status":"error"}`.

### `POST /api/server/change_comment` — изменить комментарий

**Тело:** `{ "id": 1234567, "comment": "новый комментарий" }`.

**Ответ `200`:** `{"status":"ok"}` / `{"status":"error"}`.

### `GET /api/server/config?id={id}` — скачать конфиг сервера

Возвращает файл `server_<id>.json` как вложение (`Content-Disposition: attachment`).

**Ответы:** `200` (файл), `400` (нет `id`), `404` (конфиг не найден).

### `GET /api/ports/list` — свободные порты пула

**Ответ `200`:**

```json
{ "status": "success", "count": 8990, "ranges": "30000-38989, 39090" }
```

Если пул пуст: `{ "status": "empty", "ranges": "" }`.

### `POST /api/ports/add` — добавить порт(ы) в пул

**Тело:** `{ "first": 30100, "second": 30199 }` (`second` необязателен — одиночный порт).

**Ответ `200`:** `{"status":"ok"}` / `{"status":"error"}`.

### `POST /api/ports/delete` — удалить порт(ы) из пула

**Тело:** `{ "first": 30100, "second": 30199 }` (`second` необязателен).

**Ответ `200`:** `{"status":"ok"}` / `{"status":"error"}`.

### `GET /api/logs` — последние строки лога

**Ответ `200`:**

```json
{ "logs": "последние ~4096 байт лога\n" }
```

---

## 5. Релевантная конфигурация

Поля `/api`-безопасности (читаются из `config.json` / env, подробнее см. README и `.env.example`):

| Поле / env | Описание |
|---|---|
| `web_bind` / `OBELISK_WEB_BIND` | Адрес, на котором слушает web (`127.0.0.1` по умолчанию). |
| `web_port` / `OBELISK_WEB_PORT` | Порт web-интерфейса. |
| `service_api_key` / `OBELISK_SERVICE_API_KEY` | Секрет для `X-Service-Key`. Не логируется. |
| `allow_api_peers` / `OBELISK_ALLOW_API_PEERS` | CSV IP-адресов, с которых разрешён `/api/service/*` (пусто — любой с верным ключом). |
| `admin_username` / `OBELISK_ADMIN_USER` | Логин админ-панели. |
| `admin_password_hash` / `admin_password_salt` | Хэш/соль пароля (генерируются из `OBELISK_ADMIN_PASS`). |
| `max_sessions` / `OBELISK_MAX_SESSIONS` | Лимит сессий → `503` в `POST /api/service/users`. |
| `max_pending_clients` / `OBELISK_MAX_PENDING_CLIENTS` | Макс. незапаренных клиентских сокетов. |
| `data_pool_max` / `OBELISK_DATA_POOL_MAX` | Потолок data-пула Phantom (раздаётся клиентам). |

> `service_api_key` и `admin_pass` передаются **только** через env на сервере, не в repository и не в логах.

---

## 6. Примеры

### Создать пользователя (Кенни-бэкенд)

```bash
curl -k -X POST https://127.0.0.1:8000/api/service/users \
  -H "X-Service-Key: ${OBELISK_SERVICE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"u-123","comment":"friend","requested_port":30123}'
```

### Список серверов (админ)

```bash
curl -k -u admin:change-me https://127.0.0.1:8000/api/servers
```

### Освободить порт (удалить пользователя)

```bash
curl -k -X DELETE https://127.0.0.1:8000/api/service/users/u-123 \
  -H "X-Service-Key: ${OBELISK_SERVICE_API_KEY}"
```

### Статистика узла одним запросом

```bash
curl -k https://127.0.0.1:8000/api/service/stats \
  -H "X-Service-Key: ${OBELISK_SERVICE_API_KEY}"
```
