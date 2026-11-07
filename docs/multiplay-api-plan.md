# Obelisk: API + мониторинг для «Играть с друзьями» (фаза 1)

Это план изменений **только в Obelisk**. Один узел, без балансировщика.
Кенни-бэкенд и лаунчер — отдельно, здесь не рассматриваются.

---

## 1. Сервисный API (машина-машина)

Obelisk должен быть управляемым программно через HTTPS. Дёргает **только Кенни-бэкенд** —
по заголовку `X-Service-Key` (не админ-пароль).

### 1.1 Авторизация

- В `Config` (`manager/Setup_wizard.h`) добавить поле `service_api_key`.
- Генерировать 256-битный случайный hex при `set_up`/`load`, если пуст; хранить в `config.json`.
- **Не логировать** ключ.
- В `web/Web.cpp` `apply_auth_middleware`:
  - путь `/api/service/*` → проверка `X-Service-Key == service_api_key`, иначе `401`;
  - `/api/*` → как сейчас (Basic `admin_username/password`) — это админ-панель;
  - `/metrics` → как есть (read-only, приватная сеть).

### 1.2 Эндпоинты `POST/GET/DELETE`) под `/api/service/*`

| Метод/путь | Назначение | Ответ |
|---|---|---|
| `POST /api/service/users` | Создать (идемпотентно по `user_id`). Тело: `{user_id, comment?, requested_port?}` | `{status, id, client_port, public_ip, enabled, exists, config}` |
| `GET /api/service/users/{user_id}` | Состояние/адрес игрока | `{id, client_port, public_ip, enabled, online, active_pairs, last_active}` |
| `POST /api/service/users/{user_id}/enable` | Разрешить ждать → `enabled=true` | `{status, enabled, public_ip, client_port, config}` |
| `POST /api/service/users/{user_id}/suspend` | Не ждать → `enabled=false`; **порт и запись сохраняются** | `{status, enabled}` |
| `DELETE /api/service/users/{user_id}` | Удалить полностью + **освободить порт** | `{status, deleted}` |

**Поведение:**

- `create` — **идемпотентный**: если запись с `user_id` уже есть → вернуть её (`exists=true`), не плодить дубликаты.
- `requested_port` — если задан и свободен (в пуле) → использовать как **постоянный порт** игрока; иначе взять первый свободный из пула.
- `enabled` — это **гейт на подключение Phantom** (см. 1.4). `suspend` ≠ `delete`.

**Service/общесистемные эндпоинты (вне `/api/service/users`):**

| Метод/путь | Аутентификация | Назначение | Ответ |
|---|---|---|---|
| `GET /api/health` | нет (биндится на `web_bind`, нечувствителен) | самопроверка узла: жив ли, всё ли ок | `{status:"ok", version, uptime_sec, online_servers, free_ports}` |
| `POST /api/admin/restart` | Basic (админ) | ручной перезапуск: грациозно выйти (`exit 0`), supervisor поднимет заново | `{status:"restarting"}` |

> `/api/health` — для supervisor'а/вачдога: если он перестаёт отвечать или возвращает не `ok` — перезапуск.
> `/api/admin/restart` — намеренный перезапуск «изнутри»; процесс сам не перезапускается, а завершается и поднимается сервис-менеджером.

### 1.3 Модель данных

`manager/Data.h` → `Server_struct` дополнить:
- `std::string user_id;`
- `bool enabled = false;`

Отразить в `to_string()` / `from_string()` (json-поля `user_id`, `enabled`).

`manager/Data.cpp` → `DataServers` новые методы:
- `create_user(user_id, comment, requested_port, control_port, server_ip, trusted_cert)` →
  возвращает `Server_struct` (или empty на ошибке). Внутри: идемпотентность по `user_id`, выбор порта,
  генерация сертификата (как в `add_id`), запись `server_<id>.json`, `save_all()`.
- `get_by_user_id(user_id) -> optional<Server_struct>`
- `set_enabled(id, bool)`
- `is_enabled(id) -> bool`

### 1.4 Гейт `enabled` в авторизации Phantom

`manager/Server_manager.cpp` → `async_authorize`. Сейчас:

```cpp
if (shared_data->authorize_id(id, peer_cert_pem) && !server_online(id)) { ... }
```

Добавить проверку `is_enabled(id)` — чтобы Phantom с верным `id`+сертификатом, но у которого
статус выключен, **не принимался**. Это и есть «разрешить/не разрешить ждать» на уровне шлюза.

### 1.5 Реализация эндпоинтов

`web/Web.cpp` → в `start()` добавить 5 обработчиков. Для ответа `config` использовать
`read_server_config_file(id)`; для `public_ip` — `detect_external_ip()`; для `id/client_port` —
из записи. `online`/`active_pairs` — через `ServerManager` (`server_online`, `get_active_pairs`).

---

## 1.6 Конфигурация узла (удобная настройка через env)

Оbelisk управляется `config.json` (пишет `Setup_wizard`). Для удобного деплоя и секретов
добавляем **env-переопределения** с префиксом `OBELISK_`: env меньше всего, конфиг как дефолт.
`Setup_wizard` должен читать env **неинтерактивно** (без промптов), если конфиг не создан
(для авто-деплоя на сервер).

| Переменная | Назначение | Пример |
|---|---|---|
| `OBELISK_NODE_ID` | идентификатор узла (мониторинг/будущие ноды) | `worker-a` |
| `OBELISK_CONTROL_PORT` | control-порт Phantom | `4455` |
| `OBELISK_DATA_PORT` | data-порт Phantom | `50021` |
| `OBELISK_WEB_PORT` | web-порт админки/API | `8000` |
| `OBELISK_WEB_BIND` | на чём слушать web (приватно) | `127.0.0.1` |
| `OBELISK_PORT_POOL_START` | начало диапазона портов сессий | `30000` |
| `OBELISK_PORT_POOL_END` | конец диапазона портов сессий | `39999` |
| `OBELISK_SERVICE_API_KEY` | секрет для машинного API (`X-Service-Key`) | `<256-бит hex>` |
| `OBELISK_ALLOW_API_PEERS` | **с кем можно общаться** — список IP, с кого пускать `/api/service/*` | `10.0.0.5,10.0.0.6` |
| `OBELISK_ADMIN_USER` | логин админ-панели | `admin` |
| `OBELISK_ADMIN_PASS` | пароль админ-панели (хэш/соль генерируются) | `—` |
| `OBELISK_MAX_PENDING_CLIENTS` | макс. незапаренных клиентов | `100` |
| `OBELISK_MAX_SESSIONS` | лимит одновременных сессий на узел (защита от исчерпания) | `500` |
| `OBELISK_LOG_LEVEL` | уровень логов | `info` |

**Правила:**

- **Секреты** (`SERVICE_API_KEY`, `ADMIN_PASS`) — только из env на сервере, **не в repo**, не в логах.
- **Пул портов**: если `PORT_POOL_START/END` заданы и пул пуст — **автозалить** этот диапазон при старте
  (заменить ручной `POST /api/ports/add`).
- **Кто может общаться с API**: `ALLOW_API_PEERS` — белый список IP для `/api/service/*`
  (плюс проверка `X-Service-Key`). Если список пуст — только по ключу, без IP-фильтра.
- **`MAX_SESSIONS`**: эндпоинт `create` возвращает `503`, если лимит достигнут (защита от абуза/исчерпания портов).
- **`WEB_BIND`**: по умолчанию `127.0.0.1` (приватно), чтобы админку не светить в интернет.

---

## 2. Мониторинг (новая вкладка в админке)

В существующую web-панель (`Web.cpp` + `INDEX_HTML`/`INDEX_JS`) добавить вкладку **«Мониторинг»**.

### 2.1 Что показывать (сводка сверху)

- **Онлайн сейчас** — число серверов, где Phantom подключён (`server_online`).
- **Активные пары** — суммарно `active_pairs`.
- **Скорость** — суммарно `speed_in` / `speed_out`.
- **Трафик** — `total_traffic` (сессия / за всё время).
- **Свободные порты** — из пула (`get_port_pool`/`ports.size()`).
- **Аптайм** процесса.

### 2.2 Список серверов (уже есть) + живые метрики

- `id`, `client_port`, `comment`, `online`, `active_pairs`, `speed_in/out`, `total_traffic`, `last_seen`.
- Автообновление раз в ~1–2 сек (как существующий `loadServers`).

Источники данных: `ServerManager` (`server_online`, `get_active_pairs`, `get_total_speed_in/out`,
`get_ping`) и `DataServers` (`get_port_pool`, `get_servers`).

---

## 3. Эксплуатация: автоматический перезапуск, самопроверка, ручной перезапуск, установка

### 3.1 Автозапуск + самопроверка (чтобы «сам рестартился и проверял себя»)

**Режим — supervisor (внешний процесс-менеджер), не самоперезапуск внутри бинаря.** Это надёжно и стандартно:

- **Linux (рекомендуется):** `systemd` unit `obelisk.service`:
  `Restart=always`, `RestartSec=5`; health-check через `ExecStartPost`/таймер или скрипт.
- **Windows:** `NSSM` (или watchdog wrapper) регистрирует Obelisk как службу с авторестартом.

**Самопроверка:**

- `GET /api/health` (без авторизации) → `{status:"ok", version, uptime_sec, online_servers, free_ports}`.
- Вачдог (systemd health-check / cron-скрипт / wrapper) поллит `/api/health`; если N раз подряд
  не `ok`/нет ответа → `systemctl restart obelisk` (или Stop-Start).
- **Fail fast при старте:** если control/data/web-acceptor не смог забиндиться (порт занят) —
  процесс завершается с ошибкой, supervisor перезапускает (и/или логирует понятную причину).
- **Самодиагностика в логах:** на старте печатать сводку — слушатели подняты, пул портов заполнен,
  `node_id`, кол-во портов.

### 3.2 Ручной перезапуск

- **Сервис-менеджер:** `systemctl restart obelisk` / `nssm restart obelisk` — основной способ.
- **HTTP (из панели/скрипта):** `POST /api/admin/restart` (Basic) → грациозное завершение
  (`exit 0`) → supervisor поднимает процесс заново. Это позволяет перезапустить не выходя с сервера.
- **CLI-флаги:** `obelisk --version`, `obelisk --check` (здоровье без запуска сервиса),
  `obelisk --dump-config` (импринт эффективного конфига **без секретов**).

### 3.3 Простая установка

- **Linux:**
  - `scripts/install.sh`: копирует бинарь в `/usr/local/bin`, пишет `/etc/obelisk/obelisk.env`
    (или `config.json`), регает `systemd unit obelisk.service`, открывает диапазон портов
    (например `ufw allow 30000:39999/tcp` + control/data/web).
  - `scripts/uninstall.sh` — снятие службы/удаление.
  - `obelisk.service` unit + `EnvironmentFile=/etc/obelisk/obelisk.env`.
- **Windows:**
  - `scripts/install.ps1` — регистрирует службу через NSSM, создаёт `%ProgramData%\Obelisk\obelisk.env`,
    прописывает автозапуск. `scripts/uninstall.ps1`.
- **Docker (самый простой деплой на одном сервере):**
  - `Dockerfile` + `docker-compose.yml` на env (`OBELISK_*`), проброс control/data/web и
    диапазона портов, `web_bind=0.0.0.0`, `restart: unless-stopped`, healthcheck на `/api/health`.
- **CMake `install()`** — собирать готовый пакет (бинарь + unit + скрипты + `.env.example`).

**Общее:**
- `.env.example` — документирует все `OBELISK_*` переменные.
- Установка неинтерактивная (env вместо промптов Setup_wizard), чтобы ставилось одной командой.
- Пул портов заливается при старте из `PORT_POOL_START/END` — оператору не нужно вручную
  добавлять порты через панель.

### 3.4 Безопасность

- `service_api_key` и `admin_pass` — только env, **не в repo**, не в логах.
- `web_port` — биндится на `web_bind` (по умолчанию `127.0.0.1`); для внешнего доступа — только
  через приватную сеть/firewall (README требует).
- `ulimit -n 65535`, `net.core.somaxconn`, диапазон портов **вне** `ip_local_port_range`,
  TCP keepalive вкл., ротация логов.

### 3.5 Поведение при рестарте / падении (как пережить простой)

**Жизненный цикл порта клиента:**
- Пока Phantom **зарегистрирован** (контроль-канал жив) — `client_port` слушается, друзья принимаются.
- Как только Phantom отвалился / Obelisk упал / рестарт — акцептор закрывается, порт перестаёт принимать.
- Порт снова начинает слушаться **после того, как Phantom переподключился и зарегистрировался**.
- Data-сокет Phantom открывается **на запрос** (по CONNECT при входящем друге) — он не держится постоянно.

**Почему это ок, а не «потеря порта»:**
- Порт **постоянный** и привязан к `Server_struct` (запись на диске), поэтому после рестарта
  он не «теряется» и не переиспользуется под другого — просто временно не принимает, пока Phantom не вернётся.

**Что закрыть, чтобы простой был коротким и без потерь:**
1. **Phantom авто-reconnect** — цикл подключаться заново, пока не завершат. (уже есть в Phantom; не сдаваться).
2. **`enabled` персистится** — пишется в `Server_struct` (`to_string/from_string`) и **сохраняется сразу**
   при `set_enabled`, а не раз в `save_data_interval`. Иначе после рестарта все сессии окажутся выключены.
3. **Durability данных с сертами** — `server_<id>.json` (содержит `PRIVATE_KEY`/`CERTIFICATE`) и файлы
   `DataServers`/free-ports. Потеря = потеря постоянной идентичности игрока. → **бэкапить каталог данных**.
4. **Supervisor с коротким `RestartSec` (1–2 c)** — минимальный простой.
5. **Health + сверка у Кенни** — Кенни поллит `/api/health`, при рестарте видит простой и может
   **пере-enable** сессии (страховка) + обновить статусы.
6. **Плановый рестарт грациозно**: `suspend` → рестарт → `enable` (друзья отключаются по-нормальному).
7. **Друзья переподключаются** — адрес постоянный (`ip:port`), после переподключения Phantom они
   возвращаются на тот же адрес. Лаунчер может показать «переподключитесь».

---

## 4. Порядок работы (по файлам)

1. `manager/Setup_wizard.h/.cpp` — чтение env `OBELISK_*` (неинтерактивно), `service_api_key`,
   `node_id`, `web_bind`, `max_sessions`, авто-заливка пула портов по `PORT_POOL_START/END`.
2. `manager/Data.h/.cpp` — `user_id`, `enabled` в `Server_struct`; `create_user`,
   `get_by_user_id`, `set_enabled`, `is_enabled`; `count()`/лимит `max_sessions`.
3. `manager/Server_manager.cpp` — гейт `is_enabled(id)` в `async_authorize`.
4. `web/Web.cpp` — `X-Service-Key` + `ALLOW_API_PEERS` (IP-фильтр) в auth-миддлвари;
   5 сервисных эндпоинтов; лимит `max_sessions` в `create`; `GET /api/health`;
   `POST /api/admin/restart` (graceful exit).
5. `web/Web.h/.cpp` — вкладка «Мониторинг» (HTML/JS + агрегированные данные).
6. `main.cpp` — fail-fast при незабиндившихся акцепторах; `--check`, `--dump-config` (без секретов).
7. Пакетирование: `systemd unit` + `scripts/install.sh|uninstall.sh` (Linux), `install.ps1` (Windows
   через NSSM), `Dockerfile` + `docker-compose.yml`, CMake `install()`, `.env.example`.

---

## 5. Тесты (Obelisk)

- Юнит: `create_user` идемпотентен; `requested_port` занимается/освобождается корректно;
  `is_enabled` = false → Phantom не принимается (mock TLS/authorize); `max_sessions` → `503`.
- Интеграция: поднять 1 узел, N mock-Phantom, проверить:
  - освобождение портов после `suspend`/`delete`;
  - `online`/`active_pairs`/`speed` в `/api/servers` и на вкладке мониторинга;
  - поведение при обрыве Phantom (cleanup);
  - `GET /api/health` корректно отвечает, вачдог перезапускает при неответе;
  - `POST /api/admin/restart` → process exits + supervisor поднимает заново.
