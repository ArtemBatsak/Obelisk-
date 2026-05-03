# Obelisk

Obelisk is a lightweight high-performance TCP relay that works together with **Phantom**.
Its job is to accept client connections on a public server and forward traffic to Phantom through managed socket pairs.

---

## 1) What this program is and why to use it

Obelisk is a bridge between public clients and private infrastructure.
It is useful when your target service is not directly reachable from the Internet.

### Typical use cases
- You host a game/backend service in a private network, but players/users connect through a public Obelisk node.
- You need a stable TCP entry point with low connection delay and central traffic routing.
- You want to separate public access (Obelisk) from internal service logic (Phantom + target service).

---

## 2) What is required to run Obelisk

### Public server requirements
- A server with a **public IPv4** address.
- Ability to open and bind TCP ports.
- Stable network connectivity to Phantom.

### Required ports (3 ports)
Obelisk requires three unique ports:
1. **Control port** — secure control channel with Phantom.
2. **Data port** — incoming Phantom data sockets for client forwarding.
3. **Web port** — HTTPS web administration interface.

### Configuration file
Obelisk stores runtime configuration in:
- `config/config.json`

Main fields:
- `control_port`
- `data_port`
- `web_port`
- `admin_username`
- `admin_password_hash`
- `admin_password_salt`
- `tls_cert_path`
- `tls_key_path`

Example:

```json
{
  "control_port": 44555,
  "data_port": 50021,
  "web_port": 8000,
  "admin_username": "admin",
  "admin_password_hash": "<sha256(password+salt)>",
  "admin_password_salt": "<random_salt>",
  "tls_cert_path": "config/tls_cert.cer",
  "tls_key_path": "config/tls_key.pem"
}
```

---

## 3) Work with Phantom

### What Obelisk expects from Phantom
- Phantom connects to Obelisk control channel (TLS).
- Phantom maintains/creates data sockets for the relay pool.
- Phantom participates in control-level validation and liveness checks.

### How forwarding works
1. Client connects to Obelisk public client port.
2. Obelisk selects an available Phantom data socket from pool.
3. Obelisk creates a pair and relays traffic in both directions.

### Authorization and validation
- Control channel is protected by TLS.
- Data socket admission uses one-time/OTP-style validation before socket is accepted into the pool.

### If Phantom crashes or disconnects
- Liveness checks (ping/pong) detect connection loss.
- Related sessions are stopped.
- Obelisk performs cleanup of sockets, pairs, and timers to avoid leaked resources.
- Manager logic removes inactive server instances safely.

### Traffic diagram

![Architecture](docs/Architecture.png)

---

## 4) Web interface

Obelisk provides an HTTPS web admin panel with API endpoints for:
- Server list and status.
- Active pairs and traffic counters.
- Recent logs.
- Add/delete/stop server actions.
- Server config download.
- Port pool operations.

### Security recommendation for web access
Even with HTTPS and authentication, it is strongly recommended to:
- **not expose web port to the public Internet**;
- allow access only from local network, private subnet, or through VPN;
- apply firewall allowlist rules for admin access.

---

## 5) Build and platform

- Build system: **CMake**.
- Supported build targets: **Linux** and **Windows**.
- Dependencies are managed via **vcpkg**.

### Performance and system recommendations
Obelisk is optimized and lightweight.
It can operate on small systems (for example, 1 CPU thread and ~1 GB RAM for low load).
At the same time, the application is asynchronous and can scale across all available CPU threads for higher concurrency.

---

## Project structure

- `src/` — source code
- `docs/` — documentation assets
- `tests/` — tests
- `CMakeLists.txt` — build configuration

---

## License
