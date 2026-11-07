#!/usr/bin/env bash
# Установка Obelisk (Linux). Тестировалось на Ubuntu/Debian.
set -euo pipefail

BIN_NAME="obelisk"
PREFIX="/usr/local"
BIN_DIR="$PREFIX/bin"
CONF_DIR="/etc/obelisk"
SERVICE_UNIT="/etc/systemd/system/obelisk.service"

echo "==> Obelisk install"

# 1) бинарь
echo "-- install binary to $BIN_DIR/$BIN_NAME"
install -d "$BIN_DIR"
install -m 0755 "$BIN_NAME" "$BIN_DIR/$BIN_NAME"

# 2) конфиг/env (не перезаписывать существующий, если есть)
install -d "$CONF_DIR"
if [ ! -f "$CONF_DIR/obelisk.env" ]; then
  echo "-- write default env to $CONF_DIR/obelisk.env"
  cat > "$CONF_DIR/obelisk.env" <<'ENV'
OBELISK_NODE_ID=obelisk-1
OBELISK_CONTROL_PORT=4455
OBELISK_DATA_PORT=50021
OBELISK_WEB_PORT=8000
OBELISK_WEB_BIND=127.0.0.1
OBELISK_PORT_POOL_START=30000
OBELISK_PORT_POOL_END=39999
OBELISK_SERVICE_API_KEY=
OBELISK_ALLOW_API_PEERS=
OBELISK_ADMIN_USER=admin
OBELISK_ADMIN_PASS=change-me
OBELISK_MAX_SESSIONS=500
OBELISK_MAX_PENDING_CLIENTS=100
OBELISK_LOG_LEVEL=info
ENV
  chmod 600 "$CONF_DIR/obelisk.env"
  echo "!! Не забудьте задать OBELISK_SERVICE_API_KEY и OBELISK_ADMIN_PASS"
fi

# 3) systemd unit
echo "-- write systemd unit"
install -m 0644 "$(dirname "$0")/obelisk.service" "$SERVICE_UNIT"

# 4) открыть порты (ufw, если есть)
if command -v ufw >/dev/null 2>&1; then
  echo "-- allow ports in ufw"
  ufw allow "$(grep OBELISK_CONTROL_PORT "$CONF_DIR/obelisk.env" | cut -d= -f2)/tcp" || true
  ufw allow "$(grep OBELISK_DATA_PORT "$CONF_DIR/obelisk.env" | cut -d= -f2)/tcp" || true
  ufw allow "$(grep OBELISK_WEB_PORT "$CONF_DIR/obelisk.env" | cut -d= -f2)/tcp" || true
  start="$(grep OBELISK_PORT_POOL_START "$CONF_DIR/obelisk.env" | cut -d= -f2)"
  end="$(grep OBELISK_PORT_POOL_END "$CONF_DIR/obelisk.env" | cut -d= -f2)"
  if [ -n "$start" ] && [ -n "$end" ]; then
    ufw allow "$start:$end/tcp" || true
  fi
fi

# 5) лимиты (этого требует большой пул портов/соединений)
echo "-- apply sysctl"
sysctl -w net.core.somaxconn=4096 >/dev/null 2>&1 || true

# 6) включить службу
echo "-- enable & start obelisk"
systemctl daemon-reload
systemctl enable --now obelisk

echo "==> Done. Логи: journalctl -u obelisk -f"
echo "    Проверка: obelisk --check"
