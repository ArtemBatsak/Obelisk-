#!/usr/bin/env bash
# Удаление Obelisk (Linux).
set -euo pipefail

BIN_NAME="obelisk"

echo "==> Obelisk uninstall"
systemctl disable --now obelisk 2>/dev/null || true
rm -f /etc/systemd/system/obelisk.service
rm -f "/usr/local/bin/$BIN_NAME"
systemctl daemon-reload

# Конфиг и данные оставляем по умолчанию (безопаснее). Для полного сноса раскомментируйте:
# rm -rf /etc/obelisk

echo "==> Done"
