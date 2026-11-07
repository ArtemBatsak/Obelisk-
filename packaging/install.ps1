# Установка Obelisk как Windows-службы через NSSM.
# Требуется: nssm (https://nssm.cc). Запускать от админа.
# Пример: powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"

$BinName  = "obelisk.exe"   # решите как переименовать
$SrcBin   = ".\out\build\win-release\Obelisk.exe"
$DestDir  = "C:\Program Files\Obelisk"
$ConfDir  = Join-Path $env:ProgramData "Obelisk"
$SvcName  = "obelisk"

# 1) каталоги
New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfDir | Out-Null

# 2) скопировать бинарь
Copy-Item -Force $SrcBin (Join-Path $DestDir $BinName)

# 3) env-файл (секреты) — не перезаписывать, если есть
$EnvFile = Join-Path $ConfDir "obelisk.env"
if (-not (Test-Path $EnvFile)) {
    @"
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
"@ | Set-Content -Path $EnvFile -Encoding ASCII
    Write-Host "!! Задайте OBELISK_SERVICE_API_KEY и OBELISK_ADMIN_PASS в $EnvFile"
}

# 4) зарегистрировать службу (NSSM)
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Error "nssm не найден. Установите: https://nssm.cc"
    exit 1
}

nssm install $SvcName (Join-Path $DestDir $BinName)
nssm set $SvcName AppDirectory $DestDir
nssm set $SvcName AppEnvironmentExtra "OBELISK_DIR=$ConfDir"
nssm set $SvcName AppExit Default Restart
nssm set $SvcName AppRestartDelay 2000
nssm set $SvcName Start SERVICE_AUTO_START
nssm start $SvcName

Write-Host "==> Служба '$SvcName' установлена и запущена. Проверка: & (Join-Path $DestDir $BinName) --check"
