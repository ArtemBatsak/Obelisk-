# Удаление Obelisk-службы (Windows). Требуется NSSM.
# Запускать от админа.
$ErrorActionPreference = "Stop"

$SvcName = "obelisk"

if (Get-Command nssm -ErrorAction SilentlyContinue) {
    nssm stop $SvcName 2>$null
    nssm remove $SvcName confirm
    Write-Host "==> Служба '$SvcName' удалена."
}
else {
    Write-Host "nssm не найден — удалите службу вручную (sc delete $SvcName)."
}

# Конфиг/данные по умолчанию оставляем. Для полного сноса раскомментируйте:
# Remove-Item -Recurse -Force (Join-Path $env:ProgramData "Obelisk") -ErrorAction SilentlyContinue
# Remove-Item -Recurse -Force "C:\Program Files\Obelisk" -ErrorAction SilentlyContinue
