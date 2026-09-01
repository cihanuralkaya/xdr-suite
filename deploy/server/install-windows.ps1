#Requires -RunAsAdministrator
# XDR C2 sunucu kurulumu (Windows, zamanlanmış görev).
# Yanında bulunması gerekenler: c2.exe, gencerts.exe (dist/windows-amd64/'den).
#
# Kullanım (Yönetici PowerShell):
#   .\install-windows.ps1 -ServerName xdr-c2
param(
    [string]$ServerName = "xdr-c2"
)
$ErrorActionPreference = "Stop"

$Here       = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = "$env:ProgramFiles\XDR Server"
$ConfDir    = "$InstallDir\conf"
$PkiDir     = "$ConfDir\pki"

foreach ($bin in @("c2.exe", "gencerts.exe")) {
    if (-not (Test-Path (Join-Path $Here $bin))) { throw "$bin bulunamadı ($Here)." }
}

New-Item -ItemType Directory -Force -Path $InstallDir, $ConfDir, $PkiDir | Out-Null
Copy-Item (Join-Path $Here "c2.exe") "$InstallDir\c2.exe" -Force

# Sertifikalar (yoksa üret).
if (-not (Test-Path "$PkiDir\ca.crt")) {
    & (Join-Path $Here "gencerts.exe") -out $PkiDir -name $ServerName
    Write-Host "PKI üretildi: $PkiDir"
} else {
    Write-Host "Mevcut PKI korunuyor: $PkiDir"
}

# 32 baytlık base64 ana anahtar + rastgele yönetici parolası üret.
function New-B64Key([int]$bytes) {
    $b = New-Object 'System.Byte[]' $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
    return [Convert]::ToBase64String($b)
}

$EnvFile = "$ConfDir\c2.env.cmd"   # ortam değişkenlerini set eden sarmalayıcı
if (-not (Test-Path $EnvFile)) {
    $MasterKey = New-B64Key 32
    $AdminPass = (New-B64Key 9)
    $wrapper = @"
@echo off
set XDR_DATABASE_URL=
set XDR_MASTER_KEY=$MasterKey
set XDR_CA_CERT=$PkiDir\ca.crt
set XDR_CA_KEY=$PkiDir\ca.key
set XDR_SERVER_CERT=$PkiDir\server.crt
set XDR_SERVER_KEY=$PkiDir\server.key
set XDR_LISTEN_AGENT=:8443
set XDR_LISTEN_ENROLL=:8444
set XDR_LISTEN_ADMIN=:8445
set XDR_DEMO_ADMIN_EMAIL=admin@local
set XDR_DEMO_ADMIN_PASSWORD=$AdminPass
set XDR_RETENTION_DAYS=90
"$InstallDir\c2.exe"
"@
    Set-Content -Path $EnvFile -Value $wrapper -Encoding ascii
    Write-Host ">>> Konsol girişi: admin@local / $AdminPass  (DEMO/bellek-içi mod)"
    Write-Host ">>> Uretim icin: XDR_DATABASE_URL ayarlayin ve tools/adminseed ile yonetici ekleyin."
} else {
    Write-Host "Mevcut yapılandırma korunuyor: $EnvFile"
}

# Açılışta SYSTEM olarak çalışacak zamanlanmış görev.
$Action    = New-ScheduledTaskAction -Execute $EnvFile
$Trigger   = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "XDR C2 Server" -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
Start-ScheduledTask -TaskName "XDR C2 Server"

Write-Host "XDR C2 kuruldu ve başlatıldı. Konsol: https://localhost:8445/"
