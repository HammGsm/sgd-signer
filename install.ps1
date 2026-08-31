# SGD-SIGNER — instalador Windows
# Registra el esquema tramitedoc:// y crea el wrapper sgd-signer.cmd.
# Requiere: Python 3.9+ en PATH (https://www.python.org/downloads/).
# Ejecutar en PowerShell como Administrador:  powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"

$AppDir = "$env:LOCALAPPDATA\sgd-signer"
$BinDir = "$env:LOCALAPPDATA\sgd-signer\bin"
$SrcDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "== SGD-SIGNER installer (Windows) =="

# 1. dependencias Python (todas las de la app: firma, GUI, vista previa)
Write-Host "[1/3] Instalando dependencias (pyhanko, websocket-client, python-pkcs11, pillow, pymupdf)..."
python -m pip install --quiet pyhanko==0.20.0 websocket-client python-pkcs11 pillow pymupdf

# 2. copiar script + assets
Write-Host "[2/3] Copiando sgd-signer.py y assets a $AppDir ..."
New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
Copy-Item "$SrcDir\sgd-signer.py" "$AppDir\sgd-signer.py" -Force
Copy-Item "$SrcDir\assets" "$AppDir\assets" -Recurse -Force

# 3. wrapper sgd-signer.cmd en PATH
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
@"
@echo off
python "$AppDir\sgd-signer.py" %*
"@ | Set-Content -Path "$BinDir\sgd-signer.cmd" -Encoding ASCII

# 4. registrar el esquema tramitedoc:// (handler de URL)
Write-Host "[3/3] Registrando el esquema tramitedoc:// ..."
$RegPath = "HKCU:\Software\Classes\tramitedoc"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "(Default)" -Value "URL:SGD-SIGNER Protocol"
Set-ItemProperty -Path $RegPath -Name "URL Protocol" -Value ""
New-Item -Path "$RegPath\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "$RegPath\shell\open\command" -Name "(Default)" `
    -Value "`"$BinDir\sgd-signer.cmd`" `"%1`""

# icono (opcional)
New-Item -Path "$RegPath\DefaultIcon" -Force | Out-Null
Set-ItemProperty -Path "$RegPath\DefaultIcon" -Name "(Default)" -Value "$AppDir\assets\icon.png"

Write-Host ""
Write-Host "Instalado. Configura tu certificado:"
Write-Host "  mkdir %USERPROFILE%\.sgd-signer\certs  y copia tu .p12/.pfx"
Write-Host "  sgd-signer pin TU_PIN   (opcional)"
Write-Host "  sgd-signer gui          (abrir la GUI)"
Write-Host ""
Write-Host "Nota: el token USB Bit4id requiere su middleware instalado y configurar"
Write-Host "      'token_lib' en %USERPROFILE%\.sgd-signer\config.json con la ruta del .dll PKCS#11."
Write-Host "      El sello de tiempo TSA se configura desde la GUI (Configuración → TSA)."
