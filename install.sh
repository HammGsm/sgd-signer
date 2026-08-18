#!/usr/bin/env bash
# Instala sgd-signer como handler de tramitedoc:// en Linux (xdg) o macOS (LaunchServices)
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${SGD_SIGNER_VENV:-/opt/sgd-signer-venv}"
BIN_DIR="${SGD_SIGNER_BIN:-$HOME/.local/bin}"
APP_DIR="${SGD_SIGNER_APP:-$HOME/.local/share/sgd-signer}"

echo "== sgd-signer installer =="

# 1. venv con dependencias
if [ ! -x "$VENV/bin/python" ]; then
    echo "[1/4] Creando venv en $VENV ..."
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q pyhanko==0.20.0 websocket-client
else
    echo "[1/4] venv ya existe: $VENV"
fi

# 2. copiar script
echo "[2/4] Copiando sgd-signer.py a $APP_DIR ..."
mkdir -p "$APP_DIR" "$BIN_DIR"
cp "$SRC_DIR/sgd-signer.py" "$APP_DIR/sgd-signer.py"
chmod +x "$APP_DIR/sgd-signer.py"

# 3. wrapper en PATH
cat > "$BIN_DIR/sgd-signer" <<EOF
#!/usr/bin/env bash
exec "$VENV/bin/python" "$APP_DIR/sgd-signer.py" "\$@"
EOF
chmod +x "$BIN_DIR/sgd-signer"

# 4. registro del protocolo tramitedoc://
if [ "$(uname)" = "Darwin" ]; then
    echo "[3/4] Registrando tramitedoc:// en LaunchServices ..."
    cat > "$HOME/Library/LaunchAgents/pe.senamhi.sgd-signer.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>pe.senamhi.sgd-signer</string>
    <key>CFBundleName</key><string>sgd-signer</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLName</key><string>Tramitedoc</string>
            <key>CFBundleURLSchemes</key>
            <array><string>tramitedoc</string></array>
        </dict>
    </array>
</dict>
</plist>
EOF
    # registrar el esquema (requiere que el LaunchAgent esté cargado)
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
        -f "$HOME/Library/LaunchAgents/pe.senamhi.sgd-signer.plist" || true
    echo "    Nota: en macOS el navegador preguntará la primera vez si abrir tramitedoc:// con sgd-signer."
else
    echo "[3/4] Registrando tramitedoc:// en xdg ..."
    mkdir -p "$HOME/.local/share/applications"
    cat > "$HOME/.local/share/applications/sgd-signer.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=sgd-signer (Tramitedoc SGD)
Exec=$BIN_DIR/sgd-signer %u
MimeType=x-scheme-handler/tramitedoc;
NoDisplay=true
EOF
    chmod +x "$HOME/.local/share/applications/sgd-signer.desktop"
    xdg-mime default sgd-signer.desktop x-scheme-handler/tramitedoc || true
    update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
fi

echo "[4/4] Listo."
echo
echo "Siguiente paso:"
echo "  1. Copia tu certificado:  mkdir -p ~/.sgd-signer/certs && cp TU_CERT.p12 ~/.sgd-signer/certs/"
echo "  2. Guarda el PIN:         sgd-signer pin TU_PIN"
echo "  3. Prueba:               sgd-signer sign documento.pdf --tipo 2"
echo "  4. En el portal SGD, al firmar se abrirá sgd-signer automáticamente."
