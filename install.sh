#!/usr/bin/env bash
# Instala sgd-signer: app + venv + wrapper + daemon systemd + tramitedoc://
#   root (PCs del portal): crea /opt/sgd-signer, /opt/sgd-signer-venv,
#     /usr/local/bin/sgd-signer y el daemon systemd sgd-signer.service.
#   usuario (macOS / escritorio sin daemon): instala en ~/ y registra el esquema.
# Variables: SGD_SIGNER_VENV, SGD_SIGNER_APP, SGD_SIGNER_BIN,
#            SGD_SIGNER_USER (cuándo root: usuario del portal, por defecto el
#            que inició la sesión o el primero de /home).
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

# --- rutas según quién ejecuta ----------------------------------------------
if [ "$IS_ROOT" -eq 1 ]; then
    VENV="${SGD_SIGNER_VENV:-/opt/sgd-signer-venv}"
    APP_DIR="${SGD_SIGNER_APP:-/opt/sgd-signer}"
    BIN_DIR="${SGD_SIGNER_BIN:-/usr/local/bin}"
else
    VENV="${SGD_SIGNER_VENV:-$HOME/sgd-signer-venv}"
    APP_DIR="${SGD_SIGNER_APP:-$HOME/.local/share/sgd-signer}"
    BIN_DIR="${SGD_SIGNER_BIN:-$HOME/.local/bin}"
fi
# usuario del portal (propio la GUI y ~/.sgd-signer): quien inició la sesión
# (logname sobrevive al sudo) o, corriendo root por SSH, el uid 1000 de
# /run/user/ (siempre el de la sesión gráfica) o el primero de /home.
TARGET_USER="${SGD_SIGNER_USER:-$(logname 2>/dev/null || true)}"
if [ -z "$TARGET_USER" ] && [ -d /run/user/1000 ]; then
    TARGET_USER="$(stat -c %U /run/user/1000 2>/dev/null || true)"
fi
[ -n "$TARGET_USER" ] || TARGET_USER="$(ls /home 2>/dev/null | head -1 || true)"
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "$(id -un)" ]; then
    USER_HOME="/home/$TARGET_USER"
else
    USER_HOME="$HOME"
fi

echo "== sgd-signer installer =="
echo "Rutas: venv=$VENV app=$APP_DIR wrapper=$BIN_DIR usuario=$TARGET_USER"

# --- 1. dependencias del sistema (requieren sudo; solo se avisa) ------------
FALTAN=()
if ! python3 -c "import tkinter" >/dev/null 2>&1; then FALTAN+=(tkinter); fi
DISTRO="desconocida"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "${ID}${ID_LIKE:-}" in
        *rhel*|*fedora*|*centos*|*ol*) DISTRO="rhel" ;;
        *ubuntu*|*debian*) DISTRO="debian" ;;
    esac
fi
if [ "$DISTRO" = "debian" ] && ! python3 -m venv --help >/dev/null 2>&1; then
    FALTAN+=(python3-venv)
fi
if [ "$DISTRO" = "debian" ] && ! command -v xdg-mime >/dev/null 2>&1; then
    FALTAN+=(xdg-utils)
fi
if [ ${#FALTAN[@]} -gt 0 ]; then
    echo "Faltan dependencias del sistema: ${FALTAN[*]}"
    if [ "$DISTRO" = "debian" ]; then
        echo "  Instálalas con:  sudo apt install python3-tk python3-venv xdg-utils"
    elif [ "$DISTRO" = "rhel" ]; then
        echo "  Instálalas con:  sudo dnf install python3-tkinter"
    else
        echo "  Instala el paquete de tkinter de tu distro y vuelve a ejecutar."
    fi
    exit 1
fi
echo "[1/5] Dependencias del sistema OK ($DISTRO)"

# --- 2. venv con dependencias -----------------------------------------------
if [ ! -x "$VENV/bin/python" ]; then
    echo "[2/5] Creando venv en $VENV ..."
    python3 -m venv "$VENV"
    # tkinter es módulo C de la stdlib: el venv lo hereda del SO (ver paso 1).
    "$VENV/bin/pip" install -q pyhanko==0.20.0 pyhanko-certvalidator python-pkcs11 \
        pillow pymupdf pikepdf websocket-client
    "$VENV/bin/python" -c "import tkinter, pyhanko, pkcs11, websocket, pymupdf, pikepdf" \
        || { echo "[AVISO] el venv quedó sin alguna dependencia — reejecuta el instalador."; exit 1; }
else
    echo "[2/5] venv ya existe: $VENV"
fi

# --- 3. copiar script + assets ----------------------------------------------
if [ "$SRC_DIR" = "$APP_DIR" ]; then
    echo "[3/5] La app ya está en $APP_DIR"
else
    echo "[3/5] Copiando sgd-signer.py y assets a $APP_DIR ..."
    mkdir -p "$APP_DIR" "$APP_DIR/assets"
    cp "$SRC_DIR/sgd-signer.py" "$APP_DIR/sgd-signer.py"
    cp "$SRC_DIR"/assets/*.jpg "$APP_DIR/assets/" 2>/dev/null || true
    [ -f "$SRC_DIR/assets/icon.png" ] && cp "$SRC_DIR/assets/icon.png" "$APP_DIR/assets/"
fi

# --- 4. wrapper en PATH + daemon systemd (root, Linux) ----------------------
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/sgd-signer" <<EOF
#!/usr/bin/env bash
exec "$VENV/bin/python" "$APP_DIR/sgd-signer.py" "\$@"
EOF
chmod +x "$BIN_DIR/sgd-signer"
echo "[4/5] Wrapper en $BIN_DIR/sgd-signer"

if [ "$IS_ROOT" -eq 1 ] && [ "$(uname)" = "Linux" ]; then
    echo "      Daemon systemd sgd-signer.service (usuario del portal: $TARGET_USER) ..."
    cat > /etc/systemd/system/sgd-signer.service <<EOF
[Unit]
Description=sgd-signer daemon (Tramitedoc SGD SENAMHI)
After=pcscd.service network-online.target
Wants=pcscd.service

[Service]
Type=simple
ExecStart=$VENV/bin/python $APP_DIR/sgd-signer.py --daemon
Restart=always
RestartSec=3
Environment=HOME=$USER_HOME
# open_path lanza apps GUI (LibreOffice) que heredan el cgroup del daemon;
# con KillMode=process el restart mata solo python y deja viva la app del usuario.
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sgd-signer
    systemctl restart sgd-signer
elif [ "$(uname)" = "Linux" ]; then
    echo "      Daemon systemd: se salta (ejecutar como root para crearlo)."
fi

# --- 5. registro del protocolo tramitedoc:// ---------------------------------
if [ "$(uname)" = "Darwin" ]; then
    echo "[5/5] Registrando tramitedoc:// en LaunchServices (bundle .app) ..."
    APP="$HOME/Applications/SGD-Signer.app"
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
    cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>SGD-Signer</string>
    <key>CFBundleDisplayName</key><string>SGD-Signer</string>
    <key>CFBundleIdentifier</key><string>pe.senamhi.sgd-signer</string>
    <key>CFBundleVersion</key><string>1.0</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleExecutable</key><string>launcher</string>
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
    # macOS entrega la URL tramitedoc:// por AppleEvent (kAEGetURL), NO por argv:
    # un launcher bash que solo lee "$@" arranca con argc=0, abre la GUI y nunca
    # reenvia la URL al daemon -> el portal queda en rojo (sin CONEXION). Hay que
    # compilar el handler Swift que captura el AppleEvent.
    cat > "$APP/Contents/MacOS/handler.swift" <<SWIFT
import Cocoa
let VENV_PY = "$VENV/bin/python"
let SCRIPT  = "$APP_DIR/sgd-signer.py"
let FALLBACK_PY = "/usr/bin/python3"
func pythonPath() -> String {
    return FileManager.default.isExecutableFile(atPath: VENV_PY) ? VENV_PY : FALLBACK_PY
}
func launch(_ url: String?) {
    let t = Process()
    t.executableURL = URL(fileURLWithPath: pythonPath())
    t.arguments = url.map { [SCRIPT, \$0] } ?? [SCRIPT]
    try? t.run()
}
if CommandLine.arguments.count > 1 {
    let a = CommandLine.arguments[1]
    if a.lowercased().hasPrefix("tramitedoc:") { launch(a); exit(0) }
}
final class Delegate: NSObject, NSApplicationDelegate {
    var gotURL = false
    @objc func handleGetURL(_ ev: NSAppleEventDescriptor, withReplyEvent reply: NSAppleEventDescriptor) {
        gotURL = true
        if let u = ev.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue { launch(u) }
    }
    func applicationDidFinishLaunching(_ n: Notification) { if !self.gotURL { launch(nil) } }
    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }
}
let app = NSApplication.shared
let d = Delegate()
app.delegate = d
app.setActivationPolicy(.accessory)
NSAppleEventManager.shared().setEventHandler(
    d,
    andSelector: #selector(Delegate.handleGetURL(_:withReplyEvent:)),
    forEventClass: AEEventClass(kInternetEventClass),
    andEventID: AEEventID(kAEGetURL))
app.run()
SWIFT
    if xcrun swiftc -O "$APP/Contents/MacOS/handler.swift" -o "$APP/Contents/MacOS/launcher" 2>/dev/null; then
        chmod +x "$APP/Contents/MacOS/launcher"
    else
        echo "    AVISO: swiftc no disponible; launcher bash de respaldo (la URL no se reenviara)."
        printf '#!/usr/bin/env bash\nexec "%s/bin/python" "%s/sgd-signer.py" "$@"\n' "$VENV" "$APP_DIR" > "$APP/Contents/MacOS/launcher"
        chmod +x "$APP/Contents/MacOS/launcher"
    fi
    [ -f "$SRC_DIR/assets/icon.png" ] && cp "$SRC_DIR/assets/icon.png" "$APP/Contents/Resources/icon.png"
    # macOS IGNORA un .png suelto en Resources: sin CFBundleIconFile+icon.icns pinta
    # el icono generico (papel). Generar el .icns con herramientas nativas.
    if [ -f "$APP/Contents/Resources/icon.png" ]; then
        IS=$(mktemp -d)/icon.iconset; mkdir -p "$IS"
        for s in 16 32 64 128 256 512; do
            sips -z $s $s "$APP/Contents/Resources/icon.png" --out "$IS/icon_${s}x${s}.png" >/dev/null 2>&1
        done
        iconutil -c icns "$IS" -o "$APP/Contents/Resources/icon.icns" 2>/dev/null \
            && rm -f "$APP/Contents/Resources/icon.png"
        rm -rf "$(dirname "$IS")"
        PB=/usr/libexec/PlistBuddy
        "$PB" -c "Add :CFBundleIconFile string icon" "$APP/Contents/Info.plist" 2>/dev/null \
            || "$PB" -c "Set :CFBundleIconFile icon" "$APP/Contents/Info.plist" 2>/dev/null || true
    fi
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
        -f "$APP" || true
    echo "    Nota: en macOS el navegador preguntará la primera vez si abrir tramitedoc:// con SGD-Signer."
else
    echo "[5/5] Registrando tramitedoc:// en xdg (usuario $TARGET_USER) ..."
    mkdir -p "$USER_HOME/.local/share/applications"
    # 1) handler del protocolo: NO debe aparecer en el menú (NoDisplay)
    cat > "$USER_HOME/.local/share/applications/sgd-signer.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=SGD-SIGNER (protocolo tramitedoc)
Exec=$BIN_DIR/sgd-signer %u
Icon=sgd-signer
MimeType=x-scheme-handler/tramitedoc;
NoDisplay=true
EOF
    # 2) entrada visible del menú: la GUI de firma (única app que ve el usuario)
    cat > "$USER_HOME/.local/share/applications/sgd-signer-gui.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=SGD-SIGNER
Comment=Firma digital para el SGD de SENAMHI
Exec=$BIN_DIR/sgd-signer gui %f
Icon=sgd-signer
Terminal=false
Categories=Office;
MimeType=application/pdf;
EOF
    if [ "$IS_ROOT" -eq 1 ]; then
        chown -R "$TARGET_USER" "$USER_HOME/.local/share/applications/sgd-signer.desktop" \
                             "$USER_HOME/.local/share/applications/sgd-signer-gui.desktop" 2>/dev/null || true
        runuser -u "$TARGET_USER" -- xdg-mime default sgd-signer.desktop x-scheme-handler/tramitedoc || true
    else
        xdg-mime default sgd-signer.desktop x-scheme-handler/tramitedoc || true
        update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
    fi
    # icono en el hicolor del usuario del portal
    ICON_DIR="$USER_HOME/.local/share/icons/hicolor/256x256/apps"
    mkdir -p "$ICON_DIR"
    [ -f "$SRC_DIR/assets/icon.png" ] && cp "$SRC_DIR/assets/icon.png" "$ICON_DIR/sgd-signer.png"
    [ "$IS_ROOT" -eq 1 ] && chown -R "$TARGET_USER" "$USER_HOME/.local/share/icons/hicolor/256x256" 2>/dev/null || true
fi

echo
echo "[5/5] Listo."
echo
echo "Siguiente paso:"
echo "  1. Certificado (.p12/.pfx):  mkdir -p ~/.sgd-signer/certs && cp TU_CERT.p12 ~/.sgd-signer/certs/"
echo "     (o token USB Bit4id: instala su middleware y el Doctor de la GUI lo detecta)"
echo "  2. Guarda el PIN:  sgd-signer pin TU_PIN"
echo "  3. Diagnóstico:    sgd-signer diag"
echo "  4. En el portal SGD, al pulsar \"Firmar\" se abrirá sgd-signer automáticamente."
