#!/usr/bin/env python3
"""
SGD-SIGNER — Firma digital para el SGD de SENAMHI (https://www.senamhi.gob.pe/sgd).

Compatible con Linux, macOS y Windows. Firma documentos PDF con certificado
digital (token USB PKCS#11 o archivo .p12) y se integra con el portal de trámite
documentario vía el protocolo `tramitedoc://`.

Flujo:
  1. El portal lanza:  tramitedoc://?accion=TraDoc&urlBase=<base>&rutaPri=<dir>&ws=<wss://...>
  2. Este programa se registra como handler del esquema `tramitedoc://` (xdg-open / LaunchServices / registro de Windows).
  3. Conecta al WebSocket del servidor y responde mensajes JSON:
       {destination:"BROWSER", error:"0", message:"OK", sender:"CSHARP", accion, nrOperacion}
  4. EJECUTAR_FIRMA: descarga el PDF, abre la GUI para que el usuario lo lea y firme
     (PAdES, campo FirmaDigital/VistoDigital, sufijo [NF]/[F]/[VF]) y responde OK.
     El portal sube el firmado vía CARGAR_DOCUMENTO.

Uso:
  sgd-signer.py "tramitedoc://?accion=TraDoc&..."   # invocado por el OS (handler de URL)
  sgd-signer.py sign <pdf> [--tipo N] [--cert x.p12] [--pos x,y] [--pagina N]   # CLI directa
  sgd-signer.py gui [<pdf>] [--tipo N]              # GUI manual (leer + firmar)
  sgd-signer.py pin <PIN>                          # guarda PIN del certificado (chmod 600)
  sgd-signer.py certs                               # lista certificados disponibles

Config: ~/.sgd-signer/config.json  (cert, pin, tsl_check)
"""
import argparse
import getpass
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

CONFIG_DIR = Path.home() / ".sgd-signer"
CONFIG_FILE = CONFIG_DIR / "config.json"
CERT_DIR = CONFIG_DIR / "certs"
LOCK_SOCK = Path(tempfile.gettempdir()) / "sgd-signer.sock"
IS_WIN = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
TSL_URL = "https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml"
# texto real del original (config_firmaonpe.xml, MENSAJE_FIRMA_MASIVA)
MENSAJE_FIRMA_MASIVA = (
    "Se recomienda poner especial atención a la siguiente consulta, dado que se va "
    "a proceder a realizar la firma digital masiva de los archivos que usted ha "
    "seleccionado y que cada una de estas firmas digitales cuentan con validez y "
    "eficacia jurídica. Al presionar el botón ACEPTAR usted declara haber leído "
    "cada uno de los archivos. ¿Procede a firmarlos?"
)

# --- tipos de firma (idénticos al original) ---------------------------------
# tipo: (campo, sufijo, motivo)
TIPOS = {
    "1": ("FirmaDigital", "[NF]", "Soy el autor del documento"),   # Firma titular (FIRMA_NUM)
    "2": ("FirmaDigital", "[F]",  "Soy el autor del documento"),   # Firma básica (FIRMA_BASICO)
    "3": ("VistoDigital", "[VF]", "Doy V° B°"),                     # V° B° (VB_FIRMA)
    "4": ("FirmaDigital", "[F]",  "Soy el autor del documento"),   # Firma avanzada (FIRMA_AVA)
    "5": ("VistoDigital", "[VF]", "Doy V° B°"),                     # V° B° avanzada (VB_AVA)
    "6": ("FirmaDigital", "[F]",  "En señal de conformidad"),      # Firma recepción (FIRMA_REC)
    "7": ("FirmaDigital", "[F]",  "Por encargo"),                  # Firma por encargo (FIRMA_ENC)
}

# layout EXACTO del original .NET (iTextSharp) por tipo — coordenadas relativas al
# BBox del campo, extraídas del stream de apariencia de los PDFs de referencia:
#   (img_w, img_h, img_x, img_y, text_x, text_y_start, font_size, leading)
# firma (1,2,4,7): imagen 62×31 a la izquierda, texto Helvetica 5pt a la derecha.
# V°B° (3,5): imagen 75×37.5 arriba, texto 5pt abajo.
# recepción (6): imagen 71×16.03 (217×49) arriba, texto 5pt abajo.
STAMP_LAYOUT = {
    "1": (62, 31, 3.39, 1, 68.39, 28, 5, 5),  # = tipo 2 (titular idéntica a básica)
    "2": (62, 31, 3.39, 1, 68.39, 28, 5, 5),
    "3": (75, 37.5, 7, 36.5, 2, 30.5, 5, 5),
    "4": (62, 31, 3.39, 1, 68.39, 28, 5, 5),
    "5": (75, 37.5, 7, 36.5, 2, 30.5, 5, 5),
    "6": (71, 16.03, 6, 66.97, 1, 62.5, 5, 5),
    "7": (62, 31, 3.39, 1, 68.39, 28, 5, 5),
}

# posición de la imagen relativa al texto, por tipo (defaults del original .NET):
# firma (1,2,4,7) → imagen a la IZQUIERDA del texto; V°B° (3,5) y recepción (6) → imagen ENCIMA.
IMG_POS_DEFAULT = {
    "1": "left", "2": "left", "3": "top", "4": "left",
    "5": "top", "6": "top", "7": "left",
}


def _layout_generico(tipo, img_pos, box):
    """Layout de imagen+texto para una posición dada (left/right/top/bottom).
    box = (x0, y0, x1, y1) en la página; devuelve la tupla STAMP_LAYOUT (coordenadas
    relativas al BBox del form XObject). Solo se usa cuando el usuario cambia la
    posición por defecto del tipo; los defaults usan STAMP_LAYOUT exacto."""
    base = STAMP_LAYOUT.get(tipo, STAMP_LAYOUT["2"])
    img_w, img_h = base[0], base[1]
    W = box[2] - box[0]
    H = box[3] - box[1]
    pad, gap = 2.0, 3.0
    font_size, leading = 5, 5
    if img_pos == "left":
        img_x, img_y = pad, (H - img_h) / 2
        text_x = img_w + pad + gap
        text_y = H - pad - font_size
    elif img_pos == "right":
        img_x, img_y = W - img_w - pad, (H - img_h) / 2
        text_x = pad
        text_y = H - pad - font_size
    elif img_pos == "top":
        img_x, img_y = (W - img_w) / 2, H - img_h - pad
        text_x = pad
        text_y = H - img_h - pad - gap
    else:  # bottom
        img_x, img_y = (W - img_w) / 2, pad
        text_x = pad
        text_y = H - pad - font_size
    return (img_w, img_h, img_x, img_y, text_x, text_y, font_size, leading)


def partir_cn(cn):
    """Parte el CN de RENIEC en 3 líneas como el original .NET (iTextSharp):
    'RUIZ CAYAO Hammerly Scoot FAU 20131366028 hard' →
      'Firmado digitalmente por RUIZ'
      'CAYAO Hammerly Scoot FAU'
      '20131366028 hard'
    Regla: primer apellido en línea 1, resto del nombre hasta el DNI en línea 2,
    DNI + sufijo en línea 3."""
    tokens = cn.split()
    if not tokens:
        return ["Firmado digitalmente por (sin CN)"]
    dni_idx = next((i for i, t in enumerate(tokens) if t.isdigit()), len(tokens))
    lineas = [
        "Firmado digitalmente por " + tokens[0],
        " ".join(tokens[1:dni_idx]),
        " ".join(tokens[dni_idx:]),
    ]
    return [l for l in lineas if l]


MESES_ES = ["", "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio", "Julio",
            "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"]


def parse_nombre_doc(rutaDoc):
    """<serie>$<tipo>$<numero>$<lugar>$<año>$<mes>$<dia>$<inNumerar>.pdf (sección 4 CONTRATO.md).
    Si el nombre no matchea el formato (firma básica/VB sin numeración), devuelve {}."""
    base = os.path.basename(rutaDoc)
    if base.lower().endswith(".pdf"):
        base = base[:-4]
    partes = base.split("$")
    if len(partes) < 8:
        return {}
    serie, tipo_doc, numero, lugar, anio, mes, dia, in_numerar = partes[:8]
    try:
        mes_txt = MESES_ES[int(mes)]
    except (ValueError, IndexError):
        mes_txt = mes
    return {
        "NumeroDoc": f"{tipo_doc} N°   {numero}".strip(),
        "Lugar": lugar,
        "FechaLarga": f"{dia} de {mes_txt} del {anio}",
        "inNumerar": in_numerar,
    }


def _log_dir():
    """Carpeta de logs según la convención de cada SO."""
    if IS_WIN:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "sgd-signer" / "logs"
    if IS_MAC:
        return Path.home() / "Library" / "Logs" / "sgd-signer"
    return Path.home() / ".sgd-signer" / "logs"


def log(msg):
    line = f"[sgd-signer] {msg}"
    print(line, flush=True)
    try:
        d = _log_dir()
        d.mkdir(parents=True, exist_ok=True)
        with open(d / "sgd-signer.log", "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")
    except Exception:
        pass


def load_config():
    cfg = {}
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return cfg


def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    os.chmod(CONFIG_FILE, 0o600)


def find_certs():
    """Certificados PKCS#12 disponibles en ~/.sgd-signer/certs/ y cwd."""
    certs = []
    for d in (CERT_DIR, Path.cwd()):
        if d.exists():
            for p in sorted(d.glob("*.p12")) + sorted(d.glob("*.pfx")):
                certs.append(p)
    return certs


def pick_cert(cfg):
    """Certificado: prioriza ~/.sgd-signer/certs/ (1 solo → sin preguntar)."""
    certs = find_certs()
    if not certs:
        raise SystemExit(
            "No hay certificado. Coloca tu .p12/.pfx en ~/.sgd-signer/certs/ "
            "o pasa --cert <archivo>."
        )
    # si hay exactamente uno en el dir de certs, usarlo directo
    in_cert_dir = [c for c in certs if str(c).startswith(str(CERT_DIR))]
    if len(in_cert_dir) == 1:
        return str(in_cert_dir[0])
    if len(certs) == 1:
        return str(certs[0])
    print("Certificados disponibles:")
    for i, c in enumerate(certs, 1):
        print(f"  {i}. {c}")
    n = input("Elige (1-{}): ".format(len(certs)))
    return str(certs[int(n) - 1])


def get_pin(cfg, ctx=None, cert_path=None):
    """Resuelve el PIN: sesión en memoria (ctx, solo mientras el daemon vive) >
    guardado en disco (cfg) > variable de entorno > interactivo (solo si hay
    tty real — el daemon systemd no tiene, preguntar ahí colgaría el proceso).

    Con cert_path (certificado .p12/.pfx) usa la clave POR ARCHIVO
    (cfg['cert_pins'] / ctx['session_pins']), no la del token."""
    if cert_path:
        if ctx and ctx.get("session_pins", {}).get(cert_path):
            return ctx["session_pins"][cert_path]
        pin = cfg.get("cert_pins", {}).get(cert_path)
        if pin:
            return pin
        pin = os.environ.get("SGD_SIGNER_PIN")
        if pin:
            return pin
        if not sys.stdin.isatty():
            raise RuntimeError(
                "No hay clave guardada para este certificado — usa la GUI o 'sgd-signer pin <PIN>'."
            )
        return getpass.getpass("Clave del certificado: ")
    if ctx and ctx.get("session_pin"):
        return ctx["session_pin"]
    pin = cfg.get("pin")
    if not pin:
        pin = os.environ.get("SGD_SIGNER_PIN")
    if not pin:
        if not sys.stdin.isatty():
            raise RuntimeError(
                "No hay PIN guardado ni en sesión — usa la GUI o 'sgd-signer pin <PIN>'."
            )
        pin = getpass.getpass("PIN del certificado: ")
    return pin


# --- firma PAdES con pyhanko ------------------------------------------------
_PKCS11_SESSION_CACHE = {"session": None, "lib_path": None, "pin": None}
_PKCS11_LOCK = threading.Lock()


PKCS11_LIBS_CONOCIDAS = [
    "/usr/lib/bit4id/libbit4xpki.so",      # Bit4id (tokenME, Cosmo)
    "/usr/lib64/opensc-pkcs11.so",         # OpenSC (DNIe, CNS, genéricas)
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/local/lib/libeTPkcs11.so",       # SafeNet
    "/Library/bit4id/pkcs11/libbit4xpki.dylib",   # Bit4id (macOS)
    "/Library/bit4id/pkcs11/libbit4opki.dylib",   # Bit4id PKCS#11 opaco (macOS)
    "C:\\Windows\\System32\\bit4xpki.dll",
    "C:\\Windows\\System32\\opensc-pkcs11.dll",
]


def _cert_info(der):
    """Extrae (CN, emisor, no_after, serial) de un cert DER. Sin dependencias
    extra: asn1crypto ya viene con pyhanko."""
    from asn1crypto import x509 as asn1_x509
    c = asn1_x509.Certificate.load(der)
    subj = c.subject.native
    return {
        "cn": subj.get("common_name", "(sin CN)"),
        "org": subj.get("organization_name", ""),
        "emisor": c.issuer.native.get("common_name", ""),
        "no_after": c.not_valid_after,
        "serial": format(c.serial_number, "x"),
    }


def _cert_info_pkcs12(path, pin=None):
    """Lee (CN, org, emisor, no_after) de un .p12/.pfx. El contenedor está
    cifrado: sin PIN devuelve solo el nombre del archivo; con PIN incorrecto
    lanza (el llamador lo captura y marca el archivo como ilegible)."""
    from pyhanko.sign import signers
    if not pin:
        return {"cn": Path(path).name, "org": "", "emisor": "", "no_after": None}
    s = signers.SimpleSigner.load_pkcs12(str(path), passphrase=pin.encode())
    c = s.signing_cert
    subj = c.subject.native
    return {
        "cn": subj.get("common_name", Path(path).name),
        "org": subj.get("organization_name", ""),
        "emisor": c.issuer.native.get("common_name", ""),
        "no_after": c.not_valid_after,
    }


def _certs_de_sesion(sess, base, pin_ok=True):
    """Extrae los certificados de firma (con clave privada) de una sesión abierta.

    Importante: se materializan primero los certificados y sólo después se
    consultan las claves privadas. Llamar a get_key() mientras el iterador de
    get_objects() sigue abierto rompe el estado del driver PKCS#11 (Bit4id:
    OperationNotInitialized), porque son dos operaciones de búsqueda a la vez.
    """
    import pkcs11
    crudos = []
    for c in sess.get_objects({pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE}):
        try:
            cid = c[pkcs11.Attribute.ID]
            der = c[pkcs11.Attribute.VALUE]
            label = c[pkcs11.Attribute.LABEL]
        except Exception:
            continue
        if cid:
            crudos.append((cid, der, label))

    out = []
    for cid, der, label in crudos:
        # sólo certificados de firma: los que tienen clave privada en el token
        # (los CA intermedios embebidos no la tienen)
        try:
            sess.get_key(pkcs11.ObjectClass.PRIVATE_KEY, id=cid)
        except Exception:
            continue
        try:
            info = _cert_info(der)
        except Exception:
            continue
        out.append({**base, **info, "key_id": cid, "label": label, "listo": pin_ok})
    return out


def listar_certificados(pin=None):
    """Detecta TODOS los certificados de firma disponibles en todos los módulos
    PKCS#11 y tokens conectados. Devuelve lista de dicts con la info necesaria
    para elegir uno y para validarlo.

    Una PC puede tener varios dispositivos (token USB + smartcard). Sin PIN sólo
    se listan los tokens; con PIN se abre sesión y se leen los certificados.

    Reusa la sesión cacheada del daemon cuando corresponde: los drivers PKCS#11
    (Bit4id) fallan con OperationNotInitialized si se abre una segunda sesión
    sobre la misma tarjeta mientras otra está viva.
    """
    import pkcs11
    encontrados = []
    vistos = set()  # (serial_token, key_id_hex) — la misma tarjeta puede verse
                    # desde dos módulos (Bit4id + OpenSC); no duplicar
    with _PKCS11_LOCK:
        cached = _PKCS11_SESSION_CACHE
        for lib_path in PKCS11_LIBS_CONOCIDAS:
            if not Path(lib_path).exists():
                continue
            try:
                lib = pkcs11.lib(lib_path)
                tokens = list(lib.get_tokens())
            except Exception:
                continue
            for tok in tokens:
                try:
                    serial = (tok.serial.decode(errors="ignore")
                              if isinstance(tok.serial, bytes) else str(tok.serial)).strip()
                    base = {"lib": lib_path, "token": tok.label.strip(), "serial_token": serial}
                except Exception:
                    continue
                if not pin:
                    encontrados.append({**base, "cn": f"(token {base['token']} — requiere PIN)",
                                        "key_id": None, "listo": False})
                    continue
                # reusar la sesión viva del daemon si es el mismo módulo y PIN
                nuevos = []
                reusar = (cached["session"] is not None
                          and cached["lib_path"] == lib_path
                          and cached["pin"] == pin)
                if reusar:
                    try:
                        nuevos = _certs_de_sesion(cached["session"], base)
                    except Exception:
                        reusar = False  # sesión muerta: abrir una nueva abajo
                if not reusar:
                    try:
                        sess = tok.open(rw=False, user_pin=pin)
                    except Exception as e:
                        # un módulo que no puede abrir esta tarjeta (p.ej. OpenSC
                        # sobre una faceta CNS sin PIN de usuario) no es un error:
                        # otro módulo sí la expone. Se omite en silencio.
                        # EXCEPCIÓN: PIN bloqueado — el token SÍ está presente y
                        # hay que mostrarlo con aviso, no hacerlo desaparecer.
                        log(f"PKCS#11 {Path(lib_path).name}/{base['token']}: {type(e).__name__}")
                        if "PinLocked" in type(e).__name__ or "PIN_LOCKED" in str(e):
                            encontrados.append({**base, "cn": f"(token {base['token']} — PIN BLOQUEADO)",
                                                "key_id": None, "listo": False,
                                                "bloqueado": True})
                        continue
                    try:
                        nuevos = _certs_de_sesion(sess, base)
                    except Exception as e:
                        log(f"PKCS#11 {Path(lib_path).name}: no se pudieron leer certs ({type(e).__name__})")
                        nuevos = []
                    finally:
                        try:
                            sess.close()
                        except Exception:
                            pass
                for c in nuevos:
                    clave = (c.get("serial_token"), c["key_id"].hex() if c.get("key_id") else None)
                    if clave in vistos:
                        continue
                    vistos.add(clave)
                    encontrados.append(c)
    return encontrados


def validar_certificado(info):
    """Comprueba que el certificado elegido esté OK para firmar.
    Devuelve (ok, [mensajes])."""
    import datetime
    msgs = []
    ok = True
    if not info.get("listo"):
        return False, ["El certificado no está accesible (¿PIN incorrecto o token desconectado?)"]
    no_after = info.get("no_after")
    if no_after:
        ahora = datetime.datetime.now(datetime.timezone.utc)
        if no_after < ahora:
            ok = False
            msgs.append(f"VENCIDO el {no_after:%d/%m/%Y}")
        else:
            dias = (no_after - ahora).days
            msgs.append(f"Vence el {no_after:%d/%m/%Y} ({dias} días)")
            if dias < 30:
                msgs.append("Vence pronto: renuévalo")
    if info.get("emisor"):
        msgs.append(f"Emisor: {info['emisor']}")
    return ok, msgs


def _detectar_token_pkcs11():
    """Devuelve la ruta del primer módulo PKCS#11 que tiene un token presente,
    o None si no hay ninguno. No abre sesión (no toca el PIN)."""
    import pkcs11
    for lib_path in PKCS11_LIBS_CONOCIDAS:
        if not Path(lib_path).exists():
            continue
        try:
            lib = pkcs11.lib(lib_path)
            if list(lib.get_tokens()):
                return lib_path
        except Exception:
            continue
    return None


def desbloquear_token(puk, nuevo_pin, lib_path=None):
    """Desbloquea un token con PIN bloqueado usando el PUK (SO PIN).

    Abre sesión SO (rw) con el PUK y restablece el PIN de usuario con
    init_pin (C_InitPIN — la función correcta para PIN bloqueado; C_SetPIN
    exige conocer el PIN actual y falla con PinIncorrect aunque el PUK sea
    correcto). Fallback a set_pin para tokens que no soportan init_pin.
    Devuelve el label del token desbloqueado.
    """
    import pkcs11
    lib_path = lib_path or _detectar_token_pkcs11()
    if not lib_path:
        raise RuntimeError("No hay token USB conectado")
    lib = pkcs11.lib(lib_path)
    toks = list(lib.get_tokens())
    if not toks:
        raise RuntimeError("No hay token USB conectado")
    tok = toks[0]
    sess = tok.open(rw=True, so_pin=puk)
    try:
        try:
            sess.init_pin(nuevo_pin)
        except Exception:
            # tokens que no exponen C_InitPIN: set_pin con el nuevo como viejo
            sess.set_pin(nuevo_pin, nuevo_pin)
    finally:
        try:
            sess.close()
        except Exception:
            pass
    return tok.label


# --- diagnóstico y auto-instalación (autocontenido, estilo AnyDesk) ---------

def _middleware_presente():
    """True si hay al menos un módulo PKCS#11 instalado en el sistema."""
    return any(Path(p).exists() for p in PKCS11_LIBS_CONOCIDAS)


def _esquema_registrado():
    """True si tramitedoc:// está registrado como handler en este OS."""
    if IS_WIN:
        # registro de Windows: HKCU\Software\Classes\tramitedoc
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Classes\tramitedoc") as k:
                return True
        except Exception:
            return False
    if IS_LINUX:
        # xdg-mime query default x-scheme-handler/tramitedoc
        try:
            r = subprocess.run(
                ["xdg-mime", "query", "default", "x-scheme-handler/tramitedoc"],
                capture_output=True, text=True, timeout=5)
            return bool(r.stdout.strip())
        except Exception:
            return False
    # macOS: bundle .app registrado en LaunchServices
    app = Path.home() / "Applications" / "SGD-Signer.app"
    return app.exists()


def _deps_presentes():
    """True si las dependencias Python (pyhanko, pkcs11, websocket-client) están."""
    for mod in ("pyhanko", "pkcs11", "websocket"):
        try:
            __import__(mod)
        except Exception:
            return False
    return True


def diagnostico():
    """Revisa el estado de instalación y devuelve una lista de dicts:
    {item, ok, detalle, accion}. 'accion' es None si no hay nada que arreglar
    automáticamente, o una clave que auto_instalar() sabe resolver."""
    out = []

    # 1. daemon
    daemon_ok = _sock_alive()
    out.append({
        "item": "Daemon",
        "ok": daemon_ok,
        "detalle": "corriendo" if daemon_ok else "no está corriendo",
        "accion": None if daemon_ok else "daemon",
    })

    # 2. middleware PKCS#11 (driver del token)
    mw = _middleware_presente()
    out.append({
        "item": "Middleware Bit4id (driver PKCS#11)",
        "ok": mw,
        "detalle": "instalado" if mw else "no instalado",
        "accion": None,  # requiere sudo + descarga del fabricante: solo instrucciones
    })

    # 3. esquema tramitedoc://
    esq = _esquema_registrado()
    out.append({
        "item": "Protocolo tramitedoc://",
        "ok": esq,
        "detalle": "registrado" if esq else "no registrado",
        "accion": None if esq else "esquema",
    })

    # 4. token conectado
    tok = _detectar_token_pkcs11() if mw else None
    out.append({
        "item": "Token USB conectado",
        "ok": bool(tok),
        "detalle": f"detectado ({tok})" if tok else "no detectado",
        "accion": None,
    })

    # 5. dependencias Python
    deps = _deps_presentes()
    out.append({
        "item": "Dependencias Python",
        "ok": deps,
        "detalle": "instaladas" if deps else "faltan",
        "accion": None if deps else "deps",
    })

    # 6. servicio de autoarranque del daemon (systemd / LaunchAgent)
    svc = _servicio_instalado()
    out.append({
        "item": "Servicio daemon (autoarranque)",
        "ok": svc,
        "detalle": "instalado" if svc else "no instalado",
        "accion": None if svc else "servicio",
    })

    # 7. certificados importados (.p12/.pfx) — guardados en la PC
    importados = sorted(CERT_DIR.glob("*.p12")) + sorted(CERT_DIR.glob("*.pfx"))
    out.append({
        "item": "Certificados importados",
        "ok": bool(importados),
        "detalle": (f"{len(importados)} en ~/.sgd-signer/certs/"
                    if importados else "ninguno (usa 'Importar certificado…')"),
        "accion": None,
    })

    # 8. certificado activo (archivo importado o token USB)
    cfg = load_config()
    activo = cfg.get("cert")
    if activo:
        existe = Path(activo).exists()
        out.append({
            "item": "Certificado activo",
            "ok": existe,
            "detalle": Path(activo).name if existe else f"no existe: {activo}",
            "accion": None,
        })
    else:
        out.append({
            "item": "Certificado activo",
            "ok": bool(cfg.get("cert_key_id")),
            "detalle": "token USB (auto)" if cfg.get("cert_key_id") else "ninguno elegido",
            "accion": None,
        })

    return out


def auto_instalar(acciones):
    """Ejecuta las auto-reparaciones que no requieren sudo. Devuelve lista de
    (item, ok, mensaje). Las que requieren sudo (middleware) se reportan como
    pendientes con instrucciones."""
    resultados = []
    for accion in acciones:
        if accion == "daemon":
            try:
                _ensure_daemon()
                ok = _sock_alive()
                resultados.append(("Daemon", ok,
                                   "arrancado" if ok else "no pudo arrancar"))
            except Exception as e:
                resultados.append(("Daemon", False, str(e)))
        elif accion == "esquema":
            resultados.append(_registrar_esquema())
        elif accion == "deps":
            resultados.append(_instalar_deps())
        elif accion == "servicio":
            resultados.append(_instalar_servicio())
        elif accion == "middleware":
            resultados.append(("Middleware Bit4id", False,
                               "requiere sudo: ver instrucciones"))
    return resultados


def _registrar_esquema():
    """Registra tramitedoc:// en el OS actual. Sin sudo (usa el HOME del usuario)."""
    try:
        if IS_WIN:
            import winreg
            # HKCU\Software\Classes\tramitedoc -> comando
            exe = sys.executable
            script = os.path.abspath(__file__)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Classes\tramitedoc") as k:
                winreg.SetValue(k, None, winreg.REG_SZ, "URL:tramitedoc protocol")
                winreg.SetValueEx(k, "URL Protocol", 0, winreg.REG_SZ, "")
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Classes\tramitedoc\shell\open\command") as k:
                winreg.SetValue(k, None, winreg.REG_SZ,
                                f'"{exe}" "{script}" "%1"')
            return ("Protocolo tramitedoc://", True, "registrado (Windows)")
        if IS_LINUX:
            bin_dir = Path.home() / ".local" / "bin"
            app_dir = Path.home() / ".local" / "share" / "sgd-signer"
            app_dir.mkdir(parents=True, exist_ok=True)
            bin_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(os.path.abspath(__file__), app_dir / "sgd-signer.py")
            wrapper = bin_dir / "sgd-signer"
            wrapper.write_text(
                f"#!/usr/bin/env bash\nexec {sys.executable} "
                f"{app_dir / 'sgd-signer.py'} \"$@\"\n")
            wrapper.chmod(0o755)
            desktop = Path.home() / ".local" / "share" / "applications" / "sgd-signer.desktop"
            desktop.parent.mkdir(parents=True, exist_ok=True)
            desktop.write_text(
                "[Desktop Entry]\nType=Application\n"
                "Name=SGD-SIGNER (protocolo tramitedoc)\n"
                f"Exec={wrapper} %u\n"
                "MimeType=x-scheme-handler/tramitedoc;\nNoDisplay=true\n")
            desktop.chmod(0o755)
            subprocess.run(["xdg-mime", "default", "sgd-signer.desktop",
                            "x-scheme-handler/tramitedoc"], timeout=10)
            return ("Protocolo tramitedoc://", True, "registrado (Linux)")
        # macOS: bundle .app con handler Swift nativo.
        # Un launcher bash NO puede recibir el AppleEvent kAEGetURL que macOS
        # envía al lanzar un esquema de URL (por eso "abre para firmar" en vez
        # de conectar el portal). Compilamos un binario Swift que captura el
        # evento y reenvía la URL al script. Si no hay swiftc (CLT), caemos al
        # launcher bash (abre la GUI, pero no captura URL).
        app = Path.home() / "Applications" / "SGD-Signer.app"
        (app / "Contents" / "MacOS").mkdir(parents=True, exist_ok=True)
        (app / "Contents" / "Resources").mkdir(parents=True, exist_ok=True)
        (app / "Contents" / "Info.plist").write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            '<key>CFBundleName</key><string>SGD-Signer</string>\n'
            '<key>CFBundleIdentifier</key><string>pe.senamhi.sgd-signer</string>\n'
            '<key>CFBundleVersion</key><string>1.0</string>\n'
            '<key>CFBundleExecutable</key><string>launcher</string>\n'
            '<key>CFBundlePackageType</key><string>APPL</string>\n'
            '<key>CFBundleURLTypes</key><array><dict>\n'
            '<key>CFBundleURLName</key><string>Tramitedoc</string>\n'
            '<key>CFBundleURLSchemes</key><array><string>tramitedoc</string></array>\n'
            '</dict></array>\n</dict></plist>\n')
        launcher = app / "Contents" / "MacOS" / "launcher"
        py = sys.executable
        script = os.path.abspath(__file__)
        swift_src = (
            'import Cocoa\n'
            f'let PY = "{py}"\n'
            f'let SCRIPT = "{script}"\n'
            'func launch(_ url: String?) {\n'
            '    let t = Process()\n'
            '    t.executableURL = URL(fileURLWithPath: PY)\n'
            '    t.arguments = url.map { [SCRIPT, $0] } ?? [SCRIPT]\n'
            '    try? t.run()\n'
            '}\n'
            '// LaunchServices pasa la URL del esquema como argv[1] al lanzar la\n'
            '// app (síncrono y fiable). Si viene, la reenviamos y salimos sin\n'
            '// abrir NSApplication ni esperar timers.\n'
            'if CommandLine.arguments.count > 1 {\n'
            '    let a = CommandLine.arguments[1]\n'
            '    if a.lowercased().hasPrefix("tramitedoc:") {\n'
            '        launch(a)\n'
            '        exit(0)\n'
            '    }\n'
            '}\n'
            '// Sin argv (doble clic): modo NSApplication con AppleEvent como\n'
            '// fallback por si el lanzador no pasó argv.\n'
            'final class Delegate: NSObject, NSApplicationDelegate {\n'
            '    var gotURL = false\n'
            '    @objc func handleGetURL(_ ev: NSAppleEventDescriptor, withReplyEvent reply: NSAppleEventDescriptor) {\n'
            '        gotURL = true\n'
            '        if let u = ev.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue {\n'
            '            launch(u)\n'
            '        }\n'
            '    }\n'
            '    func applicationDidFinishLaunching(_ n: Notification) {\n'
            '        if !self.gotURL { launch(nil) }\n'
            '    }\n'
            '    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }\n'
            '}\n'
            'let app = NSApplication.shared\n'
            'let d = Delegate()\n'
            'app.delegate = d\n'
            'app.setActivationPolicy(.accessory)\n'
            'NSAppleEventManager.shared().setEventHandler(\n'
            '    d,\n'
            '    andSelector: #selector(Delegate.handleGetURL(_:withReplyEvent:)),\n'
            '    forEventClass: AEEventClass(kInternetEventClass),\n'
            '    andEventID: AEEventID(kAEGetURL))\n'
            'app.run()\n'
        )
        swift_file = app / "Contents" / "MacOS" / "handler.swift"
        swift_file.write_text(swift_src)
        try:
            subprocess.run(["swiftc", "-O", str(swift_file), "-o", str(launcher)],
                           timeout=120, check=True)
        except Exception:
            # fallback: launcher bash (abre GUI, no captura URL)
            launcher.write_text(
                f"#!/usr/bin/env bash\nexec {py} {script} \"$@\"\n")
            launcher.chmod(0o755)
        subprocess.run([
            "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
            "LaunchServices.framework/Support/lsregister", "-f", str(app)],
            timeout=15)
        return ("Protocolo tramitedoc://", True, "registrado (macOS)")
    except Exception as e:
        return ("Protocolo tramitedoc://", False, str(e))


def _servicio_instalado():
    """True si el daemon está instalado como servicio de autoarranque del SO."""
    if IS_LINUX:
        return (Path("/etc/systemd/system/sgd-signer.service").exists()
                or (Path.home() / ".config/systemd/user/sgd-signer.service").exists())
    if IS_MAC:
        return (Path.home() / "Library/LaunchAgents/pe.senamhi.sgd-signer.plist").exists()
    return True  # Windows: el daemon se lanza con la GUI, no hay servicio


def _instalar_servicio():
    """Instala el daemon como servicio del SO desde la propia app (sin install.sh).

    Linux: unit systemd (root, para el token USB) -> requiere sudo.
    macOS: LaunchAgent del usuario (sin sudo, el daemon corre como el usuario).
    """
    try:
        if IS_LINUX:
            unit = (
                "[Unit]\nDescription=sgd-signer daemon (Tramitedoc SGD SENAMHI)\n"
                "After=pcscd.service network-online.target\nWants=pcscd.service\n\n"
                "[Service]\nType=simple\n"
                f"ExecStart={sys.executable} {os.path.abspath(__file__)} --daemon\n"
                "Restart=always\nRestartSec=3\n"
                f"Environment=HOME={Path.home()}\n"
                "KillMode=process\n\n"
                "[Install]\nWantedBy=multi-user.target\n"
            )
            tmp = Path(tempfile.gettempdir()) / "sgd-signer.service"
            tmp.write_text(unit)
            # sudo -n: si no hay sudo sin password, reportamos el comando manual
            r = subprocess.run(["sudo", "-n", "cp", str(tmp),
                                "/etc/systemd/system/sgd-signer.service"],
                               timeout=15)
            if r.returncode != 0:
                return ("Servicio daemon (systemd)", False,
                        "requiere sudo: 'sudo cp %s /etc/systemd/system/ && "
                        "sudo systemctl enable --now sgd-signer'" % tmp)
            subprocess.run(["sudo", "-n", "systemctl", "daemon-reload"], timeout=15)
            subprocess.run(["sudo", "-n", "systemctl", "enable", "--now",
                            "sgd-signer"], timeout=30)
            return ("Servicio daemon (systemd)", True, "instalado y activo")
        if IS_MAC:
            plist = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                '<plist version="1.0"><dict>\n'
                '<key>Label</key><string>pe.senamhi.sgd-signer</string>\n'
                '<key>ProgramArguments</key><array>\n'
                f'<string>{sys.executable}</string>\n'
                f'<string>{os.path.abspath(__file__)}</string>\n'
                '<string>--daemon</string>\n'
                '</array>\n'
                '<key>RunAtLoad</key><true/>\n'
                '<key>KeepAlive</key><true/>\n'
                '</dict></plist>\n'
            )
            agent = Path.home() / "Library/LaunchAgents/pe.senamhi.sgd-signer.plist"
            agent.parent.mkdir(parents=True, exist_ok=True)
            agent.write_text(plist)
            subprocess.run(["launchctl", "unload", str(agent)], timeout=10)
            subprocess.run(["launchctl", "load", str(agent)], timeout=10)
            return ("Servicio daemon (LaunchAgent)", True, "instalado y activo")
        return ("Servicio daemon", True, "no aplica (Windows)")
    except Exception as e:
        return ("Servicio daemon", False, str(e))


def _instalar_deps():
    """Instala las dependencias Python que falten con pip (sin sudo, en el venv)."""
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q",
                        "pyhanko==0.20.0", "websocket-client", "python-pkcs11"],
                       timeout=300, check=True)
        return ("Dependencias Python", _deps_presentes(), "instaladas")
    except Exception as e:
        return ("Dependencias Python", False, str(e))


def make_signer(cfg, pin, cert_path=None):
    """Construye el firmante: .p12/.pfx elegido (importado o --cert) o PKCS#11.

    Prioridad: archivo elegido (cfg['cert'] o cert_path) > token USB. Si no hay
    archivo, usa el certificado elegido en cfg['cert_key_id'] + cfg['token_lib']
    si existe; si no, auto-detecta el primero con clave privada (los certs CA
    no la tienen).

    La sesión PKCS#11 se cachea a nivel de proceso (daemon vive todo el día,
    firma muchas veces): abrir una sesión nueva por cada firma sin cerrar la
    anterior agota los slots de login del token y el 2do+ intento revienta
    con UserAlreadyLoggedIn. Root cause fix, no parche por caller.
    """
    # archivo .p12/.pfx explícito (--cert o importado en la GUI): prioridad
    cert_path = cert_path or cfg.get("cert")
    if cert_path and Path(cert_path).exists():
        from pyhanko.sign import signers
        if cert_path.lower().endswith((".p12", ".pfx")):
            return signers.SimpleSigner.load_pkcs12(cert_path, passphrase=pin.encode())
        return signers.SimpleSigner.load(cert_path, passphrase=pin.encode())
    # Auto-detectar el módulo PKCS#11 si hay un token conectado, aunque el
    # usuario no haya elegido certificado antes (SET_PIN valida el PIN contra
    # el token). Evita caer a la rama .p12 -> pick_cert() -> input() en el
    # daemon sin stdin (EOFError). El flag cfg["token"] ya no se usa: la señal
    # real es tener un módulo PKCS#11 con un token presente.
    lib_path = cfg.get("token_lib")
    if not lib_path:
        lib_path = _detectar_token_pkcs11()
    if lib_path:
        import pkcs11
        from pyhanko.sign.pkcs11 import PKCS11Signer
        elegido = cfg.get("cert_key_id")  # hex del ID del cert elegido
        with _PKCS11_LOCK:
            cached = _PKCS11_SESSION_CACHE
            if (cached["session"] is not None and cached["lib_path"] == lib_path
                    and cached["pin"] == pin):
                sess = cached["session"]
            else:
                if cached["session"] is not None:
                    try:
                        cached["session"].close()
                    except Exception:
                        pass
                lib = pkcs11.lib(lib_path)
                toks = list(lib.get_tokens())
                if not toks:
                    raise SystemExit("No hay token USB conectado")
                # si se eligió un token concreto por serial, usarlo
                serial_pref = cfg.get("cert_token_serial")
                tok = toks[0]
                if serial_pref:
                    for t in toks:
                        s = (t.serial.decode(errors="ignore") if isinstance(t.serial, bytes)
                             else str(t.serial)).strip()
                        if s == serial_pref:
                            tok = t
                            break
                sess = tok.open(rw=False, user_pin=pin)
                cached["session"] = sess
                cached["lib_path"] = lib_path
                cached["pin"] = pin
        # certificados del token
        certs = []
        for c in sess.get_objects({pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE}):
            try:
                label = c[pkcs11.Attribute.LABEL]
            except Exception:
                label = ""
            try:
                cid = c[pkcs11.Attribute.ID]
            except Exception:
                cid = None
            certs.append((label, cid))
        # 1) el elegido explícitamente en configuración
        if elegido:
            for label, cid in certs:
                if cid and cid.hex() == elegido:
                    return PKCS11Signer(sess, key_id=cid, cert_label=label or None)
        # 2) auto: el cert de usuario (con clave privada del mismo ID)
        for label, cid in certs:
            if not cid:
                continue
            try:
                sess.get_key(pkcs11.ObjectClass.PRIVATE_KEY, id=cid)
                return PKCS11Signer(sess, key_id=cid, cert_label=label or None)
            except Exception:
                continue
        raise SystemExit("No se encontró certificado de firma en el token")


# en binario PyInstaller los assets viven en sys._MEIPASS, no junto al .py
ASSETS_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "assets"
# imagen de firma real (extraída del MSI original) por tipo; 6→imagenFirma6.jpg, resto→imagenFirma<N>.jpg
# tipo 7 (por encargo) no tiene imagen propia en el MSI: usa la genérica imagenFirma.jpg.
IMG_POR_TIPO = {t: ASSETS_DIR / f"imagenFirma{t}.jpg" for t in TIPOS}
IMG_POR_TIPO["7"] = ASSETS_DIR / "imagenFirma.jpg"


FIRMA_W, FIRMA_H = 190, 60  # recuadro de firma manual (pt) — 5 líneas a leading 6 + imagen


def firma_box(tipo, W, H, pos=None, ms=0):
    """Caja de la firma en coordenadas PDF (x0, y0, x1, y1, desde abajo).
    Única fuente de verdad: la usa sign_pdf para firmar y la GUI para la vista
    previa, así la preview ocupa exactamente el espacio real de la firma."""
    if pos:
        x, y = pos
        # el click marca la esquina superior izquierda; la caja crece hacia abajo.
        # 35pt era demasiado bajo: comprimía las 5 líneas del texto y escalaba la
        # imagen (168x84 px) al 10%, por eso la firma "no se notaba".
        x = max(0, min(x, W - FIRMA_W))
        y_top = max(FIRMA_H, min(H - y, H))
        return (x, y_top - FIRMA_H, x + FIRMA_W, y_top)
    if tipo == "3":   # VB_FIRMA: abajo izquierda
        return (5, 50, 90, 125)
    if tipo == "6":   # FIRMA_REC: abajo izquierda
        return (20, H - 95 - ms, 105, H - 12 - ms)
    # 1 (titular, = básica), 2 (básica) y 4/5 (avanzadas sin pos): abajo derecha
    return (W - 180, H - 59 - ms, W - 25, H - 24 - ms)


def _contar_firmas(pdf_path, campo_base):
    """Cuenta los campos de firma existentes cuyo nombre empieza con campo_base.
    Devuelve el número de firmas ya presentes (0 si ninguna)."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils import generic
    try:
        r = PdfFileReader(open(pdf_path, "rb"))
    except Exception:
        return 0
    root = r.root
    acro = root.get("/AcroForm")
    if acro is None:
        return 0
    acro = r.get_object(acro) if not isinstance(acro, generic.DictionaryObject) else acro
    fields = acro.get("/Fields")
    if fields is None:
        return 0
    n = 0
    for f in fields:
        f = r.get_object(f) if not isinstance(f, generic.DictionaryObject) else f
        t = f.get("/T")
        if t is not None and str(t).startswith(campo_base):
            n += 1
    return n


def sign_pdf(pdf_path, tipo, cert_path, pin, pos=None, pagina=1, extra=None, cfg=None, out_path=None):
    from pyhanko.sign import signers, fields
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.images import PdfImage
    from pyhanko.pdf_utils.reader import PdfFileReader
    from PIL import Image as PILImage

    campo, sufijo, motivo = TIPOS[tipo]
    extra = extra or {}
    cfg = cfg or {}

    signer = make_signer(cfg, pin, cert_path)
    subj = signer.signing_cert.subject.native
    cn = subj.get("common_name", "Firmante")

    # tamaño de página (puntos) para posiciones relativas.
    # strict=False: PDFs con hybrid xref (ciertos generadores) bloquean la firma
    # con "Attempting to sign document with hybrid cross-reference sections while
    # hybrid xrefs are disabled" si el reader es estricto (pyhanko pdf_signer.py).
    r = PdfFileReader(open(pdf_path, "rb"), strict=False)

    def page_obj(reader, n):
        """Navega el árbol /Pages y devuelve el objeto de la página n (1-based)."""
        from pyhanko.pdf_utils.generic import DictionaryObject
        stack = [reader.root["/Pages"]]
        count = 0
        while stack:
            node = stack.pop()
            if not isinstance(node, DictionaryObject):
                node = reader.get_object(node)
            for kid in node["/Kids"]:
                k = kid if isinstance(kid, DictionaryObject) else reader.get_object(kid)
                if "/Kids" in k:
                    stack.append(k)
                else:
                    count += 1
                    if count == n:
                        return k
        raise IndexError(f"página {n} no existe")

    page = page_obj(r, pagina)
    mb = page["/MediaBox"]
    W, H = float(mb[2]), float(mb[3])

    # posiciones idénticas al original (iText, coordenadas PDF desde abajo)
    # override de posición configurado por el usuario (persistente, por tipo) —
    # solo aplica si el caller no forzó una posición puntual (pos=None).
    apariencia_tipo = (cfg.get("apariencia") or {}).get(tipo, {})
    if pos is None and apariencia_tipo.get("pos"):
        pos = tuple(apariencia_tipo["pos"])

    ms = 0  # margen superior (inNumerar) — el portal no lo envía
    box = firma_box(tipo, W, H, pos=pos, ms=ms)

    # apilar firmas múltiples: si ya hay firmas del mismo tipo, numerar el campo
    # y desplazar la caja hacia abajo para no superponer (el original .NET usaba
    # FirmaDigital1, FirmaDigital2, ...). Sin esto, append_signature_field lanza
    # PdfWriteError('Signature field with name ... already exists').
    n_previas = _contar_firmas(pdf_path, campo)
    campo_num = campo if n_previas == 0 else f"{campo}{n_previas + 1}"
    if n_previas > 0:
        h = box[3] - box[1]  # altura de la firma
        dy = n_previas * (h + 5)  # 5pt de separación entre firmas
        box = (box[0], max(0, box[1] - dy), box[2], max(0, box[3] - dy))

    # texto visible: replica el stream EXACTO del original .NET (iTextSharp):
    # CN partido en 3 líneas (partir_cn) + motivo + fecha, Helvetica 5pt negro.
    fecha_hora = time.strftime("%d.%m.%Y %H:%M:%S -05:00")
    lineas = partir_cn(cn)
    lineas.append(f"Motivo: {motivo}")
    lineas.append(f"Fecha: {fecha_hora}")

    # tipo 1 (FIRMA_NUM): número + lugar/fecha se dibujan aparte en 13pt/12pt
    # (stream exacto del original .NET, ver render()). No van en el bloque 5pt.
    lugar_fecha = extra.get("Lugar") or ""
    if extra.get("FechaLarga"):
        lugar_fecha = f"{lugar_fecha}, {extra['FechaLarga']}" if lugar_fecha else extra["FechaLarga"]
    if tipo != "1" and (extra.get("NumeroDoc") or lugar_fecha):
        lineas = [extra.get("NumeroDoc") or lugar_fecha, lugar_fecha if extra.get("NumeroDoc") else None, ""] if extra.get("NumeroDoc") else [lugar_fecha] + lineas
        lineas = [l for l in lineas if l is not None]

    img_path = Path(apariencia_tipo["imagen"]) if apariencia_tipo.get("imagen") else IMG_POR_TIPO.get(tipo)
    # posición de la imagen relativa al texto (left/right/top/bottom), configurable
    # por tipo. Defaults del original .NET: firma→left, V°B°/recepción→top.
    img_pos = apariencia_tipo.get("img_pos") or IMG_POS_DEFAULT.get(tipo, "left")
    if img_pos == IMG_POS_DEFAULT.get(tipo, "left"):
        layout = STAMP_LAYOUT.get(tipo, STAMP_LAYOUT["2"])
    else:
        layout = _layout_generico(tipo, img_pos, box)

    # stamp custom que replica el stream del original: imagen a escala fija (opacidad
    # 1.0) + texto Helvetica 5pt negro en coordenadas fijas. Reemplaza a TextStampStyle
    # (Courier 7pt, opacidad 0.6, NO_SCALING) que producía firmas opacas y descolocadas.
    from pyhanko.stamp import BaseStamp
    from pyhanko.pdf_utils.content import ResourceType
    from pyhanko.pdf_utils.generic import TextStringObject, DictionaryObject, pdf_name, StreamObject, ArrayObject, FloatObject
    from pyhanko.pdf_utils.layout import BoxConstraints
    from io import BytesIO

    class _SgdStamp(BaseStamp):
        def __init__(self, writer, box, tipo):
            super().__init__(writer=writer, style=None, box=box)
            self.tipo = tipo

        def as_form_xobject(self):
            # pyhanko escribe el BBox con origen arriba-izquierda (0, H, W, 0);
            # el original .NET usa (0, 0, W, H) con origen abajo-izquierda, que
            # es el sistema de STAMP_LAYOUT. Emitir el BBox del original para
            # que las coordenadas no salgan invertidas verticalmente.
            # render() PRIMERO: registra los recursos (imagen/fuente) en self.resources.
            stream = self.render()
            return StreamObject({
                pdf_name('/BBox'): ArrayObject([
                    FloatObject(0), FloatObject(0),
                    FloatObject(self.box.width), FloatObject(self.box.height),
                ]),
                pdf_name('/Resources'): self.resources.as_pdf_object(),
                pdf_name('/Type'): pdf_name('/XObject'),
                pdf_name('/Subtype'): pdf_name('/Form'),
            }, stream_data=stream)

        def render(self):
            img_w, img_h, img_x, img_y, text_x, text_y_start, font_size, leading = layout
            cmds = [b'q']
            if img_path and img_path.exists():
                img = PdfImage(PILImage.open(img_path), writer=self.writer)
                # image_ref registra el XObject con el writer; emitimos la matriz cm
                # con los floats EXACTOS del original (BoxConstraints trunca a int:
                # 37.5→37, 16.03→16, y el original usa fracciones).
                ref = img.image_ref
                name = '/Img' + img.name
                self.set_resource(ResourceType.XOBJECT, pdf_name(name), ref)
                cmds.append(b'q %g 0 0 %g %g %g cm %s Do Q' % (img_w, img_h, img_x, img_y, name.encode('ascii')))
            self.set_resource(
                ResourceType.FONT, pdf_name('/F1'),
                DictionaryObject({
                    pdf_name('/Type'): pdf_name('/Font'),
                    pdf_name('/BaseFont'): pdf_name('/Helvetica'),
                    pdf_name('/Subtype'): pdf_name('/Type1'),
                    pdf_name('/Encoding'): pdf_name('/WinAnsiEncoding'),
                }),
            )
            for i, line in enumerate(lineas):
                y = text_y_start - i * leading
                buf = BytesIO()
                TextStringObject(line).write_to_stream(buf)
                cmds.append(
                    b'BT 1 0 0 1 %g %g Tm /F1 %g Tf 0 0 0 rg '
                    % (text_x, y, font_size) + buf.getvalue() + b' Tj ET'
                )
            cmds.append(b'Q')
            return b' '.join(cmds)

    class _SgdStampStyle:
        def create_stamp(self, writer, box, text_params):
            return _SgdStamp(writer, box, tipo)

    style = _SgdStampStyle()
    text_params = {}

    # OCSP/CRL online (F9): chequeo informativo tipo check_tsl — NO se cablea a
    # PdfSignatureMetadata.validation_context porque eso fuerza validación de cadena
    # completa ANTES de firmar y puede abortar la firma real si la CA raíz de
    # RENIEC/Bit4id no está en el trust store del sistema (probado: rompe con cert
    # self-signed → InvalidCertificateError). Mismo soft-fail que TSL: solo loguea.
    if (cfg or {}).get("ocsp_crl_check", True):
        check_ocsp_crl(signer)

    meta = signers.PdfSignatureMetadata(
        field_name=campo_num,
        reason=motivo,
        location=extra.get("Lugar") or "",
        name=cn,
        md_algorithm="sha256",
        use_pades_lta=False,
    )

    # TSA opcional: si cfg['tsa_url'] está configurado, se añade sello de
    # tiempo RFC 3161 a la firma (PAdES B-T). El verificador del portal
    # mostrará la sección TSA en vez de "no se utilizó sello de tiempo".
    # Soporta login/password (auth) y política de sello (tsa_policy).
    timestamper = None
    tsa_url = (cfg or {}).get("tsa_url")
    if tsa_url:
        try:
            from pyhanko.sign.timestamps import HTTPTimeStamper
            tsa_auth = None
            if (cfg or {}).get("tsa_user"):
                tsa_auth = ((cfg or {}).get("tsa_user"), (cfg or {}).get("tsa_pass") or "")
            tsa_policy = (cfg or {}).get("tsa_policy")

            class _TSAConPolitica(HTTPTimeStamper):
                """Inyecta la política de sello en la petición RFC 3161."""
                def request_cms(self, message_digest, md_algorithm):
                    req = super().request_cms(message_digest, md_algorithm)
                    req["req_policy"] = {"policy_identifier": tsa_policy}
                    return req

            cls = _TSAConPolitica if tsa_policy else HTTPTimeStamper
            timestamper = cls(tsa_url, timeout=10, auth=tsa_auth)
        except Exception as e:
            log(f"AVISO: TSA {tsa_url} no disponible ({e}); se firma sin sello")

    pdf_signer = signers.PdfSigner(
        meta,
        signer,
        timestamper=timestamper,
        stamp_style=style,
    )

    # campo de firma visible. El writer recibe el reader no-estricto como 'prev'
    # para que el check de hybrid xrefs (pdf_signer.py) no bloquee la firma.
    w = IncrementalPdfFileWriter(open(pdf_path, "rb"), prev=r, strict=False)
    fields.append_signature_field(
        w, fields.SigFieldSpec(campo_num, on_page=pagina - 1, box=box)
    )

    out_path = out_path or (pdf_path[:-4] + sufijo + ".pdf")
    with open(out_path, "wb") as outf:
        pdf_signer.sign_pdf(w, output=outf, appearance_text_params=text_params or None)
    return out_path


def verificar_firma(pdf_path):
    """Valida las firmas embebidas de un PDF y devuelve un resumen legible.

    Usa pyhanko (validate_pdf_signature) — el mismo motor que firma. Devuelve
    lista de dicts: {firmante, valida, motivo, fecha, algoritmo, detalle}.
    Sin dependencias nuevas: pyhanko ya está en el venv.
    """
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    resumen = []
    with open(pdf_path, "rb") as f:
        r = PdfFileReader(f, strict=False)
        for sig in r.embedded_signatures:
            try:
                status = validate_pdf_signature(sig, skip_diff=True)
                valida = status.valid
                detalle = status.pretty_print_details() if hasattr(status, "pretty_print_details") else str(status)
            except Exception as e:
                valida = False
                detalle = f"{type(e).__name__}: {e}"
            try:
                firmante = sig.signer_cert.subject.native.get("common_name", "?")
            except Exception:
                firmante = "?"
            try:
                fecha = sig.self_reported_timestamp.isoformat() if sig.self_reported_timestamp else None
            except Exception:
                fecha = None
            try:
                info = sig.summarise_integrity_info()
                algo = info.get("signature_algorithm") or info.get("md_algorithm")
            except Exception:
                algo = None
            resumen.append({
                "firmante": firmante,
                "valida": valida,
                "motivo": None,
                "fecha": fecha,
                "algoritmo": str(algo) if algo else None,
                "detalle": detalle,
            })
    return resumen


def check_tsl(cfg, pin, cert_path=None):
    """Verifica que el certificado esté en la TSL de INDECOPI (como el original)."""
    signer = make_signer(cfg, pin, cert_path)
    digest = hashlib.sha256(signer.signing_cert.dump()).hexdigest().upper()
    try:
        req = urllib.request.Request(TSL_URL, headers={"User-Agent": "sgd-signer"})
        xml = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
    except Exception as e:
        log(f"AVISO: no se pudo descargar TSL ({e}); se omite verificación TSL")
        return True
    if digest in xml.upper():
        return True
    log(f"ERROR: el certificado NO está en la TSL de INDECOPI ({TSL_URL})")
    return False


def check_ocsp_crl(signer):
    """F9: descarga el CRL del emisor (mismo patrón que check_tsl) y verifica que el
    certificado NO esté en la lista de revocados. Solo informativo — nunca bloquea la
    firma (ver comentario en sign_pdf: validar cadena completa antes de firmar puede
    abortar la firma real si la CA raíz no está en el trust store del sistema)."""
    import asn1crypto.crl
    cert = signer.signing_cert
    urls = list(cert.crl_distribution_points_value or [])
    cdp_urls = []
    for dp in urls:
        name = dp["distribution_point"]
        if name.name == "full_name":
            for gn in name.chosen:
                if gn.name == "uniform_resource_identifier":
                    cdp_urls.append(gn.native)
    if not cdp_urls:
        log("OCSP/CRL: certificado sin CDP (CRL Distribution Point) declarado; se omite")
        return True
    for url in cdp_urls[:1]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sgd-signer"})
            data = urllib.request.urlopen(req, timeout=15).read()
            crl = asn1crypto.crl.CertificateList.load(data)
            revoked = {r["user_certificate"].native for r in (crl["tbs_cert_list"]["revoked_certificates"] or [])}
            if cert.serial_number in revoked:
                log(f"ERROR: el certificado está REVOCADO según CRL ({url})")
                return False
            log(f"OCSP/CRL: certificado no revocado según CRL ({url})")
            return True
        except Exception as e:
            log(f"AVISO: no se pudo verificar CRL ({e}); se omite (no bloquea la firma)")
            return True
    return True


# --- protocolo WebSocket (Tramitedoc) ---------------------------------------
def _chown_a_usuario(path):
    """El daemon corre como root y escribe archivos/dirs como root; hruiz no puede
    guardarlos (LibreOffice: 'error general de entrada y salida'). Chown al dueño
    del primer ancestro NO-root (TDOCUMENTOS, propiedad de hruiz). Windows: no-op
    (no hay root/uid)."""
    if IS_WIN:
        return
    try:
        # subir desde path hasta el primer ancestro existente cuyo dueño no sea root
        d = path if os.path.isdir(path) else os.path.dirname(path)
        while d and os.path.exists(d) and os.stat(d).st_uid == 0:
            d = os.path.dirname(d)
        if d and os.path.exists(d):
            uid = os.stat(d).st_uid
            gid = os.stat(d).st_gid
            os.chown(path, uid, gid)
    except Exception:
        pass  # best-effort: si falla, el archivo queda como root (no rompe la descarga)


def http_get(url, dest, detect_std=False):
    # el rutaDoc del portal trae subdirectorios (año, etc.) vía "|" → os.sep;
    # crear el directorio padre antes de escribir o open(dest,"wb") revienta con
    # [Errno 2] No such file or directory (root cause del error en GENERAR_DOCUMENTO).
    parent = os.path.dirname(dest) or "."
    os.makedirs(parent, exist_ok=True)
    req = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=60) as r:
        ctype = r.headers.get("Content-Type", "")
        # el original (bajarGeneraDocURL) distingue: si el servidor responde
        # application/std es un mensaje de error/aviso, NO un documento. Grabarlo
        # como .docx binario produce un archivo corrupto que LibreOffice no abre.
        if detect_std and "application/std" in ctype:
            return r.read().decode("utf-8", "replace").strip()
        with open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
    # el archivo y su subdir quedan como root; pasarlos a hruiz para que pueda
    # abrirlos/guardarlos con LibreOffice (root cause del 'error general E/S').
    _chown_a_usuario(dest)
    _chown_a_usuario(parent)
    return dest


def http_post_file(url, path):
    """CARGAR_DOCUMENTO: POST application/octet-stream con header filename."""
    req = urllib.request.Request(url, data=open(path, "rb").read(), method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("filename", os.path.basename(path))
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", "replace").strip()


def open_path(p):
    """Abre un archivo con la app predeterminada del usuario.

    Windows: os.startfile. macOS: open. Linux: el daemon corre como root sin
    DISPLAY, así que xdg-open directo no abre nada en la sesión real — se delega
    a la sesión gráfica de hruiz (runuser + entorno DISPLAY/DBUS detectado en vivo)."""
    if sys.platform == "win32":
        os.startfile(p)
        return
    if sys.platform == "darwin":
        subprocess.Popen(["open", p])
        return
    env_gui = _entorno_grafico_usuario("hruiz")
    if env_gui:
        env = dict(os.environ)
        env.update(env_gui)
        try:
            subprocess.Popen(
                ["runuser", "-u", "hruiz", "--", "xdg-open", p],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=env, start_new_session=True,
            )
            return
        except Exception:
            pass  # fallback abajo
    subprocess.Popen(["xdg-open", p])


def machine_info(ruta_principal):
    import uuid
    host = socket.gethostname()
    user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    ip = socket.gethostbyname(host) if host else "127.0.0.1"
    return {
        "nombrePC": host, "usuPC": user, "ipPC": ip,
        "swFirma": "O", "rutaPrincipal": ruta_principal,
    }


def handle_message(msg, ctx):
    """Procesa un mensaje del portal; devuelve respuesta (dict) o None."""
    accion = msg.get("accion")
    nr = msg.get("nrOperacion", "")
    url_base = ctx["urlBase"]
    ruta_pri = ctx["rutaPri"]
    cfg = ctx["cfg"]

    def reply(error="0", message="OK", extra=None):
        r = {"destination": "BROWSER", "error": error, "message": message,
             "sender": "CSHARP", "accion": accion, "nrOperacion": nr}
        if extra:
            r.update(extra)
        return r

    if accion == "CONEXION":
        return reply(message=json.dumps(machine_info(ruta_pri)))
    if accion == "TERMINATE_APP":
        return reply()
    if accion == "CONTINUE_APP":
        return reply()
    if accion == "VER_RUTA_PRINCIPAL":
        open_path(ruta_pri)
        return reply()
    if accion == "VERIFICAR_DIRECTORIO":
        try:
            d = json.loads(msg.get("message", "{}")).get("rutaDir", "")
            return reply(message="SI" if os.path.isdir(d) else "NO")
        except Exception:
            return reply("1", "ERROR")
    if accion == "VER_DOCUMENTO":
        try:
            m = json.loads(msg.get("message", "{}"))
            ruta = os.path.join(ruta_pri, m["rutaDoc"].replace("%7C", os.sep).replace("|", os.sep))
            http_get(url_base + m["urlDoc"], ruta)
            open_path(ruta)
            return reply()
        except Exception as e:
            return reply("1", f"Error al abrir documento: {e}")
    if accion == "ABRIR_DOCUMENTO_PC":
        try:
            m = json.loads(msg.get("message", "{}"))
            ruta = os.path.join(ruta_pri, m["rutaDoc"].replace("%7C", os.sep).replace("|", os.sep))
            if os.path.exists(ruta):
                open_path(ruta)
                return reply()
            return reply("1", f"El archivo {ruta} No Existe")
        except Exception as e:
            return reply("1", f"Error: {e}")
    if accion == "CARGAR_DOCUMENTO":
        try:
            m = json.loads(msg.get("message", "{}"))
            ruta = os.path.join(ruta_pri, m["rutaDoc"].replace("%7C", os.sep).replace("|", os.sep))
            if not os.path.exists(ruta):
                return reply("1", "No existe archivo: " + ruta)
            resp = http_post_file(url_base + m["urlDoc"], ruta)
            return reply(message=resp)
        except Exception as e:
            return reply("1", f"Error al cargar archivo: {e}")
    if accion == "CARGAR_DOCUMENTO_MASIVO":
        try:
            err = "O"
            msgs = []
            for item in msg.get("messageCD", []):
                ruta = os.path.join(ruta_pri, item["rutaDoc"].replace("%7C", os.sep).replace("|", os.sep))
                try:
                    resp = http_post_file(url_base + item["urlDoc"], ruta)
                    msgs.append({"message": resp})
                except Exception as e:
                    err = "1"
                    msgs.append({"message": str(e)})
            return reply(err, "", {"messageMR": msgs})
        except Exception as e:
            return reply("1", f"Error: {e}")
    if accion == "GENERAR_DOCUMENTO":
        try:
            m = json.loads(msg.get("message", "{}"))
            ruta = os.path.join(ruta_pri, m["rutaDoc"].replace("%7C", os.sep).replace("|", os.sep))
            # remplazaArchivo: si el archivo existe y está bloqueado por otro proceso,
            # el original devuelve "Documento utilizado por otro proceso" (no lo pisa).
            if m.get("remplazaArchivo") and os.path.exists(ruta):
                try:
                    with open(ruta, "rb"):
                        pass
                except OSError:
                    return reply("1", "Documento utilizado por otro proceso")
            resp = http_get(url_base + m["urlDoc"], ruta, detect_std=True)
            # application/std = mensaje de error/aviso del servidor, no un documento:
            # en ese caso http_get devuelve el mensaje (≠ ruta), no escribe el archivo.
            if resp != ruta:
                return reply("1", resp)
            open_path(ruta)
            return reply()
        except Exception as e:
            return reply("1", f"Error: {e}")
    if accion == "VERIFICAR_EXISTE_DOC":
        try:
            m = json.loads(msg.get("message", "{}"))
            ruta = os.path.join(ruta_pri, m["rutaDoc"].replace("%7C", os.sep).replace("|", os.sep))
            if not os.path.exists(ruta):
                return reply(message="NO")
            if m.get("verBloqueo"):
                try:
                    with open(ruta, "ab"):
                        pass
                    return reply(message="BNO")
                except OSError:
                    return reply(message="BSI")
            return reply(message="SI")
        except Exception as e:
            return reply("1", f"ERROR: {e}")
    if accion == "VERIFICAR_EXISTE_DOC_MASIVO":
        try:
            res = "SI"
            for item in msg.get("messageVE", []):
                ruta = os.path.join(ruta_pri, item["rutaDoc"].replace("%7C", os.sep).replace("|", os.sep))
                if not os.path.exists(ruta):
                    res = "NO"
                elif item.get("verBloqueo"):
                    try:
                        with open(ruta, "ab"):
                            pass
                    except OSError:
                        res = "BSI"
            return reply(message=res)
        except Exception as e:
            return reply("1", f"ERROR: {e}")
    if accion == "EJECUTAR_FIRMA":
        try:
            m = json.loads(msg.get("message", "{}"))
            ruta = os.path.join(ruta_pri, m["rutaDoc"].replace("%7C", os.sep).replace("|", os.sep))
            http_get(url_base + m["urlDoc"], ruta)
            tipo = m.get("tipoFirma", "2")
            extra = {"Area": m.get("deMesaPartes", ""), "Telefono": m.get("fonoInstitucion", ""),
                     "Anexo": m.get("anexo", ""), "Url": m.get("pagWeb", "")}
            extra.update(parse_nombre_doc(m["rutaDoc"]))
            # flujo original: abrir la GUI para que el usuario LEA el documento y
            # luego firme. La respuesta al portal se envía desde el op SIGN (cuando
            # el usuario pulsa Firmar en la GUI), no aquí.
            ctx["pending_firma"] = {"nr": nr, "accion": accion, "ruta": ruta,
                                    "tipo": tipo, "extra": extra}
            if not lanzar_gui_usuario(ruta, tipo):
                ctx.pop("pending_firma", None)
                return reply("1", "No se pudo abrir la GUI (sin sesión gráfica)")
            return None  # responderá el op SIGN tras firmar
        except Exception as e:
            log(f"Error EJECUTAR_FIRMA: {e}")
            return reply("1", f"Error al ejecutar firma: {e}")
    if accion == "EJECUTAR_FIRMA_MASIVA":
        try:
            items = msg.get("messageFM", [])
            if not confirmar_en_gui_usuario(MENSAJE_FIRMA_MASIVA, "Confirmación de la Firma Digital Masiva"):
                log("Firma masiva CANCELADA por el usuario (o sin sesión gráfica para confirmar).")
                return reply("1", "Firma masiva cancelada por el usuario")
            pin = get_pin(cfg, ctx)
            if cfg.get("tsl_check", True) and not check_tsl(cfg, pin):
                return reply("1", "Certificado no está en la TSL de INDECOPI")
            for item in items:
                ruta = os.path.join(ruta_pri, item["rutaDoc"].replace("%7C", os.sep).replace("|", os.sep))
                http_get(url_base + item["urlDoc"], ruta)
                sign_pdf(ruta, item.get("tipoFirma", "2"), None, pin, cfg=cfg)
            return reply(message="OK")
        except Exception as e:
            log(f"Error EJECUTAR_FIRMA_MASIVA: {e}")
            return reply("1", f"Error al ejecutar firma masiva: {e}")
    if accion == "SELECCIONAR_DIRECTORIO":
        return reply()  # sin UI de diálogo; el portal usa rutaPri
    log(f"Acción desconocida: {accion}")
    return reply("1", f"opcion no disponible -- {accion}")


def _entorno_grafico_usuario(usuario="hruiz"):
    """Detecta DISPLAY/DBUS_SESSION_BUS_ADDRESS reales de la sesión gráfica activa
    de `usuario`, leyendo el environ de un proceso de su sesión (gnome-shell/Xorg).
    No hardcodea :1 / uid 1000 — la sesión puede reiniciar con otro número.
    En Windows no aplica (el daemon corre como el mismo usuario): devuelve {}."""
    if IS_WIN:
        return {}
    if IS_MAC:
        # el daemon corre como el mismo usuario en la sesión gráfica; no hay
        # DISPLAY/DBUS que heredar (macOS usa WindowServer, no X11).
        return {}
    try:
        pid = subprocess.check_output(
            ["pgrep", "-u", usuario, "-n", "gnome-shell"], text=True
        ).strip()
    except subprocess.CalledProcessError:
        pid = None
    if not pid:
        for proc in ("gnome-session", "Xorg", "Xwayland"):
            try:
                pid = subprocess.check_output(
                    ["pgrep", "-u", usuario, "-n", proc], text=True
                ).strip()
                if pid:
                    break
            except subprocess.CalledProcessError:
                continue
    if not pid:
        return None
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            raw = f.read()
    except OSError:
        return None
    env = {}
    for kv in raw.split(b"\0"):
        if b"=" in kv:
            k, v = kv.split(b"=", 1)
            env[k.decode()] = v.decode()
    out = {k: env[k] for k in ("DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR") if k in env}
    return out or None


def _ejecutar_dialogo(script, marca, usuario, timeout):
    """Ejecuta un script Tkinter de diálogo y devuelve su stdout (str) o None si
    timeout/error. Linux: runuser + entorno gráfico detectado. Windows: directo
    (el daemon corre como el mismo usuario)."""
    env_gui = _entorno_grafico_usuario(usuario)
    if env_gui is None:
        log(f"AVISO: no se encontró sesión gráfica de {usuario}")
        return None
    env = dict(os.environ)
    env.update(env_gui)
    if IS_WIN:
        cmd = [sys.executable, "-c", script]
    elif IS_MAC:
        cmd = [sys.executable, "-c", script]
    else:
        cmd = ["runuser", "-u", usuario, "--", "/opt/sgd-signer-venv/bin/python3", "-c", script]
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env, start_new_session=True,
        )
        stdout, _ = proc.communicate(timeout=timeout)
        return stdout.strip()
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, 9)
        except Exception:
            pass
        proc.kill()
        proc.communicate()
        if not IS_WIN:
            subprocess.run(["pkill", "-9", "-u", usuario, "-f", marca], check=False)
        log(f"AVISO: diálogo sin respuesta tras {timeout}s")
        return None
    except Exception as e:
        log(f"AVISO: no se pudo mostrar el diálogo ({e})")
        return None


def confirmar_en_gui_usuario(mensaje, titulo, usuario="hruiz", timeout=120):
    """Muestra un diálogo Sí/No nativo (Tkinter) en la sesión gráfica del usuario y
    devuelve True/False. Usado para replicar el diálogo de confirmación de firma
    masiva del original, que corría en la GUI de escritorio — el daemon vive
    headless como root, así que delega la pregunta a la sesión real de hruiz."""
    marca = f"SGD_SIGNER_CONFIRM_{os.getpid()}_{int(time.time())}"
    script = (
        f"{marca}=True; "  # marca única en el CMDLINE (visible a pkill -f), no en environ
        "import tkinter as tk; from tkinter import messagebox; "
        "root = tk.Tk(); root.withdraw(); "
        f"r = messagebox.askyesno({titulo!r}, {mensaje!r}); "
        "print('SI' if r else 'NO')"
    )
    out = _ejecutar_dialogo(script, marca, usuario, timeout)
    return out == "SI"


def pedir_pin_gui_usuario(usuario="hruiz", timeout=120):
    """Pide el PIN del token con un diálogo Tkinter en la sesión gráfica del usuario.
    Devuelve el PIN o None si cancela/timeout."""
    marca = f"SGD_SIGNER_PIN_{os.getpid()}_{int(time.time())}"
    script = (
        f"{marca}=True; "
        "import tkinter as tk; from tkinter import simpledialog; "
        "root = tk.Tk(); root.withdraw(); "
        "r = simpledialog.askstring('PIN del certificado', 'Ingresa el PIN del token:', show='*'); "
        "print(r if r else '')"
    )
    out = _ejecutar_dialogo(script, marca, usuario, timeout)
    return out or None


def lanzar_gui_usuario(pdf_path, tipo, usuario="hruiz"):
    """Abre la GUI de firma (sgd-signer gui) en la sesión gráfica del usuario, con el
    PDF ya cargado y el tipo preseleccionado. Linux: el daemon es root sin DISPLAY,
    delega a la sesión real vía runuser. Windows: directo (mismo usuario)."""
    env_gui = _entorno_grafico_usuario(usuario)
    if env_gui is None:
        log(f"AVISO: no se encontró sesión gráfica de {usuario}; no se puede abrir la GUI")
        return False
    env = dict(os.environ)
    env.update(env_gui)
    script = Path(__file__).resolve()
    if IS_WIN:
        cmd = [sys.executable, str(script), "gui", pdf_path, "--tipo", tipo]
    elif IS_MAC:
        # el daemon corre como el mismo usuario en la sesión gráfica; lanza la
        # GUI directo con el python del venv (sin runuser, que no existe en macOS).
        cmd = [sys.executable, str(script), "gui", pdf_path, "--tipo", tipo]
    else:
        cmd = ["runuser", "-u", usuario, "--", "/opt/sgd-signer-venv/bin/python3",
               str(script), "gui", pdf_path, "--tipo", tipo]
    try:
        subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env, start_new_session=True,
        )
        return True
    except Exception as e:
        log(f"AVISO: no se pudo lanzar la GUI ({e})")
        return False


def run_ws(url_ws, ctx):
    import websocket
    # el bridge del portal enruta por sufijo de rol: browser -> /BROWSER, app -> /APPCLIENT.
    # el portal manda la url base sin sufijo (bare); si conectamos ahí nunca nos llega
    # nada del lado /BROWSER (verificado: bare/root no recibe, /APPCLIENT sí).
    url_app = url_ws.rstrip("/") + "/APPCLIENT"
    while True:
        try:
            ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
            ws.connect(url_app, timeout=30)
            # sin timeout de lectura: el bridge mantiene la conexión abierta y el
            # navegador manda mensajes esporádicamente. Con el timeout de 30s del
            # connect, recv() moría por inactividad y el daemon dejaba de escuchar
            # (root cause de "no abre el pdf/docx"). El C# original bloquea indefinido.
            ws.settimeout(None)
            ctx["ws"] = ws  # para que el op SIGN pueda responder al portal tras firmar
            log(f"Conectado a {url_app}")
            while True:
                raw = ws.recv()
                if not raw:
                    continue
                try:
                    msg = json.loads(raw)
                except Exception:
                    log(f"Mensaje no-JSON: {raw[:200]}")
                    continue
                log(f"<- {msg.get('accion')} nr={msg.get('nrOperacion')}")
                resp = handle_message(msg, ctx)
                if resp:
                    ws.send(json.dumps(resp))
                    log(f"-> {resp.get('accion')} error={resp.get('error')}")
        except Exception as e:
            log(f"WS cerrado: {e}; reconectando en 3s...")
            time.sleep(3)


def parse_tramitedoc_url(url):
    """Replica el parseo del binario original (Parametros.cs).

    Formato real del portal:  Tramitedoc:accion=TraDoc?ws=WSS?urlBase=URL?rutaPri=DIR
    (scheme sin '//', parámetros separados por '?', valores clave=valor).
    También acepta el formato alternativo tramitedoc://?accion=...&ws=...
    """
    idx = url.find(":")
    if idx < 0:
        return None
    rest = url[idx + 1:]
    params = {}
    if rest.startswith("//"):
        qs = rest[2:].lstrip("?")
        params = {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}
    else:
        for part in rest.split("?"):
            kv = part.split("=", 1)
            if len(kv) == 2:
                params[kv[0]] = kv[1]
    accion = params.get("accion", "")
    if accion == "TraDoc":
        url_base = params.get("urlBase", "")
        # el portal puede enviar el prefijo literal "@url:" (visto en logs reales)
        if url_base.startswith("@url:"):
            url_base = url_base[len("@url:"):]
        return {
            "accion": accion,
            "urlBase": url_base,
            "rutaPri": urllib.parse.unquote(params.get("rutaPri", "")),
            "ws": params.get("ws", ""),
        }
    if accion == "VerifConf":
        return {"accion": accion, "browser": params.get("browser", ""),
                "ws": params.get("ws", "")}
    return None


def _sock_addr():
    """Dirección del socket del daemon: AF_UNIX en Linux/macOS, TCP localhost en
    Windows (no hay AF_UNIX). Única fuente de verdad para cliente y servidor."""
    if IS_WIN:
        return (socket.AF_INET, ("127.0.0.1", 45678))
    return (socket.AF_UNIX, str(LOCK_SOCK))


def _sock_alive():
    if IS_WIN:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(("127.0.0.1", 45678))
            s.close()
            return True
        except Exception:
            return False
    # Unix: no basta con que el archivo exista — puede ser un socket huérfano
    # de un daemon que ya murió. Probamos la conexión real.
    # NO borramos aquí: durante el arranque del daemon el socket puede existir
    # pero aún no escuchar (ConnectionRefused) y borrarlo lo rompería. El
    # borrado de un socket muerto es responsabilidad de _ensure_daemon.
    if not LOCK_SOCK.exists():
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(str(LOCK_SOCK))
        s.close()
        return True
    except Exception:
        return False


def _ensure_daemon():
    """Arranca el daemon en segundo plano si no está corriendo.
    En Linux el daemon es un servicio systemd (root, para el token USB) y el
    socket ya existe. En macOS/Windows no hay systemd: la GUI lanza el daemon
    ella misma y espera a que el socket aparezca. Idempotente: si ya está vivo,
    no hace nada.
    """
    if _sock_alive():
        return
    # socket huérfano de un daemon muerto: borrarlo antes de relanzar
    if LOCK_SOCK.exists():
        try:
            LOCK_SOCK.unlink()
        except Exception:
            pass
    # binario PyInstaller: sys.executable ES el binario; script: python + __file__
    # Usamos __file__ (no sys.argv[0]) porque si este módulo se importa desde un
    # test/otro script, sys.argv[0] apunta al test y relanzarlo con --daemon
    # causaría un bucle de respawn infinito (el test no maneja --daemon).
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "--daemon"]
    else:
        cmd = [sys.executable, os.path.abspath(__file__), "--daemon"]
    kw = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
              start_new_session=True)
    if IS_WIN:
        # sin CREATE_NO_WINDOW, Windows abre una consola visible para el daemon
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    subprocess.Popen(cmd, **kw)
    # esperar a que el socket aparezca (máx ~6s). El check hace un connect de
    # hasta 1s si el socket existe pero aún no escucha; con sleep corto no
    # bloquea demasiado.
    for _ in range(12):
        if _sock_alive():
            return
        time.sleep(0.5)


def forward_to_daemon(url):
    """Si ya hay un daemon corriendo, le pasa la URL y sale."""
    if not _sock_alive():
        return False
    try:
        fam, addr = _sock_addr()
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(addr)
        s.sendall(url.encode())
        s.close()
        return True
    except Exception:
        return False


def call_daemon_op(op_payload, timeout=60):
    """Cliente genérico del protocolo OP: — la GUI (usuario hruiz) no ve el token/PIN
    real, solo el daemon root; todo pasa por este socket."""
    _ensure_daemon()
    if not _sock_alive():
        raise RuntimeError(
            f"El daemon sgd-signer no pudo arrancar ({LOCK_SOCK} no existe). "
            + ("Verifica: systemctl status sgd-signer" if IS_LINUX else
               "Reinicia la aplicación.")
        )
    fam, addr = _sock_addr()
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(addr)
    s.sendall(b"OP:" + json.dumps(op_payload).encode())
    s.shutdown(socket.SHUT_WR)  # EOF de escritura: el server usa recv()=="" para saber que ya mandamos todo
    chunks = []
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
    s.close()
    resp = json.loads(b"".join(chunks).decode())
    if not resp.get("ok"):
        raise RuntimeError(resp.get("error", "error desconocido del daemon"))
    return resp


def manual_sign_via_daemon(pdf_path, tipo, pos=None, pagina=1, extra=None, timeout=60):
    return call_daemon_op({"op": "SIGN", "pdf_path": pdf_path, "tipo": tipo, "pos": pos,
                            "pagina": pagina, "extra": extra or {}}, timeout=timeout)["out"]


def get_pin_status_via_daemon():
    """'sesion' (recordado solo mientras el daemon vive), 'disco' (persistente), 'ninguno'."""
    return call_daemon_op({"op": "GET_STATUS"})["pin_status"]


def set_pin_via_daemon(pin, recordar, cert=None):
    """recordar: 'sesion' (memoria, hasta que el daemon reinicie), 'disco' (persistente),
    o None (solo usarlo para esta firma, no recordarlo). Verifica el PIN contra el token
    real antes de devolver éxito -- si es incorrecto, la excepción llega a la GUI.
    cert: ruta del .p12/.pfx activo (clave por archivo, no la del token)."""
    payload = {"op": "SET_PIN", "pin": pin, "recordar": recordar}
    if cert:
        payload["cert"] = cert
    call_daemon_op(payload, timeout=30)


def get_apariencia_via_daemon():
    return call_daemon_op({"op": "GET_APARIENCIA"})["apariencia"]


def set_apariencia_via_daemon(tipo, imagen=None, pos=None, img_pos=None):
    payload = {"op": "SET_APARIENCIA", "tipo": tipo}
    if imagen is not None:
        payload["imagen"] = imagen
    if pos is not None:
        payload["pos"] = list(pos)
    if img_pos is not None:
        payload["img_pos"] = img_pos
    call_daemon_op(payload)


def sign_masivo_via_daemon(pdfs, tipo, pos=None, modo="pdf", timeout=600):
    """Firma N PDFs locales con el mismo tipo/posición.
    modo "pdf" = 1 firma por archivo; modo "hoja" = 1 firma por página.
    Devuelve (firmados, errores)."""
    resp = call_daemon_op({"op": "SIGN_MASIVO", "pdfs": pdfs, "tipo": tipo,
                           "pos": pos, "modo": modo}, timeout=timeout)
    return resp.get("firmados", []), resp.get("errores", [])


def set_config_via_daemon(config):
    call_daemon_op({"op": "SET_CONFIG", "config": config})


def get_config_via_daemon():
    return call_daemon_op({"op": "GET_CONFIG"})["config"]


def listar_certs_via_daemon(pin=None):
    payload = {"op": "LISTAR_CERTS"}
    if pin:
        payload["pin"] = pin
    return call_daemon_op(payload, timeout=90)["certs"]


def elegir_cert_via_daemon(key_id, lib, serial_token=None):
    call_daemon_op({"op": "ELEGIR_CERT", "key_id": key_id, "lib": lib,
                    "serial_token": serial_token})


def elegir_archivo_cert_via_daemon(archivo):
    call_daemon_op({"op": "ELEGIR_CERT", "archivo": archivo})


def importar_cert_via_daemon(archivo, pin=None):
    payload = {"op": "IMPORTAR_CERT", "archivo": archivo}
    if pin:
        payload["pin"] = pin
    return call_daemon_op(payload)["archivo"]


def eliminar_cert_via_daemon(archivo):
    call_daemon_op({"op": "ELIMINAR_CERT", "archivo": archivo})


def desbloquear_token_via_daemon(puk, nuevo_pin):
    return call_daemon_op({"op": "DESBLOQUEAR_TOKEN", "puk": puk,
                           "nuevo_pin": nuevo_pin}, timeout=60)["token"]


def dispatch_gui_op(req, ctx):
    """Verbos del protocolo local de la GUI (F8), todos sobre el socket del daemon
    porque solo el daemon root ve el token/PIN real."""
    op = req.get("op")
    cfg = ctx["cfg"]

    if op == "SIGN":
        pend = ctx.get("pending_firma")
        es_pendiente = bool(pend and pend["ruta"] == req["pdf_path"])
        tipo = pend["tipo"] if es_pendiente else req["tipo"]
        extra = pend["extra"] if es_pendiente else (req.get("extra") or {})
        cert_activo = cfg.get("cert")
        out = sign_pdf(
            req["pdf_path"], tipo, None, get_pin(cfg, ctx, cert_activo),
            pos=tuple(req["pos"]) if req.get("pos") else None,
            pagina=req.get("pagina", 1), extra=extra, cfg=cfg,
        )
        if es_pendiente:
            # la firma vino del flujo del portal (EJECUTAR_FIRMA): responder OK por el WS
            ctx.pop("pending_firma", None)
            ws = ctx.get("ws")
            if ws:
                try:
                    ws.send(json.dumps({
                        "destination": "BROWSER", "error": "0", "message": "OK",
                        "sender": "CSHARP", "accion": pend["accion"],
                        "nrOperacion": pend["nr"],
                    }))
                except Exception as e:
                    log(f"AVISO: no se pudo responder al portal: {e}")
        return {"ok": True, "out": out}

    if op == "GET_STATUS":
        if cfg.get("cert"):
            # certificado importado: su clave vive en cert_pins / session_pins
            if ctx.get("session_pins", {}).get(cfg["cert"]):
                estado = "sesion"
            elif cfg.get("cert_pins", {}).get(cfg["cert"]):
                estado = "disco"
            else:
                estado = "ninguno"
        elif ctx.get("session_pin"):
            estado = "sesion"
        elif cfg.get("pin"):
            estado = "disco"
        else:
            estado = "ninguno"
        return {"ok": True, "pin_status": estado}

    if op == "SET_PIN":
        pin = req["pin"]
        cert_activo = req.get("cert") or cfg.get("cert")
        if req.get("recordar") == "disco":
            if cert_activo:
                cfg.setdefault("cert_pins", {})[cert_activo] = pin
            else:
                cfg["pin"] = pin
            save_config(cfg)
        elif req.get("recordar") == "sesion":
            if cert_activo:
                ctx.setdefault("session_pins", {})[cert_activo] = pin
            else:
                ctx["session_pin"] = pin
        # verificación real: si el PIN es incorrecto, make_signer/PKCS11 lo revienta aquí
        # y se lo devolvemos al usuario antes de que crea que quedó guardado.
        make_signer(cfg, pin, cert_activo)
        return {"ok": True}

    if op == "CLEAR_PIN":
        # olvida el PIN de disco y de sesión (sin validar contra el token)
        if cfg.get("cert"):
            cfg.setdefault("cert_pins", {}).pop(cfg["cert"], None)
            ctx.setdefault("session_pins", {}).pop(cfg["cert"], None)
        else:
            cfg["pin"] = ""
            ctx["session_pin"] = None
        save_config(cfg)
        return {"ok": True}

    if op == "GET_APARIENCIA":
        return {"ok": True, "apariencia": cfg.get("apariencia", {})}

    if op == "GET_CONFIG":
        return {"ok": True, "config": {k: v for k, v in cfg.items()
                                       if k not in ("pin", "apariencia")}}

    if op == "LISTAR_CERTS":
        # sólo el daemon ve el token; la GUI (usuario) pide por socket.
        # Si hay PIN guardado (disco/sesión) se usa para leer los certificados
        # reales del token y mostrarlos como "Listo para firmar". Si no hay PIN,
        # se listan los tokens como "requiere PIN" (sin fallar).
        pin = req.get("pin")
        if not pin:
            try:
                pin = get_pin(cfg, ctx)  # PIN guardado en disco/sesión
            except RuntimeError:
                pin = None  # sin PIN: listar tokens como "requiere PIN"
        try:
            certs = listar_certificados(pin)
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        elegido = cfg.get("cert_key_id")
        salida = []
        # 1) archivos .p12/.pfx importados (o en cwd): no requieren token
        for p in find_certs():
            # la clave del archivo es la suya (cert_pins), NO la del token
            pin_archivo = None
            try:
                pin_archivo = get_pin(cfg, ctx, str(p))
            except RuntimeError:
                pass
            try:
                info = _cert_info_pkcs12(p, pin_archivo)
            except Exception as e:
                if pin_archivo and isinstance(e, (AttributeError, ValueError)):
                    info = {"cn": p.name, "org": "", "emisor": "", "no_after": None,
                            "aviso_import": "clave incorrecta o archivo corrupto"}
                else:
                    info = {"cn": p.name, "org": "", "emisor": "", "no_after": None,
                            "aviso_import": f"no se pudo leer: {e}"}
            activo = cfg.get("cert") == str(p)
            ok, msgs = validar_certificado({**info, "listo": True})
            if info.get("aviso_import"):
                msgs = msgs + [info["aviso_import"]]
            salida.append({
                "cn": info.get("cn", p.name), "org": info.get("org", ""),
                "emisor": info.get("emisor", ""), "token": "archivo importado",
                "lib": "", "serial_token": "", "key_id": None,
                "archivo": str(p), "listo": True, "ok": ok, "avisos": msgs,
                "activo": activo,
                "no_after": info.get("no_after").isoformat() if info.get("no_after") else None,
            })
        # 2) tokens PKCS#11
        for c in certs:
            ok, msgs = validar_certificado(c)
            salida.append({
                "cn": c.get("cn", ""), "org": c.get("org", ""),
                "emisor": c.get("emisor", ""), "token": c.get("token", ""),
                "lib": c.get("lib", ""), "serial_token": c.get("serial_token", ""),
                "key_id": c["key_id"].hex() if c.get("key_id") else None,
                "listo": c.get("listo", False), "ok": ok, "avisos": msgs,
                "activo": bool(c.get("key_id") and c["key_id"].hex() == elegido),
                "bloqueado": bool(c.get("bloqueado")),
                "no_after": c.get("no_after").isoformat() if c.get("no_after") else None,
            })
        return {"ok": True, "certs": salida}

    if op == "ELEGIR_CERT":
        if req.get("archivo"):
            # certificado importado (.p12/.pfx): el archivo manda sobre el token
            cfg["cert"] = req["archivo"]
            cfg.pop("cert_key_id", None)
            cfg.pop("token_lib", None)
            cfg.pop("cert_token_serial", None)
            save_config(cfg)
            return {"ok": True}
        cfg["cert_key_id"] = req["key_id"]
        cfg["token_lib"] = req["lib"]
        # root cause: sin esto, make_signer cae a la rama .p12 -> pick_cert()
        # -> input() en el daemon sin stdin -> EOFError al guardar el PIN.
        cfg["token"] = True
        cfg.pop("cert", None)  # elegir token desactiva el archivo importado
        if req.get("serial_token"):
            cfg["cert_token_serial"] = req["serial_token"]
        save_config(cfg)
        # invalidar la sesión cacheada: el próximo firmado abre el token elegido
        with _PKCS11_LOCK:
            if _PKCS11_SESSION_CACHE["session"] is not None:
                try:
                    _PKCS11_SESSION_CACHE["session"].close()
                except Exception:
                    pass
                _PKCS11_SESSION_CACHE["session"] = None
        return {"ok": True}

    if op == "IMPORTAR_CERT":
        # copia el .p12/.pfx elegido a ~/.sgd-signer/certs/ y lo activa
        src = Path(req["archivo"])
        if not src.exists():
            return {"ok": False, "error": f"no existe: {src}"}
        if not src.suffix.lower() in (".p12", ".pfx"):
            return {"ok": False, "error": "solo se admiten .p12/.pfx"}
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        dst = CERT_DIR / src.name
        if dst.exists() and dst.resolve() != src.resolve():
            dst = CERT_DIR / (src.stem + "-" + hashlib.sha1(str(src).encode()).hexdigest()[:6] + src.suffix)
        shutil.copy2(src, dst)
        os.chmod(dst, 0o600)
        # clave del archivo: la pide la GUI (IMPORTAR_CERT lleva 'pin'); se
        # verifica leyendo el .p12 ANTES de activarlo (si falla, no se toca cfg)
        if req.get("pin"):
            try:
                _cert_info_pkcs12(dst, req["pin"])
            except Exception:
                os.unlink(dst)
                return {"ok": False, "error": "clave incorrecta o archivo corrupto"}
        cfg["cert"] = str(dst)
        cfg.pop("cert_key_id", None)
        cfg.pop("token_lib", None)
        cfg.pop("cert_token_serial", None)
        if req.get("pin"):
            cfg.setdefault("cert_pins", {})[str(dst)] = req["pin"]
        save_config(cfg)
        return {"ok": True, "archivo": str(dst)}

    if op == "ELIMINAR_CERT":
        # borra un .p12/.pfx importado; si era el activo, limpia la selección.
        # Los tokens USB NO se eliminan: viven en el dispositivo (hardware).
        target = Path(req["archivo"]).resolve()
        if not str(target).startswith(str(CERT_DIR.resolve())):
            return {"ok": False, "error": "solo se pueden eliminar certificados importados"}
        if not target.exists():
            return {"ok": False, "error": f"no existe: {target}"}
        if cfg.get("cert") == str(target):
            cfg.pop("cert", None)
            cfg.setdefault("cert_pins", {}).pop(str(target), None)
            ctx.setdefault("session_pins", {}).pop(str(target), None)
            save_config(cfg)
        target.unlink()
        return {"ok": True}

    if op == "DESBLOQUEAR_TOKEN":
        # desbloquea el token con PUK (SO PIN) y restablece el PIN de usuario.
        # Solo el daemon root ve el token; la GUI pide PUK + nuevo PIN.
        try:
            label = desbloquear_token(req["puk"], req["nuevo_pin"])
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        # el PIN nuevo queda como el de usuario: guardarlo en disco
        cfg["pin"] = req["nuevo_pin"]
        save_config(cfg)
        # invalidar sesión cacheada (el PIN cambió)
        with _PKCS11_LOCK:
            if _PKCS11_SESSION_CACHE["session"] is not None:
                try:
                    _PKCS11_SESSION_CACHE["session"].close()
                except Exception:
                    pass
                _PKCS11_SESSION_CACHE["session"] = None
        return {"ok": True, "token": label}

    if op == "SET_APARIENCIA":
        tipo = req["tipo"]
        apariencia = cfg.setdefault("apariencia", {})
        entry = apariencia.setdefault(tipo, {})
        if "imagen" in req:
            entry["imagen"] = req["imagen"]
        if "pos" in req:
            entry["pos"] = req["pos"]
        if "img_pos" in req:
            entry["img_pos"] = req["img_pos"]
        save_config(cfg)
        return {"ok": True}

    if op == "SIGN_MASIVO":
        # firma N PDFs locales (seleccionados en la GUI) con el mismo tipo/posición.
        # modo "pdf" = 1 firma por archivo; modo "hoja" = 1 firma por página
        # (se encadena incrementalmente: página 1 → tmp, página 2 sobre tmp, ...).
        # El diálogo de confirmación ya lo mostró la GUI antes de llamar aquí.
        import tempfile
        pdfs = req["pdfs"]
        tipo = req.get("tipo", "2")
        pos = tuple(req["pos"]) if req.get("pos") else None
        modo = req.get("modo", "pdf")
        cert_activo = cfg.get("cert")
        pin = get_pin(cfg, ctx, cert_activo)
        firmados = []
        errores = []
        for p in pdfs:
            try:
                out = None
                if modo == "hoja":
                    n = _pdf_num_paginas(p)
                    if n <= 1:
                        out = sign_pdf(p, tipo, None, pin, pos=pos, pagina=1, cfg=cfg)
                    else:
                        tmp = p
                        temporales = []
                        for pg in range(1, n + 1):
                            if pg < n:
                                fd, tmp_out = tempfile.mkstemp(suffix=".pdf", prefix="sgd-masiva-")
                                os.close(fd)
                                temporales.append(tmp_out)
                                tmp = sign_pdf(tmp, tipo, None, pin, pos=pos, pagina=pg, cfg=cfg, out_path=tmp_out)
                            else:
                                out = sign_pdf(tmp, tipo, None, pin, pos=pos, pagina=pg, cfg=cfg,
                                               out_path=p[:-4] + TIPOS[tipo][1] + ".pdf")
                        for t in temporales:
                            try:
                                os.unlink(t)
                            except OSError:
                                pass
                else:
                    out = sign_pdf(p, tipo, None, pin, pos=pos, pagina=1, cfg=cfg)
                firmados.append(out)
            except Exception as e:
                errores.append({"pdf": p, "error": f"{type(e).__name__}: {e}"})
        return {"ok": True, "firmados": firmados, "errores": errores}

    if op == "SET_CONFIG":
        # claves de config de primer nivel (tsl_check, etc.) — no toca pin ni apariencia
        for k, v in req.get("config", {}).items():
            if k in ("pin", "apariencia", "token", "token_lib"):
                continue
            cfg[k] = v
        save_config(cfg)
        return {"ok": True}

    return {"ok": False, "error": f"operación desconocida: {op}"}


def daemon_loop(url):
    """Daemon: procesa la URL inicial (si hay) y espera más URLs por el socket local."""
    import threading
    cfg = load_config()
    # limpieza de huérfanos: cert_pins de archivos ya borrados (p.ej. un
    # certificado eliminado con ELIMINAR_CERT o a mano) no deben quedar en config
    pins = cfg.get("cert_pins") or {}
    huerfanos = [p for p in pins if not Path(p).exists()]
    if huerfanos:
        for p in huerfanos:
            pins.pop(p, None)
        if not pins:
            cfg.pop("cert_pins", None)
        save_config(cfg)
        log(f"limpieza: cert_pins huérfanos eliminados ({len(huerfanos)})")
    ctx = {"urlBase": "", "rutaPri": "", "cfg": cfg, "ws_url": None}
    ws_thread = None

    def start_session(u):
        nonlocal ws_thread
        p = parse_tramitedoc_url(u)
        if not p:
            log(f"URL no reconocida: {u[:120]}")
            return
        if p["accion"] == "VerifConf":
            log("VerifConf: configuración OK (cert: %s)" % (ctx["cfg"].get("cert") or "auto"))
            return
        ctx["urlBase"] = p["urlBase"]
        # rutaPri del portal viene como ruta Windows (C:\Users\...\TDOCUMENTOS).
        # En Windows es válida y se usa directo. En Linux/macOS se mapea a
        # ~/Documentos/TDOCUMENTOS (GNOME) o ~/TDOCUMENTOS.
        rp = p["rutaPri"] or ""
        if IS_WIN:
            if not rp:
                rp = str(Path.home() / "Documents" / "TDOCUMENTOS")
        elif not rp or "\\" in rp or ":" in rp.split("/")[0]:
            docs = Path.home() / "Documentos"
            rp = str(docs / "TDOCUMENTOS") if docs.exists() else str(Path.home() / "TDOCUMENTOS")
        ctx["rutaPri"] = rp
        Path(ctx["rutaPri"]).mkdir(parents=True, exist_ok=True)
        # si el WS cambió (nueva sesión del portal), reconectar
        if ws_thread and ws_thread.is_alive() and ctx.get("ws_url") == p["ws"]:
            log("Sesión ya activa con el mismo WS; ignorando URL duplicada")
            return
        if ws_thread and ws_thread.is_alive():
            log("WS cambió; cerrando sesión anterior y reconectando")
        ctx["ws_url"] = p["ws"]
        ws_thread = threading.Thread(target=run_ws, args=(p["ws"], ctx), daemon=True)
        ws_thread.start()

    if url:
        start_session(url)

    ctx["session_pin"] = None  # PIN "recordado en esta sesión" — solo en memoria, muere con el daemon

    if not IS_WIN:
        # instancia única: si ya hay un daemon vivo escuchando en el socket,
        # NO lo borramos ni nos enlazamos (un segundo daemon huérfano compite
        # por el socket y cuelga la firma). Solo se borra un socket muerto.
        if _sock_alive():
            log("Ya hay un daemon sgd-signer activo; saliendo (instancia única)")
            return
        if LOCK_SOCK.exists():
            LOCK_SOCK.unlink()
    fam, addr = _sock_addr()
    srv = socket.socket(fam, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(addr)
    if not IS_WIN:
        os.chmod(str(LOCK_SOCK), 0o666)  # hruiz (handler) escribe, daemon root lee
    srv.listen(4)
    log(f"Daemon escuchando en {addr}")
    while True:
        conn, _ = srv.accept()
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        if data.startswith(b"OP:"):
            # protocolo genérico de la GUI local (F8): {"op": "...", ...} sobre el
            # mismo socket que usa tramitedoc:// — root cause fix del patrón ad-hoc
            # MANUAL_SIGN: un solo despachador de verbos en vez de apilar prefijos.
            resp = {"ok": False, "error": "desconocido"}
            try:
                req = json.loads(data[len(b"OP:"):].decode())
                resp = dispatch_gui_op(req, ctx)
            except BaseException as e:
                import traceback
                log(f"ERROR en OP {data[:60]!r}: {traceback.format_exc()}")
                resp = {"ok": False, "error": f"{type(e).__name__}: {e}" or type(e).__name__}
            try:
                conn.sendall(json.dumps(resp).encode())
            except Exception:
                pass
            conn.close()
            continue
        conn.close()
        if data:
            start_session(data.decode().strip())


# --- CLI --------------------------------------------------------------------
def cmd_sign(args):
    cfg = load_config()
    pin = get_pin(cfg)
    if not args.no_tsl and cfg.get("tsl_check", True) and not check_tsl(cfg, pin, args.cert):
        raise SystemExit("Certificado no está en la TSL de INDECOPI (usa --no-tsl para saltar)")
    pos = tuple(map(int, args.pos.split(","))) if args.pos else None
    out = sign_pdf(args.pdf, args.tipo, args.cert, pin, pos=pos, pagina=args.pagina, cfg=cfg)
    print(f"Firmado: {out}")


def cmd_pin(args):
    cfg = load_config()
    cfg["pin"] = args.pin
    save_config(cfg)
    print("PIN guardado en ~/.sgd-signer/config.json (chmod 600)")


def cmd_certs(args):
    for c in find_certs():
        print(c)
    if not find_certs():
        print("No hay certificados en ~/.sgd-signer/certs/ ni en el directorio actual.")


# --- GUI manual — visor PDF + firmar archivo local -------------------------
def _tiene_poppler():
    """poppler-utils está en Linux, pero no en Windows/macOS empaquetados."""
    return shutil.which("pdftoppm") is not None and shutil.which("pdfinfo") is not None


def _pdf_page_size_pt(pdf_path, pagina):
    """Tamaño de página en puntos. poppler si está, si no PyMuPDF (Win/macOS)."""
    if _tiene_poppler():
        out = subprocess.run(
            ["pdfinfo", "-f", str(pagina), "-l", str(pagina), pdf_path],
            capture_output=True, text=True, check=True,
        ).stdout
        for line in out.splitlines():
            if line.startswith("Page") and "size" in line:
                # "Page    1 size: 595.32 x 841.92 pts"
                parts = line.split(":")[1].split("x")
                return float(parts[0]), float(parts[1].split("pts")[0])
    import pymupdf as fitz  # PyMuPDF
    with fitz.open(pdf_path) as doc:
        r = doc[pagina - 1].rect
        return float(r.width), float(r.height)


def _pdf_num_paginas(pdf_path):
    """Número de páginas. poppler si está, si no PyMuPDF."""
    if _tiene_poppler():
        try:
            out = subprocess.run(["pdfinfo", pdf_path], capture_output=True,
                                 text=True, check=True).stdout
            for line in out.splitlines():
                if line.startswith("Pages:"):
                    return int(line.split(":")[1].strip())
        except Exception:
            pass
    try:
        import pymupdf as fitz
        with fitz.open(pdf_path) as doc:
            return doc.page_count
    except Exception:
        return 1


def _render_pdf_png(pdf_path, pagina, dpi):
    """Renderiza una página a PNG y devuelve la ruta. poppler o PyMuPDF."""
    tmp = tempfile.mktemp(prefix="sgd-signer-preview-")
    if _tiene_poppler():
        subprocess.run(
            ["pdftoppm", "-png", "-r", str(dpi), "-f", str(pagina), "-l", str(pagina),
             pdf_path, tmp],
            check=True,
        )
        for cand in (f"{tmp}-{pagina}.png", f"{tmp}-1.png",
                     f"{tmp}-{pagina:02d}.png", f"{tmp}-{pagina:03d}.png"):
            if os.path.exists(cand):
                return cand
        hits = list(Path(tempfile.gettempdir()).glob(os.path.basename(tmp) + "*.png"))
        if hits:
            return str(hits[0])
        raise RuntimeError("pdftoppm no generó la vista previa")
    import pymupdf as fitz  # PyMuPDF: Windows/macOS sin poppler
    png = tmp + ".png"
    with fitz.open(pdf_path) as doc:
        doc[pagina - 1].get_pixmap(dpi=dpi).save(png)
    return png


# --- paleta warm monochrome (minimalist-ui) ---------------------------------
UI = {
    # Premium Utilitarian Minimalism: bone canvas, 1px borders, pastel accents.
    # Color es recurso escaso: solo semántico (OK/aviso/error). CTA sólido oscuro.
    "bg": "#F7F6F3", "surface": "#FFFFFF", "border": "#EAEAEA",
    "ink": "#2F3437", "muted": "#787774",
    "accent": "#111111", "accent_hover": "#333333",   # CTA sólido oscuro (skill)
    "accent_bg": "#EDF3EC", "accent_fg": "#346538",   # verde pastel (OK)
    "warn_bg": "#FBF3DB", "warn_fg": "#956400",       # amarillo pastel (aviso)
    "danger_bg": "#FDEBEC", "danger_fg": "#9F2F2D",   # rojo pastel (error)
    "info_bg": "#E1F3FE", "info_fg": "#1F6C9F",       # azul pastel (info)
    "canvas": "#DADAD8", "preview_bg": "#E8E8E6", "outline": "#B8B8B4",
    "mono": ("SF Mono", 9), "mono_b": ("SF Mono", 9, "bold"),
    "ui": ("Helvetica Neue", 10), "ui_b": ("Helvetica Neue", 10, "bold"),
}


def _hover(btn, bg, fg, bg_h=None, fg_h=None):
    """Micro-transición: cambio sutil de color al pasar el ratón, con un
    pequeño retardo (120ms) que simula fade — tkinter no anima, pero el
    retardo suaviza la transición visual. Respeta el estado disabled."""
    bg_h = bg_h or UI["border"]
    fg_h = fg_h or fg
    def _enter(_e):
        if str(btn["state"]) == "disabled":
            return
        btn.after(120, lambda: btn.config(bg=bg_h, fg=fg_h))
    def _leave(_e):
        if str(btn["state"]) == "disabled":
            return
        btn.after(120, lambda: btn.config(bg=bg, fg=fg))
    btn.bind("<Enter>", _enter)
    btn.bind("<Leave>", _leave)
    return btn
NOMBRES_TIPO = {"1": "1 · Titular", "2": "2 · Básica", "3": "3 · V°B°",
                "4": "4 · Avanzada", "5": "5 · V°B° avanzada", "6": "6 · Recepción",
                "7": "7 · Encargo"}


def _chequeo_instalacion(root):
    """Al arrancar la GUI: revisa el estado de instalación y, si falta algo
    auto-reparable, ofrece arreglarlo con un diálogo (estilo AnyDesk). El
    middleware Bit4id requiere sudo: se muestra con instrucciones y enlace."""
    import tkinter as tk
    from tkinter import messagebox
    try:
        diag = diagnostico()
    except Exception as e:
        # el diagnóstico no debe romper el arranque de la GUI
        return

    faltan_auto = [d for d in diag if d["accion"]]
    falta_mw = [d for d in diag if d["item"].startswith("Middleware") and not d["ok"]]

    if not faltan_auto and not falta_mw:
        return  # todo OK, no molestar

    # construir el mensaje
    lineas = []
    for d in diag:
        marca = "✓" if d["ok"] else "✗"
        lineas.append(f"{marca}  {d['item']}: {d['detalle']}")
    cuerpo = "\n".join(lineas)

    if faltan_auto:
        cuerpo += "\n\n¿Instalar/arreglar automáticamente lo que falta?"
        if messagebox.askyesno("sgd-signer — instalación", cuerpo):
            acciones = [d["accion"] for d in faltan_auto]
            res = auto_instalar(acciones)
            resumen = "\n".join(f"{'✓' if ok else '✗'}  {item}: {msg}"
                                for item, ok, msg in res)
            messagebox.showinfo("sgd-signer — resultado", resumen)
            return

    if falta_mw:
        # middleware requiere sudo: instrucciones claras + enlace de descarga
        msg = ("Falta el middleware Bit4id (driver PKCS#11) para leer el token USB.\n\n"
               "Este componente requiere permisos de administrador (sudo) y no se\n"
               "puede instalar automáticamente desde la app.\n\n"
               "Descárgalo e instálalo desde el fabricante:\n"
               "  https://www.bit4id.com/ (sección descargas / middleware)\n\n"
               "Tras instalarlo, reinicia sgd-signer.")
        messagebox.showwarning("sgd-signer — middleware requerido", msg)


def gui_main(pdf_path=None, tipo=None):
    """GUI de firma manual: abrir PDF, elegir tipo de firma,
    click en la página para posición/imagen por tipo (persistente), gestión de
    PIN con indicador de estado. Tkinter + pdftoppm (poppler-utils, ya instalado)
    — sin dependencias nuevas. Estilo: minimalist-ui (warm monochrome, sin
    gradientes/sombras pesadas)."""
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
    from PIL import Image, ImageTk

    def pill(parent, text, bg, fg):
        lbl = tk.Label(parent, text=text, bg=bg, fg=fg, font=UI["mono"],
                        padx=8, pady=2)
        return lbl

    def btn_plano(parent, text, command, fg=UI["ink"], bg=UI["surface"]):
        """Botón plano con borde 1px y hover sutil (estilo minimalist-ui)."""
        b = tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                      relief="flat", highlightbackground=UI["border"],
                      highlightthickness=1, font=UI["ui"], padx=8, pady=2,
                      activebackground=UI["border"], activeforeground=fg,
                      disabledforeground=UI["muted"])
        return _hover(b, bg, fg, bg_h=UI["border"])

    def btn_cta(parent, text, command, state="normal"):
        """Botón CTA sólido oscuro (estilo minimalist-ui, sin ttkbootstrap)."""
        b = tk.Button(parent, text=text, command=command, bg=UI["accent"],
                      fg=UI["surface"], relief="flat", highlightthickness=0,
                      font=UI["ui_b"], padx=14, pady=4, state=state,
                      activebackground=UI["accent_hover"], activeforeground=UI["surface"],
                      disabledforeground=UI["muted"])
        return _hover(b, UI["accent"], UI["surface"], bg_h=UI["accent_hover"])

    class App:
        def __init__(self, root):
            self.root = root
            self.pdf_path = None
            self.pagina = 1
            self.n_paginas = 1
            self.pos_pt = None
            self.tk_img = None
            self.page_w_pt = self.page_h_pt = 0.0
            self.imagen_tipo_actual = None
            self.scale = 1.0
            self.zoom = 1.0            # 1.0 = 100% (72 dpi = 1pt por pixel)
            self.zoom_modo = "ajustar"  # ajustar | ancho | manual
            self.img_offset = (0, 0)    # offset de centrado de la página en el canvas
            self._last_canvas_w = self._last_canvas_h = 0

            root.configure(bg=UI["bg"])
            # NO llamar style.theme_use("clam"): anula el tema ttkbootstrap
            # (litera) y rompe la coherencia visual de la ventana principal.
            # La configuración no lo llama y por eso se ve bien.
            style = ttk.Style()
            style.configure("TFrame", background=UI["bg"])
            # Unificar TODOS los botones ttkbootstrap a la paleta (el tema
            # "litera" pinta hover azul y primary azul — fuera de la paleta).
            # light.TButton = secundario (superficie + borde), dark.TButton = CTA.
            style.configure("light.TButton",
                            background=UI["surface"], foreground=UI["ink"],
                            bordercolor=UI["border"], lightcolor=UI["surface"],
                            darkcolor=UI["surface"], focuscolor=UI["border"],
                            padding=(10, 4), font=UI["ui"])
            style.map("light.TButton",
                      background=[("active", UI["border"]), ("pressed", UI["border"]),
                                  ("disabled", UI["bg"])],
                      foreground=[("disabled", UI["muted"])])
            style.configure("dark.TButton",
                            background=UI["accent"], foreground=UI["surface"],
                            bordercolor=UI["accent"], lightcolor=UI["accent"],
                            darkcolor=UI["accent"], focuscolor=UI["accent"],
                            padding=(12, 4), font=UI["ui"])
            style.map("dark.TButton",
                      background=[("active", UI["accent_hover"]), ("pressed", UI["accent_hover"]),
                                  ("disabled", UI["border"])],
                      foreground=[("disabled", UI["muted"])])

            # --- barra superior: certificado + acciones ----------------------
            # Grid ponderado: columna 0 (estado) expande, columna 1 (botones)
            # se compacta — no se desborda en pantallas pequeñas.
            pin_bar = tk.Frame(root, bg=UI["surface"], highlightbackground=UI["border"],
                                highlightthickness=1)
            pin_bar.pack(fill="x", padx=12, pady=(12, 6))
            pin_bar.columnconfigure(0, weight=1)
            pin_bar.columnconfigure(1, weight=0)
            f_estado = tk.Frame(pin_bar, bg=UI["surface"])
            f_estado.grid(row=0, column=0, sticky="w", padx=(10, 8), pady=8)
            tk.Label(f_estado, text="Certificado", bg=UI["surface"], fg=UI["ink"],
                     font=UI["ui_b"]).pack(side="left")
            self.pin_pill = pill(f_estado, "…", UI["warn_bg"], UI["warn_fg"])
            self.pin_pill.pack(side="left", padx=(8, 0))
            self.venc_pill = pill(f_estado, "", UI["accent_bg"], UI["accent_fg"])
            self.venc_pill.pack(side="left", padx=(8, 0))
            f_acciones = tk.Frame(pin_bar, bg=UI["surface"])
            f_acciones.grid(row=0, column=1, sticky="e", padx=(0, 10), pady=6)
            btn_plano(f_acciones, "🔔", self.abrir_notificaciones).pack(side="right", padx=(4, 0))
            btn_plano(f_acciones, "PIN", self.pedir_pin).pack(side="right", padx=(4, 0))
            btn_plano(f_acciones, "Config", self.abrir_configuracion).pack(side="right", padx=(4, 0))
            btn_plano(f_acciones, "Doctor", self.abrir_doctor).pack(side="right", padx=(4, 0))
            self._refrescar_estado_pin()
            self._refrescar_vencimiento()

            # --- barra archivo/tipo ------------------------------------------
            top = tk.Frame(root, bg=UI["bg"])
            top.pack(fill="x", padx=12, pady=(0, 6))
            top.columnconfigure(0, weight=0)
            top.columnconfigure(1, weight=1)
            top.columnconfigure(2, weight=0)
            btn_cta(top, "Abrir PDF", self.abrir).grid(row=0, column=0, sticky="w")
            self.lbl_archivo = tk.Label(top, text="(sin archivo)", bg=UI["bg"],
                                        fg=UI["muted"], font=UI["ui"])
            self.lbl_archivo.grid(row=0, column=1, sticky="w", padx=10)
            f_tipo = tk.Frame(top, bg=UI["bg"])
            f_tipo.grid(row=0, column=2, sticky="e")
            tk.Label(f_tipo, text="Tipo", bg=UI["bg"], fg=UI["muted"],
                     font=UI["ui"]).pack(side="left", padx=(0, 6))
            self.tipo = tk.StringVar(value="2")
            om = tk.OptionMenu(f_tipo, self.tipo, *[NOMBRES_TIPO[t] for t in sorted(TIPOS)],
                                command=self._set_tipo)
            om.config(bg=UI["surface"], fg=UI["ink"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1, font=UI["ui"])
            om.pack(side="left")

            # --- barra navegación/posición + zoom (una sola fila) ------------
            nav = tk.Frame(root, bg=UI["bg"])
            nav.pack(fill="x", padx=12, pady=(0, 6))
            nav.columnconfigure(0, weight=0)
            nav.columnconfigure(1, weight=1)
            nav.columnconfigure(2, weight=0)
            f_nav = tk.Frame(nav, bg=UI["bg"])
            f_nav.grid(row=0, column=0, sticky="w")
            btn_plano(f_nav, "‹", lambda: self.cambiar_pagina(-1)).pack(side="left")
            self.lbl_pagina = tk.Label(f_nav, text="- / -", bg=UI["bg"], fg=UI["ink"],
                                       font=UI["mono"])
            self.lbl_pagina.pack(side="left", padx=6)
            btn_plano(f_nav, "›", lambda: self.cambiar_pagina(1)).pack(side="left")
            self.lbl_pos = tk.Label(nav, text="Click en la página para fijar posición",
                                    bg=UI["bg"], fg=UI["muted"], font=UI["ui"])
            self.lbl_pos.grid(row=0, column=1, sticky="w", padx=12)
            f_zoom = tk.Frame(nav, bg=UI["bg"])
            f_zoom.grid(row=0, column=2, sticky="e")
            btn_plano(f_zoom, "−", lambda: self.zoom_paso(0.8)).pack(side="left")
            self.lbl_zoom = tk.Label(f_zoom, text="100%", bg=UI["bg"], fg=UI["ink"],
                                     font=UI["mono"], width=5)
            self.lbl_zoom.pack(side="left")
            btn_plano(f_zoom, "+", lambda: self.zoom_paso(1.25)).pack(side="left")
            btn_plano(f_zoom, "Ajustar", self.zoom_ajustar).pack(side="left", padx=(4, 0))
            btn_plano(f_zoom, "Ancho", self.zoom_ancho).pack(side="left", padx=(4, 0))

            # --- visor: canvas con scrollbars (el PDF puede exceder la ventana) --
            visor = tk.Frame(root, bg=UI["border"], highlightbackground=UI["border"],
                             highlightthickness=1)
            visor.pack(fill="both", expand=True, padx=12, pady=(0, 6))
            self.canvas = tk.Canvas(visor, bg=UI["canvas"], highlightthickness=0,
                                    cursor="crosshair")
            vsb = tk.Scrollbar(visor, orient="vertical", command=self.canvas.yview)
            hsb = tk.Scrollbar(visor, orient="horizontal", command=self.canvas.xview)
            self.canvas.config(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            self.canvas.grid(row=0, column=0, sticky="nsew")
            vsb.grid(row=0, column=1, sticky="ns")
            hsb.grid(row=1, column=0, sticky="ew")
            visor.rowconfigure(0, weight=1)
            visor.columnconfigure(0, weight=1)

            self.canvas.bind("<Button-1>", self.click_pagina)
            # rueda: scroll vertical; Shift+rueda: horizontal; Ctrl+rueda: zoom.
            # Linux manda Button-4/5 en vez de MouseWheel.
            self.canvas.bind("<MouseWheel>", self._on_wheel)
            self.canvas.bind("<Shift-MouseWheel>", self._on_wheel_shift)
            self.canvas.bind("<Control-MouseWheel>", self._on_wheel_ctrl)
            self.canvas.bind("<Button-4>", self._on_wheel)
            self.canvas.bind("<Button-5>", self._on_wheel)
            self.canvas.bind("<Shift-Button-4>", self._on_wheel_shift)
            self.canvas.bind("<Shift-Button-5>", self._on_wheel_shift)
            self.canvas.bind("<Control-Button-4>", self._on_wheel_ctrl)
            self.canvas.bind("<Control-Button-5>", self._on_wheel_ctrl)
            # re-ajustar al redimensionar la ventana cuando el modo es "ajustar"
            self.canvas.bind("<Configure>", self._on_canvas_resize)

            # --- barra inferior: firmar + verificar + estado ------------------
            bottom = tk.Frame(root, bg=UI["bg"])
            bottom.pack(fill="x", padx=12, pady=(0, 12))
            bottom.columnconfigure(0, weight=0)
            bottom.columnconfigure(1, weight=1)
            bottom.columnconfigure(2, weight=0)
            self.btn_firmar = btn_cta(bottom, "Firmar", self.firmar, state="disabled")
            self.btn_firmar.grid(row=0, column=0, sticky="w")
            f_acc = tk.Frame(bottom, bg=UI["bg"])
            f_acc.grid(row=0, column=2, sticky="e")
            btn_plano(f_acc, "Verificar firma", self.verificar).pack(side="right")
            btn_plano(f_acc, "Firma masiva…", self.firma_masiva).pack(side="right", padx=(0, 8))
            self.lbl_status = tk.Label(bottom, text="", bg=UI["bg"], fg=UI["muted"], font=UI["mono"])
            self.lbl_status.grid(row=0, column=1, sticky="w", padx=10)

            if pdf_path:
                self.cargar(pdf_path)
            if tipo:
                self.tipo.set(tipo)
                self._cargar_pos_guardada()

        # --- estado del PIN --------------------------------------------------
        def _refrescar_estado_pin(self):
            try:
                estado = get_pin_status_via_daemon()
            except Exception as e:
                self.pin_pill.config(text=f"daemon no disponible", bg=UI["danger_bg"], fg=UI["danger_fg"])
                return
            textos = {
                "disco": ("PIN en disco", UI["accent_bg"], UI["accent_fg"]),
                "sesion": ("PIN en sesión", UI["accent_bg"], UI["accent_fg"]),
                "ninguno": ("Sin PIN", UI["warn_bg"], UI["warn_fg"]),
            }
            texto, bg, fg = textos.get(estado, ("desconocido", UI["warn_bg"], UI["warn_fg"]))
            self.pin_pill.config(text=texto, bg=bg, fg=fg)

        def _cert_activo_info(self):
            """(cn, no_after) del certificado activo (archivo o token) vía daemon."""
            try:
                certs = listar_certs_via_daemon()
            except Exception:
                return None, None
            for c in certs:
                if c.get("activo"):
                    return c.get("cn"), c.get("no_after")
            return None, None

        def _refrescar_vencimiento(self):
            """Pill sutil con los días restantes del certificado activo.
            <30 días: ámbar; vencido: rojo. Alerta única por sesión si <30."""
            import datetime
            cn, no_after = self._cert_activo_info()
            if not no_after:
                self.venc_pill.config(text="", bg=UI["accent_bg"], fg=UI["accent_fg"])
                return
            try:
                vence = datetime.datetime.fromisoformat(no_after)
                dias = (vence - datetime.datetime.now(vence.tzinfo)).days
            except Exception:
                self.venc_pill.config(text="", bg=UI["accent_bg"], fg=UI["accent_fg"])
                return
            if dias < 0:
                texto, bg, fg = f"VENCIDO hace {-dias}d", UI["danger_bg"], UI["danger_fg"]
            elif dias <= 30:
                texto, bg, fg = f"Vence en {dias}d", UI["warn_bg"], UI["warn_fg"]
            else:
                texto, bg, fg = f"Vence en {dias}d", UI["accent_bg"], UI["accent_fg"]
            self.venc_pill.config(text=texto, bg=bg, fg=fg)
            if dias <= 30 and not getattr(self, "_aviso_venc_hecho", False):
                self._aviso_venc_hecho = True
                messagebox.showwarning(
                    "Certificado por vencer",
                    f"El certificado activo ({cn or '?'}) vence el {vence:%d/%m/%Y} "
                    f"({dias} días).\n\nRenueva el certificado antes de esa fecha.")

        def abrir_notificaciones(self):
            """Panel sutil: salud del doctor + vencimientos de todos los certificados."""
            import datetime
            win = tk.Toplevel(self.root)
            win.title("Notificaciones — sgd-signer")
            win.geometry("520x420")
            win.minsize(460, 300)
            win.configure(bg=UI["bg"])
            win.transient(self.root)
            win.grab_set()

            _cont = tk.Frame(win, bg=UI["bg"])
            _cont.pack(fill="both", expand=True, padx=16, pady=16)
            _cv = tk.Canvas(_cont, bg=UI["bg"], highlightthickness=0)
            _sb = tk.Scrollbar(_cont, orient="vertical", command=_cv.yview)
            _cv.configure(yscrollcommand=_sb.set)
            _sb.pack(side="right", fill="y")
            _cv.pack(side="left", fill="both", expand=True)
            body = tk.Frame(_cv, bg=UI["bg"])
            _win_id = _cv.create_window((0, 0), window=body, anchor="nw")
            body.configure(padx=8, pady=8)

            def _ajustar(_e=None):
                _cv.configure(scrollregion=_cv.bbox("all"))
                _cv.itemconfigure(_win_id, width=_cv.winfo_width())
            body.bind("<Configure>", _ajustar)
            _cv.bind("<Configure>", _ajustar)

            def seccion(titulo):
                # Card Material (estilo Flutter): superficie blanca, borde 1px,
                # sombra sutil de 2px (elevación) — consistente en todos los módulos.
                f = tk.Frame(body, bg=UI["surface"], highlightbackground=UI["border"],
                             highlightthickness=1)
                f.pack(fill="x", pady=(0, 10))
                tk.Label(f, text=titulo, bg=UI["surface"], fg=UI["ink"],
                         font=UI["ui_b"]).pack(anchor="w", padx=12, pady=(10, 4))
                return f

            # --- salud del doctor ---
            f_doc = seccion("Salud del sistema (Doctor)")
            try:
                diag = diagnostico()
            except Exception as e:
                tk.Label(f_doc, text=f"Error al diagnosticar: {e}", bg=UI["surface"],
                         fg=UI["danger_fg"], font=UI["ui"]).pack(anchor="w", padx=12, pady=(0, 10))
                diag = []
            for d in diag:
                marca = "✓" if d["ok"] else "✗"
                color = UI["accent_fg"] if d["ok"] else UI["danger_fg"]
                tk.Label(f_doc, text=f"{marca}  {d['item']}: {d['detalle']}", bg=UI["surface"],
                         fg=color, font=UI["ui"], anchor="w").pack(anchor="w", padx=12, pady=1)
            if not diag:
                tk.Label(f_doc, text="(sin datos)", bg=UI["surface"], fg=UI["muted"],
                         font=UI["ui"]).pack(anchor="w", padx=12, pady=(0, 10))

            # --- vencimientos ---
            f_venc = seccion("Vencimiento de certificados")
            try:
                certs = listar_certs_via_daemon()
            except Exception as e:
                tk.Label(f_venc, text=f"No se pudo listar: {e}", bg=UI["surface"],
                         fg=UI["danger_fg"], font=UI["ui"]).pack(anchor="w", padx=12, pady=(0, 10))
                certs = []
            ahora = datetime.datetime.now(datetime.timezone.utc)
            for c in certs:
                no_after = c.get("no_after")
                if not no_after:
                    continue
                try:
                    vence = datetime.datetime.fromisoformat(no_after)
                    dias = (vence - ahora).days
                except Exception:
                    continue
                if dias < 0:
                    estado, color = f"VENCIDO hace {-dias}d", UI["danger_fg"]
                elif dias <= 30:
                    estado, color = f"vence en {dias}d", UI["warn_fg"]
                else:
                    estado, color = f"vence en {dias}d", UI["accent_fg"]
                marca = "✓ " if c.get("activo") else "  "
                tk.Label(f_venc, text=f"{marca}{c['cn']} — {estado} ({vence:%d/%m/%Y})",
                         bg=UI["surface"], fg=color, font=UI["ui"], anchor="w").pack(anchor="w", padx=12, pady=1)
            if not certs:
                tk.Label(f_venc, text="(sin certificados)", bg=UI["surface"], fg=UI["muted"],
                         font=UI["ui"]).pack(anchor="w", padx=12, pady=(0, 10))

            btn_cta(body, "Cerrar", win.destroy).pack(pady=(4, 0))

        def pedir_pin(self):
            cert_activo = None
            try:
                cert_activo = get_config_via_daemon().get("cert")
            except Exception:
                pass
            titulo = "Clave del certificado" if cert_activo else "PIN del certificado"
            pin = simpledialog.askstring(titulo, "Ingresa la clave:", show="*")
            if not pin:
                return
            recordar = messagebox.askyesno(
                "Recordar clave",
                "¿Guardar la clave de forma permanente (sobrevive reinicios del daemon)?\n\n"
                "Sí = guardar en disco.\nNo = recordar solo mientras el servicio siga corriendo."
            )
            try:
                set_pin_via_daemon(pin, "disco" if recordar else "sesion", cert=cert_activo)
                self._refrescar_estado_pin()
                messagebox.showinfo("OK", "Clave verificada y guardada.")
            except Exception as e:
                messagebox.showerror("Clave rechazada", str(e))

        # --- ventana de configuración ----------------------------------------
        def abrir_doctor(self):
            """Doctor: muestra el estado de instalación y permite instalar lo que
            falta (daemon, esquema, deps, servicio). El middleware Bit4id requiere
            sudo: se muestra con instrucciones y enlace."""
            win = tk.Toplevel(self.root)
            win.title("Doctor — sgd-signer")
            win.geometry("560x520")
            win.minsize(480, 360)
            win.configure(bg=UI["bg"])
            win.transient(self.root)
            win.grab_set()

            _cont = tk.Frame(win, bg=UI["bg"])
            _cont.pack(fill="both", expand=True, padx=16, pady=16)
            _cv = tk.Canvas(_cont, bg=UI["bg"], highlightthickness=0)
            _sb = tk.Scrollbar(_cont, orient="vertical", command=_cv.yview)
            _cv.configure(yscrollcommand=_sb.set)
            _sb.pack(side="right", fill="y")
            _cv.pack(side="left", fill="both", expand=True)
            body = tk.Frame(_cv, bg=UI["bg"])
            _win_id = _cv.create_window((0, 0), window=body, anchor="nw")
            body.configure(padx=8, pady=8)

            def _ajustar(_e=None):
                _cv.configure(scrollregion=_cv.bbox("all"))
                _cv.itemconfigure(_win_id, width=_cv.winfo_width())
            body.bind("<Configure>", _ajustar)
            _cv.bind("<Configure>", _ajustar)

            def _render():
                for w in body.winfo_children():
                    w.destroy()
                try:
                    diag = diagnostico()
                except Exception as e:
                    tk.Label(body, text=f"Error al diagnosticar: {e}", bg=UI["bg"],
                             fg=UI["danger"], font=UI["ui"]).pack(anchor="w")
                    return
                faltan_auto = [d for d in diag if d["accion"]]
                for d in diag:
                    marca = "✓" if d["ok"] else "✗"
                    color = UI["accent_fg"] if d["ok"] else UI["danger_fg"]
                    fila = tk.Frame(body, bg=UI["bg"])
                    fila.pack(fill="x", pady=2)
                    tk.Label(fila, text=f"{marca}  {d['item']}", bg=UI["bg"],
                             fg=color, font=UI["ui_b"], width=30, anchor="w").pack(side="left")
                    tk.Label(fila, text=d["detalle"], bg=UI["bg"], fg=UI["muted"],
                             font=UI["ui"], anchor="w").pack(side="left", padx=8)
                    # botón individual de instalar por ítem faltante
                    if d.get("accion"):
                        btn_cta(fila, "Instalar",
                                lambda a=d["accion"]: self._instalar_doctor(body, [a])
                                ).pack(side="right", padx=4)
                if faltan_auto:
                    btn_cta(body, "Instalar todo lo que falta",
                            lambda: self._instalar_doctor(body, faltan_auto)).pack(pady=(16, 4))
                else:
                    tk.Label(body, text="Todo en orden ✓", bg=UI["bg"], fg=UI["accent_fg"],
                             font=UI["ui_b"]).pack(pady=(16, 4))

            def _instalar_doctor(body, faltan_auto):
                acciones = [d["accion"] for d in faltan_auto]
                res = auto_instalar(acciones)
                for w in body.winfo_children():
                    w.destroy()
                for item, ok, msg in res:
                    marca = "✓" if ok else "✗"
                    color = UI["accent_fg"] if ok else UI["danger_fg"]
                    tk.Label(body, text=f"{marca}  {item}: {msg}", bg=UI["bg"],
                             fg=color, font=UI["ui"], anchor="w").pack(anchor="w", pady=2)
                btn_cta(body, "Re-diagnosticar", _render).pack(pady=(16, 4))

            _render()

        def abrir_configuracion(self):
            win = tk.Toplevel(self.root)
            win.title("Configuración — sgd-signer")
            win.geometry("600x760")
            win.minsize(520, 420)
            win.configure(bg=UI["bg"])
            win.transient(self.root)
            win.grab_set()

            # contenido scrollable: las secciones no caben en una altura fija y en
            # pantallas bajas los botones quedaban fuera de la ventana.
            _cont = tk.Frame(win, bg=UI["bg"])
            _cont.pack(fill="both", expand=True)
            _cv = tk.Canvas(_cont, bg=UI["bg"], highlightthickness=0)
            _sb = tk.Scrollbar(_cont, orient="vertical", command=_cv.yview)
            _cv.configure(yscrollcommand=_sb.set)
            _sb.pack(side="right", fill="y")
            _cv.pack(side="left", fill="both", expand=True)
            body = tk.Frame(_cv, bg=UI["bg"])
            _win_id = _cv.create_window((0, 0), window=body, anchor="nw")
            body.configure(padx=16, pady=16)

            def _ajustar(_e=None):
                _cv.configure(scrollregion=_cv.bbox("all"))
                _cv.itemconfigure(_win_id, width=_cv.winfo_width())

            body.bind("<Configure>", _ajustar)
            _cv.bind("<Configure>", _ajustar)
            _cv.bind_all("<Button-4>", lambda e: _cv.yview_scroll(-2, "units"), add="+")
            _cv.bind_all("<Button-5>", lambda e: _cv.yview_scroll(2, "units"), add="+")
            win.bind("<Destroy>", lambda e: (_cv.unbind_all("<Button-4>"),
                                             _cv.unbind_all("<Button-5>"))
                     if e.widget is win else None)

            def seccion(titulo):
                # Card Material (estilo Flutter): superficie blanca, borde 1px,
                # sombra sutil de 2px (elevación) — consistente en todos los módulos.
                f = tk.Frame(body, bg=UI["surface"], highlightbackground=UI["border"],
                             highlightthickness=1)
                f.pack(fill="x", pady=(0, 12))
                tk.Label(f, text=titulo, bg=UI["surface"], fg=UI["ink"],
                         font=UI["ui_b"]).pack(anchor="w", padx=12, pady=(10, 4))
                return f

            # --- PIN ----------------------------------------------------------
            f_pin = seccion("PIN del certificado")
            self.cfg_pin_status = tk.Label(f_pin, text="", bg=UI["surface"], fg=UI["muted"],
                                           font=UI["mono"])
            self.cfg_pin_status.pack(anchor="w", padx=12, pady=(0, 6))
            fila = tk.Frame(f_pin, bg=UI["surface"])
            fila.pack(fill="x", padx=12, pady=(0, 10))
            self.cfg_pin_var = tk.StringVar()
            tk.Entry(fila, textvariable=self.cfg_pin_var, show="*", relief="flat",
                     highlightbackground=UI["border"], highlightthickness=1,
                     font=UI["mono"]).pack(fill="x", ipady=3)

            # radios + botones en su propia fila: con todo en una sola línea el
            # botón "Guardar PIN" quedaba fuera del área visible de la ventana.
            fila2 = tk.Frame(f_pin, bg=UI["surface"])
            fila2.pack(fill="x", padx=12, pady=(0, 10))
            self.cfg_recordar = tk.StringVar(value="sesion")
            tk.Radiobutton(fila2, text="Solo esta sesión", variable=self.cfg_recordar,
                           value="sesion", bg=UI["surface"], fg=UI["ink"], font=UI["ui"],
                           activebackground=UI["surface"]).pack(side="left")
            tk.Radiobutton(fila2, text="Permanente (disco)", variable=self.cfg_recordar,
                           value="disco", bg=UI["surface"], fg=UI["ink"], font=UI["ui"],
                           activebackground=UI["surface"]).pack(side="left", padx=(8, 0))

            fila3 = tk.Frame(f_pin, bg=UI["surface"])
            fila3.pack(fill="x", padx=12, pady=(0, 10))
            btn_cta(fila3, "Guardar PIN", lambda: self._guardar_pin_desde_cfg(win)).pack(side="left")
            btn_plano(fila3, "Olvidar PIN guardado", self._olvidar_pin, fg=UI["danger_fg"]).pack(side="left", padx=(8, 0))
            self._refrescar_cfg_pin_status()
            # --- certificado de firma ------------------------------------------
            f_cert = seccion("Certificado de firma")
            tk.Label(f_cert, text="Importados (.p12/.pfx) y tokens USB. Los importados se guardan\n"
                                  "en ~/.sgd-signer/certs/ y se eliminan; los tokens viven en el dispositivo.",
                     bg=UI["surface"], fg=UI["muted"], font=UI["ui"], justify="left").pack(anchor="w", padx=12, pady=(0, 6))
            cont_cert = tk.Frame(f_cert, bg=UI["surface"])
            cont_cert.pack(fill="x", padx=12, pady=(0, 6))
            self.cfg_cert_lista = tk.Listbox(cont_cert, height=3, relief="flat", font=UI["mono"],
                                             highlightbackground=UI["border"], highlightthickness=1,
                                             activestyle="none", selectbackground=UI["ink"],
                                             selectforeground=UI["surface"])
            self.cfg_cert_lista.pack(fill="x")
            self.cfg_cert_detalle = tk.Label(f_cert, text="", bg=UI["surface"], fg=UI["muted"],
                                             font=UI["ui"], justify="left", anchor="w")
            self.cfg_cert_detalle.pack(fill="x", padx=12, pady=(0, 6))
            fila_cert = tk.Frame(f_cert, bg=UI["surface"])
            fila_cert.pack(fill="x", padx=12, pady=(0, 10))
            btn_plano(fila_cert, "Detectar certificados", self._cfg_detectar_certs).pack(side="left")
            btn_plano(fila_cert, "Importar certificado…", self._cfg_importar_cert).pack(side="left", padx=(8, 0))
            btn_plano(fila_cert, "Eliminar", self._cfg_eliminar_cert, fg=UI["danger_fg"]).pack(side="left", padx=(8, 0))
            btn_plano(fila_cert, "Desbloquear con PUK", self._cfg_desbloquear_puk, fg=UI["warn_fg"]).pack(side="left", padx=(8, 0))
            btn_cta(fila_cert, "Usar este certificado", self._cfg_usar_cert).pack(side="right")
            self._cfg_certs_data = []

            # --- imagen por tipo ----------------------------------------------
            f_img = seccion("Imagen de firma por tipo")
            self.cfg_tipo = tk.StringVar(value=self.tipo.get())
            tk.OptionMenu(f_img, self.cfg_tipo, *[NOMBRES_TIPO[t] for t in sorted(TIPOS)],
                          command=self._cfg_tipo_cambia).config(
                bg=UI["surface"], fg=UI["ink"], relief="flat",
                highlightbackground=UI["border"], highlightthickness=1, font=UI["ui"])
            f_img.winfo_children()[-1].pack(anchor="w", padx=12, pady=(0, 6))
            fila_img = tk.Frame(f_img, bg=UI["surface"])
            fila_img.pack(fill="x", padx=12, pady=(0, 6))
            self.cfg_img_lbl = tk.Label(fila_img, text="(imagen por defecto)", bg=UI["surface"],
                                        fg=UI["muted"], font=UI["mono"])
            self.cfg_img_lbl.pack(side="left")
            btn_plano(fila_img, "Elegir imagen…", self._cfg_elegir_imagen).pack(side="right")
            # vista previa: sobre tablero gris con borde, la imagen de firma es
            # casi blanca y sobre fondo blanco no se distinguía nada.
            marco_prev = tk.Frame(f_img, bg=UI["border"], highlightbackground=UI["border"],
                                  highlightthickness=1)
            marco_prev.pack(anchor="w", padx=12, pady=(0, 8))
            self.cfg_img_preview = tk.Label(marco_prev, text="(sin imagen)", bg=UI["preview_bg"],
                                            fg=UI["muted"], font=UI["mono"],
                                            width=26, height=6)
            self.cfg_img_preview.pack(padx=1, pady=1)
            # posición de la imagen dentro del stamp
            tk.Label(f_img, text="Posición de la imagen dentro de la firma", bg=UI["surface"],
                     fg=UI["muted"], font=UI["ui"]).pack(anchor="w", padx=12, pady=(4, 2))
            fila_pos = tk.Frame(f_img, bg=UI["surface"])
            fila_pos.pack(fill="x", padx=12, pady=(0, 10))
            self.cfg_img_pos = tk.StringVar(value="left")
            tk.OptionMenu(fila_pos, self.cfg_img_pos, "left", "right", "top", "bottom",
                          command=lambda _v: self._cfg_render_firma()).config(
                bg=UI["surface"], fg=UI["ink"], relief="flat", font=UI["ui"])
            fila_pos.winfo_children()[-1].pack(side="left")
            tk.Label(fila_pos, text="(izquierda / derecha / encima / debajo del texto)",
                     bg=UI["surface"], fg=UI["muted"], font=UI["ui"]).pack(side="left", padx=(6, 0))
            btn_cta(fila_pos, "Aplicar", self._cfg_aplicar_imagen).pack(side="right")

            # vista previa de la firma completa (imagen + texto) como saldrá
            tk.Label(f_img, text="Así se verá la firma:", bg=UI["surface"],
                     fg=UI["muted"], font=UI["ui"]).pack(anchor="w", padx=12, pady=(4, 2))
            marco_firma = tk.Frame(f_img, bg=UI["border"])
            marco_firma.pack(anchor="w", padx=12, pady=(0, 10))
            self.cfg_firma_canvas = tk.Canvas(marco_firma, width=FIRMA_W * 2,
                                              height=FIRMA_H * 2,
                                              bg=UI["surface"], highlightthickness=0)
            self.cfg_firma_canvas.pack(padx=1, pady=1)

            # --- posición de la firma en la página ----------------------------
            f_pos = seccion("Posición de la firma en la página")
            self.cfg_pos_lbl = tk.Label(f_pos, text="", bg=UI["surface"], fg=UI["muted"],
                                        font=UI["mono"])
            self.cfg_pos_lbl.pack(anchor="w", padx=12, pady=(0, 6))
            tk.Label(f_pos, text="Haz click en la página del documento para fijarla (se guarda por tipo).",
                     bg=UI["surface"], fg=UI["muted"], font=UI["ui"]).pack(anchor="w", padx=12, pady=(0, 10))

            # --- verificación TSL ---------------------------------------------
            f_tsl = seccion("Verificación")
            self.cfg_tsl = tk.BooleanVar(value=True)
            try:
                self.cfg_tsl.set(bool(get_config_via_daemon().get("tsl_check", True)))
            except Exception:
                pass
            tk.Checkbutton(f_tsl, text="Verificar certificado en la TSL de INDECOPI antes de firmar",
                           variable=self.cfg_tsl, bg=UI["surface"], fg=UI["ink"],
                           font=UI["ui"], activebackground=UI["surface"],
                           command=self._cfg_guardar_tsl).pack(anchor="w", padx=12, pady=10)

            # --- sello de tiempo (TSA) ----------------------------------------
            f_tsa = seccion("Sello de tiempo (TSA)")
            tk.Label(f_tsa, text="Añade sello RFC 3161 a las firmas (PAdES B-T).\n"
                                 "Preconfigurado con FreeTSA (gratuita, sin credenciales).",
                     bg=UI["surface"], fg=UI["muted"], font=UI["ui"], justify="left").pack(anchor="w", padx=12, pady=(0, 6))
            try:
                _cfg_tsa = get_config_via_daemon()
            except Exception:
                _cfg_tsa = {}
            self.cfg_tsa_on = tk.BooleanVar(value=bool(_cfg_tsa.get("tsa_url")))
            tk.Checkbutton(f_tsa, text="Habilitar sello de tiempo",
                           variable=self.cfg_tsa_on, bg=UI["surface"], fg=UI["ink"],
                           font=UI["ui"], activebackground=UI["surface"]).pack(anchor="w", padx=12, pady=(0, 6))
            self.cfg_tsa_url = tk.StringVar(value=_cfg_tsa.get("tsa_url") or "https://freetsa.org/tsr")
            self.cfg_tsa_user = tk.StringVar(value=_cfg_tsa.get("tsa_user", ""))
            self.cfg_tsa_pass = tk.StringVar(value=_cfg_tsa.get("tsa_pass", ""))
            self.cfg_tsa_policy = tk.StringVar(value=_cfg_tsa.get("tsa_policy", ""))
            for lbl, var, show in (("URL:", self.cfg_tsa_url, None),
                                   ("Usuario:", self.cfg_tsa_user, None),
                                   ("Password:", self.cfg_tsa_pass, "*"),
                                   ("Política:", self.cfg_tsa_policy, None)):
                fila = tk.Frame(f_tsa, bg=UI["surface"])
                fila.pack(fill="x", padx=12, pady=(0, 6))
                tk.Label(fila, text=lbl, bg=UI["surface"], fg=UI["muted"],
                         font=UI["ui"], width=10, anchor="w").pack(side="left")
                tk.Entry(fila, textvariable=var, show=show or "", bg=UI["surface"],
                         fg=UI["ink"], relief="flat", highlightbackground=UI["border"],
                         highlightthickness=1, font=UI["ui"]).pack(side="left", fill="x", expand=True)
            btn_cta(f_tsa, "Guardar TSA", self._cfg_guardar_tsa).pack(anchor="w", padx=12, pady=(0, 10))

            btn_cta(body, "Cerrar", win.destroy).pack(pady=(4, 0))

            # cargar apariencia al final (ya existen cfg_pos_lbl y cfg_img_lbl)
            self._cfg_cargar_apariencia()
            # detectar certificados en segundo plano (abrir el token tarda ~2s)
            win.after(150, self._cfg_detectar_certs)

        def _refrescar_cfg_pin_status(self):
            try:
                estado = get_pin_status_via_daemon()
            except Exception:
                estado = "ninguno"
            textos = {"disco": "Guardado en disco (permanente)", "sesion": "Guardado en esta sesión",
                      "ninguno": "Sin PIN guardado"}
            self.cfg_pin_status.config(text=textos.get(estado, estado))

        def _guardar_pin_desde_cfg(self, win):
            pin = self.cfg_pin_var.get()
            if not pin:
                messagebox.showwarning("PIN", "Ingresa un PIN primero.")
                return
            try:
                set_pin_via_daemon(pin, self.cfg_recordar.get())
                self._refrescar_estado_pin()
                self._refrescar_cfg_pin_status()
                self.cfg_pin_var.set("")
                messagebox.showinfo("OK", "PIN verificado contra el token y guardado.")
            except Exception as e:
                messagebox.showerror("PIN rechazado", str(e))

        def _olvidar_pin(self):
            if not messagebox.askyesno("Olvidar PIN", "¿Eliminar el PIN guardado (disco y sesión)?"):
                return
            try:
                call_daemon_op({"op": "CLEAR_PIN"})
            except Exception:
                pass
            self._refrescar_estado_pin()
            self._refrescar_cfg_pin_status()

        def _cfg_tipo_cambia(self, _nombre):
            for t, n in NOMBRES_TIPO.items():
                if n == _nombre:
                    self.cfg_tipo.set(t)
                    self._cfg_cargar_apariencia()
                    return

        def _cfg_detectar_certs(self):
            self.cfg_cert_detalle.config(text="Buscando certificados en tokens y smartcards…")
            self.cfg_cert_lista.delete(0, "end")
            self.root.update_idletasks()
            try:
                certs = listar_certs_via_daemon()
            except Exception as e:
                self.cfg_cert_detalle.config(text=f"No se pudo detectar: {e}")
                return
            self._cfg_certs_data = certs
            if not certs:
                self.cfg_cert_detalle.config(
                    text="No se detectaron certificados. Conecta el token/smartcard, "
                         "importa un .p12/.pfx o guarda el PIN.")
                return
            sel = 0
            for i, c in enumerate(certs):
                marca = "✓ " if c.get("activo") else "  "
                estado = "" if c.get("ok") else "  [REVISAR]"
                origen = c.get("archivo") and "archivo" or c.get("token", "?")
                self.cfg_cert_lista.insert("end", f"{marca}{c['cn']} — {origen}{estado}")
                if c.get("activo"):
                    sel = i
            self.cfg_cert_lista.selection_set(sel)
            self._cfg_mostrar_detalle_cert(sel)
            self.cfg_cert_lista.bind(
                "<<ListboxSelect>>",
                lambda _e: self._cfg_mostrar_detalle_cert(
                    self.cfg_cert_lista.curselection()[0]
                    if self.cfg_cert_lista.curselection() else 0))
            # doble-click = elegir y guardar (mismo flujo que 'Usar este certificado')
            self.cfg_cert_lista.bind("<Double-Button-1>", lambda _e: self._cfg_usar_cert())

        def _cfg_mostrar_detalle_cert(self, idx):
            if not (0 <= idx < len(self._cfg_certs_data)):
                return
            c = self._cfg_certs_data[idx]
            lineas = []
            if c.get("org"):
                lineas.append(c["org"])
            lineas += c.get("avisos", [])
            if c.get("bloqueado"):
                lineas.append("El PIN del token está BLOQUEADO (se falló varias veces).")
                lineas.append("Desbloquéalo con el PUK o en el portal del fabricante.")
            if c.get("archivo"):
                lineas.append(f"Archivo: {c['archivo']}")
            else:
                lineas.append(f"Dispositivo: {c.get('token','?')} (serie {c.get('serial_token','?')})")
            estado = "Listo para firmar" if c.get("ok") else "No utilizable"
            self.cfg_cert_detalle.config(
                text=f"{estado}\n" + "\n".join(lineas),
                fg=UI["ink"] if c.get("ok") else UI["danger_fg"])

        def _cfg_usar_cert(self):
            sel = self.cfg_cert_lista.curselection()
            if not sel:
                messagebox.showinfo("Certificado", "Primero pulsa 'Detectar certificados' y elige uno.")
                return
            c = self._cfg_certs_data[sel[0]]
            if c.get("archivo"):
                # certificado importado: no requiere token ni PIN para elegirlo
                try:
                    elegir_archivo_cert_via_daemon(c["archivo"])
                except Exception as e:
                    messagebox.showerror("Error", f"No se pudo guardar la elección: {e}")
                    return
                messagebox.showinfo("Certificado", f"Se firmará con:\n{c['cn']}\n({c['archivo']})")
                self._cfg_detectar_certs()
                return
            if not c.get("key_id"):
                messagebox.showwarning("Certificado", "Ese dispositivo no expone un certificado utilizable.")
                return
            if not c.get("ok") and not messagebox.askyesno(
                    "Certificado con avisos",
                    "\n".join(c.get("avisos", [])) + "\n\n¿Usarlo de todas formas?"):
                return
            try:
                elegir_cert_via_daemon(c["key_id"], c["lib"], c.get("serial_token"))
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar la elección: {e}")
                return
            messagebox.showinfo("Certificado", f"Se firmará con:\n{c['cn']}\n({c['token']})")
            self._cfg_detectar_certs()

        def _cfg_importar_cert(self):
            """Importa un .p12/.pfx a ~/.sgd-signer/certs/ y lo activa."""
            archivo = filedialog.askopenfilename(
                title="Importar certificado (.p12/.pfx)",
                filetypes=[("Certificado PKCS#12", "*.p12 *.pfx"), ("Todos", "*.*")])
            if not archivo:
                return
            pin = simpledialog.askstring("Clave del certificado",
                                         "Ingresa la clave del archivo (se verifica antes de importar):",
                                         show="*")
            if not pin:
                return
            try:
                dst = importar_cert_via_daemon(archivo, pin)
            except Exception as e:
                messagebox.showerror("Importar certificado", f"No se pudo importar: {e}")
                return
            messagebox.showinfo("Importar certificado",
                                f"Certificado importado y activado:\n{dst}\n\n"
                                "La clave quedó guardada; para cambiarla usa 'Ingresar / cambiar PIN'.")
            self._cfg_detectar_certs()

        def _cfg_eliminar_cert(self):
            """Elimina un certificado importado (.p12/.pfx). Los tokens USB no se
            eliminan: viven en el dispositivo y reaparecen al reconectarlo."""
            sel = self.cfg_cert_lista.curselection()
            if not sel:
                messagebox.showinfo("Certificado", "Selecciona un certificado de la lista.")
                return
            c = self._cfg_certs_data[sel[0]]
            if not c.get("archivo"):
                messagebox.showinfo(
                    "Certificado de token",
                    "Los certificados de token USB viven en el dispositivo (hardware) y no se "
                    "pueden eliminar desde aquí: reaparecen al reconectarlo.\n\n"
                    "Si quieres dejar de usarlo, elige otro certificado con 'Usar este certificado'.")
                return
            if not messagebox.askyesno(
                    "Eliminar certificado",
                    f"¿Eliminar el certificado importado?\n\n{c['archivo']}\n\n"
                    "Se borrará el archivo de ~/.sgd-signer/certs/ y su clave guardada."):
                return
            try:
                eliminar_cert_via_daemon(c["archivo"])
            except Exception as e:
                messagebox.showerror("Eliminar certificado", f"No se pudo eliminar: {e}")
                return
            messagebox.showinfo("Certificado", "Certificado eliminado.")
            self._cfg_detectar_certs()

        def _cfg_desbloquear_puk(self):
            """Desbloquea el token USB con PUK (SO PIN) y restablece el PIN."""
            puk = simpledialog.askstring("Desbloquear token con PUK",
                                         "Ingresa el PUK del token:", show="*")
            if not puk:
                return
            nuevo = simpledialog.askstring("Nuevo PIN",
                                           "Ingresa el nuevo PIN de usuario (mínimo 4 dígitos):",
                                           show="*")
            if not nuevo:
                return
            if not messagebox.askyesno(
                    "Desbloquear token",
                    f"Se desbloqueará el token USB con el PUK y el PIN de usuario "
                    f"quedará como:\n\n{nuevo}\n\n¿Proceder?"):
                return
            try:
                label = desbloquear_token_via_daemon(puk, nuevo)
            except Exception as e:
                messagebox.showerror("Desbloquear token",
                                      f"No se pudo desbloquear: {e}\n\n"
                                      "Si el PUK es incorrecto, el token puede volver a bloquearse.")
                return
            messagebox.showinfo("Token desbloqueado",
                                f"Token {label} desbloqueado.\nPIN de usuario restablecido a: {nuevo}")
            self._cfg_detectar_certs()

        def _cfg_render_firma(self):
            """Dibuja la firma como saldrá: imagen en su posición + texto.
            Usa el layout REAL del tipo (STAMP_LAYOUT) escalado al canvas,
            para que la preview muestre exactamente las proporciones del PDF."""
            cv = getattr(self, "cfg_firma_canvas", None)
            if cv is None:
                return
            cv.delete("all")
            # layout real del tipo (imagen + texto), escalado 2x
            tipo = self.cfg_tipo.get()
            base = STAMP_LAYOUT.get(tipo, STAMP_LAYOUT["2"])
            img_w, img_h, img_x, img_y, text_x, text_y, fs, lead = base
            S = 2  # escala: el canvas es 2x la caja real
            W, H = FIRMA_W * S, FIRMA_H * S
            img = self.cfg_img_actual_path()
            if img and img.exists():
                try:
                    pil = Image.open(img)
                    pil.thumbnail((img_w * S, img_h * S))
                    self._cfg_firma_img_tk = ImageTk.PhotoImage(pil)
                    cv.create_image(img_x * S, img_y * S, image=self._cfg_firma_img_tk, anchor="nw")
                except Exception:
                    pass
            # texto del stamp en su posición real
            texto = ("Firmado digitalmente por\nNOMBRE APELLIDO\nSENAMHI\n"
                     "Motivo: Soy el autor del documento.\nFecha: 01.01.2026 09:00:00 -05:00")
            cv.create_text(text_x * S, text_y * S, text=texto, anchor="nw",
                           font=("TkDefaultFont", 6), fill=UI["accent"], width=W - text_x * S - 6)
            cv.create_rectangle(1, 1, W - 1, H - 1, outline=UI["outline"], dash=(2, 2))

        def cfg_img_actual_path(self):
            """Ruta de la imagen que se usará para el tipo elegido en Configuración."""
            try:
                apariencia = get_apariencia_via_daemon()
            except Exception:
                apariencia = {}
            entry = apariencia.get(self.cfg_tipo.get(), {})
            img = entry.get("imagen")
            return Path(img) if img else IMG_POR_TIPO.get(self.cfg_tipo.get())

        def _cfg_cargar_apariencia(self):
            try:
                apariencia = get_apariencia_via_daemon()
            except Exception:
                apariencia = {}
            entry = apariencia.get(self.cfg_tipo.get(), {})
            img = entry.get("imagen")
            self.cfg_img_lbl.config(text=os.path.basename(img) if img else "(imagen por defecto)")
            self.cfg_img_pos.set(entry.get("img_pos") or IMG_POS_DEFAULT.get(self.cfg_tipo.get(), "left"))
            pos = entry.get("pos")
            self.cfg_pos_lbl.config(
                text=f"Posición guardada: x={pos[0]:.0f} y={pos[1]:.0f} pt" if pos
                else "Sin posición guardada (usa la del tipo por defecto)")
            # vista previa de la imagen (custom o la por defecto del tipo)
            img_path = Path(img) if img else IMG_POR_TIPO.get(self.cfg_tipo.get())
            try:
                if img_path and img_path.exists():
                    pil = Image.open(img_path)
                    pil.thumbnail((180, 90))
                    self._cfg_img_tk = ImageTk.PhotoImage(pil)
                    self.cfg_img_preview.config(image=self._cfg_img_tk, text="")
                else:
                    self.cfg_img_preview.config(image="", text="(sin imagen)")
            except Exception:
                self.cfg_img_preview.config(image="", text="(no se pudo previsualizar)")
            self._cfg_render_firma()

        def _cfg_elegir_imagen(self):
            p = filedialog.askopenfilename(title="Imagen de firma",
                                           filetypes=[("Imagen", "*.jpg *.jpeg *.png")])
            if not p:
                return
            try:
                set_apariencia_via_daemon(self.cfg_tipo.get(), imagen=p)
                self._cfg_cargar_apariencia()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def _cfg_aplicar_imagen(self):
            try:
                set_apariencia_via_daemon(self.cfg_tipo.get(),
                                          img_pos=self.cfg_img_pos.get())
                self._cfg_cargar_apariencia()
                messagebox.showinfo("OK", "Posición de la imagen aplicada.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def _cfg_guardar_tsl(self):
            try:
                set_config_via_daemon({"tsl_check": bool(self.cfg_tsl.get())})
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def _cfg_guardar_tsa(self):
            """Guarda la config de TSA. Si el checkbox está apagado, se
            deshabilita (tsa_url vacío = sin sello)."""
            try:
                if self.cfg_tsa_on.get():
                    set_config_via_daemon({
                        "tsa_url": self.cfg_tsa_url.get().strip(),
                        "tsa_user": self.cfg_tsa_user.get().strip(),
                        "tsa_pass": self.cfg_tsa_pass.get().strip(),
                        "tsa_policy": self.cfg_tsa_policy.get().strip(),
                    })
                else:
                    set_config_via_daemon({
                        "tsa_url": "", "tsa_user": "", "tsa_pass": "", "tsa_policy": "",
                    })
            except Exception as e:
                messagebox.showerror("Error", str(e))
                return
            messagebox.showinfo("TSA", "Configuración de sello de tiempo guardada.")

        # --- firma masiva -----------------------------------------------------
        def firma_masiva(self):
            """Módulo de firma masiva: elegir varios PDFs, agruparlos, elegir
            tipo de firma y modo (1 firma por PDF / 1 firma por hoja)."""
            win = tk.Toplevel(self.root)
            win.title("Firma masiva — sgd-signer")
            win.geometry("640x520")
            win.minsize(560, 400)
            win.configure(bg=UI["bg"])
            win.transient(self.root)
            win.grab_set()

            # Card Material (estilo Flutter): superficie blanca, borde 1px,
            # sombra sutil de 2px (elevación) — consistente en todos los módulos.
            f_lista = tk.Frame(win, bg=UI["surface"], highlightbackground=UI["border"],
                               highlightthickness=1)
            f_lista.pack(fill="both", expand=True, padx=16, pady=(16, 8))
            tk.Label(f_lista, text="Documentos a firmar", bg=UI["surface"], fg=UI["ink"],
                     font=UI["ui_b"]).pack(anchor="w", padx=12, pady=(10, 4))
            lista = tk.Listbox(f_lista, selectmode="extended", relief="flat",
                               font=UI["mono"], highlightbackground=UI["border"],
                               highlightthickness=1, activestyle="none")
            lista.pack(fill="both", expand=True, padx=12, pady=(0, 6))
            self._masiva_pdfs = []

            def _agregar():
                pdfs = filedialog.askopenfilenames(title="Selecciona los PDF a firmar",
                                                   filetypes=[("PDF", "*.pdf")])
                for p in pdfs:
                    if p not in self._masiva_pdfs:
                        self._masiva_pdfs.append(p)
                        lista.insert("end", os.path.basename(p))
                _resumen()

            def _quitar():
                for i in reversed(lista.curselection()):
                    lista.delete(i)
                    del self._masiva_pdfs[i]
                _resumen()

            def _resumen():
                n = len(self._masiva_pdfs)
                lbl_resumen.config(text=f"{n} documento(s)")

            fila_lista = tk.Frame(f_lista, bg=UI["surface"])
            fila_lista.pack(fill="x", padx=12, pady=(0, 10))
            btn_plano(fila_lista, "Agregar PDFs…", _agregar).pack(side="left")
            btn_plano(fila_lista, "Quitar seleccionados", _quitar, fg=UI["danger_fg"]).pack(side="left", padx=(8, 0))

            # Card Material (estilo Flutter): superficie blanca, borde 1px,
            # sombra sutil de 2px (elevación) — consistente en todos los módulos.
            f_opc = tk.Frame(win, bg=UI["surface"], highlightbackground=UI["border"],
                             highlightthickness=1)
            f_opc.pack(fill="x", padx=16, pady=(0, 8))
            tk.Label(f_opc, text="Opciones de firma", bg=UI["surface"], fg=UI["ink"],
                     font=UI["ui_b"]).pack(anchor="w", padx=12, pady=(10, 4))

            fila_tipo = tk.Frame(f_opc, bg=UI["surface"])
            fila_tipo.pack(fill="x", padx=12, pady=(0, 6))
            tk.Label(fila_tipo, text="Tipo:", bg=UI["surface"], fg=UI["muted"],
                     font=UI["ui"]).pack(side="left")
            tipo_var = tk.StringVar(value=self.tipo.get())
            tk.OptionMenu(fila_tipo, tipo_var, *[NOMBRES_TIPO[t] for t in sorted(TIPOS)]).config(
                bg=UI["surface"], fg=UI["ink"], relief="flat",
                highlightbackground=UI["border"], highlightthickness=1, font=UI["ui"])
            fila_tipo.winfo_children()[-1].pack(side="left", padx=(8, 0))

            fila_modo = tk.Frame(f_opc, bg=UI["surface"])
            fila_modo.pack(fill="x", padx=12, pady=(0, 6))
            tk.Label(fila_modo, text="Modo:", bg=UI["surface"], fg=UI["muted"],
                     font=UI["ui"]).pack(side="left")
            modo_var = tk.StringVar(value="pdf")
            tk.Radiobutton(fila_modo, text="1 por PDF", variable=modo_var, value="pdf",
                           bg=UI["surface"], fg=UI["ink"], font=UI["ui"],
                           activebackground=UI["surface"]).pack(side="left", padx=(8, 0))
            tk.Radiobutton(fila_modo, text="1 por hoja", variable=modo_var, value="hoja",
                           bg=UI["surface"], fg=UI["ink"], font=UI["ui"],
                           activebackground=UI["surface"]).pack(side="left", padx=(8, 0))
            tk.Label(fila_modo, text="(cada página)", bg=UI["surface"],
                     fg=UI["muted"], font=UI["ui"]).pack(side="left", padx=(6, 0))

            lbl_resumen = tk.Label(f_opc, text="0 documento(s)",
                                   bg=UI["surface"], fg=UI["muted"], font=UI["mono"])
            lbl_resumen.pack(anchor="w", padx=12, pady=(0, 10))

            def _firmar():
                if not self._masiva_pdfs:
                    messagebox.showwarning("Firma masiva", "Agrega al menos un PDF.")
                    return
                tipo = next(t for t, n in NOMBRES_TIPO.items() if n == tipo_var.get())
                modo = modo_var.get()
                n_firmas = sum(_pdf_num_paginas(p) for p in self._masiva_pdfs) if modo == "hoja" \
                    else len(self._masiva_pdfs)
                if not messagebox.askyesno(
                    "Confirmación — Firma Masiva",
                    f"{len(self._masiva_pdfs)} documento(s) — {n_firmas} firma(s) "
                    f"({modo_var.get() == 'hoja' and '1 por hoja' or '1 por PDF'}) "
                    f"con tipo {NOMBRES_TIPO[tipo]}.\n\n"
                    "Al aceptar declaras haber leído cada archivo. ¿Proceder?"
                ):
                    return
                pos = self.pos_pt
                self.lbl_status.config(text=f"Firmando {n_firmas} firma(s)…", fg=UI["muted"])
                self.root.update_idletasks()
                try:
                    firmados, errores = sign_masivo_via_daemon(self._masiva_pdfs, tipo,
                                                               pos=pos, modo=modo)
                    resumen = f"{len(firmados)} firmados, {len(errores)} con error"
                    self.lbl_status.config(text=resumen,
                                           fg=UI["accent_fg"] if not errores else UI["warn_fg"])
                    detalle = "\n".join([f"✓ {f}" for f in firmados] +
                                         [f"✗ {e['pdf']}: {e['error']}" for e in errores])
                    messagebox.showinfo("Firma masiva", f"{resumen}\n\n{detalle}")
                    win.destroy()
                except Exception as e:
                    self.lbl_status.config(text="Error en firma masiva", fg=UI["danger_fg"])
                    messagebox.showerror("Error", str(e))

            fila_btn = tk.Frame(win, bg=UI["bg"])
            fila_btn.pack(fill="x", padx=16, pady=(0, 16))
            btn_plano(fila_btn, "Cancelar", win.destroy).pack(side="right")
            btn_cta(fila_btn, "Firmar", _firmar).pack(side="right", padx=(0, 8))

        # --- tipo / imagen -----------------------------------------------------
        def _set_tipo(self, _nombre_mostrado):
            for t, n in NOMBRES_TIPO.items():
                if n == _nombre_mostrado:
                    self.tipo.set(t)
                    self._cargar_pos_guardada()
                    self._dibujar_preview_firma()
                    return

        def _cargar_pos_guardada(self):
            try:
                apariencia = get_apariencia_via_daemon()
            except Exception:
                return
            entry = apariencia.get(self.tipo.get(), {})
            if entry.get("pos"):
                x, y = entry["pos"]
                self.lbl_pos.config(text=f"Posición guardada para este tipo: x={x:.0f} y={y:.0f} pt")
            else:
                self.lbl_pos.config(text="Click en la página para fijar posición (se recuerda por tipo)")

        def elegir_imagen(self):
            p = filedialog.askopenfilename(
                title=f"Imagen de firma para tipo {self.tipo.get()}",
                filetypes=[("Imagen", "*.jpg *.jpeg *.png")],
            )
            if not p:
                return
            try:
                set_apariencia_via_daemon(self.tipo.get(), imagen=p)
                messagebox.showinfo("OK", f"Imagen guardada para el tipo {self.tipo.get()}.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def abrir(self):
            p = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
            if p:
                self.cargar(p)

        def cargar(self, p):
            try:
                self.n_paginas = _pdf_num_paginas(p)
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo leer el PDF: {e}")
                return
            self.pdf_path = p
            self.pagina = 1
            self.lbl_archivo.config(text=os.path.basename(p))
            self.btn_firmar.config(state="normal")
            self._cargar_pos_guardada()
            self.render_pagina()

        def _dibujar_preview_firma(self):
            """Dibuja un rectángulo semitransparente donde irá la firma, usando la
            misma caja que sign_pdf (firma_box) para que la preview ocupe el espacio
            real. Coordenadas PDF (desde abajo) → canvas (desde arriba)."""
            self.canvas.delete("preview_firma")
            if not self.pdf_path:
                return
            pos = self.pos_pt
            box = firma_box(self.tipo.get(), self.page_w_pt, self.page_h_pt, pos=pos)
            x0, y0, x1, y1 = box
            ox, oy = self.img_offset
            cx0 = x0 * self.scale + ox
            cx1 = x1 * self.scale + ox
            cy_top = (self.page_h_pt - y1) * self.scale + oy
            cy_bot = (self.page_h_pt - y0) * self.scale + oy
            self.canvas.create_rectangle(
                cx0, cy_top, cx1, cy_bot,
                outline=UI["accent_fg"], width=2, dash=(4, 3), tags="preview_firma",
            )
            self.canvas.create_text(
                (cx0 + cx1) / 2, (cy_top + cy_bot) / 2,
                text="FIRMA", fill="#007AFF", font=UI["mono_b"], tags="preview_firma",
            )

        def render_pagina(self):
            self.page_w_pt, self.page_h_pt = _pdf_page_size_pt(self.pdf_path, self.pagina)
            if self.zoom_modo in ("ajustar", "ancho"):
                self.zoom = self._zoom_calculado(self.zoom_modo)
            dpi = max(20, min(400, int(72 * self.zoom)))
            png_path = _render_pdf_png(self.pdf_path, self.pagina, dpi)
            img = Image.open(png_path)
            self.scale = img.width / self.page_w_pt
            self.tk_img = ImageTk.PhotoImage(img)
            self.canvas.delete("all")
            # centrar la página cuando es más chica que el canvas visible
            cw = max(self.canvas.winfo_width(), img.width)
            ch = max(self.canvas.winfo_height(), img.height)
            ox = max(0, (cw - img.width) // 2)
            oy = max(0, (ch - img.height) // 2)
            self.canvas.config(scrollregion=(0, 0, cw, ch))
            self.canvas.create_image(ox, oy, anchor="nw", image=self.tk_img)
            self.img_offset = (ox, oy)
            os.remove(png_path)
            self.lbl_pagina.config(text=f"{self.pagina} / {self.n_paginas}")
            self.lbl_zoom.config(text=f"{self.zoom * 100:.0f}%")
            self._dibujar_preview_firma()

        # --- zoom / scroll ---------------------------------------------------
        def _zoom_calculado(self, modo):
            """Zoom para que la página quepa en el canvas ('ajustar') o llene el
            ancho ('ancho'). Se recalcula al redimensionar la ventana."""
            cw = self.canvas.winfo_width()
            ch = self.canvas.winfo_height()
            if cw <= 1 or ch <= 1 or not self.page_w_pt:
                return self.zoom
            margen = 16
            z_ancho = (cw - margen) / self.page_w_pt
            if modo == "ancho":
                return max(0.1, z_ancho)
            z_alto = (ch - margen) / self.page_h_pt
            return max(0.1, min(z_ancho, z_alto))

        def zoom_paso(self, factor):
            if not self.pdf_path:
                return
            self.zoom_modo = "manual"
            self.zoom = max(0.2, min(5.0, self.zoom * factor))
            self.render_pagina()

        def zoom_ajustar(self):
            if not self.pdf_path:
                return
            self.zoom_modo = "ajustar"
            self.render_pagina()

        def zoom_ancho(self):
            if not self.pdf_path:
                return
            self.zoom_modo = "ancho"
            self.render_pagina()

        def _wheel_dir(self, event):
            """Normaliza la rueda: Windows/macOS usan event.delta, X11 Button-4/5."""
            if getattr(event, "num", None) == 4:
                return -1
            if getattr(event, "num", None) == 5:
                return 1
            return -1 if event.delta > 0 else 1

        def _on_wheel(self, event):
            self.canvas.yview_scroll(self._wheel_dir(event) * 3, "units")

        def _on_wheel_shift(self, event):
            self.canvas.xview_scroll(self._wheel_dir(event) * 3, "units")

        def _on_wheel_ctrl(self, event):
            self.zoom_paso(0.9 if self._wheel_dir(event) > 0 else 1.1)
            return "break"

        def _on_canvas_resize(self, event):
            # sólo re-renderiza en modos automáticos y si el tamaño cambió de verdad
            if not self.pdf_path or self.zoom_modo == "manual":
                return
            if abs(event.width - self._last_canvas_w) < 20 and \
               abs(event.height - self._last_canvas_h) < 20:
                return
            self._last_canvas_w, self._last_canvas_h = event.width, event.height
            self.render_pagina()

        def cambiar_pagina(self, delta):
            if not self.pdf_path:
                return
            nueva = self.pagina + delta
            if 1 <= nueva <= self.n_paginas:
                self.pagina = nueva
                self.pos_pt = None  # la posición marcada era de la página anterior
                self.render_pagina()

        def click_pagina(self, event):
            if not self.pdf_path:
                return
            # canvasx/y traduce el click a coordenadas del contenido (con scroll),
            # y luego se resta el offset de centrado para llegar a la página.
            ox, oy = self.img_offset
            x_pt = (self.canvas.canvasx(event.x) - ox) / self.scale
            y_pt = (self.canvas.canvasy(event.y) - oy) / self.scale  # y desde arriba (PosicionXY)
            if not (0 <= x_pt <= self.page_w_pt and 0 <= y_pt <= self.page_h_pt):
                return  # click fuera de la página: ignorar
            self.pos_pt = (x_pt, y_pt)
            self.lbl_pos.config(text=f"Posición fijada: x={x_pt:.0f} y={y_pt:.0f} pt (desde arriba)")
            self._dibujar_preview_firma()
            try:
                set_apariencia_via_daemon(self.tipo.get(), pos=self.pos_pt)
            except Exception:
                pass  # falla silenciosa: la posición sigue aplicándose a esta firma aunque no se persista

        def firmar(self):
            tipo = self.tipo.get()
            pos = self.pos_pt
            self.btn_firmar.config(state="disabled")
            self.lbl_status.config(text="Firmando (vía daemon, token USB)...", fg=UI["muted"])
            self.root.update_idletasks()
            try:
                # F8: el token USB solo lo ve el daemon root; delegamos por socket
                # en vez de firmar in-process (aquí corremos como hruiz, sin acceso al token).
                out = manual_sign_via_daemon(self.pdf_path, tipo, pos=pos, pagina=self.pagina)
                self.lbl_status.config(text=f"Firmado: {out}", fg=UI["accent_fg"])
                messagebox.showinfo("OK", f"Documento firmado:\n{out}")
            except Exception as e:
                self.lbl_status.config(text="Error al firmar", fg=UI["danger_fg"])
                if "No hay PIN" in str(e) or "PIN" in str(e) or "clave" in str(e).lower():
                    if messagebox.askyesno("Clave requerida", f"{e}\n\n¿Ingresar la clave ahora?"):
                        self.pedir_pin()
                else:
                    messagebox.showerror("Error al firmar", str(e))
            finally:
                self.btn_firmar.config(state="normal")

        def verificar(self):
            """Verifica las firmas del PDF abierto con pyhanko y muestra el
            resultado en un diálogo (misma info que el portal: firmante,
            validez, motivo, fecha, algoritmo)."""
            if not self.pdf_path:
                messagebox.showinfo("Verificar firma", "Abre un PDF primero.")
                return
            self.lbl_status.config(text="Verificando firma…", fg=UI["muted"])
            self.root.update_idletasks()
            try:
                resumen = verificar_firma(self.pdf_path)
            except Exception as e:
                self.lbl_status.config(text="Error al verificar", fg=UI["danger_fg"])
                messagebox.showerror("Verificar firma", f"No se pudo verificar: {e}")
                return
            if not resumen:
                self.lbl_status.config(text="Sin firmas en el documento", fg=UI["warn_fg"])
                messagebox.showinfo("Verificar firma", "El documento no tiene firmas digitales.")
                return
            lineas = []
            for s in resumen:
                estado = "VÁLIDA" if s["valida"] else "NO VÁLIDA"
                lineas.append(f"{'✓' if s['valida'] else '✗'} {estado}")
                lineas.append(f"  Firmante: {s['firmante']}")
                if s.get("fecha"):
                    lineas.append(f"  Fecha: {s['fecha']}")
                if s.get("algoritmo"):
                    lineas.append(f"  Algoritmo: {s['algoritmo']}")
                if s.get("motivo"):
                    lineas.append(f"  Motivo: {s['motivo']}")
                lineas.append("")
            self.lbl_status.config(text=f"{sum(1 for s in resumen if s['valida'])}/{len(resumen)} firmas válidas",
                                   fg=UI["accent_fg"] if all(s["valida"] for s in resumen) else UI["warn_fg"])
            messagebox.showinfo("Verificar firma", "\n".join(lineas))

    root = tk.Tk()
    root.title("SGD-SIGNER — Firma digital")
    # Responsive: grid ponderado en las barras (estado expande, acciones se
    # compactan) + visor con expand=True — todo visible sin estirar la ventana.
    root.geometry("720x640")
    root.minsize(480, 420)
    root.configure(bg=UI["bg"])
    # icono de la ventana (assets/icon.png); si no existe, se omite sin romper
    try:
        icon = ImageTk.PhotoImage(Image.open(ASSETS_DIR / "icon.png"))
        root.iconphoto(True, icon)
        root._icon_ref = icon  # mantener referencia viva
    except Exception:
        pass
    App(root)
    # --- chequeo de instalación al arrancar (autocontenido, estilo AnyDesk) ---
    # Si falta algo crítico (daemon, esquema, deps), se ofrece auto-reparar.
    # El middleware Bit4id requiere sudo: solo se informa con instrucciones.
    root.after(300, lambda: _chequeo_instalacion(root))
    root.mainloop()



def main():
    # modo daemon (systemd, corre como root para acceder al token USB)
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        daemon_loop(None)
        return
    # modo URL (invocado por el OS como handler de tramitedoc://)
    # formato real del portal: "Tramitedoc:accion=TraDoc?ws=...?urlBase=...?rutaPri=..."
    if len(sys.argv) > 1 and sys.argv[1].lower().startswith("tramitedoc:"):
        url = sys.argv[1]
        if forward_to_daemon(url):
            return
        daemon_loop(url)
        return

    ap = argparse.ArgumentParser(description="sgd-signer: firma digital SGD SENAMHI (Linux/macOS)")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("certs", help="lista certificados")
    sub.add_parser("diag", help="diagnóstico de instalación (daemon, middleware, esquema, token, deps)")
    p = sub.add_parser("pin", help="guarda el PIN del certificado")
    p.add_argument("pin")
    p = sub.add_parser("sign", help="firma un PDF directamente")
    p.add_argument("pdf")
    p.add_argument("--tipo", default="2", choices=sorted(TIPOS), help="tipo de firma (1-6)")
    p.add_argument("--cert", help="ruta al .p12/.pfx")
    p.add_argument("--pos", help="posición 'x,y' (desde esquina superior izquierda)")
    p.add_argument("--pagina", type=int, default=1)
    p.add_argument("--no-tsl", action="store_true", help="salta verificación TSL")
    p = sub.add_parser("gui", help="GUI manual: abrir PDF, elegir tipo/posición, firmar")
    p.add_argument("pdf", nargs="?", help="PDF a abrir directamente (opcional)")
    p.add_argument("--tipo", default=None, choices=sorted(TIPOS), help="tipo de firma preseleccionado")
    args = ap.parse_args()

    if args.cmd == "certs":
        return cmd_certs(args)
    if args.cmd == "diag":
        for d in diagnostico():
            marca = "OK " if d["ok"] else "FALTA"
            print(f"[{marca}] {d['item']}: {d['detalle']}")
        return 0
    if args.cmd == "pin":
        return cmd_pin(args)
    if args.cmd == "sign":
        return cmd_sign(args)
    if args.cmd == "gui":
        return gui_main(args.pdf, tipo=args.tipo)
    # sin subcomando (doble clic / ejecutar directo) → abrir la GUI
    return gui_main(None)


if __name__ == "__main__":
    main()
