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
}


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


def log(msg):
    print(f"[sgd-signer] {msg}", flush=True)


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


def get_pin(cfg, ctx=None):
    """Resuelve el PIN: sesión en memoria (ctx, solo mientras el daemon vive) >
    guardado en disco (cfg) > variable de entorno > interactivo (solo si hay
    tty real — el daemon systemd no tiene, preguntar ahí colgaría el proceso)."""
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
                        log(f"PKCS#11 {Path(lib_path).name}/{base['token']}: {type(e).__name__}")
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


def make_signer(cfg, pin):
    """Construye el firmante: PKCS#11 (token USB) si cfg['token'], si no .p12.

    Usa el certificado elegido en cfg['cert_key_id'] + cfg['token_lib'] si existe;
    si no, auto-detecta el primero con clave privada (los certs CA no la tienen).

    La sesión PKCS#11 se cachea a nivel de proceso (daemon vive todo el día,
    firma muchas veces): abrir una sesión nueva por cada firma sin cerrar la
    anterior agota los slots de login del token y el 2do+ intento revienta
    con UserAlreadyLoggedIn. Root cause fix, no parche por caller.
    """
    if cfg.get("token"):
        import pkcs11
        from pyhanko.sign.pkcs11 import PKCS11Signer
        lib_path = cfg.get("token_lib", "/usr/lib/bit4id/libbit4xpki.so")
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
    cert_path = cfg.get("cert")
    if not cert_path:
        cert_path = pick_cert(cfg)
    from pyhanko.sign import signers
    if cert_path.lower().endswith((".p12", ".pfx")):
        return signers.SimpleSigner.load_pkcs12(cert_path, passphrase=pin.encode())
    return signers.SimpleSigner.load(cert_path, passphrase=pin.encode())


# en binario PyInstaller los assets viven en sys._MEIPASS, no junto al .py
ASSETS_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "assets"
# imagen de firma real (extraída del MSI original) por tipo; 6→imagenFirma6.jpg, resto→imagenFirma<N>.jpg
IMG_POR_TIPO = {t: ASSETS_DIR / f"imagenFirma{t}.jpg" for t in TIPOS}


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
    if tipo == "1":   # FIRMA_NUM: ancho casi completo, arriba
        return (85, H - 140 - ms, W - 27, H - 12 - ms)
    if tipo == "3":   # VB_FIRMA: abajo izquierda
        return (5, 50, 90, 125)
    if tipo == "6":   # FIRMA_REC: abajo izquierda
        return (20, H - 95 - ms, 105, H - 12 - ms)
    # 2 (básica) y 4/5 (avanzadas sin pos): abajo derecha
    return (W - 180, H - 59 - ms, W - 25, H - 24 - ms)


def sign_pdf(pdf_path, tipo, cert_path, pin, pos=None, pagina=1, extra=None, cfg=None):
    from pyhanko.sign import signers, fields
    from pyhanko.stamp import TextStampStyle
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.text import TextBoxStyle
    from pyhanko.pdf_utils.layout import SimpleBoxLayoutRule, AxisAlignment, Margins
    from pyhanko.pdf_utils.images import PdfImage
    from pyhanko.pdf_utils.reader import PdfFileReader
    from PIL import Image as PILImage

    campo, sufijo, motivo = TIPOS[tipo]
    extra = extra or {}
    cfg = cfg or {}

    signer = make_signer(cfg, pin)
    subj = signer.signing_cert.subject.native
    cn = subj.get("common_name", "Firmante")
    # nombre limpio para el stamp: apellido + nombre (sin el "FAU ... hard" del CN)
    nombre = f"{subj.get('surname') or ''} {subj.get('given_name') or ''}".strip() or cn
    org = subj.get("organization_name") or ""
    if "METEOROLOGIA" in org.upper():
        org = "SENAMHI"

    # tamaño de página (puntos) para posiciones relativas
    r = PdfFileReader(open(pdf_path, "rb"))

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

    # texto visible: replica el layout real del PDF de ejemplo ONPE (sección 10 del CONTRATO.md)
    # bloque derecho 5pt: nombre partido en líneas de ~25 chars (como el CN del ejemplo)
    def wrap_cn(name, width=25):
        words, lines, cur = name.split(), [], ""
        for w in words:
            if len(cur) + len(w) + 1 <= width:
                cur = f"{cur} {w}".strip()
            else:
                lines.append(cur)
                cur = w
        if cur:
            lines.append(cur)
        return lines

    fecha_hora = time.strftime("%d.%m.%Y %H:%M:%S -05:00")
    bloque_cn = "\n".join(wrap_cn(f"Firmado digitalmente por {nombre}"))
    if org:
        bloque_cn += f"\n{org}"
    stamp_text = bloque_cn + f"\nMotivo: {motivo}\nFecha: {fecha_hora}"
    # tipo 1 (FIRMA_NUM): el widget original lleva número+lugar/fecha arriba, aparte del
    # bloque firmante — ponytail: una sola caja de texto (no dos columnas independientes
    # como el original iText); alcanza para el requisito visible, layout 2-col si se pide.
    if extra.get("NumeroDoc"):
        stamp_text = f"%(numero_doc)s\n%(lugar_fecha)s\n\n" + stamp_text
    elif extra.get("Lugar"):
        stamp_text = f"%(lugar_fecha)s\n" + stamp_text

    img_path = Path(apariencia_tipo["imagen"]) if apariencia_tipo.get("imagen") else IMG_POR_TIPO.get(tipo)
    background = None
    if img_path and img_path.exists():
        # la imagen se estampa TAL CUAL, sin alterar color ni calidad: debe salir
        # idéntica a la vista previa (que la abre directo con PIL).
        background = PdfImage(PILImage.open(img_path))

    # posición de la imagen DENTRO del stamp (configurable por tipo): el usuario
    # elige dónde va la imagen respecto al texto. Default = derecha/abajo (como el
    # original ONPE). Mapeo a AxisAlignment (PDF: y crece hacia arriba).
    img_x = apariencia_tipo.get("img_x", "right")
    img_y = apariencia_tipo.get("img_y", "bottom")
    x_align = {"left": AxisAlignment.ALIGN_MIN, "center": AxisAlignment.ALIGN_MID,
               "right": AxisAlignment.ALIGN_MAX}.get(img_x, AxisAlignment.ALIGN_MAX)
    y_align = {"bottom": AxisAlignment.ALIGN_MIN, "middle": AxisAlignment.ALIGN_MID,
               "top": AxisAlignment.ALIGN_MAX}.get(img_y, AxisAlignment.ALIGN_MIN)

    style = TextStampStyle(
        stamp_text=stamp_text,
        background=background,
        background_layout=SimpleBoxLayoutRule(
            x_align=x_align, y_align=y_align,
            margins=Margins(left=0, right=0, top=0, bottom=0),
        ),
        text_box_style=TextBoxStyle(
            font_size=7,
            leading=8,
            border_width=0,
            box_layout_rule=SimpleBoxLayoutRule(
                x_align=AxisAlignment.ALIGN_MAX, y_align=AxisAlignment.ALIGN_MIN,
                margins=Margins(left=0, right=4, top=0, bottom=4),
            ),
        ),
        border_width=0,
    )

    lugar_fecha = extra.get("Lugar") or ""
    if extra.get("FechaLarga"):
        lugar_fecha = f"{lugar_fecha}, {extra['FechaLarga']}" if lugar_fecha else extra["FechaLarga"]

    text_params = {}
    if extra.get("NumeroDoc"):
        text_params["numero_doc"] = extra["NumeroDoc"]
        text_params["lugar_fecha"] = lugar_fecha
    elif lugar_fecha:
        text_params["lugar_fecha"] = lugar_fecha

    # OCSP/CRL online (F9): chequeo informativo tipo check_tsl — NO se cablea a
    # PdfSignatureMetadata.validation_context porque eso fuerza validación de cadena
    # completa ANTES de firmar y puede abortar la firma real si la CA raíz de
    # RENIEC/Bit4id no está en el trust store del sistema (probado: rompe con cert
    # self-signed → InvalidCertificateError). Mismo soft-fail que TSL: solo loguea.
    if (cfg or {}).get("ocsp_crl_check", True):
        check_ocsp_crl(signer)

    meta = signers.PdfSignatureMetadata(
        field_name=campo,
        reason=motivo,
        location=extra.get("Lugar") or "",
        name=cn,
        md_algorithm="sha256",
        use_pades_lta=False,
    )

    pdf_signer = signers.PdfSigner(
        meta,
        signer,
        stamp_style=style,
    )

    # campo de firma visible
    w = IncrementalPdfFileWriter(open(pdf_path, "rb"))
    fields.append_signature_field(
        w, fields.SigFieldSpec(campo, on_page=pagina - 1, box=box)
    )

    out_path = pdf_path[:-4] + sufijo + ".pdf"
    with open(out_path, "wb") as outf:
        pdf_signer.sign_pdf(w, output=outf, appearance_text_params=text_params or None)
    return out_path


def check_tsl(cfg, pin):
    """Verifica que el certificado esté en la TSL de INDECOPI (como el original)."""
    signer = make_signer(cfg, pin)
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
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
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


def set_pin_via_daemon(pin, recordar):
    """recordar: 'sesion' (memoria, hasta que el daemon reinicie), 'disco' (persistente),
    o None (solo usarlo para esta firma, no recordarlo). Verifica el PIN contra el token
    real antes de devolver éxito -- si es incorrecto, la excepción llega a la GUI."""
    call_daemon_op({"op": "SET_PIN", "pin": pin, "recordar": recordar}, timeout=30)


def get_apariencia_via_daemon():
    return call_daemon_op({"op": "GET_APARIENCIA"})["apariencia"]


def set_apariencia_via_daemon(tipo, imagen=None, pos=None, img_x=None, img_y=None):
    payload = {"op": "SET_APARIENCIA", "tipo": tipo}
    if imagen is not None:
        payload["imagen"] = imagen
    if pos is not None:
        payload["pos"] = list(pos)
    if img_x is not None:
        payload["img_x"] = img_x
    if img_y is not None:
        payload["img_y"] = img_y
    call_daemon_op(payload)


def sign_masivo_via_daemon(pdfs, tipo, pos=None, timeout=300):
    """Firma N PDFs locales con el mismo tipo/posición. Devuelve (firmados, errores)."""
    resp = call_daemon_op({"op": "SIGN_MASIVO", "pdfs": pdfs, "tipo": tipo, "pos": pos},
                          timeout=timeout)
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
        out = sign_pdf(
            req["pdf_path"], tipo, None, get_pin(cfg, ctx),
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
        if ctx.get("session_pin"):
            estado = "sesion"
        elif cfg.get("pin"):
            estado = "disco"
        else:
            estado = "ninguno"
        return {"ok": True, "pin_status": estado}

    if op == "SET_PIN":
        pin = req["pin"]
        if req.get("recordar") == "disco":
            cfg["pin"] = pin
            save_config(cfg)
        elif req.get("recordar") == "sesion":
            ctx["session_pin"] = pin
        # verificación real: si el PIN es incorrecto, make_signer/PKCS11 lo revienta aquí
        # y se lo devolvemos al usuario antes de que crea que quedó guardado.
        make_signer(cfg, pin)
        return {"ok": True}

    if op == "CLEAR_PIN":
        # olvida el PIN de disco y de sesión (sin validar contra el token)
        cfg["pin"] = ""
        save_config(cfg)
        ctx["session_pin"] = None
        return {"ok": True}

    if op == "GET_APARIENCIA":
        return {"ok": True, "apariencia": cfg.get("apariencia", {})}

    if op == "GET_CONFIG":
        return {"ok": True, "config": {k: v for k, v in cfg.items()
                                       if k not in ("pin", "apariencia")}}

    if op == "LISTAR_CERTS":
        # sólo el daemon ve el token; la GUI (usuario) pide por socket.
        # Sin PIN listamos los tokens como "requiere PIN" (listar_certificados
        # acepta pin=None); NO llamamos get_pin aquí porque lanzaría una
        # excepción y la Configuración no podría detectar los tokens.
        pin = req.get("pin")
        try:
            certs = listar_certificados(pin)
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        elegido = cfg.get("cert_key_id")
        salida = []
        for c in certs:
            ok, msgs = validar_certificado(c)
            salida.append({
                "cn": c.get("cn", ""), "org": c.get("org", ""),
                "emisor": c.get("emisor", ""), "token": c.get("token", ""),
                "lib": c.get("lib", ""), "serial_token": c.get("serial_token", ""),
                "key_id": c["key_id"].hex() if c.get("key_id") else None,
                "listo": c.get("listo", False), "ok": ok, "avisos": msgs,
                "activo": bool(c.get("key_id") and c["key_id"].hex() == elegido),
            })
        return {"ok": True, "certs": salida}

    if op == "ELEGIR_CERT":
        cfg["cert_key_id"] = req["key_id"]
        cfg["token_lib"] = req["lib"]
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

    if op == "SET_APARIENCIA":
        tipo = req["tipo"]
        apariencia = cfg.setdefault("apariencia", {})
        entry = apariencia.setdefault(tipo, {})
        if "imagen" in req:
            entry["imagen"] = req["imagen"]
        if "pos" in req:
            entry["pos"] = req["pos"]
        if "img_x" in req:
            entry["img_x"] = req["img_x"]
        if "img_y" in req:
            entry["img_y"] = req["img_y"]
        save_config(cfg)
        return {"ok": True}

    if op == "SIGN_MASIVO":
        # firma N PDFs locales (seleccionados en la GUI) con el mismo tipo/posición.
        # El diálogo de confirmación ya lo mostró la GUI antes de llamar aquí.
        pdfs = req["pdfs"]
        tipo = req.get("tipo", "2")
        pos = tuple(req["pos"]) if req.get("pos") else None
        pin = get_pin(cfg, ctx)
        firmados = []
        errores = []
        for p in pdfs:
            try:
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
    ctx = {"urlBase": "", "rutaPri": "", "cfg": load_config(), "ws_url": None}
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

    if not IS_WIN and LOCK_SOCK.exists():
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
            except Exception as e:
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
    if not args.no_tsl and cfg.get("tsl_check", True) and not check_tsl(cfg, pin):
        raise SystemExit("Certificado no está en la TSL de INDECOPI (usa --no-tsl para saltar)")
    pos = tuple(map(int, args.pos.split(","))) if args.pos else None
    out = sign_pdf(args.pdf, args.tipo, None, pin, pos=pos, pagina=args.pagina, cfg=cfg)
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
    "bg": "#FBFBFA", "surface": "#FFFFFF", "border": "#EAEAEA",
    "ink": "#111111", "muted": "#787774",
    "accent_bg": "#EDF3EC", "accent_fg": "#346538",   # pale green: éxito / guardado
    "warn_bg": "#FBF3DB", "warn_fg": "#956400",       # pale yellow: aviso / sin PIN
    "danger_bg": "#FDEBEC", "danger_fg": "#9F2F2D",   # pale red: error
    "mono": ("SF Mono", 9), "mono_b": ("SF Mono", 9, "bold"),
    "ui": ("Helvetica Neue", 10), "ui_b": ("Helvetica Neue", 10, "bold"),
}
NOMBRES_TIPO = {"1": "1 · Titular", "2": "2 · Básica", "3": "3 · V°B°",
                "4": "4 · Avanzada", "5": "5 · V°B° avanzada", "6": "6 · Recepción"}


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
            style = ttk.Style()
            try:
                style.theme_use("clam")
            except Exception:
                pass
            style.configure("TFrame", background=UI["bg"])

            # --- barra PIN (arriba de todo: siempre visible el estado) ------
            pin_bar = tk.Frame(root, bg=UI["surface"], highlightbackground=UI["border"],
                                highlightthickness=1)
            pin_bar.pack(fill="x", padx=12, pady=(12, 6))
            tk.Label(pin_bar, text="Certificado", bg=UI["surface"], fg=UI["ink"],
                     font=UI["ui_b"]).pack(side="left", padx=(10, 8), pady=8)
            self.pin_pill = pill(pin_bar, "…", UI["warn_bg"], UI["warn_fg"])
            self.pin_pill.pack(side="left", pady=8)
            tk.Button(pin_bar, text="Ingresar / cambiar PIN", command=self.pedir_pin,
                      bg=UI["ink"], fg="#FFFFFF", activebackground="#333333",
                      relief="flat", font=UI["ui"], padx=10, pady=4,
                      borderwidth=0).pack(side="right", padx=10, pady=6)
            tk.Button(pin_bar, text="Configuración", command=self.abrir_configuracion,
                      bg=UI["surface"], fg=UI["ink"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1,
                      font=UI["ui"], padx=10, pady=4).pack(side="right", padx=6, pady=6)
            self._refrescar_estado_pin()

            # --- barra archivo/tipo ------------------------------------------
            top = tk.Frame(root, bg=UI["bg"])
            top.pack(fill="x", padx=12, pady=(0, 6))
            tk.Button(top, text="Abrir PDF", command=self.abrir, bg=UI["ink"],
                      fg="#FFFFFF", activebackground="#333333", relief="flat",
                      font=UI["ui"], padx=10, pady=4, borderwidth=0).pack(side="left")
            self.lbl_archivo = tk.Label(top, text="(sin archivo)", bg=UI["bg"],
                                        fg=UI["muted"], font=UI["ui"])
            self.lbl_archivo.pack(side="left", padx=10)

            tk.Label(top, text="Tipo de firma", bg=UI["bg"], fg=UI["muted"],
                     font=UI["ui"]).pack(side="left", padx=(20, 6))
            self.tipo = tk.StringVar(value="2")
            om = tk.OptionMenu(top, self.tipo, *[NOMBRES_TIPO[t] for t in sorted(TIPOS)],
                                command=self._set_tipo)
            om.config(bg=UI["surface"], fg=UI["ink"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1, font=UI["ui"])
            om.pack(side="left")

            tk.Button(top, text="Imagen de este tipo…", command=self.elegir_imagen,
                      bg=UI["surface"], fg=UI["ink"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1,
                      font=UI["ui"], padx=8, pady=4).pack(side="left", padx=(20, 0))

            # --- barra navegación/posición -----------------------------------
            nav = tk.Frame(root, bg=UI["bg"])
            nav.pack(fill="x", padx=12, pady=(0, 6))
            tk.Button(nav, text="‹ Pág", command=lambda: self.cambiar_pagina(-1),
                      bg=UI["surface"], fg=UI["ink"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1,
                      font=UI["ui"], padx=8).pack(side="left")
            self.lbl_pagina = tk.Label(nav, text="- / -", bg=UI["bg"], fg=UI["ink"], font=UI["mono"])
            self.lbl_pagina.pack(side="left", padx=8)
            tk.Button(nav, text="Pág ›", command=lambda: self.cambiar_pagina(1),
                      bg=UI["surface"], fg=UI["ink"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1,
                      font=UI["ui"], padx=8).pack(side="left")
            self.lbl_pos = tk.Label(nav, text="Click en la página para fijar posición (se recuerda por tipo)",
                                     bg=UI["bg"], fg=UI["muted"], font=UI["ui"])
            self.lbl_pos.pack(side="left", padx=16)

            # --- controles de zoom (a la derecha de la barra de navegación) ---
            def btn_zoom(txt, cmd, w=3):
                return tk.Button(nav, text=txt, command=cmd, bg=UI["surface"], fg=UI["ink"],
                                 relief="flat", highlightbackground=UI["border"],
                                 highlightthickness=1, font=UI["ui"], width=w)
            btn_zoom("Ancho", self.zoom_ancho, 6).pack(side="right", padx=(4, 0))
            btn_zoom("Ajustar", self.zoom_ajustar, 7).pack(side="right", padx=4)
            btn_zoom("+", lambda: self.zoom_paso(1.25)).pack(side="right")
            self.lbl_zoom = tk.Label(nav, text="100%", bg=UI["bg"], fg=UI["ink"],
                                      font=UI["mono"], width=5)
            self.lbl_zoom.pack(side="right", padx=2)
            btn_zoom("−", lambda: self.zoom_paso(0.8)).pack(side="right")

            # --- visor: canvas con scrollbars (el PDF puede exceder la ventana) --
            visor = tk.Frame(root, bg=UI["border"], highlightbackground=UI["border"],
                             highlightthickness=1)
            visor.pack(fill="both", expand=True, padx=12, pady=(0, 6))
            self.canvas = tk.Canvas(visor, bg="#DADAD8", highlightthickness=0,
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

            # --- barra inferior: firmar + estado ------------------------------
            bottom = tk.Frame(root, bg=UI["bg"])
            bottom.pack(fill="x", padx=12, pady=(0, 12))
            self.btn_firmar = tk.Button(bottom, text="Firmar", command=self.firmar,
                                         state="disabled", bg=UI["ink"], fg="#FFFFFF",
                                         activebackground="#333333", relief="flat",
                                         font=UI["ui_b"], padx=14, pady=6, borderwidth=0)
            self.btn_firmar.pack(side="left")
            tk.Button(bottom, text="Firma masiva…", command=self.firma_masiva,
                      bg=UI["surface"], fg=UI["ink"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1,
                      font=UI["ui"], padx=10, pady=6).pack(side="left", padx=(8, 0))
            self.lbl_status = tk.Label(bottom, text="", bg=UI["bg"], fg=UI["muted"], font=UI["mono"])
            self.lbl_status.pack(side="left", padx=10)

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
                "disco": ("PIN guardado en memoria (permanente)", UI["accent_bg"], UI["accent_fg"]),
                "sesion": ("PIN guardado en memoria (esta sesión)", UI["accent_bg"], UI["accent_fg"]),
                "ninguno": ("Sin PIN guardado", UI["warn_bg"], UI["warn_fg"]),
            }
            texto, bg, fg = textos.get(estado, ("desconocido", UI["warn_bg"], UI["warn_fg"]))
            self.pin_pill.config(text=texto, bg=bg, fg=fg)

        def pedir_pin(self):
            pin = simpledialog.askstring("PIN del certificado", "Ingresa el PIN:", show="*")
            if not pin:
                return
            recordar = messagebox.askyesno(
                "Recordar PIN",
                "¿Guardar el PIN de forma permanente (sobrevive reinicios del daemon)?\n\n"
                "Sí = guardar en disco.\nNo = recordar solo mientras el servicio siga corriendo."
            )
            try:
                set_pin_via_daemon(pin, "disco" if recordar else "sesion")
                self._refrescar_estado_pin()
                messagebox.showinfo("OK", "PIN verificado contra el token y guardado.")
            except Exception as e:
                messagebox.showerror("PIN rechazado", str(e))

        # --- ventana de configuración ----------------------------------------
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
            tk.Button(fila3, text="Guardar PIN", command=lambda: self._guardar_pin_desde_cfg(win),
                      bg=UI["ink"], fg="#FFFFFF", relief="flat", font=UI["ui"],
                      padx=10, pady=4, borderwidth=0).pack(side="left")
            tk.Button(fila3, text="Olvidar PIN guardado", command=self._olvidar_pin,
                      bg=UI["surface"], fg=UI["danger_fg"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1,
                      font=UI["ui"], padx=10, pady=4).pack(side="left", padx=(8, 0))
            self._refrescar_cfg_pin_status()

            # --- certificado de firma ------------------------------------------
            f_cert = seccion("Certificado de firma")
            tk.Label(f_cert, text="Certificados detectados en tokens USB y smartcards conectados.",
                     bg=UI["surface"], fg=UI["muted"], font=UI["ui"]).pack(anchor="w", padx=12, pady=(0, 6))
            cont_cert = tk.Frame(f_cert, bg=UI["surface"])
            cont_cert.pack(fill="x", padx=12, pady=(0, 6))
            self.cfg_cert_lista = tk.Listbox(cont_cert, height=3, relief="flat", font=UI["mono"],
                                             highlightbackground=UI["border"], highlightthickness=1,
                                             activestyle="none", selectbackground=UI["ink"],
                                             selectforeground="#FFFFFF")
            self.cfg_cert_lista.pack(fill="x")
            self.cfg_cert_detalle = tk.Label(f_cert, text="", bg=UI["surface"], fg=UI["muted"],
                                             font=UI["ui"], justify="left", anchor="w")
            self.cfg_cert_detalle.pack(fill="x", padx=12, pady=(0, 6))
            fila_cert = tk.Frame(f_cert, bg=UI["surface"])
            fila_cert.pack(fill="x", padx=12, pady=(0, 10))
            tk.Button(fila_cert, text="Detectar certificados", command=self._cfg_detectar_certs,
                      bg=UI["surface"], fg=UI["ink"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1,
                      font=UI["ui"], padx=8, pady=2).pack(side="left")
            tk.Button(fila_cert, text="Usar este certificado", command=self._cfg_usar_cert,
                      bg=UI["ink"], fg="#FFFFFF", relief="flat", font=UI["ui"],
                      padx=8, pady=2, borderwidth=0).pack(side="right")
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
            tk.Button(fila_img, text="Elegir imagen…", command=self._cfg_elegir_imagen,
                      bg=UI["surface"], fg=UI["ink"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1,
                      font=UI["ui"], padx=8, pady=2).pack(side="right")
            # vista previa: sobre tablero gris con borde, la imagen de firma es
            # casi blanca y sobre fondo blanco no se distinguía nada.
            marco_prev = tk.Frame(f_img, bg=UI["border"], highlightbackground=UI["border"],
                                  highlightthickness=1)
            marco_prev.pack(anchor="w", padx=12, pady=(0, 8))
            self.cfg_img_preview = tk.Label(marco_prev, text="(sin imagen)", bg="#E8E8E6",
                                            fg=UI["muted"], font=UI["mono"],
                                            width=26, height=6)
            self.cfg_img_preview.pack(padx=1, pady=1)
            # posición de la imagen dentro del stamp
            tk.Label(f_img, text="Posición de la imagen dentro de la firma", bg=UI["surface"],
                     fg=UI["muted"], font=UI["ui"]).pack(anchor="w", padx=12, pady=(4, 2))
            fila_pos = tk.Frame(f_img, bg=UI["surface"])
            fila_pos.pack(fill="x", padx=12, pady=(0, 10))
            self.cfg_img_x = tk.StringVar(value="right")
            self.cfg_img_y = tk.StringVar(value="bottom")
            tk.OptionMenu(fila_pos, self.cfg_img_x, "left", "center", "right",
                          command=lambda _v: self._cfg_render_firma()).config(
                bg=UI["surface"], fg=UI["ink"], relief="flat", font=UI["ui"])
            fila_pos.winfo_children()[-1].pack(side="left")
            tk.OptionMenu(fila_pos, self.cfg_img_y, "top", "middle", "bottom",
                          command=lambda _v: self._cfg_render_firma()).config(
                bg=UI["surface"], fg=UI["ink"], relief="flat", font=UI["ui"])
            fila_pos.winfo_children()[-1].pack(side="left", padx=(6, 0))
            tk.Button(fila_pos, text="Aplicar", command=self._cfg_aplicar_imagen,
                      bg=UI["ink"], fg="#FFFFFF", relief="flat", font=UI["ui"],
                      padx=8, pady=2, borderwidth=0).pack(side="right")

            # vista previa de la firma completa (imagen + texto) como saldrá
            tk.Label(f_img, text="Así se verá la firma:", bg=UI["surface"],
                     fg=UI["muted"], font=UI["ui"]).pack(anchor="w", padx=12, pady=(4, 2))
            marco_firma = tk.Frame(f_img, bg=UI["border"])
            marco_firma.pack(anchor="w", padx=12, pady=(0, 10))
            self.cfg_firma_canvas = tk.Canvas(marco_firma, width=FIRMA_W * 2,
                                              height=FIRMA_H * 2,
                                              bg="#FFFFFF", highlightthickness=0)
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

            tk.Button(body, text="Cerrar", command=win.destroy, bg=UI["ink"], fg="#FFFFFF",
                      relief="flat", font=UI["ui"], padx=12, pady=4, borderwidth=0).pack(pady=(4, 0))

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
                    text="No se detectaron certificados. Conecta el token/smartcard y guarda el PIN.")
                return
            sel = 0
            for i, c in enumerate(certs):
                marca = "✓ " if c.get("activo") else "  "
                estado = "" if c.get("ok") else "  [REVISAR]"
                self.cfg_cert_lista.insert("end", f"{marca}{c['cn']} — {c['token']}{estado}")
                if c.get("activo"):
                    sel = i
            self.cfg_cert_lista.selection_set(sel)
            self._cfg_mostrar_detalle_cert(sel)
            self.cfg_cert_lista.bind(
                "<<ListboxSelect>>",
                lambda _e: self._cfg_mostrar_detalle_cert(
                    self.cfg_cert_lista.curselection()[0]
                    if self.cfg_cert_lista.curselection() else 0))

        def _cfg_mostrar_detalle_cert(self, idx):
            if not (0 <= idx < len(self._cfg_certs_data)):
                return
            c = self._cfg_certs_data[idx]
            lineas = []
            if c.get("org"):
                lineas.append(c["org"])
            lineas += c.get("avisos", [])
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

        def _cfg_render_firma(self):
            """Dibuja la firma como saldrá: imagen en su posición + texto.
            Usa las mismas proporciones que el stamp real (FIRMA_W x FIRMA_H)."""
            cv = getattr(self, "cfg_firma_canvas", None)
            if cv is None:
                return
            cv.delete("all")
            W, H = FIRMA_W * 2, FIRMA_H * 2  # 2x la caja real, misma proporción
            img = self.cfg_img_actual_path()
            img_w = img_h = 0
            if img and img.exists():
                try:
                    pil = Image.open(img)
                    pil.thumbnail((W // 2, H - 8))
                    self._cfg_firma_img_tk = ImageTk.PhotoImage(pil)
                    img_w, img_h = pil.size
                except Exception:
                    img_w = img_h = 0
            # posición de la imagen según los selectores (misma semántica que pyhanko)
            ax = {"left": 4, "center": (W - img_w) // 2, "right": W - img_w - 4}
            ay = {"top": 4, "middle": (H - img_h) // 2, "bottom": H - img_h - 4}
            ix = ax.get(self.cfg_img_x.get(), W - img_w - 4)
            iy = ay.get(self.cfg_img_y.get(), H - img_h - 4)
            if img_w:
                cv.create_image(ix, iy, image=self._cfg_firma_img_tk, anchor="nw")
            # texto del stamp: al lado opuesto a la imagen para que no se tape
            tx = 6 if self.cfg_img_x.get() == "right" else (img_w + 10 if img_w else 6)
            texto = ("Firmado digitalmente por\nNOMBRE APELLIDO\nSENAMHI\n"
                     "Motivo: Soy el autor del documento.\nFecha: 01.01.2026 09:00:00 -05:00")
            cv.create_text(tx, 5, text=texto, anchor="nw", font=("TkDefaultFont", 6),
                           fill="#111111", width=W - tx - 6)
            cv.create_rectangle(1, 1, W - 1, H - 1, outline="#B8B8B4", dash=(2, 2))

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
            self.cfg_img_x.set(entry.get("img_x", "right"))
            self.cfg_img_y.set(entry.get("img_y", "bottom"))
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
                                          img_x=self.cfg_img_x.get(),
                                          img_y=self.cfg_img_y.get())
                self._cfg_cargar_apariencia()
                messagebox.showinfo("OK", "Posición de la imagen aplicada.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def _cfg_guardar_tsl(self):
            try:
                set_config_via_daemon({"tsl_check": bool(self.cfg_tsl.get())})
            except Exception as e:
                messagebox.showerror("Error", str(e))

        # --- firma masiva -----------------------------------------------------
        def firma_masiva(self):
            pdfs = filedialog.askopenfilenames(title="Selecciona los PDF a firmar",
                                               filetypes=[("PDF", "*.pdf")])
            if not pdfs:
                return
            pdfs = list(pdfs)
            tipo = self.tipo.get()
            pos = self.pos_pt
            if not messagebox.askyesno(
                "Confirmación de la Firma Digital Masiva",
                f"Se firmarán {len(pdfs)} documentos con el tipo {NOMBRES_TIPO[tipo]}.\n\n"
                "Cada firma digital tiene validez y eficacia jurídica. "
                "Al aceptar declaras haber leído cada archivo. ¿Proceder?"
            ):
                return
            self.lbl_status.config(text=f"Firmando {len(pdfs)} documentos…", fg=UI["muted"])
            self.root.update_idletasks()
            try:
                firmados, errores = sign_masivo_via_daemon(pdfs, tipo, pos=pos)
                resumen = f"{len(firmados)} firmados, {len(errores)} con error"
                self.lbl_status.config(text=resumen, fg=UI["accent_fg"] if not errores else UI["warn_fg"])
                detalle = "\n".join([f"✓ {f}" for f in firmados] +
                                    [f"✗ {e['pdf']}: {e['error']}" for e in errores])
                messagebox.showinfo("Firma masiva", f"{resumen}\n\n{detalle}")
            except Exception as e:
                self.lbl_status.config(text="Error en firma masiva", fg=UI["danger_fg"])
                messagebox.showerror("Error", str(e))

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
                outline="#346538", width=2, dash=(4, 3), tags="preview_firma",
            )
            self.canvas.create_text(
                (cx0 + cx1) / 2, (cy_top + cy_bot) / 2,
                text="FIRMA", fill="#346538", font=UI["mono_b"], tags="preview_firma",
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
                if "No hay PIN" in str(e) or "PIN" in str(e):
                    if messagebox.askyesno("PIN requerido", f"{e}\n\n¿Ingresar el PIN ahora?"):
                        self.pedir_pin()
                else:
                    messagebox.showerror("Error al firmar", str(e))
            finally:
                self.btn_firmar.config(state="normal")

    root = tk.Tk()
    root.title("SGD-SIGNER — Firma digital")
    root.geometry("760x920")
    root.configure(bg=UI["bg"])
    # icono de la ventana (assets/icon.png); si no existe, se omite sin romper
    try:
        icon = ImageTk.PhotoImage(Image.open(ASSETS_DIR / "icon.png"))
        root.iconphoto(True, icon)
        root._icon_ref = icon  # mantener referencia viva
    except Exception:
        pass
    App(root)
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
