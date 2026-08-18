#!/usr/bin/env python3
"""
sgd-signer — Reemplazo multiplataforma (Linux/macOS) de Tramitedoc.exe + AppFirmaONPE.exe
para el SGD de SENAMHI (https://www.senamhi.gob.pe/sgd).

Protocolo (reingeniería del binario .NET original, v1.0.4 / FirmaONPE 1.2.4):
  1. El portal lanza:  tramitedoc://?accion=TraDoc&urlBase=<base>&rutaPri=<dir>&ws=<wss://...>
  2. Este script se registra como handler del esquema `tramitedoc://` (xdg-open / LaunchServices).
  3. Conecta al WebSocket del servidor y responde mensajes JSON idénticos al original:
       {destination:"BROWSER", error:"0", message:"OK", sender:"CSHARP", accion, nrOperacion}
  4. EJECUTAR_FIRMA: descarga el PDF, lo firma (PAdES, campo FirmaDigital/VistoDigital,
     sufijo [NF]/[F]/[VF]) y responde OK. El portal sube el firmado vía CARGAR_DOCUMENTO.

Uso:
  sgd-signer.py "tramitedoc://?accion=TraDoc&..."   # invocado por el OS (handler de URL)
  sgd-signer.py sign <pdf> [--tipo N] [--cert x.p12] [--pos x,y] [--pagina N]   # CLI directa
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


def make_signer(cfg, pin):
    """Construye el firmante: PKCS#11 (token USB) si cfg['token'], si no .p12.

    Auto-detecta el certificado de usuario del token: el primero cuyo ID
    tenga clave privada (los certs CA no tienen par de claves).

    La sesión PKCS#11 se cachea a nivel de proceso (daemon vive todo el día,
    firma muchas veces): abrir una sesión nueva por cada firma sin cerrar la
    anterior agota los slots de login del token y el 2do+ intento revienta
    con UserAlreadyLoggedIn. Root cause fix, no parche por caller.
    """
    if cfg.get("token"):
        import pkcs11
        from pyhanko.sign.pkcs11 import PKCS11Signer
        lib_path = cfg.get("token_lib", "/usr/lib/bit4id/libbit4xpki.so")
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
                sess = toks[0].open(rw=False, user_pin=pin)
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
        # elegir el cert de usuario: con clave privada del mismo ID
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


ASSETS_DIR = Path(__file__).resolve().parent / "assets"
# imagen de firma real (extraída del MSI original) por tipo; 6→imagenFirma6.jpg, resto→imagenFirma<N>.jpg
IMG_POR_TIPO = {t: ASSETS_DIR / f"imagenFirma{t}.jpg" for t in TIPOS}


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
    cn = signer.signing_cert.subject.native.get("common_name", "Firmante")

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
    if pos:
        x, y = pos
        box = (x, H - y - 35, x + 155, H - y)
    elif tipo == "1":   # FIRMA_NUM: ancho casi completo, arriba
        box = (85, H - 140 - ms, W - 27, H - 12 - ms)
    elif tipo == "2":   # FIRMA_BASICO: abajo derecha
        box = (W - 180, H - 59 - ms, W - 25, H - 24 - ms)
    elif tipo == "3":   # VB_FIRMA: abajo izquierda
        box = (5, 50, 90, 125)
    elif tipo == "6":   # FIRMA_REC: abajo izquierda
        box = (20, H - 95 - ms, 105, H - 12 - ms)
    else:               # 4/5 avanzadas sin pos → abajo derecha
        box = (W - 180, H - 59 - ms, W - 25, H - 24 - ms)

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
    bloque_cn = "\n".join(wrap_cn(f"Firmado digitalmente por {cn}"))
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
            font_size=5,
            leading=6,
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
    del primer ancestro NO-root (TDOCUMENTOS, propiedad de hruiz)."""
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
    """Abre un archivo con la app predeterminada del usuario gráfico (hruiz).

    El daemon corre como root sin DISPLAY, así que xdg-open directo no abre nada
    en la sesión real. Se delega a la sesión gráfica de hruiz (mismo patrón que
    confirmar_en_gui_usuario): runuser + entorno DISPLAY/DBUS detectado en vivo.
    """
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
    if sys.platform == "darwin":
        subprocess.Popen(["open", p])
    else:
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
            pin = get_pin(cfg, ctx)
            if cfg.get("tsl_check", True) and not check_tsl(cfg, pin):
                return reply("1", "Certificado no está en la TSL de INDECOPI")
            extra = {"Area": m.get("deMesaPartes", ""), "Telefono": m.get("fonoInstitucion", ""),
                     "Anexo": m.get("anexo", ""), "Url": m.get("pagWeb", "")}
            extra.update(parse_nombre_doc(m["rutaDoc"]))
            out = sign_pdf(ruta, tipo, None, pin, extra=extra, cfg=cfg)
            log(f"Firmado: {out}")
            return reply(message="OK")
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
    No hardcodea :1 / uid 1000 — la sesión puede reiniciar con otro número."""
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


def confirmar_en_gui_usuario(mensaje, titulo, usuario="hruiz", timeout=120):
    """Muestra un diálogo Sí/No nativo (Tkinter) en la sesión gráfica del usuario y
    devuelve True/False. Usado para replicar el diálogo de confirmación de firma
    masiva del FirmaONPE original, que corría en la GUI de escritorio — el daemon
    vive headless como root, así que delega la pregunta a la sesión real de hruiz
    (mismo patrón que MANUAL_SIGN, pero en dirección inversa: root pregunta, usuario responde)."""
    env_gui = _entorno_grafico_usuario(usuario)
    if not env_gui:
        log(f"AVISO: no se encontró sesión gráfica de {usuario}; se asume 'no confirmado' (falla segura)")
        return False
    marca = f"SGD_SIGNER_CONFIRM_{os.getpid()}_{int(time.time())}"
    script = (
        f"{marca}=True; "  # marca única en el CMDLINE (visible a pkill -f), no en environ
        "import tkinter as tk; from tkinter import messagebox; "
        "root = tk.Tk(); root.withdraw(); "
        f"r = messagebox.askyesno({titulo!r}, {mensaje!r}); "
        "print('SI' if r else 'NO')"
    )
    env = dict(os.environ)
    env.update(env_gui)
    proc = None
    try:
        proc = subprocess.Popen(
            ["runuser", "-u", usuario, "--", "/opt/sgd-signer-venv/bin/python3", "-c", script],
            stdin=subprocess.DEVNULL,  # sin esto runuser puede colgarse esperando EOF de stdin
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            start_new_session=True,  # permite matar todo el grupo (runuser + nieto Tk) si nadie responde
        )
        stdout, _ = proc.communicate(timeout=timeout)
        return stdout.strip() == "SI"
    except subprocess.TimeoutExpired:
        # runuser no siempre propaga la señal al nieto (proceso Tk real bajo hruiz);
        # matar el grupo completo por PGID, y por si acaso también por marca en cmdline.
        try:
            os.killpg(proc.pid, 9)
        except Exception:
            pass
        proc.kill()
        proc.communicate()
        subprocess.run(["pkill", "-9", "-u", usuario, "-f", marca], check=False)
        log(f"AVISO: diálogo de confirmación sin respuesta tras {timeout}s; se asume 'no confirmado'")
        return False
    except Exception as e:
        log(f"AVISO: no se pudo mostrar el diálogo de confirmación ({e}); se asume 'no confirmado'")
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


def forward_to_daemon(url):
    """Si ya hay un daemon corriendo, le pasa la URL y sale."""
    if not LOCK_SOCK.exists():
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(str(LOCK_SOCK))
        s.sendall(url.encode())
        s.close()
        return True
    except Exception:
        return False


def call_daemon_op(op_payload, timeout=60):
    """Cliente genérico del protocolo OP: — la GUI (usuario hruiz) no ve el token/PIN
    real, solo el daemon root; todo pasa por este socket."""
    if not LOCK_SOCK.exists():
        raise RuntimeError(
            f"El daemon sgd-signer no está corriendo ({LOCK_SOCK} no existe). "
            "Verifica: systemctl status sgd-signer"
        )
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(LOCK_SOCK))
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


def dispatch_gui_op(req, ctx):
    """Verbos del protocolo local de la GUI (F8), todos sobre el socket del daemon
    porque solo el daemon root ve el token/PIN real."""
    op = req.get("op")
    cfg = ctx["cfg"]

    if op == "SIGN":
        out = sign_pdf(
            req["pdf_path"], req["tipo"], None, get_pin(cfg, ctx),
            pos=tuple(req["pos"]) if req.get("pos") else None,
            pagina=req.get("pagina", 1), extra=req.get("extra") or {},
            cfg=cfg,
        )
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
        # rutaPri del portal puede venir como ruta Windows (C:\Users\...\TDOCUMENTOS)
        rp = p["rutaPri"] or ""
        if not rp or "\\" in rp or ":" in rp.split("/")[0]:
            # "Mis documentos/TDOCUMENTOS" → ~/Documentos/TDOCUMENTOS (GNOME) o ~/TDOCUMENTOS
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

    if LOCK_SOCK.exists():
        LOCK_SOCK.unlink()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(LOCK_SOCK))
    os.chmod(str(LOCK_SOCK), 0o666)  # hruiz (handler) escribe, daemon root lee
    srv.listen(4)
    log(f"Daemon escuchando en {LOCK_SOCK}")
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


# --- F8: GUI manual (fork FirmaONPE) — visor PDF + firmar archivo local -----
def _pdf_page_size_pt(pdf_path, pagina):
    """Tamaño de página en puntos vía pdfinfo (poppler-utils, ya instalado)."""
    out = subprocess.run(
        ["pdfinfo", "-f", str(pagina), "-l", str(pagina), pdf_path],
        capture_output=True, text=True, check=True,
    ).stdout
    for line in out.splitlines():
        if line.startswith("Page") and "size" in line:
            # "Page    1 size: 595.32 x 841.92 pts"
            parts = line.split(":")[1].split("x")
            return float(parts[0]), float(parts[1].split("pts")[0])
    raise RuntimeError(f"no se pudo leer tamaño de página de {pdf_path}")


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


def gui_main(pdf_path=None):
    """GUI de firma manual (fork FirmaONPE): abrir PDF, elegir tipo de firma,
    click en la página para posición/imagen por tipo (persistente), gestión de
    PIN con indicador de estado. Tkinter + pdftoppm (poppler-utils, ya instalado)
    — sin dependencias nuevas. Estilo: minimalist-ui (warm monochrome, sin
    gradientes/sombras pesadas)."""
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
    from PIL import Image, ImageTk

    DPI = 100

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

            self.canvas = tk.Canvas(root, bg="#DADAD8", highlightthickness=0)
            self.canvas.pack(fill="both", expand=True, padx=12, pady=(0, 6))
            self.canvas.bind("<Button-1>", self.click_pagina)

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
            win.geometry("560x640")
            win.configure(bg=UI["bg"])
            win.transient(self.root)
            win.grab_set()

            body = tk.Frame(win, bg=UI["bg"])
            body.pack(fill="both", expand=True, padx=16, pady=16)

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
                     font=UI["mono"], width=20).pack(side="left")
            self.cfg_recordar = tk.StringVar(value="sesion")
            tk.Radiobutton(fila, text="Solo esta sesión", variable=self.cfg_recordar,
                           value="sesion", bg=UI["surface"], fg=UI["ink"], font=UI["ui"],
                           activebackground=UI["surface"]).pack(side="left", padx=(10, 4))
            tk.Radiobutton(fila, text="Permanente (disco)", variable=self.cfg_recordar,
                           value="disco", bg=UI["surface"], fg=UI["ink"], font=UI["ui"],
                           activebackground=UI["surface"]).pack(side="left", padx=4)
            tk.Button(fila, text="Guardar PIN", command=lambda: self._guardar_pin_desde_cfg(win),
                      bg=UI["ink"], fg="#FFFFFF", relief="flat", font=UI["ui"],
                      padx=8, pady=2, borderwidth=0).pack(side="right")
            tk.Button(f_pin, text="Olvidar PIN guardado", command=self._olvidar_pin,
                      bg=UI["surface"], fg=UI["danger_fg"], relief="flat",
                      highlightbackground=UI["border"], highlightthickness=1,
                      font=UI["ui"], padx=8, pady=2).pack(anchor="w", padx=12, pady=(0, 10))
            self._refrescar_cfg_pin_status()

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
            # posición de la imagen dentro del stamp
            tk.Label(f_img, text="Posición de la imagen dentro de la firma", bg=UI["surface"],
                     fg=UI["muted"], font=UI["ui"]).pack(anchor="w", padx=12, pady=(4, 2))
            fila_pos = tk.Frame(f_img, bg=UI["surface"])
            fila_pos.pack(fill="x", padx=12, pady=(0, 10))
            self.cfg_img_x = tk.StringVar(value="right")
            self.cfg_img_y = tk.StringVar(value="bottom")
            tk.OptionMenu(fila_pos, self.cfg_img_x, "left", "center", "right").config(
                bg=UI["surface"], fg=UI["ink"], relief="flat", font=UI["ui"])
            fila_pos.winfo_children()[-1].pack(side="left")
            tk.OptionMenu(fila_pos, self.cfg_img_y, "top", "middle", "bottom").config(
                bg=UI["surface"], fg=UI["ink"], relief="flat", font=UI["ui"])
            fila_pos.winfo_children()[-1].pack(side="left", padx=(6, 0))
            tk.Button(fila_pos, text="Aplicar", command=self._cfg_aplicar_imagen,
                      bg=UI["ink"], fg="#FFFFFF", relief="flat", font=UI["ui"],
                      padx=8, pady=2, borderwidth=0).pack(side="right")

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
                out = subprocess.run(["pdfinfo", p], capture_output=True, text=True, check=True).stdout
                self.n_paginas = 1
                for line in out.splitlines():
                    if line.startswith("Pages:"):
                        self.n_paginas = int(line.split(":")[1].strip())
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo leer el PDF: {e}")
                return
            self.pdf_path = p
            self.pagina = 1
            self.lbl_archivo.config(text=os.path.basename(p))
            self.btn_firmar.config(state="normal")
            self._cargar_pos_guardada()
            self.render_pagina()

        def render_pagina(self):
            self.page_w_pt, self.page_h_pt = _pdf_page_size_pt(self.pdf_path, self.pagina)
            tmp = tempfile.mktemp(prefix="sgd-signer-preview-")
            subprocess.run(
                ["pdftoppm", "-png", "-r", str(DPI), "-f", str(self.pagina), "-l", str(self.pagina),
                 self.pdf_path, tmp],
                check=True,
            )
            png_path = tmp + f"-{self.pagina}.png" if self.n_paginas > 1 else tmp + "-1.png"
            if not os.path.exists(png_path):
                cand = [f for f in Path(tempfile.gettempdir()).glob(os.path.basename(tmp) + "*.png")]
                if not cand:
                    raise RuntimeError("pdftoppm no generó la vista previa")
                png_path = str(cand[0])
            img = Image.open(png_path)
            self.scale = img.width / self.page_w_pt
            self.tk_img = ImageTk.PhotoImage(img)
            self.canvas.delete("all")
            self.canvas.config(scrollregion=(0, 0, img.width, img.height))
            self.canvas.create_image(0, 0, anchor="nw", image=self.tk_img)
            os.remove(png_path)
            self.lbl_pagina.config(text=f"{self.pagina} / {self.n_paginas}")
            self.pos_pt = None

        def cambiar_pagina(self, delta):
            if not self.pdf_path:
                return
            nueva = self.pagina + delta
            if 1 <= nueva <= self.n_paginas:
                self.pagina = nueva
                self.render_pagina()

        def click_pagina(self, event):
            if not self.pdf_path:
                return
            x_pt = event.x / self.scale
            y_pt = event.y / self.scale  # y desde arriba, como el original (PosicionXY)
            self.pos_pt = (x_pt, y_pt)
            self.lbl_pos.config(text=f"Posición fijada: x={x_pt:.0f} y={y_pt:.0f} pt (desde arriba)")
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
    root.title("sgd-signer — Firma manual (fork FirmaONPE)")
    root.geometry("760x920")
    root.configure(bg=UI["bg"])
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
    args = ap.parse_args()

    if args.cmd == "certs":
        return cmd_certs(args)
    if args.cmd == "pin":
        return cmd_pin(args)
    if args.cmd == "sign":
        return cmd_sign(args)
    if args.cmd == "gui":
        return gui_main(args.pdf)
    ap.print_help()


if __name__ == "__main__":
    main()
