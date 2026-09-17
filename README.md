# SGD-SIGNER — Firma digital para el SGD de SENAMHI

Aplicación de firma digital para el Sistema de Gestión Documental (SGD) de
SENAMHI. Compatible con **Linux (Pop!_OS, RHEL/Ubuntu/Debian), macOS y Windows**.

Firma documentos PDF con certificado digital (token USB PKCS#11 o archivo
`.p12`/`.pfx`) y se integra con el portal de trámite documentario a través del
protocolo `tramitedoc://`.

## Qué hace

1. El portal SGD lanza `tramitedoc://?accion=TraDoc&urlBase=…&rutaPri=…&ws=wss://…`
   al pulsar "Firmar" o "Abrir documento".
2. SGD-SIGNER se registra como handler de ese esquema y conecta al WebSocket del
   servidor, respondiendo los mensajes JSON que el portal espera.
3. **Firmar**: descarga el PDF, abre la **GUI** para que el usuario lo lea y
   confirme, y al pulsar "Firmar" aplica la firma PAdES visible (campo
   `FirmaDigital`/`VistoDigital`, sufijo `[NF]`/`[F]`/`[VF]`).
4. El portal sube el documento firmado automáticamente.

## Características

- **Firma PAdES** visible, 7 tipos (titular, básica, V°B°, avanzada, recepción, encargo).
- **Certificados importados** (.p12/.pfx): importar desde la GUI, listar junto a
  los tokens USB, eliminar, clave por archivo, doble-click para elegir.
- **Token USB PKCS#11**: auto-detección, desbloqueo con **PUK** (C_InitPIN),
  aviso si el PIN está bloqueado.
- **Sello de tiempo TSA** (PAdES B-T): FreeTSA preconfigurada (gratuita, sin
  credenciales), habilitar/deshabilitar desde la GUI, soporta TSA con
  login/password y política (ej. Camerfirma).
- **Verificador de firma integrado**: botón "Verificar firma" — firmante,
  validez, fecha, algoritmo (mismo motor que firma: pyhanko).
- **Aviso de vencimiento**: pill con días restantes del certificado activo
  (ámbar ≤30 días, rojo vencido) + panel de notificaciones (Doctor + vencimientos).
- **Firma masiva**: 1 firma por PDF o por hoja, con confirmación.
- **Doctor**: diagnóstico de instalación (daemon, middleware, esquema, token,
  deps, certificados) con auto-reparación.
- **Rediseño**: tk puro (sin ttkbootstrap), paleta warm monochrome, cards
  Material, hover con transición, layout responsive.

## Plataformas probadas

| Sistema | Estado | Notas |
|---|---|---|
| **Pop!_OS 24.04** (PC SENAMHI) | ✅ Producción | Daemon systemd (root) + token USB Bit4id + GUI COSMIC |
| **Pop!_OS 24.04** (PC de Luis) | ✅ Producción | Daemon systemd + certificado importado (.pfx) |
| **macOS 26.6** (MacBook Intel) | ✅ Producción | LaunchAgent + token USB |
| Oracle Linux 9 / RHEL 9 | ✅ Soportado | Verificado antes de migrar a Pop!_OS |
| Ubuntu 22.04+ / Debian 12+ | ✅ Soportado | install.sh multi-distro (no probado en producción) |
| Windows x64 | ⚠️ Soportado | install.ps1 (no probado en producción) |

## Instalación

Clona el repo y ejecuta el instalador:

```bash
git clone https://github.com/HammGsm/sgd-signer.git && cd sgd-signer
chmod +x install.sh && ./install.sh
```

- **Linux (Pop!_OS/RHEL/Ubuntu/Debian)**: detecta la distro, verifica dependencias
  del sistema (tkinter, python3-venv, xdg-utils) con instrucciones por distro,
  instala las deps del venv (`/opt/sgd-signer-venv`) y crea el wrapper
  `/usr/local/bin/sgd-signer` + daemon systemd `sgd-signer.service` (la
  integración con el portal requiere el daemon; el instalador lo crea y arranca).
  Registra `tramitedoc://` vía `xdg-mime`. El token USB Bit4id requiere su
  middleware (`libbit4xpki.so`) — el Doctor de la GUI lo detecta y da el
  enlace para descargarlo por distro.
- **macOS**: registra el esquema vía LaunchServices (el navegador pide permiso la 1ª vez).
- **Windows**: `powershell -ExecutionPolicy Bypass -File install.ps1` (como Administrador).

## Uso

```bash
# 1. certificado (token USB PKCS#11, o DNIe exportado a .p12)
mkdir -p ~/.sgd-signer/certs && cp TU_CERT.p12 ~/.sgd-signer/certs/

# 2. PIN (opcional; si no, lo pide al firmar)
sgd-signer pin TU_PIN

# 3. GUI manual (leer + firmar un PDF local)
sgd-signer gui documento.pdf

# 4. firma directa desde terminal
sgd-signer sign documento.pdf --tipo 2

# 5. en el portal SGD: al pulsar "Firmar" se abre SGD-SIGNER automáticamente
```

Tipos de firma: `1`=Firma titular, `2`=Firma básica, `3`=V° B°, `4`=Firma
avanzada, `5`=V° B° avanzada, `6`=Firma recepción, `7`=Encargo.

## Configuración (`~/.sgd-signer/config.json`)

```json
{
  "cert": "/ruta/cert.p12",
  "pin": "1234",
  "tsl_check": true,
  "tsa_url": "https://freetsa.org/tsr",
  "tsa_user": "",
  "tsa_pass": "",
  "tsa_policy": ""
}
```

- `tsl_check: true` (default) verifica que el certificado esté en la TSL de
  INDECOPI (`https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`) antes de firmar.
- `tsa_url` activa el sello de tiempo RFC 3161 (PAdES B-T). FreeTSA no requiere
  credenciales; para TSA con auth (ej. Camerfirma) usa `tsa_user`/`tsa_pass` y
  `tsa_policy` (OID de la política). Todo configurable desde la GUI.
- `cert_pins`: claves por archivo importado (se gestionan desde la GUI).
- El PIN se guarda con permisos `600`.
- La GUI permite configurar por tipo de firma: imagen de firma, posición de la
  imagen dentro del sello, y posición del sello en la página.

## Requisitos

- Python 3.9+
- `pyhanko==0.20.0` + `pyhanko-certvalidator` (firma PAdES)
- `python-pkcs11` (token USB) — opcional si usas `.p12`
- `pillow`, `pymupdf` (vista previa de la GUI)
- `python3-tk` — para la GUI (paquete del sistema)

## Verificación

Desde la GUI: abre el PDF firmado y pulsa **"Verificar firma"** (firmante,
validez, fecha, algoritmo). O desde terminal:

```bash
sgd-signer sign doc.pdf --tipo 2
# comprobar con pyhanko:
python3 -c "
from pyhanko.pdf_utils.reader import PdfFileReader
r = PdfFileReader(open('doc[F].pdf','rb'))
s = r.embedded_signatures[0]
s.compute_integrity_info()
print(s.field_name, s.summarise_integrity_info()['coverage'])
"
```

## Notas

- El WebSocket del portal es una **IP interna** de la red SENAMHI: solo funciona
  dentro de la red institucional.
- La verificación TSL/OCSP/CRL es informativa (no bloquea la firma si el
  certificado no está en el trust store del sistema).
- "Certificado raíz de TSA en TSL: No" en el verificador del portal es normal
  con FreeTSA (TSA alemana no acreditada por INDECOPI) — el sello es válido
  (PAdES B-T); para "Sí" se necesita una TSA acreditada en Perú.
- El token USB Bit4id requiere su middleware (`libbit4xpki.so` en Linux,
  `bit4xpki.dll` en Windows) — el Doctor lo detecta y da instrucciones.
