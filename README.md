# SGD-SIGNER — Firma digital para el SGD de SENAMHI

Aplicación de firma digital para el Sistema de Gestión Documental (SGD) de
SENAMHI. Compatible con **Linux, macOS y Windows**.

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

## Flujo de firma

- **Abrir el programa → leer el documento → firmar.**
- Si el PIN está guardado y el sistema lo reconoce, **no pide clave**.
- Si no hay PIN guardado, lo pide al momento de firmar.

## Instalación

### Opción A — binario listo (recomendado)

Descargar de [Releases](https://github.com/HammGsm/sgd-signer/releases) el archivo del sistema:

| Sistema | Archivo |
|---|---|
| Linux (RHEL/Oracle/Ubuntu x64) | `sgd-signer-linux-x64.tar.gz` |
| Windows x64 | `sgd-signer-windows-x64.zip` |
| macOS Intel | `sgd-signer-macos-x64.tar.gz` |
| macOS Apple Silicon (M1/M2/M3) | `sgd-signer-macos-arm64.tar.gz` |

```bash
tar xzf sgd-signer-linux-x64.tar.gz
./sgd-signer gui
```

No requiere Python ni dependencias: todo va dentro del binario. En Linux el
binario se compila sobre glibc 2.34 (RHEL/Oracle Linux 9). En macOS, la primera
vez: clic derecho → Abrir (Gatekeeper, binario sin firmar por Apple).

### Opción B — desde el código

```bash
chmod +x install.sh && ./install.sh
```

- **Linux**: registra `tramitedoc://` vía `xdg-mime` (Firefox/Chrome lo respetan).
- **macOS**: registra el esquema vía LaunchServices (el navegador pide permiso la 1ª vez).
- **Windows**: el motor de firma (Python + pyhanko + tkinter) es multiplataforma; el
  registro del esquema `tramitedoc://` en Windows está pendiente (ver `install.ps1` cuando se agregue).

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
avanzada, `5`=V° B° avanzada, `6`=Firma recepción.

## Configuración (`~/.sgd-signer/config.json`)

```json
{ "cert": "/ruta/cert.p12", "pin": "1234", "tsl_check": true }
```

- `tsl_check: true` (default) verifica que el certificado esté en la TSL de
  INDECOPI (`https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`) antes de firmar.
- El PIN se guarda con permisos `600`.
- La GUI permite configurar por tipo de firma: imagen de firma, posición de la
  imagen dentro del sello, y posición del sello en la página.

## Requisitos

- Python 3.9+
- `pyhanko` + `pyhanko-certvalidator` (firma PAdES)
- `python-pkcs11` (token USB) — opcional si usas `.p12`
- `poppler-utils` (`pdftoppm`, `pdfinfo`) — para la vista previa de la GUI
- `python3-tkinter` — para la GUI

## Verificación

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
