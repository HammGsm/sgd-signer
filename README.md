# sgd-signer — Firma digital para el SGD de SENAMHI en Linux/macOS

Reemplazo multiplataforma de **Tramitedoc.exe** + **AppFirmaONPE.exe** (los instaladores
MSI de ONPE que el portal SGD de SENAMHI usa para firmar documentos).

## ¿Qué son realmente esos MSI?

**No son Java.** Son aplicaciones **.NET Framework (C#/WPF)** empaquetadas con WiX:

| Componente | Tecnología | Función |
|---|---|---|
| `InstallerTramiteDoc.msi` | .NET 4.5, WPF, websocket-sharp | Helper de escritorio: se registra como protocolo `tramitedoc://` y habla con el portal por WebSocket |
| `InstallerFirmaONPE.msi` | .NET 4.0, WPF, iTextSharp, BouncyCastle | Motor de firma PAdES de PDFs (firma visible + PKCS#7 detached) |

El portal SGD sí es Java (Payara 5.2020.2) — de ahí la confusión de "plugin Java".

## Cómo funciona el protocolo (reingeniería del binario)

1. El portal lanza `tramitedoc://?accion=TraDoc&urlBase=<base>&rutaPri=<dir>&ws=<wss://...>`
   (el endpoint WS real está en el HTML del login: `wss://10.10.20.29:8181/wstradoc/chat/`).
2. Tramitedoc conecta al WebSocket y responde mensajes JSON:
   `{destination:"BROWSER", error:"0", message:"OK", sender:"CSHARP", accion, nrOperacion}`
3. `EJECUTAR_FIRMA`: descarga el PDF (`GET urlBase+urlDoc`), lo firma con el certificado
   del usuario (campo `FirmaDigital`/`VistoDigital`, sufijo `[NF]`/`[F]`/`[VF]`), responde OK.
4. El portal sube el PDF firmado con `CARGAR_DOCUMENTO` (POST octet-stream + header `filename`).

## Instalación

```bash
chmod +x install.sh && ./install.sh
```

- Linux: registra `tramitedoc://` vía `xdg-mime` (Firefox/Chrome lo respetan).
- macOS: registra el esquema vía LaunchServices (el navegador pedirá permiso la 1ª vez).

## Uso

```bash
# 1. certificado (DNI electrónico / token, exportado a .p12)
mkdir -p ~/.sgd-signer/certs && cp TU_CERT.p12 ~/.sgd-signer/certs/

# 2. PIN (opcional; si no, lo pide cada firma)
sgd-signer pin TU_PIN

# 3. firma directa desde terminal
sgd-signer sign documento.pdf --tipo 2

# 4. en el portal SGD: al pulsar "Firmar" se abre sgd-signer automáticamente
```

Tipos de firma (idénticos al original): `1`=Firma titular, `2`=Firma básica,
`3`=V° B°, `4`=Firma avanzada, `5`=V° B° avanzada, `6`=Firma recepción.

## Configuración (`~/.sgd-signer/config.json`)

```json
{ "cert": "/ruta/cert.p12", "pin": "1234", "tsl_check": true }
```

- `tsl_check: true` (default) verifica que el certificado esté en la TSL de INDECOPI
  (`https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`) antes de firmar, como hace el original.
- El PIN se guarda con permisos `600`.

## Limitaciones conocidas

- El WebSocket del portal (`wss://10.10.20.29:8181`) es una **IP interna** de la red
  SENAMHI: solo funciona dentro de la red institucional (igual que el original).
- La verificación TSL/OCSP/CRL del original es más estricta; aquí se verifica TSL
  (descargable) y se omite OCSP/CRL en línea (el certificado del DNIe suele validar igual).
- Firma masiva: soportada (EJECUTAR_FIRMA_MASIVA), sin diálogo de confirmación.
- `SELECCIONAR_DIRECTORIO` responde OK sin abrir diálogo (usa `rutaPri` del portal).

## Verificación

```bash
# el PDF firmado debe abrir en cualquier visor con la firma visible y válida
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
