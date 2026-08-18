# CONTRATO — sgd-signer: fork Linux/macOS de FirmaONPE + TramiteDoc (SGD SENAMHI)

**Estado:** EN EJECUCIÓN — 18-ago-2026
**Objetivo:** Reemplazo multiplataforma (Linux/macOS) de los instaladores MSI de ONPE
(`InstallerFirmaONPE.msi` + `InstallerTramiteDoc.msi`) que usa el SGD de SENAMHI
(https://www.senamhi.gob.pe/sgd) para firma digital de documentos.

---

## 1. Qué son los MSI (verificado por reingeniería — NO son Java)

| MSI | Rol | Tecnología real |
|---|---|---|
| `InstallerTramiteDoc.msi` (1.8 MB) | Helper invisible: handler `tramitedoc://` + WebSocket con el portal | .NET 4.5, WPF, websocket-sharp |
| `InstallerFirmaONPE.msi` (14 MB) | Motor PAdES + **app GUI manual** (visor PDF, firmar archivos locales) | .NET 4.0, WPF, iTextSharp, BouncyCastle |

El portal SGD sí es Java (Payara 5.2020.2) — de ahí la confusión de "plugin Java".
El "plugin" que pide el navegador es un **URL handler** (`tramitedoc://`), no un applet.

## 2. Protocolo (replicado del binario + JS del portal)

1. Portal lanza: `Tramitedoc:accion=TraDoc?ws=wss://www.senamhi.gob.pe/wstradoc/chat/<idChannel>/?urlBase=<base>?rutaPri=<dir>`
   - Scheme **sin `//`**, parámetros separados por `?`, `T` mayúscula.
   - `urlBase` puede venir con prefijo literal `@url:` → **limpiarlo** (bug pendiente).
   - `rutaPri` suele venir vacío → fallback `~/Documentos/TDOCUMENTOS` (GNOME) o `~/TDOCUMENTOS`.
   - `idChannel` cambia por sesión → el daemon debe reconectar si cambia.
2. WebSocket: mensajes JSON `{destination:"BROWSER", error:"0", message:"OK", sender:"CSHARP", accion, nrOperacion}`.
   Acciones: CONEXION, VER_RUTA_PRINCIPAL, VER_DOCUMENTO, ABRIR_DOCUMENTO_PC, CARGAR_DOCUMENTO,
   CARGAR_DOCUMENTO_MASIVO, GENERAR_DOCUMENTO, VERIFICAR_EXISTE_DOC(_MASIVO), EJECUTAR_FIRMA(_MASIVA),
   VERIFICAR_DIRECTORIO, TERMINATE_APP, CONTINUE_APP, SELECCIONAR_DIRECTORIO.
3. EJECUTAR_FIRMA: GET `urlBase+urlDoc` → firmar → responder OK. El portal sube el firmado con
   CARGAR_DOCUMENTO (POST octet-stream + header `filename`).

## 3. Tipos de firma (idénticos al original)

| tipo | campo | sufijo | motivo | posición (PDF, desde abajo) |
|---|---|---|---|---|
| 1 Firma titular | FirmaDigital | [NF] | Soy el autor del documento | FIRMA_NUM: (85, H-140, W-27, H-12) |
| 2 Firma básica | FirmaDigital | [F] | Soy el autor del documento | FIRMA_BASICO: (W-180, H-59, W-25, H-24) |
| 3 V° B° | VistoDigital | [VF] | Doy V° B° | VB_FIRMA: (5, 50, 90, 125) |
| 4 Firma avanzada | FirmaDigital | [F] | Soy el autor del documento | manual |
| 5 V° B° avanzada | VistoDigital | [VF] | Doy V° B° | manual |
| 6 Firma recepción | FirmaDigital | [F] | En señal de conformidad | FIRMA_REC: (20, H-95, 105, H-12) |

Subfilter: `/adbe.pkcs7.detached`, SHA-256, campo visible.
Verificado contra PDF real firmado por ONPE: rect [85, 701.92, 568.32, 829.92] en A4 (H=841.92) = fórmula FIRMA_NUM exacta.

## 4. Apariencia de la firma (del PDF de ejemplo R101.83989227$...)

El nombre del archivo codifica metadatos separados por `$`:
`<serie>$<tipo>$<numero>$<lugar>$<año>$<mes>$<dia>$<inNumerar>.pdf`
(8 campos → Fecha "X de Mes del YYYY", Lugar, Numero "N° ...", inNumerar con margen).

Apariencia visible (stream del widget):
- Arriba: número del documento (ej. `INFORME N°   D000004-2026-SENAMHI-GG-OTI-HSRC`)
- Debajo: `Lugar, dia de Mes del año` (ej. `Jesus Maria, 14 de Agosto del 2026`)
- Derecha (bloque): `Firmado digitalmente por <CN>` (3 líneas si CN largo) + `Motivo: ...` + `Fecha: dd.mm.yyyy hh:mm:ss -05:00`

## 5. Arquitectura instalada (OL9 sc1-ws-dba01, ago-2026)

- `/opt/sgd-signer/sgd-signer.py` + `/opt/sgd-signer-venv` (pyhanko 0.20.0, websocket-client, python-pkcs11, pikepdf).
- Wrapper `/usr/local/bin/sgd-signer` → `$VENV/bin/python /opt/sgd-signer/sgd-signer.py "$@"`.
- **Daemon systemd `sgd-signer.service`** corre como **root** (el token USB solo es visible para root;
  hruiz no ve slots PKCS#11). `Environment=HOME=/home/hruiz` (config + ruta TDOCUMENTOS del usuario real).
  Escucha en `/tmp/sgd-signer.sock` (chmod 666). `--daemon` = modo servicio.
- Handler hruiz: `~/.local/share/applications/sgd-signer.desktop` + `xdg-mime default sgd-signer.desktop x-scheme-handler/tramitedoc`.
  Firefox prefs: `network.protocol-handler.external.tramitedoc=true`, `warn-external.tramitedoc=false`.
- Config: `/home/hruiz/.sgd-signer/config.json` → `{"token": true, "token_lib": "/usr/lib/bit4id/libbit4xpki.so", "pin": "...", "tsl_check": false}`.

## 6. Token (Bit4id tokenME FIPS v3)

- Lector: Alcor AU9540 (058f:9540). Token: 25dd:2342. Middleware YA instalado: `/usr/lib/bit4id/libbit4xpki.so` (v11.836).
- Certificado: `RUIZ CAYAO Hammerly Scoot FAU 20131366028 hard` (RENIEC). Clave privada SIN label → usar `key_id` (hex del ID del cert).
- opensc NO sirve para este token (CKR_USER_PIN_NOT_INITIALIZED, bug #2763). Usar SIEMPRE libbit4xpki.so.
- `make_signer()` en sgd-signer.py: auto-detecta cert de usuario (el que tiene clave privada del mismo ID).
- PIN: [REDACTADO] (guardado en config.json chmod 600; borrar campo `pin` si se quiere pedir cada vez).

## 7. Plan de trabajo (marcar con [x] lo realizado)

- [x] **F1. Reingeniería de los MSI** — descompilación completa (msiextract + ilspycmd), protocolo documentado.
- [x] **F2. Motor de firma PAdES** — pyhanko, subfilter `/adbe.pkcs7.detached`, campos/posiciones idénticos.
- [x] **F3. Handler tramitedoc:// + daemon WebSocket** — parser del formato real del portal, reconexión por idChannel.
- [x] **F4. Integración token PKCS#11** — Bit4id libbit4xpki.so, auto-detección cert de usuario, PIN en config.
- [x] **F5. Despliegue en OL9 sc1-ws-dba01** — systemd daemon root + handler hruiz + Firefox prefs + verificación end-to-end.
- [x] **F6. Fix `@url:` en urlBase** — el portal envía `urlBase=@url:https://...`; limpiar prefijo en el parser. ✅ verificado con URL real del log del navegador.
- [x] **F12. Enrutamiento WS del servidor** — root cause: el bridge del portal enruta por SUFIJO DE ROL, no por orden de conexión. El navegador siempre conecta a `.../<idChannel>/BROWSER`; el daemon conectaba al path bare (`.../<idChannel>/`) que el propio portal manda en `ws=`, y ese path bare **nunca recibe** lo que llega a `/BROWSER` (probado con sockets aislados: bare→BROWSER funciona, BROWSER→bare nunca, sin importar quién conecta primero). El path correcto para el rol app es `/APPCLIENT` (confirmado por prueba directa). Fix: `run_ws()` ahora conecta a `url_ws.rstrip("/") + "/APPCLIENT"`. ✅ verificado end-to-end en Edge (círculo antes rojo, ahora verde).
- [x] **F13. Edge no lanza el handler (picker vacío)** — root cause distinto de F12: Edge (sandboxed) invoca protocolos vía `xdg-desktop-portal` (`OpenURI`→`PermissionStore.Lookup`→`NotFound`→`AppChooser.ChooseApplication` con `choices=[]` vacío) porque `sgd-signer.desktop` tenía `NoDisplay=true`, que GNOME excluye de la lista de apps "recomendadas" que puebla ese picker. El diálogo quedaba vacío/sin resolver → Edge nunca recibía respuesta → "aplicación no disponible". Firefox no pasa por el portal (usa su propio `handlers.json`), por eso solo Edge fallaba. Fix: quitar `NoDisplay=true` de `~/.local/share/applications/sgd-signer.desktop` + `update-desktop-database` + reiniciar `xdg-desktop-portal(-gnome)`. ✅ verificado, Edge ya no pide "aplicación no disponible".
- [x] **F7. Apariencia de firma exacta** — implementado con `TextStampStyle(background=PdfImage(...))`: imagen real de firma extraída del MSI (`assets/imagenFirma<N>.jpg`, una por tipo 1-6) como fondo + texto 5pt superpuesto (bloque derecho) con el layout exacto del PDF de ejemplo (número/lugar-fecha arriba, "Firmado digitalmente por" + CN partido en 3 líneas + Motivo + Fecha abajo). Metadatos (NumeroDoc/Lugar/Fecha) se extraen del NOMBRE del archivo (`parse_nombre_doc()`: `<serie>$<tipo>$<numero>$<lugar>$<año>$<mes>$<dia>$<inNumerar>.pdf`, formato real confirmado en `EJECUTAR_FIRMA` — el JSON del portal solo manda urlDoc/rutaDoc/tipoFirma, no metadatos sueltos). Bug lateral encontrado y corregido: `make_signer()` no importaba `signers` (path .p12 nunca se había probado, solo token PKCS#11) — un solo import agregado, no afecta el flujo token real usado en producción. ✅ verificado firmando PDF real: rect y content-stream idénticos al ejemplo ONPE (imagen + 6 líneas de texto en el orden documentado).
- [x] **F8. GUI manual (fork FirmaONPE)** — Tkinter (stdlib, ya en el venv) + `pdftoppm`/`pdfinfo` (poppler-utils, ya instalado) para render, sin dependencias nuevas. `sgd-signer gui [pdf]`: abrir PDF, navegar páginas, elegir tipo 1-6, click en la página para posición manual (tipos 4/5), botón Firmar. Registrado como `.desktop` (`sgd-signer-gui.desktop`, MimeType `application/pdf`) para lanzar desde el menú de hruiz. Dos bugs de arquitectura encontrados y corregidos en el camino (ambos root-cause, no parches):
  - **Token invisible para hruiz**: la GUI corre como hruiz (necesita DISPLAY), pero el token USB solo lo ve el daemon root (ver sección 5) → `sign_pdf()` in-process fallaba con "No hay token USB conectado". Fix: `manual_sign_via_daemon()` delega la firma real al daemon existente por el mismo socket Unix que usa `tramitedoc://` (protocolo nuevo `MANUAL_SIGN:<json>` sobre `/tmp/sgd-signer.sock`), la GUI nunca toca el token directamente.
  - **Deadlock cliente-servidor**: el server hace `recv()` en loop hasta EOF; el cliente nunca cerraba el lado de escritura tras enviar la petición → ambos quedaban esperando al otro. Fix: `s.shutdown(socket.SHUT_WR)` tras `sendall()` en el cliente.
  - **`UserAlreadyLoggedIn` al firmar 2+ veces**: `make_signer()` abría una sesión PKCS#11 nueva (con login) en cada llamada sin cerrar la anterior — el daemon vive todo el día y firma muchas veces, agotando los slots de login del token. Fix: sesión PKCS#11 cacheada a nivel de proceso (`_PKCS11_SESSION_CACHE` + lock), reutilizada mientras lib_path/pin no cambien. ✅ verificado con 3 firmas consecutivas + flujo GUI completo (click→firmar→daemon→token real→OCSP/CRL→stamp) simulando eventos Tkinter reales en la sesión gráfica de hruiz.
- [x] **F9. Verificación OCSP/CRL** — `check_ocsp_crl()`, mismo patrón best-effort que `check_tsl()`: lee `crl_distribution_points_value` del cert, descarga el CRL del emisor y verifica que el número de serie no esté en la lista de revocados. Deliberadamente NO se usa `PdfSignatureMetadata.validation_context` (que valida la cadena completa online antes de firmar) porque eso puede ABORTAR la firma real si la CA raíz de RENIEC/Bit4id no está en el trust store del sistema — probado con cert self-signed, rompe con `InvalidCertificateError`. Soft-fail: sin CDP declarado o sin red → solo loguea, nunca bloquea. ✅ verificado con CRL real de producción (Google/GTS) end-to-end: fetch, parse ASN.1, chequeo de revocado.
- [x] **F10. Firma masiva con diálogo de confirmación** — `EJECUTAR_FIRMA_MASIVA` pide confirmación antes de firmar N documentos, replicando el texto y comportamiento exacto del original (`MENSAJE_FIRMA_MASIVA` del `config_firmaonpe.xml`; "No" o sin respuesta en 120s → cancela, igual que `TipoMensaje.FirmaCancelar`). El daemon corre headless como root sin sesión gráfica propia, así que `confirmar_en_gui_usuario()` detecta el DISPLAY/DBUS real de la sesión activa de hruiz (leyendo `/proc/<pid>/environ` de gnome-shell — sin hardcodear `:1`/uid 1000, la sesión puede reiniciar con otro número) y lanza el diálogo Tkinter vía `runuser -u hruiz` (mismo patrón que F8, invertido: root pregunta, usuario responde). Dos bugs de proceso encontrados y corregidos:
  - **`runuser` colgado indefinidamente**: sin `stdin=DEVNULL` el proceso podía esperar EOF de stdin y nunca soltar el `communicate()`, ignorando el timeout por completo. Fix: `stdin=subprocess.DEVNULL`.
  - **Diálogo huérfano tras timeout**: `proc.kill()` mata `runuser` pero no siempre al nieto real (proceso Tk bajo hruiz), dejando ventanas fantasma acumulándose en la sesión del usuario. Fix: `start_new_session=True` + `os.killpg()` para matar el grupo completo, con `pkill -f <marca única>` como respaldo. ✅ verificado: timeout limpio en 8s exactos sin procesos residuales, y captura de respuesta ("SI"/"NO") funcionando vía `runuser`.
- [ ] **F11. Empaquetado .deb/.rpm/.dmg** para distribución.

### F8b. Mejoras post-entrega a la GUI manual (PIN, apariencia por tipo, diseño)
- **PIN obligatorio con indicador de estado**: antes la GUI firmaba directo con el PIN ya guardado en disco sin decir nada — ahora hay una barra superior fija con una "pill" de estado ("PIN guardado en memoria (permanente)" / "(esta sesión)" / "Sin PIN guardado") y botón "Ingresar / cambiar PIN". El PIN se valida contra el token real (`make_signer()`) antes de aceptar el guardado — si es incorrecto, se rechaza con el error real de PKCS#11 (`PinIncorrect`) en vez de guardar algo que luego falla al firmar.
- **Recordar en sesión vs disco**: nuevo verbo `SET_PIN` con `recordar="sesion"` (memoria del proceso daemon, se pierde al reiniciar el servicio) o `"disco"` (persistente en `~/.sgd-signer/config.json`, como ya existía). `GET_STATUS` distingue los tres estados.
- **Imagen y posición configurables por tipo, persistentes**: nuevo botón "Imagen de este tipo…" (file picker) y click en la página guarda la posición automáticamente por tipo de firma (antes solo aplicaba a la firma puntual, tipos 4/5; ahora se recuerda para todas las firmas futuras de ese tipo, cualquier tipo). Guardado en `cfg["apariencia"][tipo] = {"imagen": ..., "pos": [x, y]}`, leído por `sign_pdf()` como override sobre los defaults hardcodeados.
- **Protocolo del socket generalizado**: el prefijo ad-hoc `MANUAL_SIGN:` se reemplazó por un despachador único `OP:{"op": "...", ...}` (`SIGN`, `GET_STATUS`, `SET_PIN`, `GET_APARIENCIA`, `SET_APARIENCIA`) — root cause fix del patrón de ir apilando prefijos string por feature.
- **Rediseño visual (skill `minimalist-ui`)**: paleta warm monochrome (`#FBFBFA` fondo, `#111111` texto, `#EAEAEA` bordes 1px, pastel verde/amarillo/rojo para status), botones planos sin sombra, tipografía monospace para status/paginación. Sin gradientes ni `rounded-full`. La GUI original (v1) usaba los widgets Tk por defecto (grises de sistema, sin jerarquía visual).
- ✅ verificado end-to-end: pill de PIN refleja el estado real tras SET_PIN, click de posición persiste en config y sobrevive a reabrir el PDF, firma con override de posición aplicada, PIN incorrecto rechazado contra el token real.

### F8c. Ventana de Configuración + firma masiva en la GUI
- **Ventana "Configuración"** (botón en la barra superior, `Toplevel` modal): consolida todo lo que antes estaba disperso o no existía:
  - **PIN**: campo + radio "Solo esta sesión" / "Permanente (disco)" + botón "Guardar PIN" (valida contra el token real) + "Olvidar PIN guardado" (nuevo verbo `CLEAR_PIN`, limpia disco y sesión). Estado actual visible ("Guardado en disco (permanente)" / "Guardado en esta sesión" / "Sin PIN guardado").
  - **Imagen por tipo**: selector de tipo + "Elegir imagen…" + **posición de la imagen dentro de la firma** (horizontal left/center/right × vertical top/middle/bottom, mapeado a `AxisAlignment` de pyhanko). Antes la imagen iba fija a la derecha/abajo; ahora es configurable por tipo.
  - **Posición de la firma en la página**: muestra la guardada por tipo (se fija con click en el documento).
  - **Verificación TSL**: checkbox que persiste `tsl_check` (nuevo verbo `GET_CONFIG`/`SET_CONFIG`).
- **Firma masiva desde la GUI** (botón "Firma masiva…"): selección múltiple de PDFs → diálogo de confirmación (mismo texto jurídico del original) → firma todos con el tipo/posición actuales vía nuevo verbo `SIGN_MASIVO` (el daemon firma en loop, devuelve `firmados` + `errores` por archivo). ✅ verificado: 2 PDFs firmados con token real, resumen "2 firmados, 0 con error".
- **Bug corregido en el camino**: `_cfg_cargar_apariencia()` se llamaba antes de crear `cfg_pos_lbl` → `AttributeError` al abrir la ventana. Fix: mover la carga al final de `abrir_configuracion()`.

## 8. Pitfalls (no repetir)

- El portal lanza la URL con `Tramitedoc:` (mayúscula, sin `//`) — el parser debe aceptar ambos formatos.
- `urlBase` con prefijo `@url:` literal → strip antes de usar.
- El daemon debe correr con HOME del usuario real (no root) para encontrar config y TDOCUMENTOS.
- pyhanko 0.20: `SimpleSigner.load_pkcs12(path, passphrase=pin.encode())` (bytes, no str);
  `PdfSigner(meta, signer, stamp_style=...)` (orden posicional); `on_page` es 0-based;
  `TextStampStyle` en `pyhanko.stamp` (no `pyhanko.sign.stamp`); template usa `%(signer)s`/`%(ts)s`.
- `pkill -f 'http.server'` por SSH mata la propia sesión (el patrón coincide) → usar `fuser -k <puerto>/tcp`.
- opensc NO sirve para el token Bit4id (CKR_USER_PIN_NOT_INITIALIZED) → usar SIEMPRE libbit4xpki.so.

## 9. Referencias

- Skill: `sgd-signer` (protocolo completo, comandos, pitfalls).
- PDF de ejemplo firmado: `/home/hruiz/Documentos/TDOCUMENTOS/R101.83989227$INFORME$  D000004-2026-SENAMHI-GG-OTI-HSRC$Jesus Maria$2026$08$14$1.pdf`
- JS del portal: `https://www.senamhi.gob.pe/sgd/resources-4.10/js/wsTradoc.js`
- Middleware Bit4id: `https://cdn.bit4id.com/es/middleware.htm` (Linux v11.836, RPM/DEB)

## 10. Apariencia exacta de la firma (stream del widget, PDF de ejemplo)

Widget: campo `FirmaDigital1`, rect `[85, 701.92, 568.32, 829.92]` (A4 H=841.92 → FIRMA_NUM).
Form XObject n2 (BBox 483.32×128), fuente Helvetica, texto negro:

```
2 Tr 0.43333 w 0 0 0 RG 0 0 0 rg
(INFORME N°   D000004-2026-SENAMHI-GG-OTI-HSRC)Tj     ← número, stroke+fill, ~12pt
BT 1 0 0 1 1 28 Tm /F1 12 Tf
(Jesus Maria, 14 de Agosto del 2026)Tj                ← lugar, fecha larga, 12pt
BT 1 0 0 1 395.32 121 Tm /F1 5 Tf
(Firmado digitalmente por RUIZ)Tj                      ← bloque derecho, 5pt
(CAYAO Hammerly Scoot FAU)Tj                          ← CN partido en 3 líneas
(20131366028 hard)Tj
(Motivo: Soy el autor del documento)Tj
(Fecha: 14.08.2026 16:03:39 -05:00)Tj                 ← dd.mm.yyyy hh:mm:ss ±HH:MM
```

Además hay una imagen (img0, 168×84) = la imagen de firma del MSI (imagenFirma*.jpg).
El nombre del archivo codifica: `<serie>$<tipo>$<numero>$<lugar>$<año>$<mes>$<dia>$<inNumerar>.pdf`.
