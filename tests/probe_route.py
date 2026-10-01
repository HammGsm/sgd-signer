"""Mide el enrutado de la sala para elegir el health-check del daemon.
    P1 = APPCLIENT (hace de daemon: el que queremos comprobar si esta sordo)
    P2 = APPCLIENT (emisor alterno)
    P3 = BROWSER   (emisor alterno)
    Enviamos desde P2 y P3 hacia APPCLIENT; vemos quien recibe."""
import ssl, json, sys, threading, time
import websocket

url = sys.argv[1]
base = url.split("/chat/")[0] + "/chat/"
room = url.split("/chat/")[1].split("/")[0]


def abrir(rol):
    ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
    ws.connect(f"{base}{room}/{rol}", timeout=20)
    ws.settimeout(8)
    return ws


def escuchar(nombre, ws, segs, buf):
    fin = time.time() + segs
    while time.time() < fin:
        try:
            raw = ws.recv()
            if raw:
                buf.append((nombre, raw))
                print(f"  [{nombre}] RECIBIDO {raw[:160]}", flush=True)
        except Exception:
            pass


p1 = abrir("APPCLIENT")
p2 = abrir("APPCLIENT")
p3 = abrir("BROWSER")
print("P1,P2=APPCLIENT  P3=BROWSER  conectados", flush=True)
time.sleep(2)

buf = []
ths = [threading.Thread(target=escuchar, args=(f"P{i}", w, 26, buf), daemon=True)
       for i, w in ((1, p1), (2, p2))]

def enviar(etiqueta, ws, accion):
    ws.send(json.dumps({"message": "{}", "sender": "", "destination": "APPCLIENT",
                        "accion": accion, "nrOperacion": etiqueta}))
    print(f"[ENVIO] {etiqueta} desde {ws}", flush=True)


t = threading.Thread(target=lambda: (time.sleep(3), enviar("desde-P2-APPCLIENT", p2, "HC_P2")), daemon=True)
ths.append(t)
for h in ths:
    h.start()
time.sleep(10)
enviar("desde-P3-BROWSER", p3, "HC_P3")
time.sleep(16)

print(f"\n== recibidos: {len(buf)} ==", flush=True)
for n, m in buf:
    print(f"  {n}: {m[:130]}", flush=True)
for w in (p1, p2, p3):
    try:
        w.close()
    except Exception:
        pass
