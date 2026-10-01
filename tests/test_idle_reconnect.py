"""Arnes: comprueba que run_ws() RECONECTA cuando la sala queda sorda.
Stub de WebSocket que siempre da timeout (simula la conexion huerfana: TCP vivo,
0 datos). Con IDLE_RECONECTAR bajo, el loop debe salir por el except y reconectar."""
import importlib.util, io, sys, threading, time, types
import websocket as real_ws

spec = importlib.util.spec_from_file_location("sgd", "/opt/sgd-signer/sgd-signer.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

m.IDLE_RECONECTAR = 2  # 2s en vez de 20 min

logs = []
m.log = lambda s: logs.append((time.time(), s))


class FakeWS:
    """Siempre timeout en recv(): la sala nunca manda nada."""
    def __init__(self, *a, **k):
        pass
    def connect(self, *a, **k):
        return None
    def settimeout(self, t):
        pass
    def recv(self):
        raise real_ws.WebSocketTimeoutException("timeout simulado")
    def send(self, *a, **k):
        pass


real_ws.WebSocket = FakeWS
ctx = {"urlBase": "", "rutaPri": "/tmp", "cfg": {}, "ws_url": None, "ws_gen": 0}

t = threading.Thread(target=m.run_ws, args=("wss://fake/chat/x/APPCLIENT", ctx, 0), daemon=True)
t.start()
time.sleep(7)  # > IDLE_RECONECTAR (2s): debe haber reconectado ya

huerfana = [s for _, s in logs if "sin recibir nada en" in s]
conectados = [s for _, s in logs if "Conectado a" in s]
cerrados = [s for _, s in logs if "WS cerrado" in s]

print("logs:", [s for _, s in logs][:8])
print("conexiones:", len(conectados), "| cierres:", len(cerrados), "| huerfana:", len(huerfana))
assert huerfana, "FALLO: no detecto la sala sorda (sigue sordo para siempre)"
assert len(cerrados) >= 1, "FALLO: no cerro la conexion huerfana"
assert len(conectados) >= 2, "FALLO: no reconecto"
print("CHECK OK: sala sorda detectada y reconectada")

# --- zombi: al subir la generacion, el hilo viejo debe retirarse ---
antes = len(conectados)
ctx["ws_gen"] = ctx.get("ws_gen", 0) + 1   # lo que hace start_session al cambiar de sesion
time.sleep(6)
nuevos = [s for _, s in logs if "Conectado a" in s][antes:]
muerto = [s for _, s in logs if "obsoleto" in s]
assert muerto, "FALLO: el hilo viejo sigue vivo tras cambiar de sesion (zombi)"
assert len(nuevos) <= 2, f"FALLO: el hilo viejo siguio reconectando ({len(nuevos)} veces)"
print(f"OK zombi: hilo viejo se retiro, reconexiones tardias={len(nuevos)}")
print("CHECK TOTAL OK")
