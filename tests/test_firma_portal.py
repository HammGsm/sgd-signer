"""Regresión del flujo de firma del portal (EJECUTAR_FIRMA).

Falla si un intento de firma abandonado queda sin responder al portal -- el
portal se queda esperando para siempre y el usuario lo percibe como "ya firmé,
no se restablece". Falla también si un error de reply deja de registrarse.
"""
import importlib.util
import json
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "/opt/sgd-signer/sgd-signer.py"


def _modulo():
    spec = importlib.util.spec_from_file_location("sgd_test", SRC)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sgd_test"] = mod
    spec.loader.exec_module(mod)
    return mod


class WSFalso:
    def __init__(self):
        self.enviados = []

    def send(self, data):
        self.enviados.append(json.loads(data))


def test_libera_intento_abandonado():
    sgd = _modulo()
    sgd.http_get = lambda *a, **k: (a[1] if len(a) > 1 else "")
    sgd.lanzar_gui_usuario = lambda *a, **k: True
    ws = WSFalso()
    ctx = {"urlBase": "http://x/", "rutaPri": "/tmp", "cfg": {}, "ws": ws}
    msg = {"accion": "EJECUTAR_FIRMA", "nrOperacion": "1",
           "message": json.dumps({"rutaDoc": "a|b.pdf", "urlDoc": "/d"})}

    assert sgd.handle_message(msg, ctx) is None, "debe esperar al op SIGN"
    assert ctx["pending_firma"]["nr"] == "1"

    sgd.handle_message(dict(msg, nrOperacion="2"), ctx)
    assert len(ws.enviados) == 1, f"no liberó el intento anterior: {ws.enviados}"
    assert ws.enviados[0]["error"] == "1", ws.enviados[0]
    assert ws.enviados[0]["nrOperacion"] == "1", ws.enviados[0]
    assert ctx["pending_firma"]["nr"] == "2"
    print("OK  libera el intento abandonado (el portal deja de esperar)")


def test_reply_loguea_error():
    sgd = _modulo()
    vistos = []
    sgd.log = lambda m: vistos.append(m)
    sgd.handle_message({"accion": "VERIFICAR_EXISTE_DOC", "nrOperacion": "9",
                        "message": "no-json"},
                       {"urlBase": "", "rutaPri": "/tmp", "cfg": {}})
    assert any("VERIFICAR_EXISTE_DOC error=" in m for m in vistos), vistos
    print("OK  reply deja rastro en el log cuando falla")


def test_sign_responde_al_portal():
    sgd = _modulo()
    ws = WSFalso()
    ctx = {"ws": ws, "pending_firma": {"nr": "7", "accion": "EJECUTAR_FIRMA"}}
    assert sgd._responder_portal(ctx, ctx["pending_firma"]) is True
    assert ws.enviados[0]["nrOperacion"] == "7", ws.enviados
    assert sgd._responder_portal({}, {"nr": "8", "accion": "EJECUTAR_FIRMA"}) is False
    print("OK  respuesta al portal por WS (y falla ruidoso sin WS)")


if __name__ == "__main__":
    test_libera_intento_abandonado()
    test_reply_loguea_error()
    test_sign_responde_al_portal()
    print("3/3 OK")
