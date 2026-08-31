import sys, os, types, tempfile
from pathlib import Path

src = open("/opt/sgd-signer/sgd-signer.py").read()
mod = types.ModuleType("sgd")
mod.__file__ = "/opt/sgd-signer/sgd-signer.py"
exec(compile(src, "sgd-signer.py", "exec"), mod.__dict__)

# --- test 1: _cert_info_pkcs12 con PIN ---
info = mod._cert_info_pkcs12("/tmp/test.p12", "1234")
assert info["cn"] == "Prueba Sintetica", info
assert info["emisor"] == "Prueba Sintetica", info
print("test1 _cert_info_pkcs12 OK:", info["cn"], "| vence:", info["no_after"])

# --- test 2: sin PIN -> solo nombre ---
info2 = mod._cert_info_pkcs12("/tmp/test.p12", None)
assert info2["cn"] == "test.p12", info2
print("test2 sin PIN OK:", info2["cn"])

# --- test 3: PIN incorrecto lanza ---
try:
    mod._cert_info_pkcs12("/tmp/test.p12", "9999")
    raise AssertionError("debió lanzar")
except Exception as e:
    print("test3 PIN malo lanza OK:", type(e).__name__)

# --- test 4: make_signer con cert_path (prioridad archivo) ---
s = mod.make_signer({}, "1234", "/tmp/test.p12")
assert s.signing_cert.subject.native["common_name"] == "Prueba Sintetica"
print("test4 make_signer(archivo) OK")

# --- test 5: make_signer con cfg['cert'] (importado) ---
s2 = mod.make_signer({"cert": "/tmp/test.p12"}, "1234")
assert s2.signing_cert.subject.native["common_name"] == "Prueba Sintetica"
print("test5 make_signer(cfg cert) OK")

# --- test 6: find_certs encuentra el p12 en cwd ---
os.chdir("/tmp")
certs = mod.find_certs()
assert any(str(c).endswith("test.p12") for c in certs), certs
print("test6 find_certs OK:", [str(c) for c in certs])

# --- test 7: dispatch LISTAR_CERTS incluye archivos (con su clave propia) ---
ctx = {"cfg": {"pin": "1234", "cert_pins": {"/tmp/test.p12": "1234"}}, "session_pin": None}
resp = mod.dispatch_gui_op({"op": "LISTAR_CERTS"}, ctx)
assert resp["ok"], resp
archivos = [c for c in resp["certs"] if c.get("archivo")]
assert any("Prueba Sintetica" in c["cn"] for c in archivos), resp["certs"]
print("test7 LISTAR_CERTS archivos OK:", [(c["cn"], c["archivo"]) for c in archivos])

# --- test 8: ELEGIR_CERT con archivo ---
ctx2 = {"cfg": {"pin": "1234"}, "session_pin": None}
r = mod.dispatch_gui_op({"op": "ELEGIR_CERT", "archivo": "/tmp/test.p12"}, ctx2)
assert r["ok"] and ctx2["cfg"]["cert"] == "/tmp/test.p12"
assert "cert_key_id" not in ctx2["cfg"]
print("test8 ELEGIR_CERT archivo OK")

# --- test 9: IMPORTAR_CERT copia, verifica clave y activa ---
with tempfile.TemporaryDirectory() as td:
    mod.CONFIG_DIR = Path(td)
    mod.CERT_DIR = mod.CONFIG_DIR / "certs"
    mod.CONFIG_FILE = mod.CONFIG_DIR / "config.json"
    ctx3 = {"cfg": {}, "session_pin": None}
    r = mod.dispatch_gui_op({"op": "IMPORTAR_CERT", "archivo": "/tmp/test.p12", "pin": "1234"}, ctx3)
    assert r["ok"], r
    dst = r["archivo"]
    assert mod.Path(dst).exists()
    mode = mod.Path(dst).stat().st_mode & 0o777
    assert mode == 0o600, oct(mode)
    assert ctx3["cfg"]["cert"] == dst
    assert ctx3["cfg"]["cert_pins"][dst] == "1234"
    print("test9 IMPORTAR_CERT OK:", dst)

# --- test 9b: IMPORTAR_CERT con clave incorrecta borra y falla ---
with tempfile.TemporaryDirectory() as td:
    mod.CONFIG_DIR = Path(td)
    mod.CERT_DIR = mod.CONFIG_DIR / "certs"
    mod.CONFIG_FILE = mod.CONFIG_DIR / "config.json"
    ctx3b = {"cfg": {}, "session_pin": None}
    r = mod.dispatch_gui_op({"op": "IMPORTAR_CERT", "archivo": "/tmp/test.p12", "pin": "9999"}, ctx3b)
    assert not r["ok"] and "clave incorrecta" in r["error"], r
    assert not (mod.CERT_DIR / "test.p12").exists(), "no debe quedar el archivo"
    assert "cert" not in ctx3b["cfg"]
    print("test9b IMPORTAR_CERT clave mala OK:", r["error"])

# --- test 9c: SET_PIN con cert guarda en cert_pins y verifica ---
with tempfile.TemporaryDirectory() as td:
    mod.CONFIG_DIR = Path(td)
    mod.CERT_DIR = mod.CONFIG_DIR / "certs"
    mod.CONFIG_FILE = mod.CONFIG_DIR / "config.json"
    ctx3c = {"cfg": {"cert": "/tmp/test.p12"}, "session_pin": None}
    r = mod.dispatch_gui_op({"op": "SET_PIN", "pin": "1234", "recordar": "disco", "cert": "/tmp/test.p12"}, ctx3c)
    assert r["ok"], r
    assert ctx3c["cfg"]["cert_pins"]["/tmp/test.p12"] == "1234"
    assert "pin" not in ctx3c["cfg"]
    print("test9c SET_PIN cert OK")

# --- test 9d: GET_STATUS con cert activo sin clave -> ninguno ---
with tempfile.TemporaryDirectory() as td:
    mod.CONFIG_DIR = Path(td)
    mod.CERT_DIR = mod.CONFIG_DIR / "certs"
    mod.CONFIG_FILE = mod.CONFIG_DIR / "config.json"
    ctx3d = {"cfg": {"cert": "/tmp/test.p12"}, "session_pin": None}
    r = mod.dispatch_gui_op({"op": "GET_STATUS"}, ctx3d)
    assert r["pin_status"] == "ninguno", r
    ctx3d["cfg"]["cert_pins"] = {"/tmp/test.p12": "1234"}
    r = mod.dispatch_gui_op({"op": "GET_STATUS"}, ctx3d)
    assert r["pin_status"] == "disco", r
    print("test9d GET_STATUS cert OK")

# --- test 10: ELEGIR_CERT token limpia cfg['cert'] ---
ctx4 = {"cfg": {"cert": "/tmp/test.p12", "pin": "1234"}, "session_pin": None}
r = mod.dispatch_gui_op({"op": "ELEGIR_CERT", "key_id": "abcd", "lib": "/x/lib.so"}, ctx4)
assert r["ok"] and "cert" not in ctx4["cfg"] and ctx4["cfg"]["cert_key_id"] == "abcd"
print("test10 ELEGIR_CERT token limpia archivo OK")

print("\nTODOS LOS TESTS PASARON")
