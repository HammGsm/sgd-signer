"""Regresión: tipo 1 ignora `pos`, los demás lo respetan. Sin frameworks."""
import importlib.util

spec = importlib.util.spec_from_file_location("sgd", "/opt/sgd-signer/sgd-signer.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

W, H = 595.35, 841.95
base1 = m.firma_box("1", W, H)
con_pos = m.firma_box("1", W, H, pos=(183.67, 52.78))

# tipo 1: el pos residual no debe cambiar la caja .NET (483x128)
assert con_pos == base1, f"tipo 1 aceptó pos: {con_pos} != {base1}"
assert round(base1[2] - base1[0], 2) == 483.32, base1
assert round(base1[3] - base1[1]) == 128, base1

# los otros tipos sí aceptan pos (190x60)
for t in ("2", "3", "4", "5", "6", "7"):
    c = m.firma_box(t, W, H, pos=(183.67, 52.78))
    assert c != m.firma_box(t, W, H), f"tipo {t} dejó de aceptar pos"

out = m.firma_box("2", W, H, pos=(183.67, 52.78))
assert round(out[2] - out[0]) == m.FIRMA_W, out

print("OK: tipo 1 anclado a la caja .NET; tipos 2-7 conservan pos")
