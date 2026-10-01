"""El sello debe CABER en el rect del campo de firma.

Bug (01-oct-2026): al firmar con posición manual (caja 190x60) el layout seguía
siendo el absoluto del XObject .NET (483x128) → el número del documento y el
bloque del firmante se dibujaban FUERA del rect; el visor recortaba y en la
página sólo se veía una franja de "INFORME TECNICO" encima del encabezado.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "sgd_signer", Path(__file__).resolve().parent.parent / "sgd-signer.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# la fuente por defecto (sin Tk) no puede faltar en el venv
assert m.FIRMA_W, m.FIRMA_H


def _cabe(layout, box, lineas=5):
    _, _, ix, _, tx, ty, _, lead = layout
    w, h = box[2] - box[0], box[3] - box[1]
    return (ix + layout[0] <= w + 1e-6 and tx <= w
            and ty <= h and ty - (lineas - 1) * lead >= -1e-6)


def test_layout_default_cabe():
    """Sin posición manual: el layout .NET (caja grande) se conserva intacto."""
    box = m.firma_box("1", 595.35, 841.95)          # caja ancha .NET 483x128
    assert m.layout_para("1", box) == m.STAMP_LAYOUT["1"]
    box2 = m.firma_box("2", 595.35, 841.95)
    assert m.layout_para("2", box2) == m.STAMP_LAYOUT["2"]


def test_layout_manual_cabe():
    """Con posición manual la caja es 190x60: el layout debe caber DENTRO."""
    for tipo in m.STAMP_LAYOUT:
        box = m.firma_box(tipo, 595.35, 841.95, pos=(400, 780))
        assert box[2] - box[0] == m.FIRMA_W and box[3] - box[1] == m.FIRMA_H
        lay = m.layout_para(tipo, box, lineas=5)
        assert _cabe(lay, box, 5), f"tipo {tipo} se sale de la caja: {lay} en {box}"


def test_layout_img_pos_extremos():
    """Cualquier img_pos elegido en la GUI debe caber (degradando si hace falta)."""
    box = m.firma_box("2", 595.35, 841.95, pos=(400, 780))
    for p in ("left", "right", "top", "bottom"):
        assert _cabe(m.layout_para("2", box, p, lineas=5), box, 5), p


def test_layout_caja_chica_no_sale():
    """Caja más chica que la estándar: nada puede quedar con y negativa."""
    box = (100, 200, 100 + m.FIRMA_W, 200 + m.FIRMA_H)
    for tipo in m.STAMP_LAYOUT:
        lay = m.layout_para(tipo, box, lineas=5)
        assert lay[5] - 4 * lay[7] >= -1e-6, (tipo, lay)


def test_apilado_no_colapsa_caja():
    """Bug 01-oct-2026: con posición manual pegada al pie, el desplazamiento por
    firmas previas recortaba box[1] a 0 y el campo quedaba y0==y1 (altura 0):
    el sello no cabía en ningún sitio y la firma nueva era invisible."""
    H = 841.95
    for pos in ((400, 780), (400, 841.95), (400, 830)):
        box = m.firma_box("1", 595.35, H, pos=pos)
        for n_previas in (1, 2, 3):
            b = list(box)
            h = b[3] - b[1]
            dy = n_previas * (h + 5)
            if b[1] - dy >= 0:
                b = [b[0], b[1] - dy, b[2], b[3] - dy]
            elif b[3] + dy <= H:
                b = [b[0], b[1] + dy, b[2], b[3] + dy]
            assert b[3] - b[1] >= m.FIRMA_H - 1e-6, (pos, n_previas, b)
            assert b[1] >= 0 and b[3] <= H, (pos, n_previas, b)


def test_firma_box_no_sale_de_pagina():
    """El click cerca del borde no debe empujar la caja fuera de la página."""
    W, H = 595.35, 841.95
    for px, py in ((0, 0), (W, H), (W - 5, H - 5), (-10, -10), (999, 999)):
        x0, y0, x1, y1 = m.firma_box("1", W, H, pos=(px, py))
        assert x0 >= 0 and y0 >= 0 and x1 <= W + 1e-6 and y1 <= H + 1e-6, (px, py)


if __name__ == "__main__":
    for n, f in sorted(globals().items()):
        if n.startswith("test_"):
            f()
            print(f"OK {n}")
    print("OK layout")
