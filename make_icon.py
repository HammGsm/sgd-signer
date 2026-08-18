#!/usr/bin/env python3
"""Genera el icono de SGD-SIGNER (assets/icon.png) con Pillow, sin dependencias externas."""
from PIL import Image, ImageDraw

SIZE = 256
GREEN = (52, 101, 56, 255)      # #346538
WHITE = (255, 255, 255, 255)
INK = (17, 17, 17, 255)         # #111111

img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# fondo: cuadrado redondeado verde
r = 28
d.rounded_rectangle([0, 0, SIZE - 1, SIZE - 1], radius=r, fill=GREEN)

# hoja de documento blanca (ligeramente inclinada no; recta, centrada)
pad = 52
d.rounded_rectangle([pad, pad, SIZE - pad, SIZE - pad], radius=16, fill=WHITE)

# líneas de texto del documento (gris claro)
gris = (200, 200, 200, 255)
for i, y in enumerate(range(96, 150, 18)):
    d.rectangle([pad + 24, y, SIZE - pad - 24, y + 6], fill=gris)

# trazo de firma (pluma) en tinta oscura, curvo
pts = [(pad + 30, 190), (pad + 60, 150), (pad + 100, 175), (pad + 140, 130),
       (pad + 175, 165), (pad + 205, 140)]
d.line(pts, fill=INK, width=8, joint="curve")

# punta de pluma (triángulo) al final del trazo
tip = (pad + 205, 140)
d.polygon([(tip[0] - 4, tip[1] - 22), (tip[0] + 4, tip[1] - 22), (tip[0], tip[1] + 2)],
          fill=INK)

img.save("assets/icon.png")
print("assets/icon.png generado:", img.size)
