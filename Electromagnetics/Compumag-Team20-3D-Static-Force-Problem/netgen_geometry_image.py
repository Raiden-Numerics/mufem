"""Render data/Geometry.png from geometry.step with the netgen viewer.

The geometry is turned so that the view matches the scene of create_scene.py.
Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python netgen_geometry_image.py
"""

import math
import os

import matplotlib
import netgen
import netgen.gui
from netgen.occ import Axis, Glue, OCCGeometry, Pnt, X, Y, Z

from PIL import Image, ImageDraw, ImageFont, ImageOps

script_dir = os.path.dirname(os.path.abspath(__file__))
width, height = 1600, 1200

shape = OCCGeometry(f"{script_dir}/geometry.step").shape

# netgen shows x to the right, y up and z toward the viewer. Rotate the model so that the
# camera of create_scene.py (screen right, up, toward the viewer) maps onto these axes: the
# isometric view along (-1, -1, 1) with z up, onto the symmetry planes x = 0 and y = 0.
origin = Pnt(0, 0, 0)
shape = (
    shape.Rotate(Axis(origin, X), -45.00)
    .Rotate(Axis(origin, Y), 35.26)
    .Rotate(Axis(origin, Z), 30.00)
)

OCCGeometry(Glue(shape.solids)).Draw()

tk = netgen.gui.win.tk
tk.eval(f"wm geometry . {width}x{height}")
netgen.Redraw(blocking=True)
tk.eval("Ng_MouseMove 0 0 0 -30 zoom")
netgen.Redraw(blocking=True)

image = Image.fromarray(netgen.gui.Snapshot(width, height)).convert("RGB")

# Trim the white margins, keeping a small border.
border = 20
left, top, right, bottom = ImageOps.invert(image).getbbox()
image = image.crop(
    (
        max(left - border, 0),
        max(top - border, 0),
        min(right + border, image.width),
        min(bottom + border, image.height),
    )
)
# Label the bodies.
draw = ImageDraw.Draw(image)
font = ImageFont.truetype(f"{matplotlib.get_data_path()}/fonts/ttf/DejaVuSans-Bold.ttf", 30)


def arrow(start, end, head=18):
    draw.line([start, end], fill="black", width=4)
    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    draw.polygon(
        [end]
        + [
            (end[0] - head * math.cos(angle + s), end[1] - head * math.sin(angle + s))
            for s in (-0.35, 0.35)
        ],
        fill="black",
    )


draw.text((200, 300), "Air", font=font, fill="black", anchor="mm")
for text, position, anchor, start, end in [
    ("Coil", (280, 690), "rm", (290, 690), (352, 690)),
    ("Yoke", (590, 600), "lm", (580, 600), (512, 620)),
    ("Pole", (625, 880), "lm", (615, 875), (420, 760)),
]:
    draw.text(position, text, font=font, fill="black", anchor=anchor)
    arrow(start, end)

image.save(f"{script_dir}/data/Geometry.png")
