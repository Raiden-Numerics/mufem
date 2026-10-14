"""Render data/Geometry.png from geometry.step with the netgen viewer.

The geometry is shown in the view of the scene of create_scene.py.
Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python netgen_geometry_image.py
"""

import io
import os

import matplotlib
import matplotlib.pyplot as plt
import netgen
import netgen.gui
from netgen.occ import Axis, Glue, OCCGeometry, Pnt, X, Y, Z

from PIL import Image, ImageDraw, ImageOps

matplotlib.use("Agg")
matplotlib.rcParams["mathtext.fontset"] = "cm"

script_dir = os.path.dirname(os.path.abspath(__file__))
width, height = 1600, 1200

shape = OCCGeometry(f"{script_dir}/geometry.step").shape

# netgen shows x to the right, y up and z toward the viewer. Rotate the model so that the
# camera (screen right, up, toward the viewer) maps onto these axes: a horizontal view along
# (-1, 0, 1), so that the applied field (y) stays vertical.
origin = Pnt(0, 0, 0)
shape = (
    shape.Rotate(Axis(origin, X), 0.0).Rotate(Axis(origin, Y), 45.0).Rotate(Axis(origin, Z), 0.0)
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
# The applied field B_y(t): three vertical arrows along -y with a label.
draw = ImageDraw.Draw(image)


def arrow(start, end, head=26):
    draw.line([start, end], fill="black", width=9)
    draw.polygon(
        [
            (end[0], end[1] + 10),
            (end[0] - 13, end[1] - head + 10),
            (end[0] + 13, end[1] - head + 10),
        ],
        fill="black",
    )


arrows_x, arrows_top, arrows_length = 90, 360, 200
for dx in (0, 45, 90):
    arrow((arrows_x + dx, arrows_top), (arrows_x + dx, arrows_top + arrows_length))

figure = plt.figure(figsize=(2, 1), dpi=100)
figure.text(0, 0, "$B_y(t)$", fontsize=40)
buffer = io.BytesIO()
figure.savefig(buffer, format="png", transparent=True, bbox_inches="tight", pad_inches=0)
plt.close(figure)
label = Image.open(buffer)
image.paste(label, (arrows_x - 10, arrows_top - 75), label)

image.save(f"{script_dir}/data/Geometry.png")
