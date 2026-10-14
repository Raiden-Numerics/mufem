"""Render data/Geometry.png from geometry.step with the netgen viewer.

The geometry is shown in the isometric view of the scenes of create_scene.py.
Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python netgen_geometry_image.py
"""

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
# camera (screen right, up, toward the viewer) maps onto these axes: the isometric view along
# (1, 1, 1) with the stacking direction of the layers (y) up.
origin = Pnt(0, 0, 0)
shape = (
    shape.Rotate(Axis(origin, X), 45.0)
    .Rotate(Axis(origin, Y), -35.26)
    .Rotate(Axis(origin, Z), -30.0)
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
# Label the layers, with room on the right for the labels.
padded = Image.new("RGB", (image.width + 330, image.height), "white")
padded.paste(image, (0, 0))
image = padded
draw = ImageDraw.Draw(image)
font = ImageFont.truetype(f"{matplotlib.get_data_path()}/fonts/ttf/DejaVuSans-Bold.ttf", 28)

for text, label_y, end in [
    ("Heat sink", 380, (915, 380)),
    ("TIM 2", 455, (906, 503)),
    ("Lid", 515, (906, 513)),
    ("TIM 1", 575, (906, 525)),
    ("Die", 635, (906, 536)),
]:
    draw.text((1010, label_y), text, font=font, fill="black", anchor="lm")
    draw.line([(1000, label_y), end], fill="black", width=3)

image.save(f"{script_dir}/data/Geometry.png")
