"""Render data/Geometry.png from geometry.step with the netgen viewer and label the bodies.

Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python netgen_geometry_image.py
"""

import math
import os

import matplotlib
import netgen
import netgen.gui
from netgen.occ import Axis, Glue, OCCGeometry, Pnt, Y
from PIL import Image, ImageDraw, ImageFont, ImageOps

script_dir = os.path.dirname(os.path.abspath(__file__))
width, height = 1969, 1135

shape = OCCGeometry(f"{script_dir}/geometry.step").shape
# netgen looks along -z with y up, as the animation of paraview_gif.py; a small turn about y
# shows the depth of the air volume.
shape = shape.Rotate(Axis(Pnt(0, 0, 0), Y), 20)
OCCGeometry(Glue(shape.solids)).Draw()

tk = netgen.gui.win.tk
tk.eval(f"wm geometry . {width}x{height}")
netgen.Redraw(blocking=True)
tk.eval("Ng_MouseMove 0 0 0 -15 zoom")
netgen.Redraw(blocking=True)

image = Image.fromarray(netgen.gui.Snapshot(width, height)).convert("RGBA")
draw = ImageDraw.Draw(image)
font = ImageFont.truetype(f"{matplotlib.get_data_path()}/fonts/ttf/DejaVuSans-Bold.ttf", 44)


def arrow(start, end, head=22):
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


draw.text((1060, 290), "Air", font=font, fill="black", anchor="mm")
for text, position, anchor, start, end in [
    ("Upper Coil", (860, 395), "rm", (870, 400), (972, 440)),
    ("Lower Coil", (860, 745), "rm", (870, 740), (972, 695)),
    ("Stator", (1330, 470), "lm", (1318, 475), (1228, 520)),
    ("Rotor", (1330, 620), "lm", (1318, 620), (1120, 575)),
]:
    draw.text(position, text, font=font, fill="black", anchor=anchor)
    arrow(start, end)

# Trim the white margins, keeping a small border.
border = 20
image = image.convert("RGB")
left, top, right, bottom = ImageOps.invert(image).getbbox()
image = image.crop(
    (
        max(left - border, 0),
        max(top - border, 0),
        min(right + border, image.width),
        min(bottom + border, image.height),
    )
)
image.save(f"{script_dir}/data/Geometry.png")
