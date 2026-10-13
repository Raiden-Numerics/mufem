"""Render data/Geometry.png from geometry.step with the netgen viewer and label the bodies.

Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python netgen_geometry_image.py
"""

import math
import os

import matplotlib
import netgen
import netgen.gui
from netgen.occ import Glue, OCCGeometry
from PIL import Image, ImageDraw, ImageFont

script_dir = os.path.dirname(os.path.abspath(__file__))
width, height = 1969, 1135

shape = OCCGeometry(f"{script_dir}/geometry.step").shape
OCCGeometry(Glue(shape.solids)).Draw()

tk = netgen.gui.win.tk
tk.eval(f"wm geometry . {width}x{height}")
netgen.Redraw(blocking=True)
tk.eval("Ng_MouseMove 0 0 25 20 rotate")
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


draw.text((940, 230), "Air", font=font, fill="black", anchor="mm")
for text, position, anchor, start, end in [
    ("Upper Coil", (590, 560), "rm", (600, 552), (940, 470)),
    ("Lower Coil", (590, 665), "rm", (600, 672), (930, 742)),
    ("Stator", (1330, 520), "lm", (1318, 525), (1252, 580)),
    ("Rotor", (1330, 665), "lm", (1318, 665), (1112, 625)),
]:
    draw.text(position, text, font=font, fill="black", anchor=anchor)
    arrow(start, end)

image.save(f"{script_dir}/data/Geometry.png")
