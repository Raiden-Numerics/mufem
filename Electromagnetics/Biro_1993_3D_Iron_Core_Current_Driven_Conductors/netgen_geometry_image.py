"""Render data/Geometry.png from geometry.step with the netgen viewer.

The geometry is turned so that the view matches the scenes of create_scene.py (core and
conductors seen from below). Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python netgen_geometry_image.py
"""

import os

import netgen
import netgen.gui
from netgen.occ import Axis, Glue, OCCGeometry, Pnt, X, Y, Z

from PIL import Image, ImageOps

script_dir = os.path.dirname(os.path.abspath(__file__))
width, height = 1600, 1200

shape = OCCGeometry(f"{script_dir}/geometry.step").shape

# netgen shows x to the right, y up and z toward the viewer. Rotate the model so that the
# camera of the scenes of create_scene.py (screen right, up, toward the viewer) maps onto
# these axes.
origin = Pnt(0, 0, 0)
shape = (
    shape.Rotate(Axis(origin, X), -124.73)
    .Rotate(Axis(origin, Y), 34.1)
    .Rotate(Axis(origin, Z), -21.24)
)

OCCGeometry(Glue(shape.solids)).Draw()

tk = netgen.gui.win.tk
tk.eval(f"wm geometry . {width}x{height}")
netgen.Redraw(blocking=True)
tk.eval("Ng_MouseMove 0 0 0 -35 zoom")
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
image.save(f"{script_dir}/data/Geometry.png")
