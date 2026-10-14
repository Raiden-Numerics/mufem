"""Render data/Geometry.png from geometry.step with the netgen viewer.

The geometry is shown in an isometric view.
Needs a display; headless:

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

# The 5 mm cube is tiny in the 100 mm air ball: enlarge it for the image (not to scale).
cube = next(solid for solid in shape.solids if solid.name == "Cube").Scale(Pnt(0, 0, 0), 6)
air = next(solid for solid in shape.solids if solid.name == "Air") - cube
shape = Glue([cube, air])

# Draw the faces between cube and air in the cube color, not the translucent air color.
cube_color = cube.faces[0].col
for face in shape.solids[0].faces:
    face.col = cube_color

# netgen shows x to the right, y up and z toward the viewer. Rotate the model so that the
# camera (screen right, up, toward the viewer) maps onto these axes: the isometric view along
# (-1, 1, -1), turned by -15 deg about y, onto the symmetry planes x = 0 and z = 0, with the
# applied field (y) up.
origin = Pnt(0, 0, 0)
shape = (
    shape.Rotate(Axis(origin, X), 140.77)
    .Rotate(Axis(origin, Y), 24.09)
    .Rotate(Axis(origin, Z), 161.57)
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
image.save(f"{script_dir}/data/Geometry.png")
