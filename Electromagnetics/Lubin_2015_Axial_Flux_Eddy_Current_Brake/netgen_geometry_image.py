"""Render data/Geometry.png and data/Geometry_Magnets.png from geometry.step with netgen.

Both images look from the side of the animation of create_animation.py, 50 deg from below
(39 deg there), so that the edge of the air domain clears the magnets. The magnet-side back
iron covers the magnets in this view, so the second image leaves it out. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python netgen_geometry_image.py
"""

import os

import netgen
import netgen.gui
from netgen.occ import Axis, Glue, OCCGeometry, Pnt, X

from PIL import Image, ImageChops

script_dir = os.path.dirname(os.path.abspath(__file__))
width, height = 1600, 1200

solids = OCCGeometry(f"{script_dir}/geometry.step").shape.solids

# The faces between the magnets and their back iron carry no color in the STEP file: give
# them the color of their magnet.
for solid in solids:
    if solid.name.startswith("Magnet"):
        color = next(face.col for face in solid.faces if face.col is not None)
        for face in solid.faces:
            if face.col is None:
                face.col = color

# netgen shows x to the right, y up and z toward the viewer. Rotate the model so that the
# view comes from -y, 50 deg below the horizontal, with z up.
origin = Pnt(0, 0, 0)


def snapshot(shapes):
    shape = Glue(shapes).Rotate(Axis(origin, X), -140.0)
    OCCGeometry(Glue(shape.solids)).Draw()

    tk = netgen.gui.win.tk
    tk.eval(f"wm geometry . {width}x{height}")
    netgen.Redraw(blocking=True)
    tk.eval("Ng_MouseMove 0 0 0 -30 zoom")
    netgen.Redraw(blocking=True)
    return Image.fromarray(netgen.gui.Snapshot(width, height)).convert("RGB")


images = {
    "Geometry.png": snapshot(solids),
    "Geometry_Magnets.png": snapshot([s for s in solids if s.name != "Back Iron::Magnet Side"]),
}

# Trim the white margins of both images to the same box, keeping a small border.
border = 20
white = Image.new("RGB", (width, height), "white")
boxes = [ImageChops.difference(image, white).getbbox() for image in images.values()]
box = (
    max(min(b[0] for b in boxes) - border, 0),
    max(min(b[1] for b in boxes) - border, 0),
    min(max(b[2] for b in boxes) + border, width),
    min(max(b[3] for b in boxes) + border, height),
)
for name, image in images.items():
    image.crop(box).save(f"{script_dir}/data/{name}")
