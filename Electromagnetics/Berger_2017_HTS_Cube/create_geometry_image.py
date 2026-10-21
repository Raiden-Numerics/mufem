"""Render data/Geometry.png from geometry.step with the netgen viewer.

The cube is enlarged six times for visibility; the view looks onto the symmetry planes x = 0
and z = 0. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python create_geometry_image.py
"""

import math
from pathlib import Path

from netgen.occ import Glue, OCCGeometry, Pnt

from casekit.netgen_image import snapshot, trim

case_dir = Path(__file__).resolve().parent

solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids

# The 5 mm cube is tiny in the 100 mm air ball: enlarge it for the image.
cube = next(solid for solid in solids if solid.name == "Cube").Scale(Pnt(0, 0, 0), 6)
air = next(solid for solid in solids if solid.name == "Air") - cube
shape = Glue([cube, air])

# Draw the faces between cube and air in the cube color, not the translucent air color.
for face in shape.solids[0].faces:
    face.col = cube.faces[0].col

# The isometric view along (-1, 1, -1), turned by -15 deg about y, with the applied field (y) up:
# x' = x cos + z sin, z' = z cos - x sin.
turn = math.radians(-15.0)
direction = (-math.cos(turn) - math.sin(turn), 1.0, math.sin(turn) - math.cos(turn))
image = snapshot(shape.solids, direction=direction, up=(0, 1, 0))
trim(image).save(case_dir / "data" / "Geometry.png")
