"""Render data/Geometry.png and data/Geometry_Magnets.png from geometry.step with netgen.

Both images look from the side of the animation of create_animation.py, 50 deg from below
(39 deg there), so that the edge of the air domain clears the magnets. The magnet-side back
iron covers the magnets in this view, so the second image leaves it out. Needs a display;
headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python netgen_geometry_image.py
"""

import math
from pathlib import Path

from netgen.occ import OCCGeometry

from casekit.netgen_image import content_box, snapshot, trim

case_dir = Path(__file__).resolve().parent

solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids

# The faces between the magnets and their back iron carry no color in the STEP file: give
# them the color of their magnet.
for solid in solids:
    if solid.name.startswith("Magnet"):
        color = next(face.col for face in solid.faces if face.col is not None)
        for face in solid.faces:
            if face.col is None:
                face.col = color

# From -y, 50 deg below the horizontal, with z up.
elevation = math.radians(50.0)
view = dict(direction=(0.0, -math.cos(elevation), -math.sin(elevation)), up=(0, 0, 1))
images = {
    "Geometry.png": snapshot(solids, **view),
    "Geometry_Magnets.png": snapshot(
        [s for s in solids if s.name != "Back Iron::Magnet Side"], **view
    ),
}

# Crop both images to the same box, so that they show the brake at the same scale.
box = content_box(*images.values())
for name, image in images.items():
    trim(image, box=box).save(case_dir / "data" / name)
