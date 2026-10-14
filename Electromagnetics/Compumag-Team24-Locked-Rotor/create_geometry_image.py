"""Render data/Geometry.png from geometry.step with the netgen viewer and label the bodies.

The view looks along -z with y up, as the animation of create_scene.py, turned by 20 deg about
y to show the depth of the air volume. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python create_geometry_image.py
"""

import math
from pathlib import Path

from netgen.occ import OCCGeometry

from casekit.netgen_image import Labels, snapshot, trim

case_dir = Path(__file__).resolve().parent

turn = math.radians(20.0)
solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids
image = snapshot(
    solids,
    direction=(-math.sin(turn), 0.0, math.cos(turn)),
    up=(0, 1, 0),
    zoom=-15,
    size=(1969, 1135),
)

labels = Labels(image, font_size=44)
labels.text((1060, 290), "Air")
for text, position, anchor, start, end in [
    ("Upper Coil", (860, 395), "rm", (870, 400), (972, 440)),
    ("Lower Coil", (860, 745), "rm", (870, 740), (972, 695)),
    ("Stator", (1330, 470), "lm", (1318, 475), (1228, 520)),
    ("Rotor", (1330, 620), "lm", (1318, 620), (1120, 575)),
]:
    labels.text(position, text, anchor)
    labels.arrow(start, end, head=22)

trim(image).save(case_dir / "data" / "Geometry.png")
