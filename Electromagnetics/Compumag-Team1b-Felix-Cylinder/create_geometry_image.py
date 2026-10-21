"""Render data/Geometry.png from geometry.step with the netgen viewer.

The view is the one of the scene of create_scenes() in case.py, horizontal along (-1, 0, 1) so
that the applied field (y) stays vertical; three arrows show the applied field. Needs a display;
headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python create_geometry_image.py
"""

from pathlib import Path

from netgen.occ import OCCGeometry

from casekit.images import trim
from casekit.netgen_image import Labels, snapshot

case_dir = Path(__file__).resolve().parent

solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids
image = trim(snapshot(solids, direction=(-1, 0, 1), up=(0, 1, 0)))

# The applied field B_y(t): three arrows along -y with a label.
labels = Labels(image)
x, top, length = 90, 360, 200
for dx in (0, 45, 90):
    labels.arrow((x + dx, top), (x + dx, top + length + 10), width=9, head=26, spread=0.46)
labels.formula((x - 10, top - 75), "$B_y(t)$")

image.save(case_dir / "data" / "Geometry.png")
