"""Render data/Geometry.png from geometry.step with the netgen viewer.

The view is the isometric view of create_scenes() in case.py onto the symmetry planes x = 0
and y = 0, with the bodies labeled. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python create_geometry_image.py
"""

from pathlib import Path

from netgen.occ import OCCGeometry

from casekit.images import trim
from casekit.netgen_image import Labels, snapshot

case_dir = Path(__file__).resolve().parent

solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids
image = trim(snapshot(solids, direction=(-1, -1, 1), up=(0, 0, 1)))

labels = Labels(image)
labels.text((200, 300), "Air")
for text, position, anchor, start, end in [
    ("Coil", (280, 690), "rm", (290, 690), (352, 690)),
    ("Yoke", (590, 600), "lm", (580, 600), (512, 620)),
    ("Pole", (625, 880), "lm", (615, 875), (420, 760)),
]:
    labels.text(position, text, anchor)
    labels.arrow(start, end)

image.save(case_dir / "data" / "Geometry.png")
