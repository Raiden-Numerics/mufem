"""Render data/Geometry.png from geometry.step with the netgen viewer.

The package is shown in the isometric view of the scenes of create_scenes() in case.py, with
the layers labeled. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python create_geometry_image.py
"""

from pathlib import Path

from netgen.occ import OCCGeometry

from casekit.images import pad, trim
from casekit.netgen_image import Labels, snapshot

case_dir = Path(__file__).resolve().parent

solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids
# Isometric view along (1, 1, 1) with the stacking direction of the layers (y) up.
image = trim(snapshot(solids, direction=(1, 1, 1), up=(0, 1, 0)))

# Room on the right for the labels.
image = pad(image, right=330)
labels = Labels(image, font_size=28)
for text, label_y, end in [
    ("Heat sink", 380, (915, 380)),
    ("TIM 2", 455, (906, 503)),
    ("Lid", 515, (906, 513)),
    ("TIM 1", 575, (906, 525)),
    ("Die", 635, (906, 536)),
]:
    labels.text((1010, label_y), text, "lm")
    labels.line((1000, label_y), end)

image.save(case_dir / "data" / "Geometry.png")
