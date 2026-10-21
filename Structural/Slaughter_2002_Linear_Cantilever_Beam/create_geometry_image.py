"""Render data/Geometry.png from geometry.step with the netgen viewer.

The geometry is shown in the view of the scene of create_scenes() in case.py, with the clamped
and the loaded end labeled. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python create_geometry_image.py
"""

from pathlib import Path

from netgen.occ import OCCGeometry

from casekit.images import pad, trim
from casekit.netgen_image import Labels, snapshot

case_dir = Path(__file__).resolve().parent

solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids
image = trim(snapshot(solids, direction=(0.4, 0.3, 1.0), up=(0, 1, 0)))

# Room above the beam for the labels.
image = pad(image, left=150, top=110, right=150)
labels = Labels(image)
for text, x, tip in [("Clamped (x = 0)", 235, 152), ("Loaded (x = L)", 1453, 345)]:
    labels.text((x, 40), text)
    labels.arrow((x, 65), (x, tip))

image.save(case_dir / "data" / "Geometry.png")
