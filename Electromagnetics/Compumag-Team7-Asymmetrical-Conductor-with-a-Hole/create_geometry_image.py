"""Render data/Geometry.png from geometry.step with the netgen viewer.

The view is the one of the animation of create_scenes() in case.py. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python create_geometry_image.py
"""

from pathlib import Path

from netgen.occ import OCCGeometry

from casekit.images import trim
from casekit.netgen_image import snapshot

case_dir = Path(__file__).resolve().parent

solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids
# The camera of the animation of create_scenes() in case.py (position and focal point there), z up.
position = (-0.3697352196806951, 0.3392467327757224, 0.22955715848836572)
focal_point = (-0.3041336634862759, 0.31113183987720244, 0.20412014606490986)
image = snapshot(
    solids,
    direction=[p - f for p, f in zip(position, focal_point)],
    up=(0, 0, 1),
)
trim(image).save(case_dir / "data" / "Geometry.png")
