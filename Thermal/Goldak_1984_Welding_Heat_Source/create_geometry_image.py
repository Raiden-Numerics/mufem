"""Render data/Geometry.png from geometry.step with the netgen viewer.

The view is the one of the scenes of create_scenes() in case.py. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python create_geometry_image.py
"""

from pathlib import Path

from netgen.occ import OCCGeometry

from casekit.images import trim
from casekit.netgen_image import snapshot

case_dir = Path(__file__).resolve().parent

solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids
# The camera of the scenes of create_scenes(): onto the symmetry plane x = 0 and the top surface.
image = snapshot(solids, direction=(-0.25, 0.17, -0.15), up=(0, 1, 0))
trim(image).save(case_dir / "data" / "Geometry.png")
