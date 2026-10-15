"""Render data/Geometry.png from geometry.step with the netgen viewer.

The view is the isometric view of the scene results/TEAM-13-Results.png. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python create_geometry_image.py
"""

from pathlib import Path

from netgen.occ import OCCGeometry

from casekit.images import trim
from casekit.netgen_image import snapshot

case_dir = Path(__file__).resolve().parent

solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids
# Isometric view along (1, 1, 1) with z up, as results/TEAM-13-Results.png.
image = snapshot(solids, direction=(1, 1, 1), up=(0, 0, 1))
trim(image).save(case_dir / "data" / "Geometry.png")
