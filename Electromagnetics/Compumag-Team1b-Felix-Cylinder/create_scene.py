"""Render results/Scene_Electric_Current_Density.png from the output of case.py.

Run with `pvpython create_scene.py` after the case. The eddy currents in the cylinder at the
final time are shown as arrows, in the horizontal view along (-1, 0, 1) with y up of
data/Geometry.png.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import paraview.simple as pvs

from casekit.paraview_scene import (
    blocks,
    color_by,
    new_view,
    read_output,
    save,
    set_camera,
    show,
)

view = new_view((1600, 1300))
cylinder = blocks(read_output(case_dir), ["Cylinder"])
show(cylinder, view, color=(0.69, 0.69, 0.69))

glyph = pvs.Glyph(Input=cylinder, GlyphType="Arrow")
glyph.OrientationArray = ["POINTS", "Electric Current Density"]
glyph.ScaleArray = ["POINTS", "Electric Current Density"]
glyph.ScaleFactor = 1e-08
glyph.GlyphMode = "All Points"

color_by(
    show(glyph, view),
    view,
    "Electric Current Density",
    "Electric Current Density [A/m²]",
    [0.0, 1.0e6, 2.0e6, 3.0e6],
    "%.0e",
    position=(0.35, 0.05),
    length=0.3,
    thickness=40,
    title_size=32,
    label_size=28,
    component="Magnitude",
)

# The cylinder (radius 0.07 m, length 0.2 m) with room for the color bar below it.
set_camera(view, (-1, 0, 1), (0, 1, 0), (0.0, -0.016, 0.0), parallel_scale=0.12)
save(view, case_dir / "results" / "Scene_Electric_Current_Density.png")
