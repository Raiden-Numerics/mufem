"""Render results/Scene_Deformation.png from the output of case.py.

Run with `pvpython create_scene.py` after the case. The scene shows the deformed beam, colored by
the von Mises stress, with the edges of the undeformed beam.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import paraview.simple as pvs

from casekit.paraview_scene import (
    color_by,
    new_view,
    read_output,
    save,
    set_camera,
    show,
)

view = new_view((1600, 900))
data = read_output(case_dir)

# The undeformed beam as its edges.
edges = pvs.FeatureEdges(Input=pvs.ExtractSurface(Input=pvs.MergeBlocks(Input=data)))
edges.BoundaryEdges = 0
edges.NonManifoldEdges = 0
outline = pvs.Show(edges, view)
pvs.ColorBy(outline, None)
outline.AmbientColor = outline.DiffuseColor = [0.4, 0.4, 0.4]
outline.LineWidth = 2.0

# The deformed beam, the displacement scaled 50 times: the tip deflection (1.9 mm) is invisible
# at true scale.
stress = pvs.Calculator(Input=data)
stress.ResultArrayName = "Stress"
stress.Function = '"Von Mises Stress" / 1000'  # [kPa]
warp = pvs.WarpByVector(Input=stress)
warp.Vectors = ["POINTS", "Displacement"]
warp.ScaleFactor = 50.0

display = show(warp, view)
color_by(
    display,
    view,
    "Stress",
    "Von Mises Stress [kPa]",
    [0.0, 20.0, 40.0, 60.0],
    position=(0.35, 0.05),
    length=0.3,
)

# Mostly onto the side of the beam so that the bending shows, with the load direction (y) up,
# as data/Geometry.png.
set_camera(view, (0.4, 0.3, 1.0), (0, 1, 0), (0.5, -0.03, 0.0), parallel_scale=0.36)
save(view, case_dir / "results" / "Scene_Deformation.png")
