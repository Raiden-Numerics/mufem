"""Render results/Deformation.gif from the output of case.py.

Run with `pvpython create_scene.py` after the case (requires `ffmpeg`). The problem is linear,
so the animation scales the computed solution with the load from zero to its full value.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import paraview.simple as pvs

from casekit.images import write_gif
from casekit.paraview_scene import (
    color_by,
    new_view,
    read_output,
    save,
    set_camera,
    show,
)

# The tip deflection (1.9 mm) is invisible at true scale.
displacement_scale = 50.0
frames = 30

view = new_view((1600, 900))
data = read_output(case_dir)

# Von Mises stress [kPa] at the load fraction of each frame (set in the loop below).
stress = pvs.Calculator(Input=data)
stress.ResultArrayName = "Stress"
stress.Function = '"Von Mises Stress" / 1000'
warp = pvs.WarpByVector(Input=stress)
warp.Vectors = ["POINTS", "Displacement"]

display = show(warp, view)
color_by(
    display,
    view,
    "Stress",
    "Von Mises Stress [kPa]",
    [0.0, 20.0, 40.0, 60.0],
    position=(0.06, 0.1),
    length=0.3,
)

# Mostly onto the side of the beam so that the bending shows, with the load direction (y) up,
# as data/Geometry.png; the frame fits the beam at full load.
set_camera(view, (0.4, 0.3, 1.0), (0, 1, 0), (0.5, -0.03, 0.0), parallel_scale=0.36)

paths = []
for i in range(frames + 1):
    load = i / frames
    stress.Function = f'"Von Mises Stress" * {load} / 1000'
    warp.ScaleFactor = displacement_scale * load
    paths.append(case_dir / "vis" / f"Scene_{i:03d}.png")
    save(view, paths[-1], crop=False)

# Hold the full load for one second at the end of each cycle.
write_gif(paths + 8 * [paths[-1]], case_dir / "results" / "Deformation.gif")
