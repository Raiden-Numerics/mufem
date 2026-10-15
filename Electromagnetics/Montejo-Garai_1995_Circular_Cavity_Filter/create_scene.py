"""Render results/scene_electric_field_12GHz.png and _14GHz.png from the output of case.py.

Run with `pvpython create_scene.py` after the case. The scenes show the magnitude of the real
part of the electric field (the field at wt = 0) at the two visualized frequencies.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

from casekit.paraview_scene import (
    color_by,
    new_view,
    read_output,
    save,
    scene,
    set_camera,
    show,
)

# Two WR75 waveguides of 20 mm, two irises of 1 mm and the cavity of 100 mm along z.
total_length = 20e-3 + 1e-3 + 100e-3 + 1e-3 + 20e-3

view = new_view((1200, 650))
# Onto the middle of the filter from 14 deg above the x-z plane, 48 deg from -x toward -z.
set_camera(
    view,
    (-0.6830, 0.2588, -0.6830 - total_length / 2),
    (0, 1, 0),
    (0.0, 0.0, total_length / 2),
    parallel_scale=0.03,
)

for index, frequency in enumerate(["12GHz", "14GHz"]):
    with scene(view):
        display = show(read_output(case_dir, index), view)
        color_by(
            display,
            view,
            "Electric Field-Real",
            "Electric Field [V/m]",
            [0.0, 1000.0, 2000.0, 3000.0],
            component="Magnitude",
        )
        save(view, case_dir / "results" / f"scene_electric_field_{frequency}.png", crop=False)
