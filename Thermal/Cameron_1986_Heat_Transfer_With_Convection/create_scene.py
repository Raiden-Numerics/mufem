"""Render results/Scene_Temperature.png and data/Mesh.png from the output of case.py.

Run with `pvpython create_scene.py` after the case. The plate is seen from the front (onto the
x-y plane), as data/Geometry.png.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import paraview.simple as pvs

from casekit.images import place
from casekit.paraview_scene import (
    color_by,
    new_view,
    read_output,
    save,
    scene,
    set_camera,
    show,
)

view = new_view((1200, 1400))
data = read_output(case_dir)

# Temperature, front view onto the plate (0.6 m x 1.0 m), shifted so that the color bar fits on
# the right.
with scene(view):
    temperature = pvs.Calculator(Input=data)
    temperature.ResultArrayName = "Temperature [°C]"
    temperature.Function = '"Temperature" - 273.15'

    display = show(temperature, view)
    color_by(
        display,
        view,
        "Temperature [°C]",
        "Temperature [°C]",
        [0.0, 25.0, 50.0, 75.0, 100.0],
        orientation="Vertical",
        position=(0.74, 0.3),
    )
    set_camera(view, (0, 0, 1), (0, 1, 0), (0.42, 0.5, 0.005), parallel_scale=0.55)
    save(view, case_dir / "results" / "Scene_Temperature.png")

# Mesh, in the flat color of the plate in data/Geometry.png and at the size and position of the
# plate there (see create_geometry_image.py), so that both images of Figure 1 match.
display = show(data, view, color=(0.02, 0.69, 0.5), edges=True)
display.Ambient = 1.0
display.Diffuse = 0.0
set_camera(view, (0, 0, 1), (0, 1, 0), (0.3, 0.5, 0.005), parallel_scale=0.52)
save(view, case_dir / "data" / "Mesh.png", crop=False)
place(case_dir / "data" / "Mesh.png", (1390, 1520), left=250, top=110, width=780, height=1300)
