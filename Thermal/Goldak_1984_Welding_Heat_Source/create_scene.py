"""Render results/Scene_Temperature.png and results/Scene_Goldak_Heat_Source.png.

Run with `pvpython create_scene.py` after the case. Both scenes show the modeled half plate
at the final time, onto the symmetry plane x = 0 (weld path) and the top surface y = 0.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import paraview.simple as pvs  # noqa: E402

from casekit.paraview_scene import (  # noqa: E402
    color_by,
    new_view,
    read_output,
    save,
    set_camera,
    show,
)

view = new_view((1600, 1000))
view.CameraViewAngle = 30.0
data = read_output(case_dir)

temperature = pvs.Calculator(Input=data)
temperature.ResultArrayName = "Temperature [°C]"
temperature.Function = '"Temperature" - 273.15'

for source, array, title, labels, label_format, name in [
    (
        temperature,
        "Temperature [°C]",
        "Temperature [°C]",
        [0.0, 500.0, 1000.0, 1500.0, 2000.0, 2500.0],
        "%.0f",
        "Scene_Temperature.png",
    ),
    (
        data,
        "VolumetricHeatSource",
        "Heat Source [W/m³]",
        [0.0, 2.0e9, 4.0e9, 6.0e9, 8.0e9],
        "%.0e",
        "Scene_Goldak_Heat_Source.png",
    ),
]:
    display = show(source, view)
    color_by(display, view, array, title, labels, label_format, position=(0.3, 0.03), thickness=30)
    # The whole half plate in frame, moved up away from the color bar below it.
    set_camera(
        view,
        (-0.25, 0.17, -0.15),
        (0, 1, 0),
        (0.03, -0.03, 0.17),
        bounds=(0.0, 0.15, -0.1, 0.0, 0.0, 0.3),
        shift_up=0.025,
    )
    save(view, case_dir / "results" / name)
    display.SetScalarBarVisibility(view, False)
    pvs.Hide(source, view)
