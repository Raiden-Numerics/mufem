"""Render data/Mesh.png and the scenes results/Scene_*.png from the output of case.py.

Run with `pvpython create_scene.py` after the case. All images use the isometric view along
(1, 1, 1) with the stacking direction of the layers (y) up, as data/Geometry.png.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import paraview.simple as pvs  # noqa: E402

from casekit.paraview_scene import (  # noqa: E402
    color_by,
    new_view,
    place,
    read_output,
    save,
    set_camera,
    show,
)

view = new_view((1200, 1200))
data = read_output(case_dir)
view.ViewTime = data.TimestepValues[-1] if data.TimestepValues else 0.0
set_camera(view, (1, 1, 1), (0, 1, 0), (0.0, 0.0036, 0.0), parallel_scale=0.0125)

temperature = pvs.Calculator(Input=data)
temperature.ResultArrayName = "Temperature Rise"
temperature.Function = '"Temperature" - 273.15'

for array, title, labels, name in [
    ("Temperature Rise", "Temperature Rise [K]", [0.0, 0.2, 0.4, 0.6, 0.8, 1.0], "Temperature"),
    (
        "Specific Heat Capacity",
        "Specific Heat Capacity [J/(kg K)]",
        [300.0, 500.0, 700.0, 900.0],
        "Heat_Capacity",
    ),
    ("Density", "Density [kg/m³]", [0.0, 3000.0, 6000.0, 9000.0], "Density"),
    (
        "Thermal Conductivity",
        "Thermal Conductivity [W/(m K)]",
        [0.0, 100.0, 200.0, 300.0, 400.0],
        "Thermal_Conductivity",
    ),
]:
    display = show(temperature, view)
    color_by(
        display,
        view,
        array,
        title,
        labels,
        "%.1f" if labels[-1] < 10 else "%.0f",
        position=(0.3, 0.04),
        title_size=32,
        label_size=28,
    )
    save(view, case_dir / "results" / f"Scene_{name}.png")
    display.SetScalarBarVisibility(view, False)
    pvs.Hide(temperature, view)

# Mesh: the layers in their colors of data/Geometry.png, with the edges in black.
for name, color in [
    ("Die", "7f8d9b"),
    ("TIM1", "b1b159"),
    ("Lid", "b55b00"),
    ("TIM2", "27386d"),
    ("HeatSink", "627862"),
]:
    block = pvs.ExtractBlock(Input=data, Selectors=[f"/Root/{name}"])
    show(block, view, color=[int(color[i : i + 2], 16) / 255 for i in (0, 2, 4)], edges=True)
save(view, case_dir / "data" / "Mesh.png", crop=False)

# At the size of the package in data/Geometry.png (930 px wide, 20 px border), on a canvas of
# the same size, so that both images of Figure 1 show the package at the same scale.
place(case_dir / "data" / "Mesh.png", (1300, 852), left=20, width=930)
