"""Render results/Scene_Electric_Field.png from the output of case.py.

Run with `pvpython create_scene.py` after the case. The scene shows the x-component of the
electric field in the cross-section z = 0 of the spherical domain.
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

view = new_view((900, 1000))

section = pvs.Slice(Input=read_output(case_dir))
section.SliceType = "Plane"
section.SliceType.Origin = [0.0, 0.0, 0.0]
section.SliceType.Normal = [0.0, 0.0, 1.0]

field = pvs.Calculator(Input=section)
field.ResultArrayName = "Electric Field x"
field.Function = '"Electric Field_X" / 1e9'

display = show(field, view)
display.NonlinearSubdivisionLevel = 2
color_by(
    display,
    view,
    "Electric Field x",
    "Electric Field, x-Component [GV/m]",
    [-1.0, -0.5, 0.0, 0.5, 1.0],
    "%g",
    position=(0.3, 0.03),
)

# Front view onto the section (radius 10 m), with room for the color bar below it.
set_camera(view, (0, 0, 1), (0, 1, 0), (0.0, -2.0, 0.0), parallel_scale=12.2)
save(view, case_dir / "results" / "Scene_Electric_Field.png")
