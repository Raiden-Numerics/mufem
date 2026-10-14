"""Render data/Vis_MagneticFluxDensity.png and data/Mesh.png from the output of case.py.

Run with `pvpython create_scene.py` after the case. Both images use the isometric view along
(-1, -1, 1) onto the symmetry planes x = 0 and y = 0, with z up, as data/Geometry.png.
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

data = read_output(case_dir)


def view_onto(view, source):
    source.UpdatePipeline()
    bounds = source.GetDataInformation().GetBounds()
    center = [(bounds[2 * i] + bounds[2 * i + 1]) / 2 for i in range(3)]
    set_camera(view, (-1, -1, 1), (0, 0, 1), center, parallel_scale=1.0, bounds=bounds)


# Magnetic flux density in the yoke, the pole and the coil.
view = new_view((1900, 1600))
parts = pvs.ExtractBlock(Input=data, Selectors=["/Root/Yoke", "/Root/Pole", "/Root/Coil"])
display = show(parts, view)
color_by(
    display,
    view,
    "Magnetic Flux Density",
    "Magnetic Flux Density [T]",
    [0.0, 0.5, 1.0, 1.5, 2.0, 2.5],
    "%.1f",
    orientation="Vertical",
    position=(0.78, 0.3),
    component="Magnitude",
)
view_onto(view, parts)
save(view, case_dir / "data" / "Vis_MagneticFluxDensity.png")

# Mesh of all bodies.
view = new_view((1600, 1600))
for name, color in [
    ("Air", (0.96, 0.89, 0.83)),
    ("Yoke", (0.6, 0.6, 0.6)),
    ("Pole", (0.6, 0.6, 0.6)),
    ("Coil", (0.72, 0.45, 0.2)),
]:
    show(pvs.ExtractBlock(Input=data, Selectors=[f"/Root/{name}"]), view, color, edges=True)
view_onto(view, data)
save(view, case_dir / "data" / "Mesh.png")
