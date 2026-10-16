"""Render data/Vis_MagneticFluxDensity.png and data/Mesh.png from the output of case.py.

Run with `python create_scene.py` after the case (needs PyVista). Both images use the isometric
view along (-1, -1, 1) onto the symmetry planes x = 0 and y = 0, with z up, as data/Geometry.png.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

from casekit.pyvista_scene import (
    bodies,
    color_by,
    new_plotter,
    read_output,
    save,
    set_camera,
    show,
)

data = read_output(case_dir)

# Magnetic flux density in the yoke, the pole and the coil.
plotter = new_plotter((1900, 1600))
parts = bodies(data, ["Yoke", "Pole", "Coil"])
color_by(
    plotter,
    parts,
    "Magnetic Flux Density",
    "Magnetic Flux Density [T]",
    [0.0, 0.5, 1.0, 1.5, 2.0, 2.5],
    "%.1f",
    vertical=True,
    position=(0.78, 0.3),
)
set_camera(plotter, (-1, -1, 1), (0, 0, 1), bounds=parts.bounds)
save(plotter, case_dir / "data" / "Vis_MagneticFluxDensity.png")

# Mesh of all bodies.
plotter = new_plotter((1600, 1600))
for name, color in [
    ("Air", (0.96, 0.89, 0.83)),
    ("Yoke", (0.6, 0.6, 0.6)),
    ("Pole", (0.6, 0.6, 0.6)),
    ("Coil", (0.72, 0.45, 0.2)),
]:
    show(plotter, bodies(data, [name]), color, edges=True)
set_camera(plotter, (-1, -1, 1), (0, 0, 1), bounds=data.bounds)
save(plotter, case_dir / "data" / "Mesh.png")
