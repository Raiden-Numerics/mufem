"""Render data/Vis_MagneticFluxDensity.png and data/Mesh.png from the output of case.py.

Run with `python create_scene.py` after the case (needs PyVista). Both images use the isometric
view along (-1, -1, 1) onto the symmetry planes x = 0 and y = 0, with z up, as data/Geometry.png.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import pyvista as pv

from casekit.pyvista_scene import add_colorbar, output_files, save, theme

bodies = pv.read(output_files(case_dir)[0])

# Mesh of all bodies.
plotter = pv.Plotter(theme=theme, off_screen=True, window_size=(1600, 1600))
iron, copper, air = (0.6, 0.6, 0.6), (0.72, 0.45, 0.2), (0.96, 0.89, 0.83)
for name, color in {"Air": air, "Yoke": iron, "Pole": iron, "Coil": copper}.items():
    plotter.add_mesh(bodies[name], color=color, show_edges=True)
plotter.view_vector((-1, -1, 1), viewup=(0, 0, 1))
save(plotter, case_dir / "data" / "Mesh.png")

# Magnetic flux density in the yoke, the pole and the coil.
del bodies["Air"]
plotter = pv.Plotter(theme=theme, off_screen=True, window_size=(1100, 1600))
actor = plotter.add_mesh(bodies, scalars="Magnetic Flux Density", clim=(0.0, 2.5))
plotter.view_vector((-1, -1, 1), viewup=(0, 0, 1))
plotter.renderer.ResetCameraScreenSpace()  # tight fit on screen (VTK, no PyVista equivalent)
add_colorbar(plotter, actor, "Magnetic Flux Density [T]")
save(plotter, case_dir / "data" / "Vis_MagneticFluxDensity.png")
