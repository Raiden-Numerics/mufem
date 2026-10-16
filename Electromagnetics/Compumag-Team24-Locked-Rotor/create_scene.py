"""Render results/Scene_ElementType.png and results/Result_Animation.gif from the case output.

Run with `python create_scene.py` after the case (needs PyVista). The case exports the fields
of every time step to VisualizationOutput/ and writes the coil current and the rotor torque over
time to VisualizationOutput/Scene_Data.npz. Each frame of the animation is one window: the
scene on the left and its color bar and the plots of case.py as a matplotlib chart on the right.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import matplotlib.pyplot as plt
import numpy as np
import pyvista as pv

from casekit import PlotStyle, xy_axes
from casekit.pyvista_scene import (
    add_chart,
    add_colorbar,
    output_files,
    save,
    save_gif,
    theme,
)

tables = case_dir / "data" / "tables"
monitors = np.load(case_dir / "VisualizationOutput" / "Scene_Data.npz")
current_ref = np.loadtxt(tables / "Table_3_Coil_Current.csv", delimiter=",", skiprows=1)
torque_ref = np.loadtxt(tables / "Table_4_Torque.csv", delimiter=",", skiprows=1)
files = output_files(case_dir)


def read_iron_and_coils(path):
    bodies = pv.read(path)
    del bodies["Air"]
    return bodies


# Element types: the camera looks from +z at the symmetry plane z = 0, where the prism layers
# show as quads.
plotter = pv.Plotter(theme=theme, off_screen=True, window_size=(2000, 1500))
actor = plotter.add_mesh(
    read_iron_and_coils(files[0]),
    scalars="Element Type",
    clim=(4.0, 6.0),  # tetrahedra and prisms
    show_edges=True,
)
plotter.camera_position = [(-0.012, 0.06, 0.16), (0.0, 0.045, -0.006), (0, 1, 0)]
plotter.camera.parallel_scale = 0.0448
add_colorbar(plotter, actor, "Element Type", location="bottom").set_ticks([4, 5, 6])
save(plotter, case_dir / "results" / "Scene_ElementType.png")

# Animation: the electric current density from +z with its color bar, and the coil current and
# the rotor torque of case.py up to the time step as a matplotlib chart on the right.
plotter = pv.Plotter(
    theme=theme, off_screen=True, window_size=(1600, 800), shape=(1, 2), border=False
)
figure, (ax_current, ax_torque) = plt.subplots(2, 1, dpi=100, layout="constrained")
add_chart(plotter, figure)

common = dict(
    style=PlotStyle.LINE_AND_POINTS,
    reference_style=PlotStyle.POINTS,
    reference_label="Allen (1996)",
    xlabel="Time [s]",
    xlim=(0.0, 0.15),
    xticks=[0.0, 0.05, 0.1, 0.15],
    legend_loc="upper left",
)
frames = []
for i, path in enumerate(files):
    actor = plotter.add_mesh(
        read_iron_and_coils(path),
        scalars="Electric Current Density",
        clim=(0.0, 3.0e5),
        name="field",
    )
    if i == 0:
        plotter.view_xy()
        plotter.renderer.ResetCameraScreenSpace()  # tight fit on screen (VTK)
        add_colorbar(plotter, actor, "Current Density [A/m²]", dpi=100)
    for ax in (ax_current, ax_torque):
        ax.clear()
    xy_axes(
        ax_current,
        values=monitors["coil_current"][: i + 1],
        reference_values=current_ref,
        ylabel="Coil Current [A]",
        ylim=(0.0, 8.0),
        **common,
    )
    xy_axes(
        ax_torque,
        values=monitors["rotor_torque"][: i + 1],
        reference_values=torque_ref,
        ylabel="Rotor Torque [Nm]",
        ylim=(0.0, 3.5),
        **common,
    )
    frames.append(plotter.screenshot())
plotter.close()

save_gif(frames, case_dir / "results" / "Result_Animation.gif")
