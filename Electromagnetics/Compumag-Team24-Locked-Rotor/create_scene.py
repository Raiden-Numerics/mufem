"""Render results/Scene_ElementType.png and results/Result_Animation.gif from the case output.

Run with `python create_scene.py` after the case (needs PyVista). The case exports the fields
of every time step to VisualizationOutput/ and writes the coil current and the rotor torque over
time to VisualizationOutput/Scene_Data.npz. Each frame of the animation is one window: the
scene on the left and the plots of case.py as a matplotlib chart on the right.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import matplotlib.pyplot as plt
import numpy as np
import pyvista as pv

from casekit import PlotStyle, xy_axes
from casekit.pyvista_scene import output_files, save, save_gif, screenshot, theme

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
# show as quads. The color bar sits in the free space to the right of the rotor.
plotter = pv.Plotter(theme=theme, off_screen=True, window_size=(2000, 1500))
plotter.add_mesh(
    read_iron_and_coils(files[0]),
    scalars="Element Type",
    clim=(4.0, 6.0),  # tetrahedra and prisms
    show_edges=True,
    scalar_bar_args=dict(
        n_labels=3,
        fmt=" %.0f",
        position_x=0.9,
        position_y=0.01,
        title_font_size=40,
        label_font_size=36,
    ),
)
plotter.camera_position = [(-0.012, 0.06, 0.16), (0.0, 0.045, -0.006), (0, 1, 0)]
plotter.camera.parallel_scale = 0.0448
save(plotter, case_dir / "results" / "Scene_ElementType.png")

# Animation: the electric current density from +z and the coil current and the rotor torque of
# case.py up to the time step. The chart is drawn without anti-aliasing, with which VTK
# misplaces it off screen.
plotter = pv.Plotter(
    theme=theme,
    off_screen=True,
    window_size=(1800, 800),
    shape=(1, 2),
    col_weights=[0.55, 0.45],
    border=False,
)
plotter.subplot(0, 1)
plotter.renderer.disable_anti_aliasing()
fig, (ax_current, ax_torque) = plt.subplots(2, 1, dpi=100, layout="constrained")
plotter.add_chart(pv.ChartMPL(fig))
plotter.subplot(0, 0)

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
    plotter.add_mesh(
        read_iron_and_coils(path),
        scalars="Electric Current Density",
        clim=(0.0, 3.0e5),
        name="field",
        scalar_bar_args=dict(
            title="Current Density [A/m²]",
            n_labels=4,
            fmt=" %.0e",
            height=0.7,
            position_x=0.8,
            position_y=0.12,
            title_font_size=24,
            label_font_size=20,
        ),
    )
    if i == 0:
        plotter.view_xy()
        plotter.camera.focal_point = (0.03, 0.0, 0.0)
        plotter.camera.position = (0.03, 0.0, 1.0)
        plotter.camera.parallel_scale = 0.11
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
    frames.append(screenshot(plotter))
plotter.close()

save_gif(frames, case_dir / "results" / "Result_Animation.gif")
