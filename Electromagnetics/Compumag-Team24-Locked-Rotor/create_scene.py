"""Render results/Scene_ElementType.png and results/Result_Animation.gif from the case output.

Run with `python create_scene.py` after the case (needs PyVista). The case exports the fields
of every time step to VisualizationOutput/ and writes the coil current and the rotor torque over
time to VisualizationOutput/Scene_Data.npz. Each frame of the animation is one matplotlib
figure: the scene, its color bar and the plots of case.py.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import matplotlib.pyplot as plt
import numpy as np

from casekit import PlotStyle, xy_axes
from casekit.images import figure_image, save_gif
from casekit.pyvista_scene import (
    bodies,
    color_by,
    colorbar,
    new_plotter,
    read_output,
    read_scene_data,
    render,
    save,
    set_camera,
)

tables = case_dir / "data" / "tables"
monitors = read_scene_data(case_dir)
current_ref = np.loadtxt(tables / "Table_3_Coil_Current.csv", delimiter=",", skiprows=1)
torque_ref = np.loadtxt(tables / "Table_4_Torque.csv", delimiter=",", skiprows=1)


def read_step(index):
    return bodies(read_output(case_dir, index), ["Stator", "Rotor", "Lower Coil", "Upper Coil"])


# Element types: the camera looks from +z at the symmetry plane z = 0, where the prism layers
# show as quads. The color bar sits in the free space to the right of the rotor.
plotter = new_plotter((1989, 1471))
color_by(
    plotter,
    read_step(0),
    "Element Type",
    "Element Type",
    [4.0, 5.0, 6.0],  # tetrahedra and prisms
    vertical=True,
    position=(0.87, 0.05),
    length=0.5,
    thickness=0.054,
    title_size=40,
    label_size=36,
    edges=True,
)
set_camera(plotter, (-0.012, 0.015, 0.166), (0, 1, 0), (0.0, 0.045, -0.006), parallel_scale=0.0448)
save(plotter, case_dir / "results" / "Scene_ElementType.png")


# Animation: the electric current density from +z with its color bar, and the coil current and
# the rotor torque of case.py up to the time step on the right.
def scene_image(index):
    plotter = new_plotter((1400, 1400))
    color_by(
        plotter,
        read_step(index),
        "Electric Current Density",
        "",
        [0.0, 1.0e5, 2.0e5, 3.0e5],
        bar=False,
    )
    set_camera(plotter, (0, 0, 1), (0, 1, 0), (0.0, 0.0, 0.0), parallel_scale=0.106)
    image = render(plotter)
    plotter.close()
    return image


common = dict(
    style=PlotStyle.LINE_AND_POINTS,
    reference_style=PlotStyle.POINTS,
    reference_label="Allen (1996)",
    xlabel="Time [s]",
    xlim=(0.0, 0.15),
    xticks=[0.0, 0.05, 0.1, 0.15],
    legend_loc="upper left",
)

fig = plt.figure(figsize=(16.0, 7.2), dpi=75, layout="constrained")
grid = fig.add_gridspec(2, 3, width_ratios=[7.0, 0.25, 6.5], wspace=0.04)
ax_scene = fig.add_subplot(grid[:, 0])
ax_bar = fig.add_subplot(grid[:, 1])
ax_current = fig.add_subplot(grid[0, 2])
ax_torque = fig.add_subplot(grid[1, 2])
colorbar(ax_bar, "Electric Current Density [A/m²]", [0.0, 1.0e5, 2.0e5, 3.0e5])

frames = []
for i in range(len(monitors["coil_current"])):
    for ax in (ax_scene, ax_current, ax_torque):
        ax.clear()
    ax_scene.imshow(scene_image(i))
    ax_scene.set_axis_off()
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
    frames.append(figure_image(fig))
plt.close(fig)

save_gif(frames, case_dir / "results" / "Result_Animation.gif")
