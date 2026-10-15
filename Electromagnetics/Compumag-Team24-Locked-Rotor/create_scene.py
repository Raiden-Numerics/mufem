"""Render results/Scene_ElementType.png and results/Result_Animation.gif from the case output.

Run with `pvpython create_scene.py` after the case (requires `ffmpeg`). The case exports the
fields of every time step to VisualizationOutput/ and writes the coil current and the rotor
torque over time to VisualizationOutput/Scene_Data.npz.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import numpy as np

from casekit import PlotStyle, xy_plot
from casekit.images import combine_images, trim_frames, write_gif
from casekit.paraview_scene import (
    blocks,
    color_by,
    new_view,
    read_output,
    read_scene_data,
    save,
    scene,
    set_camera,
    show,
)

vis = case_dir / "vis"
tables = case_dir / "data" / "tables"
monitors = read_scene_data(case_dir)
current_ref = np.loadtxt(tables / "Table_3_Coil_Current.csv", delimiter=",", skiprows=1)
torque_ref = np.loadtxt(tables / "Table_4_Torque.csv", delimiter=",", skiprows=1)


def plots(i):
    """Coil current and rotor torque up to time step `i`, as the plots of case.py."""
    common = dict(
        style=PlotStyle.LINE_AND_POINTS,
        reference_style=PlotStyle.POINTS,
        reference_label="Allen (1996)",
        xlabel="Time [s]",
        xlim=(0.0, 0.15),
        xticks=[0.0, 0.05, 0.1, 0.15],
    )
    paths = [vis / f"Coil_Current_vs_Time_{i:03d}.png", vis / f"Rotor_Torque_vs_Time_{i:03d}.png"]
    xy_plot(
        values=monitors["coil_current"][: i + 1],
        reference_values=current_ref,
        ylabel="Coil Current [A]",
        ylim=(0.0, 8.0),
        path=f"{paths[0]}",
        **common,
    )
    xy_plot(
        values=monitors["rotor_torque"][: i + 1],
        reference_values=torque_ref,
        ylabel="Rotor Torque [Nm]",
        ylim=(0.0, 3.5),
        path=f"{paths[1]}",
        **common,
    )
    return paths


def read_step(index):
    return blocks(read_output(case_dir, index), ["Stator", "Rotor", "LowerCoil", "UpperCoil"])


# Element types: the camera looks from +z at the symmetry plane z = 0, where the prism layers
# show as quads.
view = new_view((1989, 1471))
display = show(read_step(0), view, edges=True)
color_by(
    display,
    view,
    "Element Type",
    "Element Type",
    [4.0, 5.0, 6.0],  # tetrahedra and prisms
    orientation="Vertical",
    position=(0.86, 0.04),
    length=0.35,
    title_size=30,
    label_size=28,
)
set_camera(view, (-0.012, 0.015, 0.166), (0, 1, 0), (0.0, 0.045, -0.006), parallel_scale=0.0448)
save(view, case_dir / "results" / "Scene_ElementType.png", crop=False)

# Animation: the electric current density in front, the coil current and the rotor torque of
# case.py on the right. The stator sits on the left so that the color bar fits on the right.
view = new_view((1900, 1300))
set_camera(view, (0, 0, 1), (0, 1, 0), (0.025, 0.0, 0.0), parallel_scale=0.12)

renders = [vis / f"Scene_Electric_Current_Density_{i:03d}.png" for i in range(31)]
for i, render in enumerate(renders):
    with scene(view):
        display = show(read_step(i), view)
        color_by(
            display,
            view,
            "Electric Current Density",
            "Electric Current Density [A/m²]",
            [0.0, 1.0e5, 2.0e5, 3.0e5],
            label_format="%.0e",
            orientation="Vertical",
            position=(0.8, 0.25),
            length=0.5,
            thickness=40,
            title_size=32,
            label_size=28,
            component="Magnitude",
        )
        save(view, render, crop=False)

# Without the white margins of the view, the plots beside the scene.
trim_frames(renders)
frames = [vis / f"Scene_{i:03d}.png" for i in range(31)]
for i, render in enumerate(renders):
    combine_images(render, plots(i), frames[i], gap=150)

write_gif(frames, case_dir / "results" / "Result_Animation.gif")
