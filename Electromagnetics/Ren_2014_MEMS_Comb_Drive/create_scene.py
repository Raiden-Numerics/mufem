"""Render results/Scene_Electric_Potential_*_Mesh.png and results/Electric_Potential.gif.

Run with `pvpython create_scene.py` after the case (requires `ffmpeg`). case.py exports the
electric potential on the initial and the refined mesh of the zero shift
(VisualizationOutput/Output_0 and Output_1) and on the refined mesh of every further shift i
(Output_<i + 1>).
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import paraview.simple as pvs

from casekit.images import write_gif
from casekit.paraview_scene import (
    color_by,
    new_view,
    read_output,
    save,
    scene,
    set_camera,
    show,
)

shifts = 17
results = case_dir / "results"


def potential(display, view, boxed=False):
    display.NonlinearSubdivisionLevel = 2
    color_by(
        display,
        view,
        "Electric Potential",
        "Electric Potential [V]",
        [0.0, 0.2, 0.4, 0.6, 0.8, 1.0],
        "%g",
        position=(0.3, 0.03),
        thickness=28,
        label_size=20,
        boxed=boxed,
    )


# Slice through the combs at the zero shift with the mesh edges, on the initial (0) and the
# refined (1) mesh, seen from above.
view = new_view((1100, 800))
set_camera(view, (0, 1, 0), (-1, 0, 0), (0.0, 0.0, 0.0), parallel_scale=2e-5)
for index in (0, 1):
    with scene(view):
        section = pvs.Slice(Input=read_output(case_dir, index))
        section.SliceType = "Plane"
        section.SliceType.Origin = [11e-6, 2e-6, 17e-6]
        section.SliceType.Normal = [0.0, 1.0, 0.0]
        moved = pvs.Transform(Input=section)
        moved.Transform.Translate = [-15e-6, 0.0, -17e-6]

        display = show(moved, view, edges=True)
        display.EdgeColor = [0.1, 0.1, 0.1]
        potential(display, view, boxed=True)
        save(view, results / f"Scene_Electric_Potential_{index}_Mesh.png", crop=False)

# Animation: the potential on the refined mesh, clipped through the combs, from the largest
# shift to zero, as the combs are pulled together when the voltage is applied.
view = new_view((1100, 800))
set_camera(view, (1, 1, 1), (0, 1, 0), (0.0, 0.0, 0.0), parallel_scale=5e-5)
frames = []
for shift in reversed(range(shifts)):
    with scene(view):
        clip = pvs.Clip(Input=read_output(case_dir, shift + 1))
        clip.ClipType = "Plane"
        clip.ClipType.Origin = [11e-6, 2e-6, 17e-6]
        clip.ClipType.Normal = [0.0, 1.0, 0.0]
        moved = pvs.Transform(Input=clip)
        moved.Transform.Translate = [7e-6, 30e-6, 0.0]

        display = show(moved, view)
        potential(display, view)
        frames.append(case_dir / "vis" / f"Scene_{shift:03d}.png")
        save(view, frames[-1], crop=False)

write_gif(frames, results / "Electric_Potential.gif", fps=5)
