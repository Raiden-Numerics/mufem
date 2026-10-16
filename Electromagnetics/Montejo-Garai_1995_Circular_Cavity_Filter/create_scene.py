"""Render results/Electric_Field.gif from the output of case.py.

Run with `pvpython create_scene.py` after the case (requires `ffmpeg`). The frames show the
magnitude of the electric field E(t) = E_r cos(wt) - E_i sin(wt) at 12 GHz (left) and 14 GHz
(right) over half a period, after which the magnitude repeats.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

from casekit.images import combine_images, trim_frames, write_gif
from casekit.paraview_scene import (
    add_text,
    color_by,
    new_view,
    phase_field,
    read_output,
    save,
    scene,
    set_camera,
    show,
)

# Two WR75 waveguides of 20 mm, two irises of 1 mm and the cavity of 100 mm along z.
total_length = 20e-3 + 1e-3 + 100e-3 + 1e-3 + 20e-3
vis = case_dir / "vis"

view = new_view((1200, 650))
# Onto the middle of the filter from 14 deg above the x-z plane, 48 deg from -x toward -z.
set_camera(
    view,
    (-0.6830, 0.2588, -0.6830 - total_length / 2),
    (0, 1, 0),
    (0.0, 0.0, total_length / 2),
    parallel_scale=0.03,
)

phases = range(0, 180, 5)
renders = {}
for index, frequency in enumerate(["12GHz", "14GHz"]):
    data = read_output(case_dir, index)
    renders[frequency] = []
    for i, phase_deg in enumerate(phases):
        with scene(view):
            display = show(phase_field(data, "Electric Field", phase_deg), view)
            color_by(
                display,
                view,
                "Electric Field",
                "Electric Field [V/m]",
                [0.0, 1000.0, 2000.0, 3000.0],
                component="Magnitude",
            )
            add_text(view, frequency.replace("GHz", " GHz"), position=(0.05, 0.85))
            renders[frequency].append(vis / f"Scene_{frequency}_{i:03d}.png")
            save(view, renders[frequency][-1], crop=False)

# Both frequencies cropped alike, side by side.
trim_frames(renders["12GHz"] + renders["14GHz"])
frames = [vis / f"Scene_{i:03d}.png" for i in range(len(phases))]
for left, right, frame in zip(renders["12GHz"], renders["14GHz"], frames):
    combine_images(left, [right], frame, gap=150)
write_gif(frames, case_dir / "results" / "Electric_Field.gif", fps=12, width=1200)
