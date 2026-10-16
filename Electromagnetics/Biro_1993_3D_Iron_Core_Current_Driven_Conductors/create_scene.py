"""Render the scenes results/Scene_*_Phase_*.png and results/animation.gif from case.py output.

Run with `pvpython create_scene.py` after the case (requires `ffmpeg`). The scenes show the
magnitude of the fields at the phase phi, |F_r cos(phi) - F_i sin(phi)|, with the core and the
conductors seen from below.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

from casekit.images import trim_frames, write_gif
from casekit.paraview_scene import (
    add_text,
    blocks,
    color_by,
    new_view,
    phase_field,
    read_output,
    save,
    scene,
    set_camera,
    show,
)

coils = [f"Coil{k}" for k in range(1, 26)]

view = new_view((1600, 1200))
data = read_output(case_dir)
set_camera(
    view,
    (-0.0725, -0.088, -0.061),
    (0, 0, 1),
    bounds=(0, 0.025, 0, 0.017, 0, 0.018),
)


def at_phase(field, names, labels, label_format, phase_deg, path, label=False):
    """Field at the phase in the bodies `names`; the current density with the core in gray."""
    with scene(view):
        values = phase_field(data, field, phase_deg)
        parts = blocks(values, names)
        if field == "Electric Current Density":
            show(blocks(data, ["Core"]), view, color=(0.6, 0.6, 0.6))
        display = show(parts, view)
        unit = "A/m²" if field == "Electric Current Density" else "T"
        color_by(
            display,
            view,
            field,
            f"{field} [{unit}]",
            labels,
            label_format,
            thickness=30,
            component="Magnitude",
        )
        if label:
            add_text(view, f"Phase = {phase_deg:.0f}°", position=(0.671, 0.886))
        save(view, path, crop=False)


current = ("Electric Current Density", coils, [0.0, 5.0e7, 1.0e8], "%.0e")
results = case_dir / "results"

# The imaginary part of B is much smaller than the real part: own color range.
stills = []
for phase_deg, name, b_max in [(0, "Real", 1.2), (90, "Imag", 0.1)]:
    stills.append(results / f"Scene_Electric_Current_Density_Phase_{name}.png")
    at_phase(*current, phase_deg, stills[-1])
    stills.append(results / f"Scene_Magnetic_Flux_Density_Phase_{name}.png")
    at_phase(
        "Magnetic Flux Density",
        ["Core", *coils],
        [0.0, b_max / 2, b_max],
        "%g",
        phase_deg,
        stills[-1],
    )
# All four cropped alike, as they stand side by side in the README.
trim_frames(stills)

frames = []
for i, phase_deg in enumerate(range(0, 360, 5)):
    frames.append(case_dir / "vis" / f"Scene_{i:03d}.png")
    at_phase(*current, phase_deg, frames[-1], label=True)
write_gif(frames, results / "animation.gif", fps=12, width=1280)
