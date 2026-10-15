"""Render results/Scene_ElementType.png and results/Result_Animation.gif from the case output.

Run the case with `output_for_animation = True` first: it exports the fields of every time step
and writes the current and torque plots into vis/. Then run `pvpython create_scene.py`
(requires `ffmpeg`).
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))


from casekit.images import combine_images, write_gif
from casekit.paraview_scene import (
    blocks,
    color_by,
    new_view,
    read_output,
    save,
    scene,
    set_camera,
    show,
)

vis = case_dir / "vis"


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

frames = []
for i in range(31):
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
        save(view, vis / f"Scene_Electric_Current_Density_{i:03d}.png", crop=False)

    frames.append(vis / f"Scene_{i:03d}.png")
    combine_images(
        vis / f"Scene_Electric_Current_Density_{i:03d}.png",
        [vis / f"Coil_Current_vs_Time_{i:03d}.png", vis / f"Rotor_Torque_vs_Time_{i:03d}.png"],
        frames[-1],
    )

write_gif(frames, case_dir / "results" / "Result_Animation.gif")
