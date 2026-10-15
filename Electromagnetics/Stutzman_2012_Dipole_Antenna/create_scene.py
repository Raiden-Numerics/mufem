"""Render results/Scene_Radiation_Pattern.png and results/Electric_Field.gif.

Run with `pvpython create_scene.py` after the case (requires `ffmpeg`). The radiation pattern
is read from results/Far_Field_3D.npz, the electric field from VisualizationOutput/.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import numpy as np  # noqa: E402
import paraview.simple as pvs  # noqa: E402
from vtkmodules.util.numpy_support import numpy_to_vtk, numpy_to_vtkIdTypeArray  # noqa: E402
from vtkmodules.vtkCommonCore import vtkPoints  # noqa: E402
from vtkmodules.vtkCommonDataModel import vtkCellArray, vtkPolyData  # noqa: E402

from casekit.paraview_scene import (  # noqa: E402
    color_by,
    new_view,
    phase_field,
    read_output,
    save,
    set_camera,
    show,
    write_gif,
)

results = case_dir / "results"


def radiation_surface(thetas, phis, pattern, scale=4.5):
    """Surface at the radius scale * pattern(theta, phi) with the pattern in dB on it."""
    theta, phi = np.meshgrid(thetas, phis, indexing="ij")
    radius = scale * pattern
    xyz = np.stack(
        [
            radius * np.sin(theta) * np.cos(phi),
            radius * np.sin(theta) * np.sin(phi),
            radius * np.cos(theta),
        ],
        axis=-1,
    ).reshape(-1, 3)

    points = vtkPoints()
    points.SetData(numpy_to_vtk(np.ascontiguousarray(xyz), deep=True))

    n_phi = len(phis)
    first = (np.arange(len(thetas) - 1)[:, None] * n_phi + np.arange(n_phi - 1)).ravel()
    quads = np.stack([first, first + 1, first + 1 + n_phi, first + n_phi], axis=-1)
    offsets = np.arange(0, 4 * len(quads) + 1, 4)
    cells = vtkCellArray()
    cells.SetData(
        numpy_to_vtkIdTypeArray(offsets, deep=True),
        numpy_to_vtkIdTypeArray(quads.ravel(), deep=True),
    )

    decibel = numpy_to_vtk(20 * np.log10(np.maximum(pattern.ravel(), 1e-6)), deep=True)
    decibel.SetName("Radiation Pattern")

    poly = vtkPolyData()
    poly.SetPoints(points)
    poly.SetPolys(cells)
    poly.GetPointData().SetScalars(decibel)
    return poly


# Far-field radiation pattern; 20 log10 since the pattern is a field amplitude.
far_field = np.load(results / "Far_Field_3D.npz")
source = pvs.TrivialProducer()
source.GetClientSideObject().SetOutput(
    radiation_surface(far_field["thetas"], far_field["phis"], far_field["radiation_pattern"])
)

view = new_view((1000, 1000))
display = show(source, view, edges=True)
display.EdgeColor = [0.1, 0.1, 0.1]
color_by(
    display,
    view,
    "Radiation Pattern",
    "Radiation Pattern [dB]",
    [-10.0, -8.0, -6.0, -4.0, -2.0, 0.0],
    position=(0.3, 0.05),
    thickness=30,
    title_size=32,
    label_size=28,
)
set_camera(view, (4, 4, 3), (0, 0, 1), (0.0, 0.0, -0.8), parallel_scale=5.0)
save(view, results / "Scene_Radiation_Pattern.png")

# Electric field in the yz-plane over half a period, after which the magnitude repeats.
data = read_output(case_dir)
view = new_view((1000, 1000))
set_camera(view, (1, 0, 0), (0, 0, 1), (0.0, 0.0, -1.0), parallel_scale=8.0)
frames = []
for i, phase_deg in enumerate(range(0, 180, 5)):
    field = phase_field(data, "Electric Field", phase_deg)
    section = pvs.Slice(Input=field)
    section.SliceType = "Plane"
    section.SliceType.Origin = [0.0, 0.0, 0.0]
    section.SliceType.Normal = [1.0, 0.0, 0.0]

    display = show(section, view)
    color_by(
        display,
        view,
        "Electric Field",
        "Electric Field [V/m]",
        [0.0, 10.0, 20.0, 30.0],
        position=(0.3, 0.05),
        thickness=30,
        title_size=32,
        label_size=28,
        component="Magnitude",
    )
    frames.append(case_dir / "vis" / f"Scene_{i:03d}.png")
    save(view, frames[-1], crop=False)
    display.SetScalarBarVisibility(view, False)
    for proxy in (section, field):
        pvs.Delete(proxy)

write_gif(frames, results / "Electric_Field.gif", fps=12)
