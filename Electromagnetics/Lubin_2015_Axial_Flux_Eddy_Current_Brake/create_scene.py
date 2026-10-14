"""Render results/Result_Animation.gif from the output of case.py.

Run with `pvpython create_scene.py` after the case with `output_for_animation = True` (requires
`ffmpeg`). The case then exports the fields to VisualizationOutput/ and the torque plots
vis/Torque_vs_RPM_<i>.png for 30 time steps per rotation rate.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import numpy as np  # noqa: E402
import paraview.simple as pvs  # noqa: E402
from PIL import Image  # noqa: E402
from vtkmodules.vtkCommonCore import vtkPoints  # noqa: E402
from vtkmodules.vtkCommonDataModel import vtkCellArray, vtkPolyData  # noqa: E402

from casekit.netgen_image import content_box, trim  # noqa: E402
from casekit.paraview_scene import (  # noqa: E402
    add_text,
    color_by,
    combine_images,
    new_view,
    save,
    set_camera,
    show,
    write_gif,
)

number_of_magnets = 10
rpms = [500, 1000, 2000]
steps_per_rpm = 30


def arrow_grid(spacing=3.5e-3):
    """Rings on the magnet-side face of the plate (radii 15-75 mm, z = 23 mm), `spacing`
    apart radially and along each ring; fixed for all frames."""
    points = vtkPoints()
    vertices = vtkCellArray()
    for r in np.arange(15.0e-3 + spacing / 2, 75.0e-3, spacing):
        n = int(round(2.0 * np.pi * r / spacing))
        for phi in np.linspace(0.0, 2.0 * np.pi, n, endpoint=False):
            vertices.InsertNextCell(1)
            point = points.InsertNextPoint(r * np.cos(phi), r * np.sin(phi), 0.0232)
            vertices.InsertCellPoint(point)
    poly = vtkPolyData()
    poly.SetPoints(points)
    poly.SetVerts(vertices)
    source = pvs.TrivialProducer()
    source.GetClientSideObject().SetOutput(poly)
    return source


grid = arrow_grid()
view = new_view((1600, 1200))
view.CameraViewAngle = 30.0


def solid(data, selectors, color):
    block = pvs.ExtractBlock(Input=data, Selectors=selectors)
    show(block, view, color)
    return block


def create_scene(index, rpm, path):
    data = pvs.OpenDataFile(f"{case_dir}/VisualizationOutput/Output_{index}.vtpc")
    copper = solid(data, ["/Root/CopperPlate"], (205 / 255, 112 / 255, 43 / 255))

    # Magnets with alternating axial magnetization: N red, S blue.
    north = solid(data, [f"/Root/Magnet{k}" for k in range(0, number_of_magnets, 2)], (1, 0, 0))
    south = solid(data, [f"/Root/Magnet{k}" for k in range(1, number_of_magnets, 2)], (0, 0, 1))

    # Eddy currents in the plate: arrows of equal length on a fixed grid, colored by |J|.
    sampled = pvs.ResampleWithDataset(SourceDataArrays=copper, DestinationMesh=grid)
    glyph = pvs.Glyph(Input=sampled, GlyphType="Arrow")
    glyph.OrientationArray = ["POINTS", "Electric Current Density"]
    glyph.ScaleArray = ["POINTS", "No scale array"]
    glyph.ScaleFactor = 3.5e-3
    glyph.GlyphMode = "All Points"
    glyph.GlyphType.TipRadius = 0.19
    glyph.GlyphType.ShaftRadius = 0.08
    glyph.GlyphType.TipResolution = 12
    glyph.GlyphType.ShaftResolution = 12

    # Sampled just inside the plate; shift the arrows into the gap so that the plate surface
    # does not hide them.
    shifted = pvs.Transform(Input=glyph)
    shifted.Transform.Translate = [0.0, 0.0, -0.7e-3]

    display = show(shifted, view)
    color_by(
        display,
        view,
        "Electric Current Density",
        "Electric Current Density [A/m²]",
        [0.0, 2.5e7, 5.0e7],
        "%.1e",
        thickness=30,
        component="Magnitude",
    )
    text = add_text(view, f"RPM: {rpm}", position=(0.2, 0.9), font_size=38)

    # Oblique view from the magnet side (the magnets lie below the plate), 50 deg from below as
    # data/Geometry.png.
    copper.UpdatePipeline()
    set_camera(
        view,
        (0.0, -0.6428, -0.7660),
        (0, 0, 1),
        (0.0, 0.0, 0.02),
        bounds=copper.GetDataInformation().GetBounds(),
    )
    view.GetActiveCamera().Dolly(1.3)
    save(view, path, crop=False)

    display.SetScalarBarVisibility(view, False)
    for proxy in (text, shifted, glyph, sampled, south, north, copper, data):
        pvs.Delete(proxy)


vis = case_dir / "vis"
count = len(rpms) * steps_per_rpm
scenes = [vis / f"Scene_Electric_Current_Density_{i:03d}.png" for i in range(count)]
for i, scene in enumerate(scenes):
    create_scene(i, rpms[i // steps_per_rpm], scene)

# Crop all scenes to the same box, so that the frames keep their size and position.
images = [Image.open(scene).convert("RGB") for scene in scenes]
box = content_box(*images)
frames = [vis / f"Scene_{i:03d}.png" for i in range(count)]
for i, (scene, image) in enumerate(zip(scenes, images)):
    trim(image, box=box).save(scene)
    combine_images(scene, [vis / f"Torque_vs_RPM_{i:03d}.png"], frames[i])

write_gif(frames, case_dir / "results" / "Result_Animation.gif")
