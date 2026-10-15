"""Render results/Result_Animation.gif from the output of case.py.

Run with `pvpython create_scene.py` after the case with `output_for_animation = True` (requires
`ffmpeg`). That run exports the eddy currents of every time step to VisualizationOutput/ and
writes the torque at the three speeds and the number of time steps per speed to
VisualizationOutput/Scene_Data.npz.
"""

import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import numpy as np
import paraview.simple as pvs
from vtkmodules.vtkCommonCore import vtkPoints
from vtkmodules.vtkCommonDataModel import vtkCellArray, vtkPolyData

from casekit import PlotStyle, xy_plot
from casekit.images import combine_images, trim_frames, write_gif
from casekit.paraview_scene import (
    add_text,
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
scene_data = read_scene_data(case_dir)
reference = np.loadtxt(case_dir / "data" / "Torque_Vs_Slip_speed.csv", delimiter=",", skiprows=1)


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

# Oblique view from the magnet side (the magnets lie below the plate), 50 deg from below as
# data/Geometry.png, fitted to the copper plate, which does not move, and moved up away from
# the color bar below it.
copper = blocks(read_output(case_dir, 0), ["CopperPlate"])
copper.UpdatePipeline()
set_camera(
    view,
    (0.0, -0.6428, -0.7660),
    (0, 0, 1),
    bounds=copper.GetDataInformation().GetBounds(),
    shift_up=0.014,
)
view.GetActiveCamera().Zoom(1.3)


def create_scene(index, rpm, path):
    with scene(view):
        data = read_output(case_dir, index)
        copper = blocks(data, ["CopperPlate"])
        show(copper, view, (205 / 255, 112 / 255, 43 / 255))

        # The 10 magnets with alternating axial magnetization: N red, S blue.
        for first, color in [(0, (1, 0, 0)), (1, (0, 0, 1))]:
            magnets = [f"Magnet{k}" for k in range(first, 10, 2)]
            show(blocks(data, magnets), view, color)

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

        # Sampled just inside the plate; shift the arrows into the gap so that the plate
        # surface does not hide them.
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
        add_text(view, f"RPM: {rpm}", position=(0.2, 0.9), font_size=38)
        save(view, path, crop=False)


def torque_plot(rpm, path):
    """Torque against slip speed as results/Torque_vs_RPM.png, with an arrow up at `rpm`."""
    xy_plot(
        values=scene_data["torque_vs_rpm"],
        style=PlotStyle.POINTS,
        reference_values=reference,
        reference_style=PlotStyle.LINE,
        reference_label="Lubin (2015)",
        xlabel="Slip Speed [rpm]",
        ylabel="Torque [Nm]",
        xlim=(0, 3000),
        ylim=(0, 35),
        path=f"{path}",
        arrows=[((rpm, 0.0), (rpm, 6.0))],
    )


# The exported time steps: steps_per_rpm at each slip speed of torque_vs_rpm, in its order.
rpms = [
    int(rpm) for rpm, _ in scene_data["torque_vs_rpm"] for _ in range(scene_data["steps_per_rpm"])
]
renders = [vis / f"Scene_Electric_Current_Density_{i:03d}.png" for i in range(len(rpms))]
for i, (rpm, render) in enumerate(zip(rpms, renders)):
    create_scene(i, rpm, render)

# Without the white margins of the view, the plot about as wide as the scene beside it.
trim_frames(renders)
gif_frames = [vis / f"Scene_{i:03d}.png" for i in range(len(rpms))]
for i, (rpm, render) in enumerate(zip(rpms, renders)):
    plot = vis / f"Torque_vs_RPM_{i:03d}.png"
    torque_plot(rpm, plot)
    combine_images(render, [plot], gif_frames[i], side_scale=0.7, gap=150)

write_gif(gif_frames, case_dir / "results" / "Result_Animation.gif")
