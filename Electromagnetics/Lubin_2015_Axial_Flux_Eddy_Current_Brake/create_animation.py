import os
import subprocess

import paraview.simple as pvs
from PIL import Image

script_dir = os.path.dirname(os.path.abspath(__file__))

view = pvs.CreateView("RenderView")
view.ViewSize = [1600, 1200]
view.OrientationAxesVisibility = 0
view.UseColorPaletteForBackground = 0
view.Background = [1.0, 1.0, 1.0]
pvs._DisableFirstRenderCameraReset()

number_of_magnets = 10

# Arrow positions: rings on the magnet-side face of the plate (radii 15-75 mm, z = 23 mm),
# 3.5 mm apart radially and along each ring; fixed for all frames.
arrow_grid_script = """
import numpy as np
from vtkmodules.vtkCommonCore import vtkPoints
from vtkmodules.vtkCommonDataModel import vtkCellArray

spacing = 3.5e-3
points = vtkPoints()
vertices = vtkCellArray()
for r in np.arange(15.0e-3 + spacing / 2, 75.0e-3, spacing):
    n = int(round(2.0 * np.pi * r / spacing))
    for phi in np.linspace(0.0, 2.0 * np.pi, n, endpoint=False):
        vertices.InsertNextCell(1)
        vertices.InsertCellPoint(points.InsertNextPoint(r * np.cos(phi), r * np.sin(phi), 0.0232))

output = self.GetPolyDataOutput()
output.SetPoints(points)
output.SetVerts(vertices)
"""


def show_solid(data, selectors, color):
    block = pvs.ExtractBlock(Input=data, Selectors=selectors)
    display = pvs.Show(block, view)
    display.Representation = "Surface"
    display.Ambient = 0.3
    display.Diffuse = 0.8
    pvs.ColorBy(display, None)
    display.AmbientColor = color
    display.DiffuseColor = color
    return block


def create_scene(index: int, rpm: int):
    data = pvs.OpenDataFile(f"{script_dir}/VisualizationOutput/Output_{index}.vtpc")

    copper = show_solid(data, ["/Root/CopperPlate"], [205 / 255, 112 / 255, 43 / 255])

    # Magnets with alternating axial magnetization: N red, S blue.
    magnets_n = show_solid(
        data, [f"/Root/Magnet{k}" for k in range(0, number_of_magnets, 2)], [1.0, 0.0, 0.0]
    )
    magnets_s = show_solid(
        data, [f"/Root/Magnet{k}" for k in range(1, number_of_magnets, 2)], [0.0, 0.0, 1.0]
    )

    # Eddy currents in the plate: arrows of equal length on a fixed grid, colored by |J|.
    grid = pvs.ProgrammableSource(OutputDataSetType="vtkPolyData", Script=arrow_grid_script)
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

    glyph_display = pvs.Show(shifted, view)
    glyph_display.Ambient = 0.3
    glyph_display.Diffuse = 0.8
    pvs.ColorBy(glyph_display, ("POINTS", "Electric Current Density", "Magnitude"))

    lut = pvs.GetColorTransferFunction("Electric Current Density")
    lut.ApplyPreset("Cool to Warm", True)
    lut.RescaleTransferFunction(0.0, 5.0e7)
    lut.AutomaticRescaleRangeMode = "Never"

    scalar_bar = pvs.GetScalarBar(lut, view)
    scalar_bar.Title = "Electric Current Density [A/m²]"
    scalar_bar.ComponentTitle = ""
    scalar_bar.Orientation = "Horizontal"
    scalar_bar.WindowLocation = "Any Location"
    scalar_bar.Position = [0.3, 0.05]
    scalar_bar.ScalarBarLength = 0.4
    scalar_bar.ScalarBarThickness = 30
    scalar_bar.UseCustomLabels = True
    scalar_bar.CustomLabels = [0.0, 2.5e7, 5.0e7]
    scalar_bar.AddRangeLabels = 0
    scalar_bar.TitleFontSize = 28
    scalar_bar.LabelFontSize = 24
    scalar_bar.TitleColor = [0, 0, 0]
    scalar_bar.LabelColor = [0, 0, 0]
    scalar_bar.TitleBold = 1
    scalar_bar.LabelBold = 1
    glyph_display.SetScalarBarVisibility(view, True)

    text = pvs.Text(Text=f"RPM: {rpm:.0f}")
    text_display = pvs.Show(text, view)
    text_display.WindowLocation = "Any Location"
    text_display.Position = [0.2, 0.9]
    text_display.FontSize = 38
    text_display.Bold = 1
    text_display.Color = [0.4, 0.4, 0.4]

    # Oblique view from the magnet side (the magnets lie below the plate), 50 deg from below as
    # the geometry images of netgen_geometry_image.py.
    view.CameraPosition = [0.0, -0.1827, -0.1978]
    view.CameraFocalPoint = [0.0, 0.0, 0.02]
    view.CameraViewUp = [0.0, 0.0, 1.0]
    view.CameraViewAngle = 30.0
    view.ResetCamera(copper.GetDataInformation().GetBounds(), False)
    view.GetActiveCamera().Dolly(1.3)

    pvs.Render(view)
    pvs.SaveScreenshot(
        f"{script_dir}/vis/Scene_Electric_Current_Density_{index:03d}.png",
        view,
        OverrideColorPalette="WhiteBackground",
    )

    for proxy in [text, shifted, glyph, sampled, grid, magnets_s, magnets_n, copper, data]:
        pvs.Delete(proxy)


def combine_images(large_path, small1_path, output_path, small_scale=0.9, right_padding=80):
    large = Image.open(large_path)
    small1 = Image.open(small1_path)

    large = large.crop((0, 0, large.width - 250, large.height))

    # resize small1 to match height, then scale down a bit
    ratio = large.height / small1.height
    new_w = int(small1.width * ratio * small_scale)
    new_h = int(small1.height * ratio * small_scale)
    small1 = small1.resize((new_w, new_h))

    # canvas: add padding on the far right; center small1 vertically
    total_width = large.width + new_w + right_padding
    total_height = large.height

    out = Image.new("RGB", (total_width, total_height), "white")

    out.paste(large, (0, 0))

    x = large.width  # start right after large
    y = (large.height - new_h) // 2
    out.paste(small1, (x, y))

    out = out.crop((100, 0, out.width - 100, out.height))

    out.save(output_path)


if __name__ == "__main__":
    # 90 is currently hard-coded to three rotation rates each for 30 time steps
    for i in range(90):
        rpm = [500, 1000, 2000][i // 30]

        create_scene(i, rpm)
        combine_images(
            large_path=f"vis/Scene_Electric_Current_Density_{i:03d}.png",
            small1_path=f"vis/Torque_vs_RPM_{i:03d}.png",
            output_path=f"vis/Scene_{i:03d}.png",
        )

    # 1) Use ffmpeg to convert the images to an animated gif

    commands = [
        (
            "ffmpeg -framerate 8 -i vis/Scene_%03d.png "
            '-vf "pad=ceil(iw/2)*2:ceil(ih/2)*2" -c:v libx264 -pix_fmt yuv420p vis/output.mp4'
        ),
        (
            "ffmpeg -i vis/output.mp4 "
            "-vf 'fps=8,scale=800:-1:flags=lanczos' "
            "-c:v gif results/Result_Animation.gif -y"
        ),
    ]
    for command in commands:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)

        if result.returncode != 0:
            print(result.stderr)
