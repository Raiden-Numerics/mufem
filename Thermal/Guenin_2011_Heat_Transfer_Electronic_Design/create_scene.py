"""Render data/Mesh.png and the scenes results/Scene_*.png from the output of case.py.

Run with `pvpython create_scene.py` after the case. All images use the isometric view along
(1, 1, 1) with the stacking direction of the layers (y) up, as data/Geometry.png.
"""

import os

import paraview.simple as pvs
from PIL import Image, ImageOps

script_dir = os.path.dirname(os.path.abspath(__file__))

view = pvs.CreateView("RenderView")
view.ViewSize = [1200, 1200]
view.OrientationAxesVisibility = 0
view.UseColorPaletteForBackground = 0
view.Background = [1.0, 1.0, 1.0]
pvs._DisableFirstRenderCameraReset()

data = pvs.XMLPartitionedDatasetCollectionReader(
    FileName=[f"{script_dir}/VisualizationOutput/Output.vtpc.series"]
)
view.ViewTime = data.TimestepValues[-1] if data.TimestepValues else 0.0

temperature = pvs.Calculator(Input=data)
temperature.ResultArrayName = "Temperature Rise"
temperature.Function = '"Temperature" - 273.15'

view.CameraFocalPoint = [0.0, 0.0036, 0.0]
view.CameraPosition = [0.05, 0.0536, 0.05]
view.CameraViewUp = [0.0, 1.0, 0.0]
view.CameraParallelProjection = 1
view.CameraParallelScale = 0.0125


def trim(path, border=20):
    image = Image.open(path).convert("RGB")
    left, top, right, bottom = ImageOps.invert(image).getbbox()
    box = (
        max(left - border, 0),
        max(top - border, 0),
        min(right + border, image.width),
        min(bottom + border, image.height),
    )
    image = image.crop(box)
    image.save(path)
    return image


def scene(array, title, value_range, labels, label_format, path):
    display = pvs.Show(temperature, view)
    display.Representation = "Surface"
    display.Ambient = 0.3
    display.Diffuse = 0.8
    pvs.ColorBy(display, ("POINTS", array))

    lut = pvs.GetColorTransferFunction(array)
    lut.ApplyPreset("Cool to Warm", True)
    lut.RescaleTransferFunction(*value_range)
    lut.AutomaticRescaleRangeMode = "Never"

    bar = pvs.GetScalarBar(lut, view)
    bar.Title = title
    bar.ComponentTitle = ""
    bar.Orientation = "Horizontal"
    bar.WindowLocation = "Any Location"
    bar.Position = [0.3, 0.04]
    bar.ScalarBarLength = 0.4
    bar.UseCustomLabels = True
    bar.CustomLabels = labels
    bar.AddRangeLabels = 0
    bar.AutomaticLabelFormat = 0
    bar.LabelFormat = label_format
    bar.TitleFontSize = 32
    bar.LabelFontSize = 28
    bar.TitleColor = [0, 0, 0]
    bar.LabelColor = [0, 0, 0]
    bar.TitleBold = 1
    bar.LabelBold = 1
    display.SetScalarBarVisibility(view, True)

    pvs.Render(view)
    pvs.SaveScreenshot(
        f"{script_dir}/results/{path}", view, OverrideColorPalette="WhiteBackground"
    )
    display.SetScalarBarVisibility(view, False)
    pvs.Hide(temperature, view)
    trim(f"{script_dir}/results/{path}")


scene(
    "Temperature Rise",
    "Temperature Rise [K]",
    (0.0, 1.0),
    [0.0, 0.2, 0.4, 0.6, 0.8, 1.0],
    "%.1f",
    "Scene_Temperature.png",
)
scene(
    "Specific Heat Capacity",
    "Specific Heat Capacity [J/(kg K)]",
    (300.0, 900.0),
    [300.0, 500.0, 700.0, 900.0],
    "%.0f",
    "Scene_Heat_Capacity.png",
)
scene(
    "Density",
    "Density [kg/m³]",
    (0.0, 9000.0),
    [0.0, 3000.0, 6000.0, 9000.0],
    "%.0f",
    "Scene_Density.png",
)
scene(
    "Thermal Conductivity",
    "Thermal Conductivity [W/(m K)]",
    (0.0, 400.0),
    [0.0, 100.0, 200.0, 300.0, 400.0],
    "%.0f",
    "Scene_Thermal_Conductivity.png",
)

# Mesh: the layers in their colors of data/Geometry.png, with the edges in black.
for name, color in [
    ("Die", "7f8d9b"),
    ("TIM1", "b1b159"),
    ("Lid", "b55b00"),
    ("TIM2", "27386d"),
    ("Heat Sink", "627862"),
]:
    block = pvs.ExtractBlock(Input=data, Selectors=[f"/Root/{name.replace(' ', '')}"])
    display = pvs.Show(block, view)
    display.Representation = "Surface With Edges"
    display.EdgeColor = [0.0, 0.0, 0.0]
    pvs.ColorBy(display, None)
    rgb = [int(color[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    display.AmbientColor = rgb
    display.DiffuseColor = rgb

pvs.Render(view)
pvs.SaveScreenshot(f"{script_dir}/data/Mesh.png", view, OverrideColorPalette="WhiteBackground")
mesh = trim(f"{script_dir}/data/Mesh.png", border=0)

# Place the mesh at the size of the package in data/Geometry.png (930 px wide, 20 px border) on a
# canvas of the same size, so that both images of Figure 1 show the package at the same scale.
geometry = Image.open(f"{script_dir}/data/Geometry.png")
mesh = mesh.resize((930, round(930 * mesh.height / mesh.width)), Image.LANCZOS)
image = Image.new("RGB", geometry.size, "white")
image.paste(mesh, (20, (geometry.height - mesh.height) // 2))
image.save(f"{script_dir}/data/Mesh.png")
