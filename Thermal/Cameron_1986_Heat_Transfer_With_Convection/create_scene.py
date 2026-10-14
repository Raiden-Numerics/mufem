"""Render results/Scene_Temperature.png and data/Mesh.png from the output of case.py.

Run with `pvpython create_scene.py` after the case. The plate is seen from the front (onto the
x-y plane), as data/Geometry.png.
"""

import os

import paraview.simple as pvs
from PIL import Image, ImageOps

script_dir = os.path.dirname(os.path.abspath(__file__))

view = pvs.CreateView("RenderView")
view.ViewSize = [1200, 1400]
view.OrientationAxesVisibility = 0
view.UseColorPaletteForBackground = 0
view.Background = [1.0, 1.0, 1.0]
pvs._DisableFirstRenderCameraReset()

data = pvs.XMLPartitionedDatasetCollectionReader(
    FileName=[f"{script_dir}/VisualizationOutput/Output.vtpc.series"]
)
temperature = pvs.Calculator(Input=data)
temperature.ResultArrayName = "Temperature [°C]"
temperature.Function = '"Temperature" - 273.15'

display = pvs.Show(temperature, view)
display.Representation = "Surface"
pvs.ColorBy(display, ("POINTS", "Temperature [°C]"))

lut = pvs.GetColorTransferFunction("Temperature [°C]")
lut.ApplyPreset("Cool to Warm", True)
lut.RescaleTransferFunction(0.0, 100.0)
lut.AutomaticRescaleRangeMode = "Never"

bar = pvs.GetScalarBar(lut, view)
bar.Title = "Temperature [°C]"
bar.ComponentTitle = ""
bar.Orientation = "Vertical"
bar.WindowLocation = "Any Location"
bar.Position = [0.74, 0.3]
bar.ScalarBarLength = 0.4
bar.UseCustomLabels = True
bar.CustomLabels = [0.0, 25.0, 50.0, 75.0, 100.0]
bar.AddRangeLabels = 0
bar.AutomaticLabelFormat = 0
bar.LabelFormat = "%.0f"
bar.TitleFontSize = 28
bar.LabelFontSize = 24
bar.TitleColor = [0, 0, 0]
bar.LabelColor = [0, 0, 0]
bar.TitleBold = 1
bar.LabelBold = 1
display.SetScalarBarVisibility(view, True)

# Front view onto the plate (0.6 m x 1.0 m), shifted so that the color bar fits on the right.
view.CameraFocalPoint = [0.42, 0.5, 0.005]
view.CameraPosition = [0.42, 0.5, 2.0]
view.CameraViewUp = [0.0, 1.0, 0.0]
view.CameraParallelProjection = 1
view.CameraParallelScale = 0.55

pvs.Render(view)
path = f"{script_dir}/results/Scene_Temperature.png"
pvs.SaveScreenshot(path, view, OverrideColorPalette="WhiteBackground")

# Trim the white margins, keeping a small border.
image = Image.open(path).convert("RGB")
left, top, right, bottom = ImageOps.invert(image).getbbox()
box = (
    max(left - 20, 0),
    max(top - 20, 0),
    min(right + 20, image.width),
    min(bottom + 20, image.height),
)
image.crop(box).save(path)

# Mesh image: the plate at the size and with the margins of data/Geometry.png (see
# netgen_geometry_image.py), so that both images of Figure 1 show the plate at the same scale.
display.SetScalarBarVisibility(view, False)
pvs.ColorBy(display, None)
display.Representation = "Surface With Edges"
display.AmbientColor = [0.02, 0.69, 0.5]
display.DiffuseColor = [0.02, 0.69, 0.5]
display.EdgeColor = [0.0, 0.0, 0.0]
display.Ambient = 1.0  # flat color, as in data/Geometry.png
display.Diffuse = 0.0
view.CameraFocalPoint = [0.3, 0.5, 0.005]
view.CameraPosition = [0.3, 0.5, 2.0]
view.CameraParallelScale = 0.52

pvs.Render(view)
path = f"{script_dir}/data/Mesh.png"
pvs.SaveScreenshot(path, view, OverrideColorPalette="WhiteBackground")

plate = Image.open(path).convert("RGB")
plate = plate.crop(ImageOps.invert(plate).getbbox())
geometry = Image.open(f"{script_dir}/data/Geometry.png")
size = (780, 1300)  # plate in data/Geometry.png [px]
margins = (250, 110)  # left, top margin in data/Geometry.png [px]
image = Image.new("RGB", geometry.size, "white")
image.paste(plate.resize(size, Image.LANCZOS), margins)
image.save(path)
