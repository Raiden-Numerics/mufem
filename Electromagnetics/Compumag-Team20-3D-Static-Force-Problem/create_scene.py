"""Render data/Vis_MagneticFluxDensity.png and data/Mesh.png from the output of case.py.

Run with `pvpython create_scene.py` after the case.
"""

import os

import paraview.simple as pvs
from PIL import Image, ImageOps

script_dir = os.path.dirname(os.path.abspath(__file__))

view = pvs.CreateView("RenderView")
view.OrientationAxesVisibility = 0
view.UseColorPaletteForBackground = 0
view.Background = [1.0, 1.0, 1.0]
pvs._DisableFirstRenderCameraReset()

data = pvs.XMLPartitionedDatasetCollectionReader(
    FileName=[f"{script_dir}/VisualizationOutput/Output.vtpc.series"]
)


def save(path, bounds):
    """Isometric view along (-1, -1, 1) onto the symmetry planes x = 0 and y = 0."""
    center = [(bounds[2 * i] + bounds[2 * i + 1]) / 2 for i in range(3)]
    view.CameraFocalPoint = center
    view.CameraPosition = [center[0] - 1.0, center[1] - 1.0, center[2] + 1.0]
    view.CameraViewUp = [0.0, 0.0, 1.0]
    view.CameraParallelProjection = 1
    view.ResetCamera(bounds, False)

    pvs.Render(view)
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


# Magnetic flux density in the yoke, the pole and the coil --------------------------------
view.ViewSize = [1900, 1600]
parts = pvs.ExtractBlock(Input=data, Selectors=["/Root/Yoke", "/Root/Pole", "/Root/Coil"])

display = pvs.Show(parts, view)
display.Representation = "Surface"
display.Ambient = 0.3
display.Diffuse = 0.8
pvs.ColorBy(display, ("POINTS", "Magnetic Flux Density", "Magnitude"))

lut = pvs.GetColorTransferFunction("Magnetic Flux Density")
lut.ApplyPreset("Cool to Warm", True)
lut.RescaleTransferFunction(0.0, 2.5)
lut.AutomaticRescaleRangeMode = "Never"

bar = pvs.GetScalarBar(lut, view)
bar.Title = "Magnetic Flux Density [T]"
bar.ComponentTitle = ""
bar.Orientation = "Vertical"
bar.HorizontalTitle = 0
bar.WindowLocation = "Any Location"
bar.Position = [0.78, 0.3]
bar.ScalarBarLength = 0.4
bar.UseCustomLabels = True
bar.CustomLabels = [0.0, 0.5, 1.0, 1.5, 2.0, 2.5]
bar.AddRangeLabels = 0
bar.AutomaticLabelFormat = 0
bar.LabelFormat = "%.1f"
bar.TitleFontSize = 28
bar.LabelFontSize = 24
bar.TitleColor = [0, 0, 0]
bar.LabelColor = [0, 0, 0]
bar.TitleBold = 1
bar.LabelBold = 1
display.SetScalarBarVisibility(view, True)

parts.UpdatePipeline()
save(f"{script_dir}/data/Vis_MagneticFluxDensity.png", parts.GetDataInformation().GetBounds())

display.SetScalarBarVisibility(view, False)
pvs.Hide(parts, view)

# Mesh of all bodies -----------------------------------------------------------------------
view.ViewSize = [1600, 1600]
for selector, color in [
    ("/Root/Air", [0.96, 0.89, 0.83]),
    ("/Root/Yoke", [0.6, 0.6, 0.6]),
    ("/Root/Pole", [0.6, 0.6, 0.6]),
    ("/Root/Coil", [0.72, 0.45, 0.2]),
]:
    block = pvs.ExtractBlock(Input=data, Selectors=[selector])
    mesh_display = pvs.Show(block, view)
    mesh_display.Representation = "Surface With Edges"
    mesh_display.EdgeColor = [0.0, 0.0, 0.0]
    mesh_display.Ambient = 0.3
    mesh_display.Diffuse = 0.8
    pvs.ColorBy(mesh_display, None)
    mesh_display.AmbientColor = color
    mesh_display.DiffuseColor = color

data.UpdatePipeline()
save(f"{script_dir}/data/Mesh.png", data.GetDataInformation().GetBounds())
