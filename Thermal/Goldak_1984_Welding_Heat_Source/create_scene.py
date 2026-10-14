import os

import paraview.simple as pvs
from PIL import Image, ImageOps

script_dir = os.path.dirname(os.path.abspath(__file__))

data = pvs.XMLPartitionedDatasetCollectionReader(
    FileName=[f"{script_dir}/VisualizationOutput/Output.vtpc.series"]
)

temperature = pvs.Calculator(Input=data)
temperature.ResultArrayName = "Temperature [°C]"
temperature.Function = '"Temperature" - 273.15'

view = pvs.CreateView("RenderView")
view.ViewSize = [1600, 1000]
view.OrientationAxesVisibility = 0
view.UseColorPaletteForBackground = 0
view.Background = [1.0, 1.0, 1.0]
pvs._DisableFirstRenderCameraReset()


def render(source, array, title, labels, label_format, path):
    display = pvs.Show(source, view)
    display.Representation = "Surface"
    display.Ambient = 0.3
    display.Diffuse = 0.8
    pvs.ColorBy(display, ("POINTS", array))

    # View the symmetry plane x = 0 (weld path) and the top surface y = 0, whole box in frame.
    view.CameraPosition = [-0.22, 0.14, 0.02]
    view.CameraFocalPoint = [0.03, -0.03, 0.17]
    view.CameraViewUp = [0.3, 0.9, 0.2]
    view.CameraViewAngle = 30.0
    view.ResetCamera([0.0, 0.15, -0.1, 0.0, 0.0, 0.3], False)  # the modeled half plate

    # Move the plate up, away from the color bar below it.
    camera = view.GetActiveCamera()
    up = camera.GetViewUp()
    shift = 0.025
    camera.SetFocalPoint(*[f - shift * u for f, u in zip(camera.GetFocalPoint(), up)])
    camera.SetPosition(*[p - shift * u for p, u in zip(camera.GetPosition(), up)])

    ctf = pvs.GetColorTransferFunction(array)
    ctf.ApplyPreset("Cool to Warm", True)
    ctf.RescaleTransferFunction(labels[0], labels[-1])

    bar = pvs.GetScalarBar(ctf, view)
    bar.Title = title
    bar.ComponentTitle = ""
    bar.Orientation = "Horizontal"
    bar.WindowLocation = "Any Location"
    bar.Position = [0.3, 0.03]
    bar.ScalarBarLength = 0.4
    bar.ScalarBarThickness = 30
    bar.UseCustomLabels = True
    bar.CustomLabels = labels
    bar.AddRangeLabels = 0
    bar.AutomaticLabelFormat = 0
    bar.LabelFormat = label_format
    bar.TitleFontSize = 28
    bar.LabelFontSize = 24
    bar.TitleColor = [0, 0, 0]
    bar.LabelColor = [0, 0, 0]
    bar.TitleBold = 1
    bar.LabelBold = 1
    display.SetScalarBarVisibility(view, True)

    pvs.Render(view)
    pvs.SaveScreenshot(path, view, OverrideColorPalette="WhiteBackground")
    display.SetScalarBarVisibility(view, False)
    pvs.Hide(source, view)

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


render(
    temperature,
    "Temperature [°C]",
    "Temperature [°C]",
    [0.0, 500.0, 1000.0, 1500.0, 2000.0, 2500.0],
    "%.0f",
    f"{script_dir}/results/Scene_Temperature.png",
)
render(
    data,
    "VolumetricHeatSource",
    "Heat Source [W/m³]",
    [0.0, 2.0e9, 4.0e9, 6.0e9, 8.0e9],
    "%.0e",
    f"{script_dir}/results/Scene_Goldak_Heat_Source.png",
)
