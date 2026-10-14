"""Render results/Deformation.gif from the output of case.py.

Run with `pvpython create_scene.py` after the case (requires `ffmpeg`). The problem is linear,
so the animation scales the computed solution with the load from zero to its full value.
"""

import os
import subprocess

import paraview.simple as pvs
from PIL import Image

script_dir = os.path.dirname(os.path.abspath(__file__))

# The tip deflection (1.9 mm) is invisible at true scale.
displacement_scale = 50.0
frames = 30

view = pvs.CreateView("RenderView")
view.ViewSize = [1600, 900]
view.OrientationAxesVisibility = 0
view.UseColorPaletteForBackground = 0
view.Background = [1.0, 1.0, 1.0]
pvs._DisableFirstRenderCameraReset()

data = pvs.XMLPartitionedDatasetCollectionReader(
    FileName=[f"{script_dir}/VisualizationOutput/Output.vtpc.series"]
)

stress = pvs.Calculator(Input=data)
stress.ResultArrayName = "Stress"
warp = pvs.WarpByVector(Input=stress)
warp.Vectors = ["POINTS", "Displacement"]

display = pvs.Show(warp, view)
display.Representation = "Surface"
display.Ambient = 0.3
display.Diffuse = 0.8
pvs.ColorBy(display, ("POINTS", "Stress"))

lut = pvs.GetColorTransferFunction("Stress")
lut.ApplyPreset("Cool to Warm", True)
lut.RescaleTransferFunction(0.0, 60.0)
lut.AutomaticRescaleRangeMode = "Never"

bar = pvs.GetScalarBar(lut, view)
bar.Title = "Von Mises Stress [kPa]"
bar.ComponentTitle = ""
bar.Orientation = "Horizontal"
bar.WindowLocation = "Any Location"
bar.Position = [0.06, 0.1]
bar.ScalarBarLength = 0.3
bar.UseCustomLabels = True
bar.CustomLabels = [0.0, 20.0, 40.0, 60.0]
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

# View along (0.4, 0.3, 1), mostly onto the side of the beam so that the bending shows, with the
# load direction (y) up, as data/Geometry.png; the frame fits the beam at full load.
view.CameraFocalPoint = [0.5, -0.03, 0.0]
view.CameraPosition = [0.9, 0.27, 1.0]
view.CameraViewUp = [0.0, 1.0, 0.0]
view.CameraParallelProjection = 1
view.CameraParallelScale = 0.36


def render(load, path):
    stress.Function = f'"Von Mises Stress" * {load} / 1000'
    warp.ScaleFactor = displacement_scale * load
    pvs.Render(view)
    pvs.SaveScreenshot(path, view, OverrideColorPalette="WhiteBackground")


vis = f"{script_dir}/vis"
os.makedirs(vis, exist_ok=True)
for i in range(frames + 1):
    render(i / frames, f"{vis}/Scene_{i:03d}.png")

# Hold the full load for one second at the end of each cycle.
for i in range(frames + 1, frames + 9):
    Image.open(f"{vis}/Scene_{frames:03d}.png").save(f"{vis}/Scene_{i:03d}.png")

subprocess.run(
    f'ffmpeg -y -i "{vis}/Scene_%03d.png" -vf "scale=800:-1:flags=lanczos,palettegen" '
    f'"{vis}/palette.png"',
    shell=True,
    check=True,
    capture_output=True,
)
subprocess.run(
    f'ffmpeg -y -framerate 8 -i "{vis}/Scene_%03d.png" -i "{vis}/palette.png" '
    f'-lavfi "scale=800:-1:flags=lanczos,paletteuse=dither=none" '
    f'"{script_dir}/results/Deformation.gif"',
    shell=True,
    check=True,
    capture_output=True,
)
