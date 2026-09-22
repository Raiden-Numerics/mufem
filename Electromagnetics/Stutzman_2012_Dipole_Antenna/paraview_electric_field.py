import os
import numpy as np
import paraview.simple as pvs
import subprocess


def create_scene(data_original, phase, screenshot_file):
    field_name_real = "Electric Field-Real"
    field_name_imag = "Electric Field-Imag"
    field_name = "Electric Field"
    field_unit = "V/m"

    data = pvs.Calculator(Input=data_original)
    data.ResultArrayName = f"{field_name}"
    data.Function = f'"{field_name_real}" * cos({phase}) - "{field_name_imag}" * sin({phase})'

    # Slice plane at z=0 ---------------------------------------------------------------
    data = pvs.Slice(Input=data)
    data.SliceType = "Plane"
    data.SliceType.Origin = (0, 0, 0)
    data.SliceType.Normal = (1, 0, 0)

    # Translate ------------------------------------------------------------------------
    data = pvs.Transform(Input=data)
    data.Transform.Translate = (0, 0, 1)

    # View settings --------------------------------------------------------------------
    view = pvs.GetRenderView()

    view.UseColorPaletteForBackground = 0
    view.BackgroundColorMode = "Single Color"
    view.Background = (1.0, 1.0, 1.0)
    view.ViewSize = (1000, 1000)
    view.OrientationAxesVisibility = 1
    view.OrientationAxesLabelColor = (0.0, 0.0, 0.0)

    # Display settings -----------------------------------------------------------------
    display = pvs.Show()

    # Scalar bar settings --------------------------------------------------------------
    pvs.ColorBy(display, ("POINTS", field_name))

    ctf = pvs.GetColorTransferFunction(field_name)
    ctf.ApplyPreset("Cool to Warm")

    scalar_bar = pvs.GetScalarBar(ctf)

    scalar_bar.Title = f"{field_name} [{field_unit}]"
    scalar_bar.ComponentTitle = ""

    scalar_bar.Orientation = "Horizontal"
    scalar_bar.WindowLocation = "Lower Center"
    scalar_bar.TitleColor = (0, 0, 0)
    scalar_bar.LabelColor = (0, 0, 0)
    scalar_bar.TitleFontSize = 32
    scalar_bar.LabelFontSize = 28
    scalar_bar.ScalarBarThickness = 32
    scalar_bar.RangeLabelFormat = "%.0f"
    scalar_bar.LabelFormat = "%.0f"

    scalar_bar.LookupTable.RescaleTransferFunction(0, 30)

    # Camera settings ------------------------------------------------------------------
    pvs.Render()

    view.CameraViewUp = (0, 0, 1)
    view.CameraPosition = (1, 0, 0)
    view.CameraFocalPoint = (0, 0, 0)
    view.CameraParallelProjection = 1
    view.CameraParallelScale = 8

    # Save screenshot ------------------------------------------------------------------
    pvs.SaveScreenshot(screenshot_file)

    pvs.Delete(view)
    pvs.Delete(data)
    pvs.Delete(display)


# **************************************************************************************
wdir = "results/images/"

phases = np.linspace(0.0, np.pi, 51)


# **************************************************************************************
data_original = pvs.OpenDataFile("VisualizationOutput/Output_0.vtpc")

os.makedirs(wdir, exist_ok=True)

for i in range(len(phases)):
    phase = phases[i]

    screenshot_file = os.path.join(wdir, f"{i}.png")

    create_scene(data_original, phase, screenshot_file)

    print(f"phase {i + 1} of {len(phases)}")


# **************************************************************************************
# 1) Use ffmpeg to convert the images to mp4 movie:
# 2) Use ffmpeg to convert mp4 movie to gif:
#    - creating mp4 first and then converting to gif results in better gif quality
# 3) Remove unnecessary files
commands = [
    (f"ffmpeg -i {wdir}/%d.png -framerate 24 -c:v libx264 -pix_fmt yuv420p {wdir}/out.mp4 -y"),
    (
        f"ffmpeg -i {wdir}/out.mp4 "
        "-vf 'fps=5,scale=800:-1:flags=lanczos' "
        "-c:v gif results/Electric_Field.gif -y"
    ),
    f"rm -rf {wdir}",
]

for command in commands:
    result = subprocess.run(command, shell=True, text=True, capture_output=True)

    if result.returncode != 0:
        print(result.stderr)
