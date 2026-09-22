import paraview.simple as pvs

import subprocess
from PIL import Image


def create_scene(index: int, show: bool = False):

    # flake8: noqa: FKA100

    import os

    renderView1 = pvs.CreateView("RenderView")

    renderView1.Set(
        ViewSize=[1600, 1300],
        CameraPosition=[0.0, 0.0, -0.45],
        # CameraFocalPoint=[0.00336064, -0.0151335, 0.00804053],
        CameraViewUp=[0, 1, 0],
        CameraViewAngle=30.0,
        EyeAngle=2.0,
        CameraFocalDisk=1.0,
        CameraFocalDistance=0.0,
    )

    pvs._DisableFirstRenderCameraReset()

    script_dir = os.path.dirname(os.path.abspath(__file__))

    data = pvs.OpenDataFile(f"{script_dir}/VisualizationOutput/Output_{index}.vtpc")

    # show data from data
    dataDisplay = pvs.Show(data, renderView1, "UnstructuredGridRepresentation")

    # trace defaults for the display properties.
    dataDisplay.Set(
        Representation="Surface",
        ColorArrayName=["POINTS", ""],
        ComputePointNormals=1,
        Assembly="Hierarchy",
        BlockSelectors=[
            "/Root/Stator",
            "/Root/Rotor",
            "/Root/LowerCoil",
            "/Root/UpperCoil",
        ],
    )

    pvs.ColorBy(dataDisplay, ("POINTS", "Electric Current Density", "Magnitude"))

    ctf = pvs.GetColorTransferFunction("ElectricCurrentDensity")
    ctf.ApplyPreset("Cool to Warm")
    ctf.RescaleTransferFunction(0, 3.0e5)

    scalar_bar = pvs.GetScalarBar(ctf)
    scalar_bar.Orientation = "Horizontal"
    scalar_bar.WindowLocation = "Any Location"

    scalar_bar.Title = "Electric Current Density [A/m²]"
    scalar_bar.ComponentTitle = ""
    scalar_bar.UseCustomLabels = True
    scalar_bar.CustomLabels = [0, 1.0e5, 2.0e5, 3.0e5]
    scalar_bar.TitleFontSize = 32
    scalar_bar.LabelFontSize = 28
    scalar_bar.TitleBold = 1
    scalar_bar.LabelBold = 1
    scalar_bar.TitleColor = [0, 0, 0]
    scalar_bar.LabelColor = [0, 0, 0]
    scalar_bar.Position = [0.58, 0.1]
    scalar_bar.ScalarBarLength = 0.3
    scalar_bar.ScalarBarThickness = 40

    pvs.Render()
    pvs.SaveScreenshot(
        f"vis/Scene_Electric_Current_Density_{index:03d}.png",
        OverrideColorPalette="WhiteBackground",
    )


def combine_images(large_path, small1_path, small2_path, output_path):
    large = Image.open(large_path)
    small1 = Image.open(small1_path)
    small2 = Image.open(small2_path)

    # Resize small images to same height as large
    target_height = large.height // 2
    ratio1 = target_height / small1.height
    ratio2 = target_height / small2.height

    small1 = small1.resize((int(small1.width * ratio1), target_height))
    small2 = small2.resize((int(small2.width * ratio2), target_height))

    # Width is max(large.width, small1.width + small2.width)
    total_width = large.width + max(small1.width, small2.width)
    total_height = large.height

    out = Image.new("RGB", (total_width, total_height), "white")

    out.paste(large, (0, 0))
    out.paste(small1, (large.width, 0))
    out.paste(small2, (large.width, target_height))

    out.save(output_path)


if __name__ == "__main__":
    # Create the scene images with a siple name pattern:
    for i in range(31):
        create_scene(i)

        combine_images(
            large_path=f"vis/Scene_Electric_Current_Density_{i:03d}.png",
            small1_path=f"vis/Coil_Current_vs_Time_{i:03d}.png",
            small2_path=f"vis/Rotor_Torque_vs_Time_{i:03d}.png",
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
