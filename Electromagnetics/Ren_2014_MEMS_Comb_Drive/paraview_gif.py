import paraview.simple as pvs

import subprocess


def create_scene(data_file, screenshot_file, show=False):
    field_name = "Electric Potential"
    field_unit = "V"

    # View settings:
    view = pvs.GetRenderView()
    view.UseColorPaletteForBackground = 0
    view.BackgroundColorMode = "Single Color"
    view.Background = [1.0, 1.0, 1.0]
    view.ViewSize = [1100, 800]
    view.OrientationAxesVisibility = 1
    view.OrientationAxesLabelColor = [0.0, 0.0, 0.0]

    pvs.Render()

    # Camera settings:
    view.CameraViewUp = [0, 1, 0]
    view.CameraPosition = [1e-4, 1e-4, 1e-4]
    view.CameraFocalPoint = [0.0, 0.0, 0.0]
    view.CameraFocalDisk = 1.0
    view.CameraParallelProjection = 1
    view.CameraParallelScale = 5e-5
    view.CenterOfRotation = [0.0, 0.0, 0.0]

    data = pvs.OpenDataFile(data_file)

    # Clip settings:
    data = pvs.Clip(Input=data)
    data.ClipType = "Plane"
    data.ClipType.Origin = [11e-6, 2e-6, 17e-6]
    data.ClipType.Normal = [0, 1, 0]

    # Transform settings:
    data = pvs.Transform(Input=data)
    data.Transform.Translate = [7e-6, 30e-6, 0.0]

    # Display settings:
    display = pvs.Show()
    display.Representation = "Surface"
    display.NonlinearSubdivisionLevel = 2

    pvs.ColorBy(display, ("POINTS", field_name))

    ctf = pvs.GetColorTransferFunction(field_name)
    ctf.ApplyPreset("Cool to Warm")

    # Scalar bar settings:
    scalar_bar = pvs.GetScalarBar(ctf)
    scalar_bar.Orientation = "Horizontal"
    scalar_bar.WindowLocation = "Lower Center"
    scalar_bar.TitleColor = [0, 0, 0]
    scalar_bar.LabelColor = [0, 0, 0]
    scalar_bar.TitleFontSize = 28
    scalar_bar.LabelFontSize = 20
    scalar_bar.ScalarBarThickness = 28
    scalar_bar.ComponentTitle = ""
    scalar_bar.Title = f"{field_name} [{field_unit}]" if field_unit else field_name
    scalar_bar.RangeLabelFormat = "%.0f"
    scalar_bar.LabelFormat = "%.0f"
    scalar_bar.LookupTable.RescaleTransferFunction([0, 1])

    pvs.Render()

    pvs.SaveScreenshot(screenshot_file)

    if show:
        pvs.Interact()

    pvs.Delete(view)
    pvs.Delete(data)
    pvs.Delete(display)


if __name__ == "__main__":
    # Create the scene images with a siple name pattern:
    for i in range(17):
        data_file = f"VisualizationOutput/Output_{2 * i + 1}.vtpc"
        screenshot_file = f"results/{i}.png"

        create_scene(data_file, screenshot_file)

    # 1) Use ffmpeg to convert the images to mp4 movie:
    #    - use the 'reverse' option to reverse the video in order to show the attractive
    #      force
    # 2) Use ffmpeg to convert mp4 movie to gif:
    #    - creating mp4 first and then converting to gif results in better gif quality
    # 3) Remove unnecessary files
    commands = [
        (
            "ffmpeg -framerate 5 -i results/%d.png "
            "-vf reverse -c:v libx264 -pix_fmt yuv420p results/output.mp4"
        ),
        (
            "ffmpeg -i results/output.mp4 "
            "-vf 'fps=5,scale=800:-1:flags=lanczos' "
            "-c:v gif results/Electric_Potential.gif -y"
        ),
        "rm results/output.mp4",
        "bash -c 'rm results/{0..16}.png'",
    ]
    for command in commands:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)

        if result.returncode != 0:
            print(result.stderr)
