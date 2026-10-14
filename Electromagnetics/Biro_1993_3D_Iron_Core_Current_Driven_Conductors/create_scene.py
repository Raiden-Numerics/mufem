import os
import subprocess

import paraview.simple as pvs

script_dir = os.path.dirname(os.path.abspath(__file__))

number_of_coils = 25
coils = [f"/Root/Coil{k}" for k in range(1, number_of_coils + 1)]

view = pvs.CreateView("RenderView")
view.ViewSize = [1600, 1200]
view.OrientationAxesVisibility = 0
view.UseColorPaletteForBackground = 0
view.Background = [1.0, 1.0, 1.0]
pvs._DisableFirstRenderCameraReset()

data = pvs.OpenDataFile(f"{script_dir}/VisualizationOutput/Output_0.vtpc")


def field_at_phase(field, phase_deg):
    """|Re(F e^{j phase})| = |F_r cos(phase) - F_i sin(phase)|."""
    calculator = pvs.Calculator(Input=data)
    calculator.ResultArrayName = f"{field} (t)"
    calculator.Function = (
        f'"{field}-Real" * cos({phase_deg} * 3.14159265358979 / 180)'
        f' - "{field}-Imag" * sin({phase_deg} * 3.14159265358979 / 180)'
    )
    return calculator


def show_blocks(source, selectors, array=None, color=(0.6, 0.6, 0.6)):
    block = pvs.ExtractBlock(Input=source, Selectors=selectors)
    display = pvs.Show(block, view)
    display.Representation = "Surface"
    display.Ambient = 0.3
    display.Diffuse = 0.8
    if array is None:
        pvs.ColorBy(display, None)
        display.AmbientColor = list(color)
        display.DiffuseColor = list(color)
    else:
        pvs.ColorBy(display, ("POINTS", array, "Magnitude"))
    return block, display


def color_bar(array, title, value_range, labels):
    lut = pvs.GetColorTransferFunction(array)
    lut.ApplyPreset("Cool to Warm", True)
    lut.RescaleTransferFunction(*value_range)
    lut.AutomaticRescaleRangeMode = "Never"

    bar = pvs.GetScalarBar(lut, view)
    bar.Title = title
    bar.ComponentTitle = ""
    bar.Orientation = "Horizontal"
    bar.WindowLocation = "Any Location"
    bar.Position = [0.3, 0.05]
    bar.ScalarBarLength = 0.4
    bar.ScalarBarThickness = 30
    bar.UseCustomLabels = True
    bar.CustomLabels = labels
    bar.AddRangeLabels = 0
    bar.TitleFontSize = 28
    bar.LabelFontSize = 24
    bar.TitleColor = [0, 0, 0]
    bar.LabelColor = [0, 0, 0]
    bar.TitleBold = 1
    bar.LabelBold = 1
    bar.Visibility = 1
    return bar


def set_camera():
    """Same view for all scenes: core and conductors seen from below (z < 0)."""
    view.CameraPosition = [-0.06, -0.08, -0.052]
    view.CameraFocalPoint = [0.0125, 0.008, 0.009]
    view.CameraViewUp = [0.0, 0.0, 1.0]
    view.CameraParallelProjection = 1
    view.ResetCamera([0, 0.025, 0, 0.017, 0, 0.018], False)


def current_density_scene(phase_deg, path, phase_label=False):
    """Current density in the conductors, with the core in gray."""
    field = field_at_phase("Electric Current Density", phase_deg)
    core, _ = show_blocks(data, ["/Root/Core"])
    conductors, _ = show_blocks(field, coils, array="Electric Current Density (t)")
    bar = color_bar(
        "Electric Current Density (t)",
        "Electric Current Density [A/m²]",
        (0.0, 1.0e8),
        [0.0, 5.0e7, 1.0e8],
    )

    text = None
    if phase_label:
        text = pvs.Text(Text=f"Phase = {phase_deg:.0f}°")
        text_display = pvs.Show(text, view)
        text_display.WindowLocation = "Upper Left Corner"
        text_display.FontSize = 40
        text_display.Bold = 1
        text_display.Color = [0.0, 0.0, 0.0]

    set_camera()
    pvs.Render(view)
    pvs.SaveScreenshot(path, view, OverrideColorPalette="WhiteBackground")
    bar.Visibility = 0

    for proxy in [text, conductors, core, field]:
        if proxy is not None:
            pvs.Delete(proxy)


def magnetic_flux_density_scene(phase_deg, path, b_max):
    """Flux density in the core and the conductors."""
    field = field_at_phase("Magnetic Flux Density", phase_deg)
    parts, _ = show_blocks(field, ["/Root/Core", *coils], array="Magnetic Flux Density (t)")
    bar = color_bar(
        "Magnetic Flux Density (t)",
        "Magnetic Flux Density [T]",
        (0.0, b_max),
        [0.0, b_max / 2, b_max],
    )

    set_camera()
    pvs.Render(view)
    pvs.SaveScreenshot(path, view, OverrideColorPalette="WhiteBackground")
    bar.Visibility = 0

    for proxy in [parts, field]:
        pvs.Delete(proxy)


if __name__ == "__main__":
    results = f"{script_dir}/results"

    # The imaginary part of B is much smaller than the real part: own color range.
    for phase, name, b_max in [(0, "Real", 1.2), (90, "Imag", 0.1)]:
        current_density_scene(phase, f"{results}/Scene_Electric_Current_Density_Phase_{name}.png")
        magnetic_flux_density_scene(
            phase, f"{results}/Scene_Magnetic_Flux_Density_Phase_{name}.png", b_max
        )

    vis = f"{script_dir}/vis"
    os.makedirs(vis, exist_ok=True)
    for i, phase in enumerate(range(0, 360, 5)):
        current_density_scene(phase, f"{vis}/Scene_{i:03d}.png", phase_label=True)

    subprocess.run(
        f'ffmpeg -y -i "{vis}/Scene_%03d.png" -vf "scale=1280:-1:flags=lanczos,palettegen" '
        f'"{vis}/palette.png"',
        shell=True,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        f'ffmpeg -y -framerate 12 -i "{vis}/Scene_%03d.png" -i "{vis}/palette.png" '
        f'-lavfi "scale=1280:-1:flags=lanczos,paletteuse=dither=none" "{results}/animation.gif"',
        shell=True,
        check=True,
        capture_output=True,
    )
