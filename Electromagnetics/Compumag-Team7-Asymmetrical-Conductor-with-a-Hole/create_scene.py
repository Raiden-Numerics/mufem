#!/usr/bin/env python3
import argparse
import math
import subprocess
from pathlib import Path

import paraview

paraview.compatibility.major = 6
paraview.compatibility.minor = 0

import paraview.simple as pvs  # noqa: E402

import numpy as np  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
from PIL import Image  # noqa: E402

pvs._DisableFirstRenderCameraReset()


def build_expression(phase: float) -> str:
    c = math.cos(phase)
    s = math.sin(phase)
    return (
        "inputs[0].PointData['Electric Current Density-Real']*{c} "
        "- inputs[0].PointData['Electric Current Density-Imag']*{s}"
    ).format(c=f"{c:.17g}", s=f"{s:.17g}")


def setup_render_view(size_width: int, size_height: int):
    view = pvs.CreateView("RenderView")
    view.ViewSize = [size_width, size_height]

    view.CameraParallelProjection = 1
    view.CameraParallelScale = 0.1
    view.CameraPosition = [-0.6, -0.3, 1.34]
    view.CameraViewUp = [0.5, 0.22, 0.83]
    view.CameraViewAngle = 20.0
    view.EyeAngle = 2.0
    view.CameraFocalDisk = 1.0
    view.CameraFocalDistance = 0.0

    return view


def load_data(input_path: str, size_width: int, size_height: int, glyph_scale: float):
    view = setup_render_view(size_width, size_height)

    # IMPORTANT in batch: bind view to a layout, otherwise SaveScreenshot may do nothing.
    layout = pvs.CreateLayout(name="Layout1")
    layout.AssignView(0, view)

    pvs.SetActiveView(view)

    data = pvs.OpenDataFile(input_path)

    # show data (background geometry)
    data_display = pvs.Show(data, view, "UnstructuredGridRepresentation")
    data_display.Representation = "Surface"
    data_display.ColorArrayName = ["POINTS", ""]
    data_display.ComputePointNormals = 1
    data_display.Assembly = "Hierarchy"
    data_display.BlockSelectors = ["/Root/Coil", "/Root/Plate"]
    pvs.ColorBy(data_display, None)

    # computed vector field J(t)
    calc = pvs.PythonCalculator(registrationName="J_of_t", Input=data)
    calc.ArrayAssociation = "Point Data"
    calc.ArrayName = "Electric Current Density"
    calc.Expression = build_expression(0.0)

    glyph = pvs.Glyph(
        registrationName="Glyph_Electric_Current_Density", Input=calc, GlyphType="Arrow"
    )
    glyph.OrientationArray = ["POINTS", "Electric Current Density"]
    glyph.ScaleArray = ["POINTS", "Electric Current Density"]
    glyph.ScaleFactor = glyph_scale
    glyph.GlyphMode = "All Points"

    # thicker arrows
    glyph.GlyphType.ShaftRadius = 0.07
    glyph.GlyphType.ShaftResolution = 100
    glyph.GlyphType.TipRadius = 0.12
    glyph.GlyphType.TipLength = 0.15
    glyph.GlyphType.TipResolution = 24

    disp = pvs.Show(glyph, view, "GeometryRepresentation")
    disp.Representation = "Surface"

    pvs.ColorBy(disp, ("POINTS", "Electric Current Density", "Magnitude"))
    lut = pvs.GetColorTransferFunction("Electric Current Density")
    pwf = pvs.GetOpacityTransferFunction("Electric Current Density")

    disp.RescaleTransferFunctionToDataRange(True, False)
    scalar_bar = pvs.GetScalarBar(lut, view)
    disp.SetScalarBarVisibility(view, True)

    # scalar bar formatting
    scalar_bar.Orientation = "Horizontal"
    scalar_bar.WindowLocation = "Any Location"
    scalar_bar.Title = "Electric Current Density [A/m²]"
    scalar_bar.ComponentTitle = ""
    scalar_bar.UseCustomLabels = True
    scalar_bar.CustomLabels = [0, 1.0e6, 2.0e6]
    scalar_bar.TitleFontSize = 32
    scalar_bar.LabelFontSize = 28
    scalar_bar.TitleBold = 1
    scalar_bar.LabelBold = 1
    scalar_bar.TitleColor = [0, 0, 0]
    scalar_bar.LabelColor = [0, 0, 0]
    scalar_bar.Position = [0.35, 0.1]
    scalar_bar.ScalarBarLength = 0.3
    scalar_bar.ScalarBarThickness = 40

    # Ensure camera is not auto-changed by pipeline updates.
    view.CameraParallelProjection = 1
    view.CameraParallelScale = 0.18
    view.CameraPosition = (-0.3697352196806951, 0.3392467327757224, 0.22955715848836572)
    view.CameraViewUp = (0.30395294501951486, -0.1429607220735116, 0.9418995908047652)
    view.CameraFocalPoint = (
        -0.3041336634862759,
        0.31113183987720244,
        0.20412014606490986,
    )

    view.CameraViewAngle = 30.0
    view.EyeAngle = 2.0
    view.CameraFocalDisk = 1.0
    view.CameraFocalDistance = 0.0

    pvs.Render(view)

    return {
        "layout": layout,
        "view": view,
        "data": data,
        "calc": calc,
        "glyph": glyph,
        "disp": disp,
        "lut": lut,
        "pwf": pwf,
        "size": [size_width, size_height],
    }


def visualize_and_save(state, phase: float, index: int, outdir: Path):
    view = state["view"]
    layout = state["layout"]
    calc = state["calc"]

    calc.Expression = build_expression(phase)

    pvs.UpdatePipeline(proxy=calc)
    pvs.Render(view)

    filename = (outdir / f"Scene_Electric_Current_Density_{index:03d}.png").resolve()

    pvs.SaveScreenshot(
        str(filename),
        viewOrLayout=layout,
        ImageResolution=state["size"],
        OverrideColorPalette="WhiteBackground",
    )


def combine_images(large_path: Path, small1_path: Path, small2_path: Path, output_path: Path):
    large = Image.open(str(large_path))
    small1 = Image.open(str(small1_path))
    small2 = Image.open(str(small2_path))

    target_height = large.height // 2

    ratio1 = target_height / small1.height
    ratio2 = target_height / small2.height

    small1 = small1.resize((int(small1.width * ratio1), target_height))
    small2 = small2.resize((int(small2.width * ratio2), target_height))

    total_width = large.width + max(small1.width, small2.width)
    total_height = large.height

    out = Image.new("RGB", (total_width, total_height), "white")
    out.paste(large, (0, 0))
    out.paste(small1, (large.width, 0))
    out.paste(small2, (large.width, target_height))

    out.save(str(output_path))


def create_plot(time_s: float, index: int, steps: int, outdir: Path, freq_hz: float):
    def coil_current(t: float) -> float:
        return math.sin(2.0 * math.pi * freq_hz * t)

    t_full = np.linspace(0.0, 1.0 / freq_hz, steps)
    filename = outdir / f"Coil_Current_{index:03d}.png"

    plt.clf()
    plt.plot(
        *zip(*[(t * 1e3, coil_current(t)) for t in t_full]),
        "-",
        color="#444444",
        linewidth=3.5,
        markersize=5.0,
    )

    plt.plot(
        *zip(*[(time_s * 1e3, coil_current(time_s))]),
        "o",
        linewidth=2.5,
        markersize=8.0,
        label="Applied Current",
        markerfacecolor="r",
        markeredgecolor="r",
    )

    plt.xlabel("Cycle Time [ms]")
    plt.ylabel("Coil Current [A]")
    plt.xlim((0, (1.0 / freq_hz) * 1e3))
    plt.yticks([-1, -0.5, 0.0, 0.5, 1.0])
    plt.xticks([0, 5, 10, 15, 20])

    plt.legend(loc="best").draw_frame(False)
    plt.savefig(str(filename), bbox_inches="tight")


def create_magnetic_flux_density_plot(step: int, phase: float):

    sim = np.loadtxt("results/Bz_A1-B1_mufem.csv", delimiter=",", comments="#")

    plt.clf()

    ref = np.loadtxt("data/Bz_A1-B1.csv", delimiter=",", comments="#")
    plt.plot(
        ref[:, 1],
        1.0e-1 * (ref[:, 2] * np.cos(phase) - ref[:, 3] * np.sin(phase)),
        "ko-",
        label="Reference",
        markersize=6.0,
        linewidth=2.0,
    )

    plt.plot(
        sim[:, 0],
        sim[:, 1] * np.cos(phase) - sim[:, 2] * np.sin(phase),
        label="$\\mu$fem",
        color="r",
        linewidth=3.0,
    )

    plt.xlim((0, 288))
    plt.ylim((-9, 9))

    plt.xticks([0, 72, 144, 216, 288])

    plt.xlabel("Position [mm]")
    plt.ylabel("Magnetic Flux Density along A1-B1 [mT]")

    plt.legend(loc="best").draw_frame(False)

    plt.savefig(
        f"vis/Magnetic_Flux_Density_{step:03d}.png",
        bbox_inches="tight",
    )


def run_ffmpeg(outdir: Path):

    print("Creating animated GIF using ffmpeg...")

    gif = outdir / "output.gif"
    palette = outdir / "palette.png"
    subprocess.run(
        f'ffmpeg -y -framerate 8 -i "{outdir}/Scene_%03d.png" '
        f'-vf "fps=8,scale=1200:-1:flags=lanczos,palettegen=stats_mode=full" "{palette}"',
        shell=True,
        text=True,
        capture_output=True,
        check=False,
    )
    subprocess.run(
        f'ffmpeg -y -framerate 8 -i "{outdir}/Scene_%03d.png" -i "{palette}" '
        f'-lavfi "fps=8,scale=1200:-1:flags=lanczos,paletteuse=dither=sierra2_4a" "{gif}"',
        shell=True,
        text=True,
        capture_output=True,
        check=False,
    )


def main():

    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--input", default="VisualizationOutput/Output.vtpc.series")
    ap.add_argument("--freq", type=float, default=50.0)
    ap.add_argument("--frames", type=int, default=40)
    ap.add_argument("--outdir", default="vis")
    ap.add_argument("--size", default="2374x1558")
    ap.add_argument("--glyph-scale", type=float, default=2e-8)
    args = ap.parse_args()

    width, height = [int(x) for x in args.size.lower().split("x")]
    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    state = load_data(args.input, width, height, args.glyph_scale)

    period_length = 1.0 / args.freq
    dt = period_length / args.frames

    for index in range(args.frames):
        time = index * dt
        phase = 2.0 * math.pi * args.freq * time

        phase_deg = phase * 180.0 / math.pi

        print(f"Creating plot for step {index:03d} at {phase_deg:.3f}deg / {time * 1e3:.3f}ms")

        create_magnetic_flux_density_plot(index, phase)
        visualize_and_save(state, phase, index, outdir)
        create_plot(time, index, args.frames, outdir, args.freq)

    for i in range(args.frames):
        combine_images(
            large_path=outdir / f"Scene_Electric_Current_Density_{i:03d}.png",
            small1_path=outdir / f"Coil_Current_{i:03d}.png",
            small2_path=outdir / f"Magnetic_Flux_Density_{i:03d}.png",
            output_path=outdir / f"Scene_{i:03d}.png",
        )

    run_ffmpeg(outdir)


if __name__ == "__main__":
    main()
