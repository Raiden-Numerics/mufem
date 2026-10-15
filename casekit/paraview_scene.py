"""ParaView helpers for the scene and animation scripts (create_scene.py) of the cases.

Run the scripts with `pvpython`. ParaView brings its own Python, so a script makes casekit
importable with

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

before `from casekit.paraview_scene import ...`. All scenes share the same look: a white
background, no orientation axes, the "Cool to Warm" color map and a color bar with fixed
labels.
"""

import math
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Sequence, Tuple

import paraview.simple as pvs
from PIL import Image, ImageOps


def new_view(size: Tuple[int, int] = (1600, 1200)):
    """Render view with a white background, no orientation axes and a camera kept as set."""
    view = pvs.CreateView("RenderView")
    view.ViewSize = list(size)
    view.OrientationAxesVisibility = 0
    view.UseColorPaletteForBackground = 0
    view.Background = [1.0, 1.0, 1.0]
    pvs._DisableFirstRenderCameraReset()
    return view


def read_output(case_dir: Path):
    """Reader of the fields that case.py exports to VisualizationOutput/."""
    return pvs.XMLPartitionedDatasetCollectionReader(
        FileName=[f"{case_dir}/VisualizationOutput/Output.vtpc.series"]
    )


def show(source, view, color: Optional[Sequence[float]] = None, edges: bool = False):
    """Show `source` as a lit surface, in a solid `color` or (without) colored later."""
    display = pvs.Show(source, view)
    display.Representation = "Surface With Edges" if edges else "Surface"
    display.EdgeColor = [0.0, 0.0, 0.0]
    display.Ambient = 0.3
    display.Diffuse = 0.8
    if color is not None:
        pvs.ColorBy(display, None)
        display.AmbientColor = list(color)
        display.DiffuseColor = list(color)
    return display


def color_by(
    display,
    view,
    array: str,
    title: str,
    labels: Sequence[float],
    label_format: str = "%.0f",
    value_range: Optional[Tuple[float, float]] = None,
    orientation: str = "Horizontal",
    position: Tuple[float, float] = (0.3, 0.05),
    length: float = 0.4,
    thickness: int = 16,
    title_size: int = 28,
    label_size: int = 24,
    component: Optional[str] = None,
    boxed: bool = False,
):
    """Color `display` by `array` with the Cool to Warm map and show a color bar.

    The color range is `value_range`, or the first to the last label. `boxed` draws the bar on a
    white box, for a bar placed over the model. Returns the color bar.
    """
    pvs.ColorBy(display, ("POINTS", array, component) if component else ("POINTS", array))

    lut = pvs.GetColorTransferFunction(array)
    lut.ApplyPreset("Cool to Warm", True)
    lut.RescaleTransferFunction(*(value_range or (labels[0], labels[-1])))
    lut.AutomaticRescaleRangeMode = "Never"

    bar = pvs.GetScalarBar(lut, view)
    bar.Title = title
    bar.ComponentTitle = ""
    bar.Orientation = orientation
    bar.WindowLocation = "Any Location"
    bar.Position = list(position)
    bar.ScalarBarLength = length
    bar.ScalarBarThickness = thickness
    bar.UseCustomLabels = True
    bar.CustomLabels = list(labels)
    bar.AddRangeLabels = 0
    bar.AutomaticLabelFormat = 0
    bar.LabelFormat = label_format
    bar.TitleFontSize = title_size
    bar.LabelFontSize = label_size
    bar.TitleColor = [0.0, 0.0, 0.0]
    bar.LabelColor = [0.0, 0.0, 0.0]
    bar.TitleBold = 1
    bar.LabelBold = 1
    bar.DrawBackground = int(boxed)
    bar.BackgroundColor = [1.0, 1.0, 1.0, 1.0]
    bar.BackgroundPadding = 10.0
    display.SetScalarBarVisibility(view, True)
    return bar


def set_camera(
    view,
    direction: Sequence[float],
    up: Sequence[float],
    focal_point: Sequence[float],
    parallel_scale: Optional[float] = None,
    bounds: Optional[Sequence[float]] = None,
    shift_up: float = 0.0,
):
    """Look at `focal_point` from `direction` (toward the viewer) with `up` up on the screen.

    The projection is parallel, so vertical edges stay vertical: the visible half height is
    `parallel_scale` [model units], or the view is fitted to `bounds`. `shift_up` [model units]
    then moves the picture up on the screen, e.g. to make room for a color bar below it.
    """
    if (parallel_scale is None) == (bounds is None):
        raise ValueError("set_camera needs either parallel_scale or bounds")

    # Only the clipping depends on the distance in a parallel projection: keep the camera well
    # outside the model.
    distance = 100.0 * parallel_scale if parallel_scale is not None else 1.0
    norm = math.sqrt(sum(d * d for d in direction))
    view.CameraFocalPoint = list(focal_point)
    view.CameraPosition = [f + distance * d / norm for f, d in zip(focal_point, direction)]
    view.CameraViewUp = list(up)
    view.CameraParallelProjection = 1
    if parallel_scale is not None:
        view.CameraParallelScale = parallel_scale
    else:
        view.ResetCamera(list(bounds), False)
    if shift_up:
        camera = view.GetActiveCamera()
        screen_up = camera.GetViewUp()
        shift = [-shift_up * u for u in screen_up]
        camera.SetFocalPoint(*[f + d for f, d in zip(camera.GetFocalPoint(), shift)])
        camera.SetPosition(*[p + d for p, d in zip(camera.GetPosition(), shift)])


def add_text(
    view,
    text: str,
    position: Optional[Tuple[float, float]] = None,
    font_size: int = 40,
    color: Sequence[float] = (0.0, 0.0, 0.0),
):
    """Bold text in the upper left corner, or at `position` (fractions of the view)."""
    source = pvs.Text(Text=text)
    display = pvs.Show(source, view)
    if position is None:
        display.WindowLocation = "Upper Left Corner"
    else:
        display.WindowLocation = "Any Location"
        display.Position = list(position)
    display.FontSize = font_size
    display.Bold = 1
    display.Color = list(color)
    return source


def phase_field(source, field: str, phase_deg: float, name: Optional[str] = None):
    """Calculator for Re(F e^{j phase}) = F_r cos(phase) - F_i sin(phase) of a complex field."""
    calculator = pvs.Calculator(Input=source)
    calculator.ResultArrayName = name or field
    phase = math.radians(phase_deg)
    calculator.Function = (
        f'"{field}-Real" * {math.cos(phase)!r} - "{field}-Imag" * {math.sin(phase)!r}'
    )
    return calculator


def trim(path: Path, border: int = 20) -> Image.Image:
    """Crop the white margins of the image at `path`, keeping `border` pixels."""
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


def save(view, path: Path, crop: bool = True, border: int = 20):
    """Render `view` to `path` on white and crop the white margins."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    pvs.Render(view)
    pvs.SaveScreenshot(str(path), view, OverrideColorPalette="WhiteBackground")
    if crop:
        trim(path, border)


def place(
    path: Path,
    canvas: Tuple[int, int],
    left: int,
    width: int,
    top: Optional[int] = None,
    height: Optional[int] = None,
):
    """Crop the image at `path` to its content and place it, scaled, on a white canvas.

    The content is scaled to `width` x `height` (`height` keeps the aspect ratio when omitted)
    and put at `left`, `top` (vertically centered when omitted). Used to show a mesh at the
    scale of the geometry image beside it.
    """
    image = trim(path, border=0)
    height = height or round(width * image.height / image.width)
    top = (canvas[1] - height) // 2 if top is None else top
    out = Image.new("RGB", canvas, "white")
    out.paste(image.resize((width, height), Image.LANCZOS), (left, top))
    out.save(path)


def combine_images(main: Path, sides: Sequence[Path], path: Path):
    """Put the images `sides` stacked on the right of `main`, each scaled to fit its height."""
    large = Image.open(main).convert("RGB")
    height = large.height // len(sides)
    smalls = []
    for side in sides:
        small = Image.open(side).convert("RGB")
        smalls.append(small.resize((round(small.width * height / small.height), height)))

    out = Image.new("RGB", (large.width + max(s.width for s in smalls), large.height), "white")
    out.paste(large, (0, 0))
    for i, small in enumerate(smalls):
        out.paste(small, (large.width, i * height + (large.height - len(sides) * height) // 2))
    out.save(path)


def write_gif(frames: Sequence[Path], path: Path, fps: int = 8, width: int = 800):
    """Encode the image files `frames` into an animated GIF of the given width."""
    if shutil.which("ffmpeg") is None:
        raise RuntimeError("write_gif needs ffmpeg on the PATH")

    work = Path(frames[0]).parent / "gif"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    for i, frame in enumerate(frames):
        shutil.copyfile(frame, work / f"{i:04d}.png")

    scale = f"scale={width}:-1:flags=lanczos"
    subprocess.run(
        ["ffmpeg", "-y", "-i", f"{work}/%04d.png", "-vf", f"{scale},palettegen",
         f"{work}/palette.png"],
        check=True,
        capture_output=True,
    )  # fmt: skip
    subprocess.run(
        ["ffmpeg", "-y", "-framerate", str(fps), "-i", f"{work}/%04d.png", "-i",
         f"{work}/palette.png", "-lavfi", f"{scale},paletteuse=dither=none", str(path)],
        check=True,
        capture_output=True,
    )  # fmt: skip
    shutil.rmtree(work)
