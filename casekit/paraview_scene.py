"""ParaView helpers for the scene and animation scripts (create_scene.py) of the cases.

Run the scripts with `pvpython`. ParaView brings its own Python, so a script makes casekit
importable with

    sys.path.insert(0, str(case_dir.parents[1]))

before `from casekit.paraview_scene import ...` (`case_dir` being the case directory). All
scenes share the same look: a white background, no orientation axes, the "Cool to Warm" color
map, a color bar with fixed labels and a parallel projection.
"""

import math
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Sequence, Tuple

import paraview.simple as pvs
from PIL import Image

from casekit.images import trim


def new_view(size: Tuple[int, int] = (1600, 1200)):
    """Render view with a white background, no orientation axes and a camera kept as set."""
    view = pvs.CreateView("RenderView")
    view.ViewSize = list(size)
    view.OrientationAxesVisibility = 0
    view.UseColorPaletteForBackground = 0
    view.Background = [1.0, 1.0, 1.0]
    pvs._DisableFirstRenderCameraReset()
    return view


def read_output(case_dir: Path, index: Optional[int] = None):
    """Reader of the fields that case.py exports to VisualizationOutput/: the whole series, or
    the single output `index` (VisualizationOutput/Output_<index>.vtpc)."""
    name = "Output.vtpc.series" if index is None else f"Output_{index}.vtpc"
    return pvs.XMLPartitionedDatasetCollectionReader(
        FileName=[f"{case_dir}/VisualizationOutput/{name}"]
    )


def read_scene_data(case_dir: Path):
    """The extra input of the scenes that case.py writes to ValidationCase.scene_data_path."""
    import numpy as np

    return np.load(case_dir / "VisualizationOutput" / "Scene_Data.npz")


def blocks(source, names: Sequence[str]):
    """The bodies `names` of `source` (e.g. "Coil1"; ParaView drops the spaces of the names in
    case.py); raises if one does not exist, which would silently leave it out of the image."""
    source.UpdatePipeline()
    hierarchy = source.GetDataInformation().DataInformation.GetHierarchy()
    missing = [name for name in names if hierarchy.GetFirstNodeByPath(f"/Root/{name}") < 0]
    if missing:
        raise ValueError(f"no bodies {missing} in the output")
    return pvs.ExtractBlock(Input=source, Selectors=[f"/Root/{name}" for name in names])


def show(source, view, color: Optional[Sequence[float]] = None, edges: bool = False):
    """Show `source` as a lit surface, in a solid `color` or (without) colored later."""
    display = pvs.Show(source, view)
    display.Representation = "Surface With Edges" if edges else "Surface"
    display.EdgeColor = [0.0, 0.0, 0.0]
    display.Ambient = 0.3
    display.Diffuse = 0.8
    if color is not None:
        if display.ColorArrayName[1]:
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

    The color range is the first to the last label. `boxed` draws the bar on a white box, for a
    bar placed over the model. Returns the color bar.
    """
    if array not in display.Input.PointData.keys():
        raise ValueError(f"no point array {array!r} in the shown data")
    pvs.ColorBy(display, ("POINTS", array, component) if component else ("POINTS", array))

    lut = pvs.GetColorTransferFunction(array)
    lut.ApplyPreset("Cool to Warm", True)
    lut.RescaleTransferFunction(labels[0], labels[-1])
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
    focal_point: Optional[Sequence[float]] = None,
    parallel_scale: Optional[float] = None,
    bounds: Optional[Sequence[float]] = None,
    shift_up: float = 0.0,
):
    """Look from `direction` (toward the viewer) with `up` up on the screen.

    The projection is parallel, so vertical edges stay vertical. The camera looks at
    `focal_point` with the visible half height `parallel_scale` [model units], or is fitted to
    `bounds` (then centered on them). `shift_up` [model units] then moves the picture up on the
    screen, e.g. to make room for a color bar below it.
    """
    if bounds is None and (focal_point is None or parallel_scale is None):
        raise ValueError("set_camera needs focal_point and parallel_scale, or bounds")
    if bounds is not None and (focal_point is not None or parallel_scale is not None):
        raise ValueError("set_camera fits bounds itself: no focal_point or parallel_scale")

    # Only the clipping depends on the distance in a parallel projection: keep the camera well
    # outside the model.
    focal_point = focal_point or [0.0, 0.0, 0.0]
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


def add_text(view, text: str, position: Optional[Tuple[float, float]] = None, font_size=40):
    """Bold black text in the upper left corner, or at `position` (fractions of the view)."""
    source = pvs.Text(Text=text)
    display = pvs.Show(source, view)
    if position is None:
        display.WindowLocation = "Upper Left Corner"
    else:
        display.WindowLocation = "Any Location"
        display.Position = list(position)
    display.FontSize = font_size
    display.Bold = 1
    display.Color = [0.0, 0.0, 0.0]
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


@contextmanager
def scene(view):
    """Clean up after one image: hides what became visible in `view` (including the color
    bars, which are shared by all views of an array) and deletes the sources created inside."""
    sources_before = set(pvs.GetSources())
    visible_before = {rep for rep in view.Representations if rep.Visibility}
    try:
        yield
    finally:
        for rep in view.Representations:
            if rep.Visibility and rep not in visible_before:
                rep.Visibility = 0
        # Newest first, so that a filter goes before its input.
        created = [key for key in pvs.GetSources() if key not in sources_before]
        for key in sorted(created, key=lambda key: int(key[1]), reverse=True):
            pvs.Delete(pvs.GetSources()[key])


def save(view, path: Path, crop: bool = True):
    """Render `view` to `path` on white and crop the white margins."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    pvs.Render(view)
    pvs.SaveScreenshot(str(path), view, OverrideColorPalette="WhiteBackground")
    if crop:
        trim(Image.open(path).convert("RGB")).save(path)
