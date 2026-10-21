"""PyVista support for the scenes of the cases (ValidationCase.create_scenes()).

Importing this module teaches `pv.read` the `.vtpc` files of the field export and provides the
common `theme` of the scenes; the scripts are otherwise plain PyVista:

    reader = FieldExportReader(case_dir)
    plotter = pv.Plotter(theme=theme, off_screen=True)
    field = dict(scalars="Temperature", clim=(300, 400), name="field")
    actor = plotter.add_mesh(reader.read(exclude=["Air"]), **field)
    plotter.camera.zoom(0.85)  # room for the color bar
    add_colorbar(plotter, actor, "Temperature [K]", n_labels=3, label_format="%.0f")
    with gif(plotter, path) as write_frame:
        for time_step in range(reader.number_time_steps):
            plotter.add_mesh(reader.read(time_step, exclude=["Air"]), **field)  # replaces it
            write_frame()

`add_mesh` with the `name` of an existing actor only swaps that actor: the camera, the color bar
and any charts stay. (Assigning new arrays to the first mesh would not show: `add_mesh` draws
surface copies of a MultiBlock.)
"""

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Sequence, Tuple

import numpy as np
import pyvista as pv
from PIL import Image, ImageFont
from vtkmodules.vtkChartsCore import vtkChartLegend, vtkPlotPoints
from vtkmodules.vtkCommonDataModel import vtkCompositeDataSet
from vtkmodules.vtkIOXML import vtkXMLPartitionedDataSetCollectionReader
from vtkmodules.vtkRenderingAnnotation import vtkScalarBarActor

from casekit.images import trim
from casekit.plots import PlotStyle

# DejaVu Sans (see fonts/LICENSE_DEJAVU), the font of the matplotlib plots; VTK's own fonts
# lack square brackets and superscripts.
FONT_FILE = str(Path(__file__).parent / "fonts" / "DejaVuSans.ttf")
if not Path(FONT_FILE).is_file():  # VTK would fall back to its own font silently
    raise FileNotFoundError(FONT_FILE)


@pv.register_reader(".vtpc")
def read_vtpc(path, **_) -> pv.MultiBlock:
    """One block per body, named as in case.py. The partitions of a body (one per MPI rank)
    are combined without merging their points, so that fields that are discontinuous between
    the cells stay so."""
    reader = vtkXMLPartitionedDataSetCollectionReader()
    reader.SetFileName(str(path))
    reader.Update()
    collection = reader.GetOutput()
    bodies = pv.MultiBlock()
    for i in range(collection.GetNumberOfPartitionedDataSets()):
        name = collection.GetMetaData(i).Get(vtkCompositeDataSet.NAME())
        partitions = pv.MultiBlock(
            [collection.GetPartition(i, j) for j in range(collection.GetNumberOfPartitions(i))]
        )
        bodies[name] = partitions.combine(merge_points=False)
    return bodies


class FieldExportReader:
    """The fields that a case exports over time (VisualizationOutput/Output.vtpc.series); PyVista
    has no reader for ParaView's .series files."""

    def __init__(self, case_dir: Path):
        path = Path(case_dir) / "VisualizationOutput" / "Output.vtpc.series"
        entries = json.loads(path.read_text())["files"]
        self._files = [path.parent / entry["name"] for entry in entries]
        self.time_values = [entry["time"] for entry in entries]

    @property
    def number_time_steps(self) -> int:
        return len(self.time_values)

    def read(self, time_step: int = 0, exclude: Sequence[str] = ()) -> pv.MultiBlock:
        """The bodies at `time_step`, without those named in `exclude`."""
        bodies = read_vtpc(self._files[time_step])
        for name in exclude:
            del bodies[name]
        return bodies


def add_colorbar(
    plotter: pv.Plotter,
    actor: pv.Actor,
    title: str,
    n_labels: int = 5,
    label_format: str = "%.1f",
    location: str = "right",
    font_size: int = 26,
    scale: float = 1.0,
) -> vtkScalarBarActor:
    """Vertical color bar of `actor` in the active renderer with `n_labels` labels from the
    lowest to the highest value of its range (the clim of the mesh), the title along the bar.
    It is half as high as the renderer, at its right edge, centered ("right") or at the bottom
    ("lower right"); its box fits the labels and the title. The labels show the values times
    `scale`, e.g. 1e-5 with a title in 10⁵ units. Move the camera to keep the content clear of
    it."""
    if location not in ("right", "lower right"):
        raise ValueError(f"location {location!r} is neither 'right' nor 'lower right'")
    title_size = font_size + 4

    # The width of the box from the texts, measured in the font of the bar. A leading space
    # keeps the labels off the bar (VTK's text pad also shifts them along the bar).
    label_format = f" {label_format}"
    low, high = scale * np.asarray(actor.mapper.scalar_range)
    labels = [label_format % value for value in np.linspace(low, high, n_labels)]
    label_width = max(ImageFont.truetype(FONT_FILE, font_size).getbbox(t)[2] for t in labels)
    title_height = ImageFont.truetype(FONT_FILE, title_size).getbbox(title)[3]
    thickness = round(1.6 * font_size)
    width = thickness + label_width + font_size + title_height

    # A copy of the colors with the scaled range of the mapper (the lookup table of a MultiBlock
    # keeps (0, 1)); the mesh keeps its own.
    lookup_table = pv.LookupTable()
    lookup_table.DeepCopy(actor.mapper.lookup_table)
    lookup_table.scalar_range = (low, high)
    bar = vtkScalarBarActor()
    bar.SetLookupTable(lookup_table)
    bar.SetMaximumNumberOfColors(lookup_table.n_values)
    bar.SetNumberOfLabels(n_labels)
    bar.SetLabelFormat(label_format)
    bar.SetTitle(title)
    _font(bar.GetTitleTextProperty(), title_size)
    _font(bar.GetLabelTextProperty(), font_size)
    bar.SetUnconstrainedFontSize(True)
    bar.SetDrawFrame(False)
    bar.SetOrientationToVertical()
    bar.SetForceVerticalTitle(True)
    bar.SetVerticalTitleSeparation(font_size)
    bar.SetBarRatio(thickness / width)

    renderer_width = plotter.renderer.GetViewport()[2] - plotter.renderer.GetViewport()[0]
    width /= renderer_width * plotter.window_size[0]  # in fractions of the renderer
    margin = font_size / (renderer_width * plotter.window_size[0])
    bar.SetPosition(1.0 - width - margin, 0.25 if location == "right" else 0.05)
    bar.SetWidth(width)
    bar.SetHeight(0.5)
    plotter.renderer.add_actor(bar)
    return bar


def _font(text_property, size: int):
    """`text_property` in black DejaVu Sans (FONT_FILE) of `size` pixels."""
    text_property.SetFontFamily(pv._vtk.VTK_FONT_FILE)
    text_property.SetFontFile(FONT_FILE)
    text_property.SetFontSize(size)
    text_property.SetColor(0.0, 0.0, 0.0)
    text_property.SetShadow(False)


def xy_chart(
    *,
    values,
    xlabel: str,
    ylabel: str,
    reference_values=None,
    reference_label: str = "Reference",
    style: PlotStyle = PlotStyle.LINE_AND_POINTS,
    reference_style: PlotStyle = PlotStyle.POINTS,
    xlim: Optional[Tuple[float, float]] = None,
    ylim: Optional[Tuple[float, float]] = None,
    xticks: Optional[Sequence[float]] = None,
    font_size: int = 18,
) -> Tuple[pv.Chart2D, "pv.charts.LinePlot2D"]:
    """PyVista chart in the style of xy_plot (same arguments): the reference black underneath,
    the mufem curve red on top, the legend top left. Returns the chart and the mufem curve,
    whose points an animation updates with `curve.update(x, y)`."""
    chart = pv.Chart2D(x_label=xlabel, y_label=ylabel, grid=False)
    if reference_values is not None:
        x, y = np.asarray(reference_values).T
        plot = chart.line if reference_style.has_line else chart.scatter
        reference = plot(x, y, color="black", label=reference_label)
        if reference_style.has_markers:
            reference.SetMarkerStyle(vtkPlotPoints.CIRCLE)
            reference.SetMarkerSize(10)
    x, y = np.asarray(values).T
    if style.has_line:
        curve = chart.line(x, y, color="red", width=3.0, label="mufem")
    else:
        curve = chart.scatter(x, y, color="red", label="mufem")
    if style.has_markers:
        curve.SetMarkerStyle(vtkPlotPoints.SQUARE)
        curve.SetMarkerSize(7)

    if xlim is not None:
        chart.x_range = list(xlim)
    if ylim is not None:
        chart.y_range = list(ylim)
    if xticks is not None:
        chart.x_axis.tick_locations = list(xticks)
        chart.x_axis.tick_labels = "2f"
    for axis in (chart.x_axis, chart.y_axis):
        _font(axis.GetTitleProperties(), font_size + 2)
        _font(axis.GetLabelProperties(), font_size)
    chart.legend.SetHorizontalAlignment(vtkChartLegend.LEFT)
    chart.legend.SetVerticalAlignment(vtkChartLegend.TOP)
    chart.legend.SetPadding(15)  # away from the axes
    chart.legend.GetPen().SetOpacity(0)
    _font(chart.legend.GetLabelProperties(), font_size)
    return chart, curve


def save(plotter: pv.Plotter, path: Path):
    """Screenshot of `plotter` without its white margins; closes the plotter."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    trim(Image.fromarray(plotter.screenshot())).save(path)
    plotter.close()


def update_curve(curve, points):
    """`curve.update` with the (x, y) `points`. A single point is drawn twice, because VTK
    leaves a curve with a single point out of the legend."""
    x, y = np.asarray(points).T
    if len(x) == 1:
        x, y = np.repeat(x, 2), np.repeat(y, 2)
    curve.update(x, y)


@contextmanager
def gif(plotter: pv.Plotter, path: Path, fps: int = 8):
    """Animated GIF of `plotter` (save_gif): call the yielded `write_frame()` after each frame
    is drawn. Closes the plotter; writes the GIF only if the block completes."""
    frames = []
    try:
        yield lambda: frames.append(plotter.screenshot())
    finally:
        plotter.close()
    save_gif(frames, path, fps)


def save_gif(frames: Sequence[np.ndarray], path: Path, fps: int = 8):
    """Animated GIF of the screenshots `frames` with one palette for all of them. Dithering keeps
    the color gradients smooth; the pixels that do not change from one frame to the next keep
    their color, so that the dithering does not shimmer."""
    images = [Image.fromarray(frame) for frame in frames]
    palette = Image.fromarray(np.vstack(frames)).quantize(method=Image.Quantize.MAXCOVERAGE)
    indices = [np.array(image.quantize(palette=palette)) for image in images]
    for i in range(1, len(frames)):
        still = (frames[i] == frames[i - 1]).all(axis=2)
        indices[i][still] = indices[i - 1][still]
    quantized = [Image.fromarray(index, "P") for index in indices]
    for image in quantized:
        image.putpalette(palette.getpalette())
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    quantized[0].save(
        path, save_all=True, append_images=quantized[1:], duration=round(1000 / fps), loop=0
    )


theme = pv.themes.DocumentTheme()
theme.window_size = [1600, 1200]
theme.anti_aliasing = "ssaa"
theme.cmap = "coolwarm"
theme.edge_color = "black"
theme.line_width = 2
theme.lighting_params.ambient = 0.3
theme.lighting_params.diffuse = 0.8
theme.camera.parallel_projection = True
theme.show_scalar_bar = False
