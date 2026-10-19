"""PyVista support for the scenes of the cases (ValidationCase.create_scenes()).

Importing this module teaches `pv.read` the `.vtpc` files of the field export and provides the
common `theme` of the scenes; the scripts are otherwise plain PyVista:

    bodies = pv.read(output_files(case_dir)[0])
    plotter = pv.Plotter(theme=theme, off_screen=True)
    actor = plotter.add_mesh(bodies, scalars="Temperature", clim=(300, 400))
    add_colorbar(plotter, actor, "Temperature [K]", n_labels=3, label_format="%.0f")
    save(plotter, path)
"""

import itertools
import json
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import numpy as np
import pyvista as pv
from PIL import Image, ImageFont
from vtkmodules.vtkChartsCore import vtkChartLegend, vtkPlotPoints
from vtkmodules.vtkCommonDataModel import vtkCompositeDataSet
from vtkmodules.vtkIOXML import vtkXMLPartitionedDataSetCollectionReader
from vtkmodules.vtkRenderingAnnotation import vtkScalarBarActor
from vtkmodules.vtkRenderingCore import vtkRenderer

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


def output_files(case_dir: Path) -> List[Path]:
    """The files of VisualizationOutput/Output.vtpc.series that case.py exports, in time order."""
    output_dir = Path(case_dir) / "VisualizationOutput"
    series = json.loads((output_dir / "Output.vtpc.series").read_text())
    return [output_dir / entry["name"] for entry in series["files"]]


def _content_margins(renderer) -> Tuple[float, float, float, float]:
    """Empty margins (left, bottom, right, top) in pixels around the visible props of
    `renderer`, from the corners of their bounds; negative where they reach beyond."""
    renderer.GetRenderWindow().Render()  # the projection of the current window size
    bounds = renderer.ComputeVisiblePropBounds()
    points = []
    for corner in itertools.product(bounds[0:2], bounds[2:4], bounds[4:6]):
        renderer.SetWorldPoint(*corner, 1.0)
        renderer.WorldToDisplay()
        points.append(renderer.GetDisplayPoint()[:2])
    (x0, y0), (x1, y1) = np.min(points, axis=0), np.max(points, axis=0)
    (left, bottom), (width, height) = renderer.GetOrigin(), renderer.GetSize()
    return x0 - left, y0 - bottom, left + width - x1, bottom + height - y1


def _insert_strip(plotter: pv.Plotter, strip: float, margin: float, vertical: bool) -> vtkRenderer:
    """A renderer in a strip of `strip` pixels right of (`vertical`) or below the active
    renderer; the renderers beside it move along and the window grows. On the right, the
    active renderer first loses the empty space beside its content down to `margin` pixels (the
    camera stays centered), so that the strip follows the content."""
    scene = plotter.renderer
    size = np.array([*plotter.window_size] * 2, dtype=float)
    x0, y0, x1, y1 = np.multiply(scene.GetViewport(), size)
    cut = 2 * max(min(_content_margins(scene)[0::2]) - margin, 0.0) if vertical else 0.0
    axis, edge = (0, x1) if vertical else (1, y0)  # everything from `edge` on moves
    rects = {r: np.multiply(r.GetViewport(), size) for r in plotter.render_window.GetRenderers()}
    for rect in rects.values():
        rect[axis::2] += np.where(rect[axis::2] >= edge - 0.5, strip - cut, 0.0)
    if vertical:
        rects[scene][2] = x1 - cut
    size[axis::2] += strip - cut
    for renderer, rect in rects.items():
        renderer.SetViewport(*(rect / size))
    plotter.window_size = size[:2].round().astype(int).tolist()

    renderer = vtkRenderer()  # a plain one: no SSAA, and alive as long as the window is
    rect = (x1 - cut, y0, x1 - cut + strip, y1) if vertical else (x0, y0, x1, y0 + strip)
    renderer.SetViewport(*(np.array(rect) / size))
    renderer.SetBackground(plotter.background_color.float_rgb)
    plotter.render_window.AddRenderer(renderer)
    return renderer


def add_colorbar(
    plotter: pv.Plotter,
    actor: pv.Actor,
    title: str,
    n_labels: int = 5,
    label_format: str = "%.1f",
    location: str = "right",
    font_size: int = 26,
    gap: int = 60,
    padding: int = 90,
) -> vtkScalarBarActor:
    """Color bar of `actor` with `n_labels` labels from the lowest to the highest value of its
    range (the clim of the mesh) in a strip added on the `location` ("right"
    or "bottom") of the active renderer; the window grows by the strip, so that the scene keeps
    its view (set the camera before). On the right, the scene first loses its empty margins
    beside the content. The strip fits the bar, its labels and its title, with `gap` pixels
    toward the scene and `padding` pixels on the other side, e.g. toward a chart beside it."""
    if location not in ("right", "bottom"):
        raise ValueError(f"location {location!r} is neither 'right' nor 'bottom'")
    vertical = location == "right"
    title_size = font_size + 4

    # The extent of the texts, measured in the font of the bar.
    # A leading space keeps the labels off a vertical bar (VTK's text pad also shifts them along).
    label_format = f" {label_format}" if vertical else label_format
    low, high = actor.mapper.scalar_range
    labels = [label_format % value for value in np.linspace(low, high, n_labels)]
    label_font = ImageFont.truetype(FONT_FILE, font_size)
    label_width = max(label_font.getbbox(label)[2] for label in labels)
    title_height = ImageFont.truetype(FONT_FILE, title_size).getbbox(title)[3]
    thickness = round(1.6 * font_size)
    content = thickness + (label_width if vertical else font_size) + font_size + title_height
    strip = gap + content + padding

    # The range of the mapper: the lookup table of a MultiBlock keeps (0, 1).
    lookup_table = actor.mapper.lookup_table
    lookup_table.scalar_range = actor.mapper.scalar_range
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
    bar.SetBarRatio(thickness / content)

    # The bar at the gap from the scene: half as long as the scene is high, or 40 % of the
    # strip wide.
    if vertical:
        bar.SetOrientationToVertical()
        bar.SetForceVerticalTitle(True)
        bar.SetVerticalTitleSeparation(font_size)
        bar.SetPosition(gap / strip, 0.25)
        bar.SetWidth(content / strip)
        bar.SetHeight(0.5)
    else:
        bar.SetOrientationToHorizontal()
        bar.SetTextPositionToPrecedeScalarBar()  # the labels below the bar
        bar.SetPosition(0.3, padding / strip)
        bar.SetWidth(0.4)
        bar.SetHeight(content / strip)
    _insert_strip(plotter, strip, 15, vertical).AddViewProp(bar)
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
