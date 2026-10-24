"""PyVista support for the scenes of the cases (ValidationCase.create_scenes()).

`FieldExportReader` reads the `.vtpc` files of the field export, and `create_scene` gives a
scene (a PyVista plotter) in their common style; the scripts are otherwise plain PyVista:

    reader = FieldExportReader(case_dir)
    scene = create_scene()
    field = dict(scalars="Temperature", clim=(300, 400), name="field")
    actor = scene.add_mesh(reader.read(hide=["Air"]), **field)
    scene.camera.zoom(0.85)  # room for the color bar
    add_colorbar(scene, actor, "Temperature [K]", n_labels=3, label_format="%.0f")
    with gif(scene, path) as write_frame:
        for time_step in range(reader.number_time_steps):
            scene.add_mesh(reader.read(time_step, hide=["Air"]), **field)
            write_frame()

`add_mesh` with the `name` of an existing actor only swaps that actor: the camera, the color bar
and any charts stay. (Assigning new arrays to the first mesh would not show: `add_mesh` draws
surface copies of a MultiBlock.)
"""

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional, Sequence, Tuple

import numpy as np
import pyvista as pv
from PIL import Image, ImageFont
from vtkmodules.vtkChartsCore import vtkChartLegend, vtkPlotPoints
from vtkmodules.vtkCommonCore import VTK_FONT_FILE
from vtkmodules.vtkCommonDataModel import vtkCompositeDataSet
from vtkmodules.vtkIOXML import vtkXMLPartitionedDataSetCollectionReader
from vtkmodules.vtkRenderingAnnotation import vtkScalarBarActor
from vtkmodules.vtkRenderingCore import vtkActor2D, vtkCoordinate, vtkPolyDataMapper2D

from casekit.plots import MUFEM_LABEL, PlotStyle

# DejaVu Sans (see fonts/LICENSE_DEJAVU), the font of the matplotlib plots; VTK's own fonts
# lack square brackets and superscripts.
FONT_FILE = str(Path(__file__).parent / "fonts" / "DejaVuSans.ttf")
if not Path(FONT_FILE).is_file():  # VTK would fall back to its own font silently
    raise FileNotFoundError(FONT_FILE)


def read_vtpc(path) -> pv.MultiBlock:
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
    """The fields that a case exports over time (VisualizationOutput/Output.vtpc.series);
    pv.SeriesReader cannot read the .vtpc files of the series."""

    def __init__(self, case_dir: Path):
        path = Path(case_dir) / "VisualizationOutput" / "Output.vtpc.series"
        entries = json.loads(path.read_text())["files"]
        self._files = [path.parent / entry["name"] for entry in entries]
        self.time_values = [entry["time"] for entry in entries]

    @property
    def number_time_steps(self) -> int:
        return len(self.time_values)

    def read(self, time_step: int = 0, hide: Sequence[str] = ()) -> pv.MultiBlock:
        """The bodies at `time_step`, all but those named in `hide` (e.g. the air)."""
        bodies = read_vtpc(self._files[time_step])
        missing = set(hide) - set(bodies.keys())
        if missing:
            raise KeyError(f"no bodies {sorted(missing)} in {self._files[time_step]}")
        return pv.MultiBlock({name: bodies[name] for name in bodies.keys() if name not in hide})


def feature_edges(mesh: pv.DataSet, angle: float = 30.0) -> pv.PolyData:
    """The edges of the outer surface of `mesh` where it bends by more than `angle` [deg], e.g.
    the outline of a body. The points of the cells are merged first: the exported cells do not
    share theirs, and their surface would hold all their faces."""
    surface = mesh.clean().extract_surface(algorithm=None, nonlinear_subdivision=0)
    return surface.extract_feature_edges(
        feature_angle=angle, boundary_edges=False, non_manifold_edges=False, manifold_edges=False
    )


def at_phase(bodies: pv.MultiBlock, field: str, phase_deg: float) -> pv.MultiBlock:
    """`bodies` with the time-harmonic `field` at the phase, Re(F e^{j phase}) = F_r cos(phase)
    - F_i sin(phase), from its parts "<field>-Real" and "<field>-Imag"; changes `bodies`."""
    phase = np.radians(phase_deg)
    for body in bodies:
        body[field] = body[f"{field}-Real"] * np.cos(phase) - body[f"{field}-Imag"] * np.sin(phase)
    return bodies


def add_colorbar(
    scene: pv.Plotter,
    actor: pv.Actor,
    title: str,
    *,
    n_labels: int = 5,
    label_format: str = "%.1f",
    location: str = "right",
    font_size: int = 26,
    scale: float = 1.0,
    boxed: bool = False,
) -> vtkScalarBarActor:
    """Color bar of `actor` in the active renderer with `n_labels` labels from the lowest to the
    highest value of its range (the clim of the mesh). Vertical with the title along it, half as
    high as the renderer, at its right edge, centered ("right") or at the bottom ("lower
    right"); or horizontal with the labels and the title above it, half as wide as the renderer,
    centered at its bottom edge ("bottom"). Its box fits the labels and the title. The labels
    show the values times `scale`, e.g. 1e-5 with a title in 10⁵ units; `boxed` draws it on a
    white box, for a bar over the content. Move the camera to keep
    the content clear of it."""
    if location not in ("right", "lower right", "bottom"):
        raise ValueError(f"location {location!r} is not 'right', 'lower right' or 'bottom'")
    vertical = location != "bottom"
    title_size = font_size + 4

    # The thickness of the box from the texts, measured in the font of the bar. A leading space
    # keeps the labels off a vertical bar (VTK's text pad also shifts them along the bar).
    label_format = f" {label_format}" if vertical else label_format
    low, high = scale * np.asarray(actor.mapper.scalar_range)
    labels = [label_format % value for value in np.linspace(low, high, n_labels)]
    label_width = max(ImageFont.truetype(FONT_FILE, font_size).getbbox(t)[2] for t in labels)
    title_height = ImageFont.truetype(FONT_FILE, title_size).getbbox(title)[3]
    thickness = round(1.6 * font_size)
    box = thickness + (label_width if vertical else font_size) + font_size + title_height

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
    bar.SetBarRatio(thickness / box)

    # The size of the renderer in pixels, for the box in fractions of it.
    x0, y0, x1, y1 = scene.renderer.GetViewport()
    width, height = (x1 - x0) * scene.window_size[0], (y1 - y0) * scene.window_size[1]
    if vertical:
        bar.SetOrientationToVertical()
        bar.SetForceVerticalTitle(True)
        bar.SetVerticalTitleSeparation(font_size)
        bar.SetPosition(1.0 - (box + font_size) / width, 0.25 if location == "right" else 0.05)
        bar.SetWidth(box / width)
        bar.SetHeight(0.5)
    else:
        # The texts above the bar, as in ParaView; below it VTK lets the labels overlap the bar
        # and the title. The line break after the title is the gap to the labels.
        bar.SetOrientationToHorizontal()
        bar.SetTextPositionToSucceedScalarBar()
        bar.SetTitle(f"{title}\n")
        bar.SetTextPad(font_size // 3)
        bar.SetPosition(0.25, font_size / height)
        bar.SetWidth(0.5)
        bar.SetHeight(box / height)
    if boxed:
        # A white box behind the bar and its texts, padded by half a label width (the end
        # labels stand out of the bar by that much) and the font size; VTK's own background of
        # the bar has no padding.
        (x, y), (w, h) = bar.GetPosition(), (bar.GetWidth(), bar.GetHeight())
        pad_x, pad_y = (label_width / 2 + font_size) / width, font_size / height
        scene.renderer.add_actor(_rectangle(x - pad_x, y - pad_y, x + w + pad_x, y + h + pad_y))
    scene.renderer.add_actor(bar)
    return bar


def _rectangle(x0: float, y0: float, x1: float, y1: float) -> vtkActor2D:
    """A white rectangle in fractions of the renderer, drawn over the scene."""
    corners = [(x0, y0, 0.0), (x1, y0, 0.0), (x1, y1, 0.0), (x0, y1, 0.0)]
    mapper = vtkPolyDataMapper2D()
    mapper.SetInputData(pv.PolyData(np.array(corners), faces=[4, 0, 1, 2, 3]))
    coordinate = vtkCoordinate()
    coordinate.SetCoordinateSystemToNormalizedViewport()
    mapper.SetTransformCoordinate(coordinate)
    actor = vtkActor2D()
    actor.SetMapper(mapper)
    actor.GetProperty().SetColor(1.0, 1.0, 1.0)
    return actor


def _font(text_property, size: int):
    """`text_property` in black DejaVu Sans (FONT_FILE) of `size` pixels."""
    text_property.SetFontFamily(VTK_FONT_FILE)
    text_property.SetFontFile(FONT_FILE)
    text_property.SetFontSize(size)
    text_property.SetColor(0.0, 0.0, 0.0)
    text_property.SetShadow(False)


def _markers(plot, marker_style: int, size: int, style: PlotStyle):
    """Markers of `size` pixels on `plot`. Without a line, the pen width is free: VTK draws the
    legend marker 2.3 times as wide as the pen, so that it matches the markers of the plot."""
    plot.SetMarkerStyle(marker_style)
    plot.SetMarkerSize(size)
    if not style.has_line:
        plot.GetPen().SetWidth(size / 2.3)


def xy_chart(
    *,
    values,
    xlabel: str,
    ylabel: str,
    label: str = MUFEM_LABEL,
    reference_values=None,
    reference_label: str = "Reference",
    style: PlotStyle = PlotStyle.LINE_AND_POINTS,
    reference_style: PlotStyle = PlotStyle.POINTS,
    xlim: Optional[Tuple[float, float]] = None,
    ylim: Optional[Tuple[float, float]] = None,
    xticks: Optional[Sequence[float]] = None,
    yticks: Optional[Sequence[float]] = None,
    legend_loc: str = "upper left",
    font_size: int = 18,
) -> Tuple[pv.Chart2D, Any, Any]:
    """PyVista chart in the style of xy_plot (same arguments): the reference black underneath,
    the mufem curve red on top, the legend at `legend_loc` ("upper left", "lower right", ...).
    Returns the chart, the mufem curve and the
    reference curve (None without reference_values), whose points an animation updates with
    update_curve."""
    chart = pv.Chart2D(x_label=xlabel, y_label=ylabel, grid=False)
    reference = None
    if reference_values is not None:
        x, y = np.asarray(reference_values).T
        if reference_style.has_line:
            reference = chart.line(x, y, color="black", width=4.0, label=reference_label)
        else:
            reference = chart.scatter(x, y, color="black", label=reference_label)
        if reference_style.has_markers:
            _markers(reference, vtkPlotPoints.CIRCLE, 10, reference_style)
    x, y = np.asarray(values).T
    if style.has_line:
        curve = chart.line(x, y, color="red", width=3.0, label=label)
    else:
        curve = chart.scatter(x, y, color="red", label=label)
    if style.has_markers:
        _markers(curve, vtkPlotPoints.SQUARE, 7 if style.has_line else 12, style)

    if xlim is not None:
        chart.x_range = list(xlim)
    if ylim is not None:
        chart.y_range = list(ylim)
    for axis, ticks in ((chart.x_axis, xticks), (chart.y_axis, yticks)):
        if ticks is not None:
            # As matplotlib: the decimals that the ticks need, the same for all of them.
            decimals = max(len(f"{tick:g}".partition(".")[2]) for tick in ticks)
            axis.tick_locations = list(ticks)
            axis.tick_labels = [f"{tick:.{decimals}f}" for tick in ticks]
    for axis in (chart.x_axis, chart.y_axis):
        _font(axis.GetTitleProperties(), font_size + 2)
        _font(axis.GetLabelProperties(), font_size)
    # A margin on the right for the last tick label, which VTK centers on the end of the axis;
    # the border of the chart, drawn at its new edge, hidden.
    chart.size = (0.97, 1.0)
    chart.border_color = "white"
    vertical, horizontal = legend_loc.split()
    chart.legend.SetVerticalAlignment(
        {"upper": vtkChartLegend.TOP, "lower": vtkChartLegend.BOTTOM}[vertical]
    )
    chart.legend.SetHorizontalAlignment(
        {"left": vtkChartLegend.LEFT, "right": vtkChartLegend.RIGHT}[horizontal]
    )
    chart.legend.SetPadding(15)  # away from the axes
    chart.legend.GetPen().SetOpacity(0)  # no frame and no background, as in xy_plot
    chart.legend.GetBrush().SetOpacity(0)
    _font(chart.legend.GetLabelProperties(), font_size)
    return chart, curve, reference


def update_curve(curve, points):
    """`curve.update` with the (x, y) `points`. A single point is drawn twice, because VTK
    leaves a curve with a single point out of the legend."""
    x, y = np.asarray(points).T
    if len(x) == 1:
        x, y = np.repeat(x, 2), np.repeat(y, 2)
    curve.update(x, y)


@contextmanager
def gif(scene: pv.Plotter, path: Path, fps: int = 8):
    """Animated GIF of `scene` (save_gif): call the yielded `write_frame()` after each frame
    is drawn. Closes the scene; writes the GIF only if the block completes."""
    frames = []

    def write_frame():
        # The charts show the data of the previous render: render once more first.
        scene.render()
        frames.append(scene.screenshot())

    try:
        yield write_frame
    finally:
        scene.close()
    save_gif(frames, path, fps)


def save_gif(frames: Sequence[np.ndarray], path: Path, fps: int = 8):
    """Animated GIF of the screenshots `frames` with one palette for all of them. Dithering keeps
    the color gradients smooth; the pixels that do not change from one frame to the next keep
    their color, so that the dithering does not shimmer."""
    images = [Image.fromarray(frame) for frame in frames]
    palette = Image.fromarray(np.vstack(frames)).quantize(method=Image.Quantize.MAXCOVERAGE)
    indices = [np.array(image.quantize(palette=palette)) for image in images]
    # Pillow looks up the palette approximately, which can turn the white background into a
    # near-white color of the palette: white stays white.
    colors = np.frombuffer(palette.palette.tobytes(), np.uint8).reshape(-1, 3)
    white = np.flatnonzero((colors == 255).all(axis=1))
    if len(white):
        for frame, index in zip(frames, indices):
            index[(frame == 255).all(axis=2)] = white[0]
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


def create_scene(window_size: Tuple[int, int] = (1600, 1200), **kwargs) -> pv.Plotter:
    """Off-screen pv.Plotter in the style of the scenes; `kwargs` go to it (e.g. shape)."""
    theme = pv.themes.DocumentTheme()
    theme.anti_aliasing = "msaa"
    theme.cmap = "coolwarm"
    theme.edge_color = "black"
    theme.line_width = 2
    theme.lighting_params.ambient = 0.3
    theme.lighting_params.diffuse = 0.8
    theme.camera.parallel_projection = True
    theme.show_scalar_bar = False
    return pv.Plotter(theme=theme, off_screen=True, window_size=window_size, **kwargs)
