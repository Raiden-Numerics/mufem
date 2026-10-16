"""PyVista support for the scene scripts (create_scene.py) of the cases.

Importing this module teaches `pv.read` the `.vtpc` files of the field export and provides the
common `theme` of the scenes; the scripts are otherwise plain PyVista:

    bodies = pv.read(output_files(case_dir)[0])
    plotter = pv.Plotter(theme=theme, off_screen=True)
    actor = plotter.add_mesh(bodies, scalars="Temperature", clim=(300, 400))
    add_colorbar(plotter, actor, "Temperature [K]")
    save(plotter, path)
"""

import itertools
import json
from pathlib import Path
from typing import List, Sequence, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pyvista as pv
from matplotlib.cm import ScalarMappable
from matplotlib.colors import ListedColormap, Normalize
from PIL import Image
from vtkmodules.vtkCommonDataModel import vtkCompositeDataSet
from vtkmodules.vtkIOXML import vtkXMLPartitionedDataSetCollectionReader

from casekit.images import trim


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


def colorbar(actor: pv.Actor, label: str, figure, box: Sequence[float], **kwargs):
    """Matplotlib color bar of `actor` (the colors and the range of its lookup table) in
    `figure` at `box` (left, bottom, width, height in fractions of the figure), labeled in the
    style of xy_axes; `kwargs` go to Figure.colorbar, e.g. orientation="horizontal". Show
    `figure` beside the scene with add_chart."""
    colors = ListedColormap(actor.mapper.lookup_table.values / 255)
    # The range of the mapper: the lookup table of a MultiBlock keeps (0, 1).
    mappable = ScalarMappable(Normalize(*actor.mapper.scalar_range), colors)
    bar = figure.colorbar(mappable, cax=figure.add_axes(box), **kwargs)
    bar.set_label(label, fontsize=15)
    bar.ax.tick_params(labelsize=13)
    bar.long_axis.get_offset_text().set_fontsize(13)
    bar.formatter.set_useMathText(True)
    bar.formatter.set_powerlimits((-2, 3))
    return bar


def _layout(plotter: pv.Plotter):
    """The renderers of the window with their viewports in pixels (x0, y0, x1, y1)."""
    width, height = plotter.window_size
    renderers = plotter.render_window.GetRenderers()
    layout = {}
    for renderer in [renderers.GetItemAsObject(i) for i in range(renderers.GetNumberOfItems())]:
        x0, y0, x1, y1 = renderer.GetViewport()
        layout[renderer] = [x0 * width, y0 * height, x1 * width, y1 * height]
    return layout


def _apply(plotter: pv.Plotter, layout, size: Tuple[float, float]):
    plotter.window_size = [round(size[0]), round(size[1])]
    for renderer, (x0, y0, x1, y1) in layout.items():
        renderer.SetViewport(x0 / size[0], y0 / size[1], x1 / size[0], y1 / size[1])


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
    xs, ys = zip(*points)
    (x0, y0), (x1, y1) = renderer.GetOrigin(), renderer.GetSize()
    return min(xs) - x0, min(ys) - y0, x0 + x1 - max(xs), y0 + y1 - max(ys)


def _insert_strip(
    plotter: pv.Plotter, strip: float, margin: float, vertical: bool
) -> Tuple[float, ...]:
    """Insert a strip of `strip` pixels right of (`vertical`) or below the active renderer, the
    renderers beside it moving along and the window growing; return the viewport of the strip.
    On the right, the renderer first loses the empty space beside its content down to `margin`
    pixels (the camera stays centered), so that the strip follows the content."""
    scene = plotter.renderer
    layout = _layout(plotter)
    width, height = plotter.window_size
    x0, y0, x1, y1 = layout[scene]
    if vertical:
        left, _, right, _ = _content_margins(scene)
        cut = 2 * max(min(left, right) - margin, 0.0)
        for rect in layout.values():
            for i in (0, 2):
                if rect[i] >= x1 - 0.5:
                    rect[i] += strip - cut
        layout[scene][2] = x1 - cut
        size, area = (width + strip - cut, height), (x1 - cut, y0, x1 - cut + strip, y1)
    else:
        for rect in layout.values():
            for i in (1, 3):
                if rect[i] >= y0 - 0.5:
                    rect[i] += strip
        size, area = (width, height + strip), (x0, y0, x1, y0 + strip)
    _apply(plotter, layout, size)
    return (area[0] / size[0], area[1] / size[1], area[2] / size[0], area[3] / size[1])


def add_colorbar(
    plotter: pv.Plotter,
    actor: pv.Actor,
    label: str,
    location: str = "right",
    dpi: int = 150,
    gap: float = 0.4,
    padding: float = 0.6,
):
    """Color bar of `actor` in a strip added on the `location` ("right" or "bottom") of the
    active renderer; the window grows by the strip, so that the scene keeps its view (set the
    camera before). On the right, the scene first loses its empty margins beside the content.
    The strip fits the bar, its labels and its title, with `gap` inches toward the scene and
    `padding` inches on the other side, e.g. toward a chart beside it. `dpi` sets the text size,
    as for the matplotlib figures of the scene. Returns the matplotlib color bar, e.g. to set
    its ticks."""
    if location not in ("right", "bottom"):
        raise ValueError(f"location {location!r} is neither 'right' nor 'bottom'")
    vertical = location == "right"
    thickness, margin = 0.25, 0.1  # inches: the bar, the scene beside its content

    # Draw the bar at a known place in a 4 x 4 in figure, measure what it takes up and size the
    # strip to that.
    figure = plt.figure(figsize=(4, 4), dpi=dpi)
    box = (0.25, 0.25, thickness / 4, 0.5) if vertical else (0.25, 0.75, 0.5, thickness / 4)
    bar = colorbar(actor, label, figure, box, orientation="vertical" if vertical else "horizontal")
    extent = figure.get_tightbbox()
    if vertical:
        strip = gap + extent.width + padding
        bar.ax.set_position(((gap + 1 - extent.x0) / strip, 0.25, thickness / strip, 0.5))
    else:
        strip = gap + extent.height + padding
        bar.ax.set_position((0.3, (padding + 3 - extent.y0) / strip, 0.4, thickness / strip))
    viewport = _insert_strip(plotter, round(strip * dpi), margin * dpi, vertical)

    # A renderer of its own, without anti-aliasing, with which VTK misplaces charts off screen.
    # It is not one of plotter.renderers: keep it alive, the chart dies with it.
    renderer = pv.Renderer(plotter, border=False)
    renderer.SetViewport(*viewport)
    renderer.set_background(plotter.background_color)
    plotter.render_window.AddRenderer(renderer)
    renderer.add_chart(pv.ChartMPL(figure))
    plotter.__dict__.setdefault("_colorbar_renderers", []).append(renderer)
    return bar


def add_chart(plotter: pv.Plotter, figure, subplot: Tuple[int, int] = (0, 1)):
    """Show the matplotlib `figure` in `subplot`, drawn without anti-aliasing, with which VTK
    misplaces it off screen."""
    plotter.subplot(*subplot)
    plotter.renderer.disable_anti_aliasing()
    plotter.add_chart(pv.ChartMPL(figure))
    plotter.subplot(0, 0)


def save(plotter: pv.Plotter, path: Path):
    """Screenshot of `plotter` without its white margins."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    trim(Image.fromarray(plotter.screenshot())).save(path)


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
