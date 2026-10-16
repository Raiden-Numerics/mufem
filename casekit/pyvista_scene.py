"""PyVista helpers for the scene and animation scripts of the cases.

The PyVista counterpart of casekit.paraview_scene: the scripts run in the Python of the cases
(`pip install pyvista`), render off screen and need no display. All scenes share the same look:
a white background, the "coolwarm" color map, a color bar with fixed labels and a parallel
projection.
"""

import json
import math
from pathlib import Path
from typing import Optional, Sequence, Tuple

import numpy as np
import pyvista as pv
from PIL import Image
from vtkmodules.vtkCommonCore import vtkDoubleArray
from vtkmodules.vtkIOXML import vtkXMLPartitionedDataSetCollectionReader
from vtkmodules.vtkRenderingCore import vtkTextActor, vtkTextRenderer

from casekit.images import trim


class ScenePlotter(pv.Plotter):
    """Plotter that keeps the titles of its vertical color bars, which save() places along the
    bars once their size is known."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bar_titles = []


def new_plotter(size: Tuple[int, int] = (1600, 1200)) -> ScenePlotter:
    """Off-screen plotter with a white background and anti-aliasing."""
    plotter = ScenePlotter(off_screen=True, window_size=list(size))
    plotter.set_background("white")
    plotter.enable_anti_aliasing("ssaa")
    return plotter


def read_output(case_dir: Path, index: int = 0) -> pv.MultiBlock:
    """The fields that case.py exports to VisualizationOutput/: output `index` of
    Output.vtpc.series, as one block per body named as in case.py.

    The partitions of a body (one per MPI rank) are combined without merging their points, so
    that fields that are discontinuous between the cells stay so.
    """
    output_dir = Path(case_dir) / "VisualizationOutput"
    series = json.loads((output_dir / "Output.vtpc.series").read_text())
    reader = vtkXMLPartitionedDataSetCollectionReader()
    reader.SetFileName(str(output_dir / series["files"][index]["name"]))
    reader.Update()
    collection = reader.GetOutput()

    data = pv.MultiBlock()
    for i in range(collection.GetNumberOfPartitionedDataSets()):
        name = collection.GetMetaData(i).Get(collection.NAME())
        partitions = collection.GetPartitionedDataSet(i)
        parts = [
            pv.wrap(partitions.GetPartition(j)) for j in range(partitions.GetNumberOfPartitions())
        ]
        data.append(pv.MultiBlock(parts).combine(), name)
    return data


def read_scene_data(case_dir: Path):
    """The extra input of the scenes that case.py writes to ValidationCase.scene_data_path."""
    return np.load(Path(case_dir) / "VisualizationOutput" / "Scene_Data.npz")


def bodies(data: pv.MultiBlock, names: Sequence[str]) -> pv.UnstructuredGrid:
    """The bodies `names` of `data` as one mesh; raises if one does not exist, which would
    silently leave it out of the image."""
    missing = [name for name in names if name not in data.keys()]
    if missing:
        raise ValueError(f"no bodies {missing} in the output")
    return pv.MultiBlock([data[name] for name in names]).combine()


def show(
    plotter: pv.Plotter,
    mesh: pv.DataSet,
    color: Optional[Sequence[float]] = None,
    edges: bool = False,
):
    """Show `mesh` as a lit surface in a solid `color` (gray without one). Use color_by to show
    a field instead."""
    return plotter.add_mesh(
        mesh,
        color=color if color is not None else (0.8, 0.8, 0.8),
        show_edges=edges,
        edge_color="black",
        line_width=2,
        ambient=0.3,
        diffuse=0.8,
        show_scalar_bar=False,
    )


def color_by(
    plotter: pv.Plotter,
    mesh: pv.DataSet,
    array: str,
    title: str,
    labels: Sequence[float],
    label_format: str = "%.0f",
    vertical: bool = False,
    position: Tuple[float, float] = (0.3, 0.05),
    length: float = 0.4,
    thickness: float = 0.05,
    title_size: int = 28,
    label_size: int = 24,
    component: Optional[int] = None,
    edges: bool = False,
):
    """Show `mesh` colored by the point array `array` (the magnitude of a vector array, or its
    `component`) with the coolwarm map and a color bar at `position` (fractions of the window).

    The color range is the first to the last label. A vertical bar has its title turned along
    it, right of the labels, as in ParaView. Returns the actor.
    """
    if array not in mesh.point_data:
        raise ValueError(f"no point array {array!r} in the shown data")
    width, height = (thickness, length) if vertical else (length, thickness)
    actor = plotter.add_mesh(
        mesh,
        scalars=array,
        preference="point",
        component=component,
        cmap="coolwarm",
        clim=(labels[0], labels[-1]),
        show_edges=edges,
        edge_color="black",
        line_width=2,
        ambient=0.3,
        diffuse=0.8,
        scalar_bar_args=dict(
            title=title,
            vertical=vertical,
            position_x=position[0],
            position_y=position[1],
            width=width,
            height=height,
            title_font_size=title_size,
            label_font_size=label_size,
            bold=True,
            color="black",
            fmt=label_format,
        ),
    )
    custom_labels = vtkDoubleArray()
    for label in labels:
        custom_labels.InsertNextValue(label)
    bar = plotter.scalar_bars[title]
    bar.SetCustomLabels(custom_labels)
    bar.SetUseCustomLabels(True)
    bar.SetTextPad(6)
    bar.SetUnconstrainedFontSize(True)
    if vertical:
        bar.SetTitle("")
        plotter.bar_titles.append((bar, _bar_title(plotter, title, title_size)))
    return actor


def _bar_title(plotter: pv.Plotter, title: str, font_size: int) -> vtkTextActor:
    actor = vtkTextActor()
    actor.SetInput(title)
    prop = actor.GetTextProperty()
    prop.SetFontSize(font_size)
    prop.SetBold(True)
    prop.SetColor(0.0, 0.0, 0.0)
    prop.SetOrientation(90.0)
    prop.SetJustificationToCentered()
    prop.SetVerticalJustificationToTop()
    plotter.add_actor(actor)
    return actor


def _place_bar_titles(plotter: ScenePlotter):
    """Put the titles of the vertical color bars right of the widest label of their bar."""
    if not plotter.bar_titles:
        return
    plotter.render_window.Render()
    text_renderer = vtkTextRenderer()
    dpi = plotter.render_window.GetDPI()
    for bar, title in plotter.bar_titles:
        rect = [0] * 4
        bar.GetScalarBarRect(rect, plotter.renderer)
        label_width = 0
        labels = bar.GetCustomLabels()
        for i in range(labels.GetNumberOfTuples()):
            box = [0] * 4
            text = bar.GetLabelFormat() % labels.GetValue(i)
            text_renderer.GetBoundingBox(bar.GetLabelTextProperty(), text, box, dpi)
            label_width = max(label_width, box[1] - box[0])
        gap = bar.GetTextPad() + label_width + title.GetTextProperty().GetFontSize() // 2
        title.SetDisplayPosition(rect[0] + rect[2] + gap, rect[1] + rect[3] // 2)


def set_camera(
    plotter: pv.Plotter,
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
    camera = plotter.camera
    camera.focal_point = list(focal_point)
    camera.position = [f + distance * d / norm for f, d in zip(focal_point, direction)]
    camera.up = list(up)
    plotter.enable_parallel_projection()
    if parallel_scale is not None:
        camera.parallel_scale = parallel_scale
        plotter.reset_camera_clipping_range()
    else:
        plotter.reset_camera(bounds=list(bounds))
    if shift_up:
        shift = [-shift_up * u for u in camera.up]
        camera.focal_point = [f + d for f, d in zip(camera.focal_point, shift)]
        camera.position = [p + d for p, d in zip(camera.position, shift)]


def add_text(plotter: pv.Plotter, text: str, position: Tuple[float, float], font_size=40):
    """Bold black text with its lower left corner at `position` (fractions of the window)."""
    actor = plotter.add_text(
        text, position=position, font_size=font_size, color="black", viewport=True
    )
    actor.GetTextProperty().SetBold(True)
    return actor


def phase_field(mesh: pv.DataSet, field: str, phase_deg: float) -> np.ndarray:
    """Re(F e^{j phase}) = F_r cos(phase) - F_i sin(phase) of a complex point field."""
    phase = math.radians(phase_deg)
    return mesh.point_data[f"{field}-Real"] * math.cos(phase) - mesh.point_data[
        f"{field}-Imag"
    ] * math.sin(phase)


def save(plotter: pv.Plotter, path: Path, crop: bool = True):
    """Render `plotter` to `path` and, with `crop`, crop the white margins. The plotter stays
    open for further images."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    _place_bar_titles(plotter)
    image = Image.fromarray(plotter.screenshot(return_img=True))
    (trim(image) if crop else image).save(path)
