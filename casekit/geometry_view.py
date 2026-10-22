"""Geometry images of the cases (ValidationCase.create_geometry_image()), rendered from the STEP.

netgen reads the STEP file with the names, colors and transparency of its bodies and faces and
triangulates its surface; PyVista draws it in the style of the scenes, off screen:

    save_geometry_image(
        step_path=self.step_path,
        image_path=self.dir_path / "data" / "Geometry.png",
        direction=(0.4, 0.3, 1.0),
        up=(0, 1, 0),
        labels=[Label(text="Loaded (x = L)", at=(1.0, 0.0, 0.0), offset=(0, 150))],
    )

The view is given like a camera, by the direction toward the viewer and the up direction, so that
a geometry image can share the view of the scenes of the case. Transparent bodies (e.g. the air)
are drawn by their edges only. The image is fitted to the geometry and the labels, so it needs no
cropping. STEP files without colors (e.g. from gmsh) are drawn opaque gray: give the bodies their
colors with `colors`, by index, and the air a transparent one.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple, Union

import numpy as np
import pyvista as pv
import vtkmodules.vtkRenderingMatplotlib  # noqa: F401 (MathText labels, e.g. "$B_y(t)$")
from vtkmodules.vtkRenderingCore import vtkTextActor, vtkTextRenderer

from casekit.pyvista_scene import create_scene, polygon_2d, set_font

Color = Tuple[float, ...]

_GRAY = (0.75, 0.75, 0.75, 1.0)  # bodies and faces without a color (e.g. from gmsh)


@dataclass(kw_only=True)
class Label:
    """A text at `offset` pixels (right, up) from the model point `at`, with a `pointer` from
    the text to the point: "arrow", "line", "dot" (a dot at the point, the text beside it) or
    "none"."""

    text: str
    at: Sequence[float]
    offset: Tuple[float, float] = (0.0, 0.0)
    pointer: str = "arrow"


def _surface(step_path: Path, colors: Dict[Union[str, int], Color]):
    """The triangulated surface of `step_path` with the RGBA color of each triangle, and its
    edges. Each body has the most common color of its own faces (named "<body>::...", as by
    casekit.netgen_geometry; the faces it shares carry the color of either body); `colors`
    overrides it, by name or by index."""
    from netgen.meshing import MeshingStep
    from netgen.occ import OCCGeometry

    geometry = OCCGeometry(str(step_path))
    solids = geometry.shape.solids
    low, high = geometry.shape.bounding_box
    extent = max(high.x - low.x, high.y - low.y, high.z - low.z)
    mesh = geometry.GenerateMesh(maxh=extent / 50, perfstepsend=MeshingStep.MESHSURFACE)
    descriptors = mesh.FaceDescriptors()
    # The STEP files of the cases keep a copy of each shared face per body, so that every body
    # is closed by its own faces; a face shared by two bodies would leave a hole next to the air.
    if any(descriptor.domout != 0 for descriptor in descriptors):
        raise ValueError(f"{step_path}: faces shared by two bodies are not supported")

    names = [solid.name for solid in solids]
    body_colors = []
    for name, solid in zip(names, solids):
        faces = [face for face in solid.faces if face.col is not None]
        own = [face for face in faces if (face.name or "").startswith(f"{name}::")]
        counts = Counter(tuple(face.col) for face in own or faces)
        body_colors.append(counts.most_common(1)[0][0] if counts else _GRAY)
    for key, color in colors.items():
        if isinstance(key, str) and key not in names:
            raise KeyError(f"{key!r} is not a body of {step_path}: {names}")
        index = names.index(key) if isinstance(key, str) else key
        body_colors[index] = tuple(color) + (1.0,) * (4 - len(color))
    # Faces of no body (domin 0) are gray.
    face_colors = np.array(body_colors + [_GRAY])[[d.domin - 1 for d in descriptors]]

    points = mesh.Coordinates()
    triangles = mesh.Elements2D().NumPy()
    surface = pv.PolyData.from_regular_faces(points, triangles["nodes"] - 1)
    surface.cell_data["rgba"] = face_colors[triangles["index"] - 1]
    edges = pv.PolyData(points, lines=pv.CellArray.from_regular_cells(_edges(mesh) - 1))
    return surface, edges


def _edges(mesh) -> np.ndarray:
    """The segments (point pairs) of the edges of the faces of `mesh`, without the seams of
    periodic faces (e.g. of a cylinder), which have the same face on both sides."""
    triangles = mesh.Elements2D().NumPy()
    faces_at = defaultdict(set)
    for nodes, face in zip(triangles["nodes"], triangles["index"]):
        for a, b in ((0, 1), (1, 2), (2, 0)):
            faces_at[frozenset((nodes[a], nodes[b]))].add(face)
    segments = mesh.Elements1D().NumPy()["nodes"][:, :2]
    return np.array([s for s in segments if len(faces_at[frozenset(s)]) != 1]).reshape(-1, 2)


def _view_axes(direction: Sequence[float], up: Sequence[float]):
    """Unit vectors toward the viewer, screen right and screen up."""
    toward = np.asarray(direction, float)
    toward /= np.linalg.norm(toward)
    right = np.cross(up, toward)
    if np.linalg.norm(right) < 1e-9:
        raise ValueError(f"up {tuple(up)} is parallel to the direction {tuple(direction)}")
    right /= np.linalg.norm(right)
    return toward, right, np.cross(toward, right)


def _text_actor(text: str, font_size: int) -> vtkTextActor:
    actor = vtkTextActor()
    actor.SetInput(text)
    set_font(actor.GetTextProperty(), font_size)
    return actor


def _text_box(actor: vtkTextActor) -> Tuple[float, float]:
    """Width and height of the text of `actor` in pixels."""
    box = [0, 0, 0, 0]
    vtkTextRenderer().GetBoundingBox(actor.GetTextProperty(), actor.GetInput(), box, 72)
    return box[1] - box[0] + 1, box[3] - box[2] + 1


def _placement(label: Label, anchor: np.ndarray, size: Tuple[float, float], gap: float):
    """Lower left corner of the text and the start of its pointer, both in pixels."""
    width, height = size
    dx, dy = label.offset
    if label.pointer == "dot":
        dx, dy = gap + 8, 0
    center = anchor + (dx, dy)
    if abs(dx) > abs(dy):  # beside the point: centered vertically, the near side at center
        corner = center + ((0 if dx > 0 else -width), -height / 2)
        start = center - (np.sign(dx) * gap, 0)
    else:  # above or below the point: centered horizontally
        corner = center + (-width / 2, 0 if dy > 0 else -height)
        start = center - (0, np.sign(dy) * gap)
    return corner, start


def _pointer(scene: pv.Plotter, label: Label, start: np.ndarray, end: np.ndarray, head: float):
    """The line, arrow or dot of `label`, in pixels; none if the text is too close to the point."""
    if label.pointer == "dot":
        scene.add_actor(polygon_2d(end + head / 2 * _circle(24)))
        return
    if np.dot(end - start, label.offset) >= 0 or np.linalg.norm(end - start) <= head:
        return
    if label.pointer in ("line", "arrow"):
        direction = (end - start) / np.linalg.norm(end - start)
        tip = end - direction * head if label.pointer == "arrow" else end
        scene.add_actor(polygon_2d(_thick_line(start, tip, 3.0)))
    if label.pointer == "arrow":
        normal = np.array([-direction[1], direction[0]])
        base = end - direction * head
        scene.add_actor(polygon_2d([end, base + normal * head / 2.5, base - normal * head / 2.5]))


def _circle(n: int) -> np.ndarray:
    angles = np.linspace(0.0, 2.0 * np.pi, n, endpoint=False)
    return np.column_stack([np.cos(angles), np.sin(angles)])


def _thick_line(start: np.ndarray, end: np.ndarray, width: float) -> np.ndarray:
    direction = (end - start) / np.linalg.norm(end - start)
    normal = np.array([-direction[1], direction[0]]) * width / 2
    return np.array([start - normal, end - normal, end + normal, start + normal])


def save_geometry_image(
    *,
    step_path: Path,
    image_path: Path,
    direction: Sequence[float],
    up: Sequence[float],
    size: int = 1600,
    margin: int = 20,
    labels: Sequence[Label] = (),
    colors: Optional[Dict[Union[str, int], Color]] = None,
    font_size: int = 30,
) -> None:
    """Render `step_path` seen from `direction` with `up` up and save it as PNG to `image_path`;
    the longer side of the geometry is `size` pixels, with a `margin` in pixels around it and
    the `labels`. `colors` overrides the colors of bodies, by name or by index (for STEP files
    without colors)."""
    surface, edges = _surface(step_path, colors or {})

    # The projection in pixels, x right and y up: the window is fitted to the geometry and labels.
    toward, right, screen_up = _view_axes(direction, up)
    points = surface.points
    x, y = points @ right, points @ screen_up
    scale = size / max(np.ptp(x), np.ptp(y))  # [px/m]
    low = np.array([x.min(), y.min()]) * scale
    high = np.array([x.max(), y.max()]) * scale

    head = 22.0
    texts = []
    for label in labels:
        anchor = np.array([np.dot(label.at, right), np.dot(label.at, screen_up)]) * scale
        actor = _text_actor(label.text, font_size)
        text_size = _text_box(actor) if label.text else (0.0, 0.0)
        corner, start = _placement(label, anchor, text_size, gap=10.0)
        texts.append((label, actor, anchor, corner, start))
        low = np.minimum(low, np.minimum(corner, anchor - head))
        high = np.maximum(high, np.maximum(corner + text_size, anchor + head))
    low -= margin
    high += margin
    window = np.ceil(high - low).astype(int)

    scene = create_scene(tuple(window))
    opaque = surface.cell_data["rgba"][:, 3] >= 1.0
    if opaque.any():
        shown = surface.extract_cells(opaque)
        scene.add_mesh(
            shown, scalars="rgba", rgba=True, smooth_shading=True, split_sharp_edges=True
        )
    scene.add_mesh(edges, color="black", line_width=2)

    center = (low + high) / 2 / scale
    focal = right * center[0] + screen_up * center[1] + toward * (points @ toward).mean()
    extent = np.ptp(points, axis=0).max()
    scene.camera.focal_point = focal
    scene.camera.position = focal + toward * 10 * extent
    scene.camera.up = screen_up
    scene.camera.parallel_scale = window[1] / 2 / scale
    scene.reset_camera_clipping_range()

    for label, actor, anchor, corner, start in texts:
        if label.text:
            actor.SetPosition(*(corner - low))
            scene.add_actor(actor)
        if label.pointer != "none":
            _pointer(scene, label, start - low, anchor - low, head)

    scene.show(screenshot=image_path)
