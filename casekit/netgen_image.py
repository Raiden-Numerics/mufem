"""Helpers for the geometry images of the cases (create_geometry_image.py), drawn by netgen.

The image is taken with the netgen viewer, so it needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python create_geometry_image.py

The view is given like a camera, by the direction toward the viewer and the up direction, so
that a geometry image can share the view of the ParaView scenes of the case. Cropping and
padding are in casekit.images.
"""

import io
import math
from typing import Sequence, Tuple

import matplotlib
from PIL import Image, ImageDraw, ImageFont


def view_rotation(direction: Sequence[float], up: Sequence[float]) -> Tuple[float, float, float]:
    """Angles [deg] about x, y and z (applied in this order) that turn the model into the view.

    netgen shows x to the right, y up and z toward the viewer; the rotation maps the camera
    (screen right, up, toward the viewer) onto these axes.
    """

    def normalize(v):
        n = math.sqrt(sum(c * c for c in v))
        return [c / n for c in v]

    def cross(a, b):
        return [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]]

    toward = normalize(direction)
    right = normalize(cross([-c for c in toward], up))
    screen_up = cross(right, [-c for c in toward])
    rows = [right, screen_up, toward]

    angle_y = -math.degrees(math.asin(max(-1.0, min(1.0, rows[2][0]))))
    if abs(rows[2][0]) > 1.0 - 1e-9:
        # Looking along x: the rotations about x and z coincide, so the roll goes into x.
        return math.degrees(math.atan2(-rows[1][2], rows[1][1])), angle_y, 0.0
    angle_x = math.degrees(math.atan2(rows[2][1], rows[2][2]))
    angle_z = math.degrees(math.atan2(rows[1][0], rows[0][0]))
    return angle_x, angle_y, angle_z


def snapshot(
    shapes,
    direction: Sequence[float],
    up: Sequence[float],
    zoom: float = -30.0,
    size: Tuple[int, int] = (1600, 1200),
) -> Image.Image:
    """Draw the solids `shapes` in netgen, seen from `direction` with `up` up, and grab it.

    `zoom` is the netgen mouse zoom (negative zooms in). Can be called several times.
    """
    import netgen
    import netgen.gui
    from netgen.occ import Axis, Glue, OCCGeometry, Pnt, X, Y, Z

    angle_x, angle_y, angle_z = view_rotation(direction, up)
    origin = Pnt(0, 0, 0)
    shape = (
        Glue(list(shapes))
        .Rotate(Axis(origin, X), angle_x)
        .Rotate(Axis(origin, Y), angle_y)
        .Rotate(Axis(origin, Z), angle_z)
    )
    OCCGeometry(Glue(shape.solids)).Draw()

    tk = netgen.gui.win.tk
    tk.eval(f"wm geometry . {size[0]}x{size[1]}")
    netgen.Redraw(blocking=True)
    tk.eval(f"Ng_MouseMove 0 0 0 {zoom} zoom")
    netgen.Redraw(blocking=True)
    return Image.fromarray(netgen.gui.Snapshot(*size)).convert("RGB")


class Labels:
    """Black text labels and arrows on an image."""

    def __init__(self, image: Image.Image, font_size: int = 30):
        self.image = image
        self.draw = ImageDraw.Draw(image)
        self.font = ImageFont.truetype(
            f"{matplotlib.get_data_path()}/fonts/ttf/DejaVuSans-Bold.ttf", font_size
        )

    def text(self, position, text: str, anchor: str = "mm"):
        self.draw.text(position, text, font=self.font, fill="black", anchor=anchor)

    def line(self, start, end, width: int = 3):
        self.draw.line([start, end], fill="black", width=width)

    def arrow(self, start, end, width: int = 4, head: int = 18, spread: float = 0.35):
        """Line to `end` with an arrowhead of length `head` and half angle `spread`."""
        self.line(start, end, width)
        angle = math.atan2(end[1] - start[1], end[0] - start[0])
        self.draw.polygon(
            [end]
            + [
                (end[0] - head * math.cos(angle + s), end[1] - head * math.sin(angle + s))
                for s in (-spread, spread)
            ],
            fill="black",
        )

    def dot(self, center, radius: int = 12):
        x, y = center
        self.draw.ellipse([x - radius, y - radius, x + radius, y + radius], fill="black")

    def formula(self, position, tex: str, font_size: int = 40):
        """Formula `tex` in matplotlib mathtext (e.g. "$B_y(t)$"), upper left at `position`."""
        import matplotlib.pyplot as plt

        with matplotlib.rc_context({"mathtext.fontset": "cm"}):
            figure = plt.figure(figsize=(2, 1), dpi=100)
            figure.text(0, 0, tex, fontsize=font_size)
            buffer = io.BytesIO()
            figure.savefig(
                buffer, format="png", transparent=True, bbox_inches="tight", pad_inches=0
            )
            plt.close(figure)
        label = Image.open(buffer)
        self.image.paste(label, tuple(position), label)
