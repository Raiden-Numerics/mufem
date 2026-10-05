"""netgen OCC geometry helpers for the cases' `build_geometry()`.

Name the bodies and faces of a geometry (the names become the mesh markers, e.g.
"Plate" @ Vol, "Plate::Insulated" @ Bnd), color them, and build common shapes:

    def build_geometry(self):
        from netgen.occ import Box, Glue, X

        from casekit.netgen_geometry import color_nice_green, name_body

        plate = Box((0, 0, 0), (0.6, 1.0, 0.01))
        name_body(plate, "Plate", color=color_nice_green)
        plate.faces.Min(X).name = "Plate::Insulated"

        Glue([plate]).WriteStep(f"{self.step_path}")

Import it inside `build_geometry()`, since it needs netgen.
"""

import math
from typing import Optional, Tuple

from netgen.occ import (
    ArcOfCircle,
    Axis,
    Box,
    Cylinder,
    Face,
    Pnt,
    Revolve,
    Segment,
    Vec,
    Wire,
    Y,
    Z,
)


Color = Tuple[float, ...]


def hex_to_float(hex: str, transparency: Optional[float] = None) -> Color:
    """RGB color from "rrggbb"; with `transparency` in [0, 1] an RGBA color."""
    rgb = tuple(int(hex[i : i + 2], 16) / 255.0 for i in (0, 2, 4))

    if transparency is None:
        return rgb

    if not 0.0 <= transparency <= 1.0:
        raise ValueError("Transparency must be between 0.0 and 1.0")

    return rgb + (1.0 - transparency,)


color_air = hex_to_float("a6e7ff", transparency=0.6)
color_aluminum = hex_to_float("848789")
color_copper = hex_to_float("B87333")
color_hts = hex_to_float("4c9173")
color_iron = hex_to_float("a19d94")
color_nice_blue = hex_to_float("00a2e8")
color_nice_green = hex_to_float("00af7f")
color_nice_red = hex_to_float("ed1c24")
color_steel = hex_to_float("71797E")


def name_body(
    body, name: str, color: Optional[Color] = None, individual_names: bool = True
) -> None:
    """Name a body and give each face a default name `<name>::<index>::Boundary`.

    With `individual_names=False` all faces share the name `<name>::Boundary`. Faces
    that carry a boundary condition are renamed afterwards, e.g.
    `body.faces.Min(X).name = f"{name}::Insulated"`.
    """
    body.mat(name)
    body.name = name

    if individual_names:
        for index, face in enumerate(body.faces):
            face.name = f"{name}::{index}::Boundary"
    else:
        body.faces.name = f"{name}::Boundary"

    if color is not None:
        body.faces.col = color


def polygon_face(points):
    """Planar face bounded by straight segments through `points`, (x, y, z) tuples in order."""
    pnts = [Pnt(*p) for p in points]
    return Face(Wire([Segment(a, b) for a, b in zip(pnts, pnts[1:] + pnts[:1])]))


def racetrack_face(x_min, x_max, y_min, y_max, radius):
    """Planar racetrack (rectangle with rounded corners) in the z = 0 plane."""
    pnt0 = Pnt(x_max - radius, y_min, 0)
    pnt1 = Pnt(x_max, y_min + radius, 0)
    pnt2 = Pnt(x_max, y_max - radius, 0)
    pnt3 = Pnt(x_max - radius, y_max, 0)
    pnt4 = Pnt(x_min + radius, y_max, 0)
    pnt5 = Pnt(x_min, y_max - radius, 0)
    pnt6 = Pnt(x_min, y_min + radius, 0)
    pnt7 = Pnt(x_min + radius, y_min, 0)

    wire = Wire(
        [
            ArcOfCircle(pnt0, Vec(1, 0, 0), pnt1),
            Segment(pnt1, pnt2),
            ArcOfCircle(pnt2, Vec(0, 1, 0), pnt3),
            Segment(pnt3, pnt4),
            ArcOfCircle(pnt4, Vec(-1, 0, 0), pnt5),
            Segment(pnt5, pnt6),
            ArcOfCircle(pnt6, Vec(0, -1, 0), pnt7),
            Segment(pnt7, pnt0),
        ]
    )

    return Face(wire)


def hollow_cylinder(r_inner, r_outer, axis, height, offset=0):
    """Hollow cylinder along `axis` from the origin, moved by `offset` along it."""
    outer = Cylinder((0.0, 0.0, 0.0), axis, r=r_outer, h=height)
    inner = Cylinder((0.0, 0.0, 0.0), axis, r=r_inner, h=height)

    return (outer - inner).Move(Vec(axis.x, axis.y, axis.z * offset))


def annular_sector(r_in, r_out, h, angle_deg):
    """Sector of `angle_deg` of an annulus along Z from z = 0 to h, centered on +X."""
    ring = Cylinder(Pnt(0, 0, 0), Z, r=r_out, h=h) - Cylinder(Pnt(0, 0, 0), Z, r=r_in, h=h)

    cut = 3 * r_out
    upper = Box(Pnt(-cut, 0, -cut), Pnt(cut, cut, h + cut)).Rotate(
        Axis(Pnt(0, 0, 0), Z), +angle_deg / 2
    )
    lower = Box(Pnt(-cut, -cut, -cut), Pnt(cut, 0, h + cut)).Rotate(
        Axis(Pnt(0, 0, 0), Z), -angle_deg / 2
    )

    return ring - upper - lower


def triangle_sector(radius=1.0, degrees=30, extrude_length=2.0):
    """Wedge of `degrees` along Y (intersected with a cylinder) to cut a periodic sector."""
    angle = math.radians(degrees)
    x = 2 * radius * math.cos(angle)
    z = 2 * radius * math.sin(angle) / 2.0

    wedge = polygon_face([(0, 0, 0), (x, 0, -z), (x, 0, z)])
    return wedge.Extrude(extrude_length, Y) * Cylinder((0, 0, 0), Y, r=radius, h=extrude_length)


def revolve_rotate_cut(face, cut, angle=90):
    """Revolve a cross-section by 360 degrees about Y, rotate it and keep the sector `cut`."""
    axis = Axis(Pnt(0, 0, 0), Vec(0, 1, 0))
    return Revolve(face, axis, 360).Rotate(axis, angle) * cut
