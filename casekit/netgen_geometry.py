"""netgen OCC geometry helpers for the cases' `build_geometry()`.

Name the bodies and faces of a geometry (the names become the mesh markers, e.g.
"Plate" @ Vol, "Plate::Insulated" @ Bnd), color them, and build common shapes:

    def build_geometry(self):
        from netgen.occ import Box, Glue, X

        from casekit.colors import color_green
        from casekit.netgen_geometry import name_body

        plate = Box((0, 0, 0), (0.6, 1.0, 0.01))
        name_body(plate, "Plate", color=color_green)
        plate.faces.Min(X).name = "Plate::Insulated"

        Glue([plate]).WriteStep(f"{self.step_path}")

Import it inside `build_geometry()`, since it needs netgen.
"""

import math
from typing import Optional

from netgen.meshing import IdentificationType
from netgen.occ import (
    ArcOfCircle,
    Axis,
    Box,
    Cylinder,
    Face,
    Glue,
    Pnt,
    Revolve,
    Rotation,
    Segment,
    Vec,
    Wire,
    Y,
    Z,
)

from casekit.colors import Color


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


# Rotationally periodic sectors about the z axis ------------------------------------------------
# A geometry that repeats every `last - first` degrees about the z axis is modeled over the sector
# from `first` to `last`. Its two cut faces are meshed alike (identify_periodic_faces) for a
# matching interface, and a cylinder between a turning and a fixed part is split into pieces
# (split_cylinder) for a sliding non-matching interface.


def _angle_deg(point) -> float:
    return math.degrees(math.atan2(point[1], point[0])) % 360.0


def on_plane(point, angle_deg: float, tol: float = 1e-6) -> bool:
    """True if `point` lies in the half-plane through the z axis at `angle_deg`."""
    return abs((_angle_deg(point) - angle_deg + 180.0) % 360.0 - 180.0) < tol


def sector(first_deg: float, last_deg: float, size: float = 1.0):
    """The wedge between the half-planes through the z axis at `first_deg` and `last_deg`
    (counter-clockwise, less than 180 deg apart), `size` in all directions; intersect a body with
    it to cut out the sector."""
    z_axis = Axis(Pnt(0, 0, 0), Z)
    half_space = Box(Pnt(-size, 0, -size), Pnt(size, size, size))
    return half_space.Rotate(z_axis, first_deg) * half_space.Rotate(z_axis, last_deg - 180.0)


def name_cut_faces(body, sector_deg, prefix: str) -> None:
    """Name the faces of `body` in the cut plane at `sector_deg[0]` `<prefix>::0` and those at
    `sector_deg[1]` `<prefix>::1`. Faces on the z axis are left alone."""
    for face in body.faces:
        if math.hypot(face.center[0], face.center[1]) < 1e-9:
            continue
        for side, angle in enumerate(sector_deg):
            if on_plane(face.center, angle):
                face.name = f"{prefix}::{side}"


def identify_periodic_faces(geometry, prefix: str, sector_deg) -> None:
    """Mesh each face `<prefix>::1` of `geometry` (named by name_cut_faces) as the face
    `<prefix>::0` that the rotation from `sector_deg[1]` to `sector_deg[0]` maps it onto, so that
    the two cut faces of the sector have matching meshes. Raises if a face has no partner.

    Call it on the final geometry and mesh that geometry directly: the identifications are not
    written to a STEP file."""
    side0 = [face for face in geometry.faces if face.name == f"{prefix}::0"]
    side1 = [face for face in geometry.faces if face.name == f"{prefix}::1"]
    if len(side0) != len(side1) or not side0:
        raise RuntimeError(f"{prefix}: {len(side0)} vs {len(side1)} cut faces")
    turn_deg = sector_deg[0] - sector_deg[1]
    cos, sin = math.cos(math.radians(turn_deg)), math.sin(math.radians(turn_deg))
    for face1 in side1:
        x, y, z = face1.center
        image = (cos * x - sin * y, sin * x + cos * y, z)
        face0 = min(side0, key=lambda face: math.dist(face.center, image))
        if math.dist(face0.center, image) > 1e-6:
            raise RuntimeError(f"{prefix}: no cut face matches {face1.center}")
        face1.Identify(
            face0,
            prefix,
            IdentificationType.PERIODIC,
            Rotation(Axis(Pnt(0, 0, 0), Z), turn_deg),
        )


def split_cylinder(body, radius: float, height: float, sector_deg, number_pieces: int, name: str):
    """Imprint `number_pieces - 1` seams along z on the cylinder face of `body` of `radius` from
    z = 0 to `height`, over the sector `sector_deg`, and name the pieces `name`. Returns the body
    with the seams.

    For a sliding interface: with different numbers of pieces on its two sides the seams pin the
    mesh columns of each side, so that the two meshes do not coincide while one side turns."""
    first, last = (math.radians(angle) for angle in sector_deg)
    piece_angle = (last - first) / number_pieces
    seams = []
    for k in range(1, number_pieces):
        x = radius * math.cos(first + k * piece_angle)
        y = radius * math.sin(first + k * piece_angle)
        seams.append(Segment(Pnt(x, y, 0.0), Pnt(x, y, height)))
    body = Glue([body] + seams)

    piece_area = piece_angle * radius * height
    # The radius of the centroid of a cylindrical strip.
    centroid = radius * math.sin(0.5 * piece_angle) / (0.5 * piece_angle)
    pieces = [
        face
        for face in body.faces
        if abs(math.hypot(face.center[0], face.center[1]) - centroid) < 1e-3 * radius
        and abs(face.center[2] - 0.5 * height) < 1e-6
        and abs(face.mass - piece_area) < 1e-3 * piece_area
    ]
    if len(pieces) != number_pieces:
        raise RuntimeError(f"{name}: {len(pieces)} cylinder pieces, expected {number_pieces}")
    for face in pieces:
        face.name = name
    return body
