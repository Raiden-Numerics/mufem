"""Reusable netgen OCC building blocks for the cases' `build_geometry()`.

Import from `build_geometry()` like `casekit.meshing`, since it needs netgen.
"""

import math

from netgen.occ import (
    ArcOfCircle,
    Axis,
    Cylinder,
    Face,
    Pnt,
    Revolve,
    Segment,
    Vec,
    Wire,
    Y,
)


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
