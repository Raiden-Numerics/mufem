"""Mesh generation helpers for the cases' `build_geometry()` / `generate_mesh()`.

Name the bodies and faces of a netgen OCC geometry, write it as STEP, then mesh the
STEP file and write a gzipped MFEM v1.3 mesh whose attribute sets carry the names
that cases refer to as markers ("Plate" @ Vol, "Plate::Insulated" @ Bnd, ...).

    from netgen.occ import Box, Glue, X
    from validation_tools.meshing import name_body, mesh_and_save, nice_green

    plate = Box((0, 0, 0), (0.6, 1.0, 0.01))
    name_body(plate, "Plate", color=nice_green)
    plate.faces.Min(X).name = "Plate::Insulated"

    Glue([plate]).WriteStep("geometry.step")

    mesh_and_save("geometry.step", basesize=0.02)

Requires netgen (`pip install netgen-mesher`), which is only needed to
regenerate a mesh; the cases themselves load the committed geometry.mesh. The mesh
depends on the netgen/OCC version, so a regenerated mesh may differ from the
committed one, and so may the results computed on it.
"""

import gzip
from pathlib import Path
from typing import Optional, Tuple, Union

from netgen.occ import Glue, OCCGeometry

Color = Tuple[float, ...]


def hex_to_float(hex: str) -> Color:
    return tuple(int(hex[i : i + 2], 16) / 255.0 for i in (0, 2, 4))


nice_green = hex_to_float("00af7f")


def name_body(body, name: str, color: Optional[Color] = None) -> None:
    """Name a body and give each face a unique default name `<name>::<index>::Boundary`.

    Faces that carry a boundary condition are renamed afterwards, e.g.
    `body.faces.Min(X).name = f"{name}::Insulated"`.
    """
    body.mat(name)
    body.name = name

    for index, face in enumerate(body.faces):
        face.name = f"{name}::{index}::Boundary"

    if color is not None:
        body.faces.col = color


def mesh_and_save(
    step_path: Union[str, Path],
    basesize: float,
    path: Union[str, Path] = "geometry.mesh",
    **kwargs,
):
    """Mesh the STEP file `step_path` with netgen and write a gzipped MFEM v1.3 mesh.

    Body and face names written by `WriteStep` are read back and become the mesh's
    attribute set names.
    """
    # The STEP file holds the bodies as separate solids; glue them again so that
    # touching bodies share their interface faces and the mesh is conforming.
    shape = OCCGeometry(str(step_path)).shape
    mesh = OCCGeometry(Glue(shape.solids)).GenerateMesh(maxh=basesize, **kwargs)

    with gzip.open(path, "wt") as file:
        file.write(_mfem_v13(mesh))

    print(f"Wrote {path} with {mesh.ne} cells.")

    return mesh


# MFEM geometry type ids and the netgen -> MFEM vertex order per element size.
_VOLUME_ELEMENTS = {
    4: ("4", (0, 1, 2, 3)),  # tetrahedron
    5: ("7", (0, 1, 2, 3, 4)),  # pyramid
    6: ("6", (3, 4, 5, 0, 1, 2)),  # prism
    8: ("5", (0, 1, 2, 3, 4, 5, 6, 7)),  # hexahedron
}
_SURFACE_ELEMENTS = {
    3: ("2", (0, 1, 2)),  # triangle
    4: ("3", (0, 1, 2, 3)),  # quadrilateral
}


def _element_lines(elements, types) -> str:
    lines = []
    for e in elements:
        if e.index < 1:
            raise ValueError(f"Element index {e.index} is not allowed in MFEM (must be >= 1).")
        if len(e.vertices) not in types:
            raise ValueError(f"Unsupported element type with {len(e.vertices)} vertices.")

        el_type, order = types[len(e.vertices)]
        nodes = " ".join(str(e.vertices[i].nr - 1) for i in order)
        lines.append(f"{e.index} {el_type} {nodes}\n")

    return "".join(lines)


def _attribute_sets(names) -> str:
    """Group 1-based attribute tags by name: `"<name>" <count> <tags...>`."""
    sets = {}
    for tag, name in names:
        sets.setdefault(name, []).append(tag)

    lines = [f'"{name}" {len(tags)} {" ".join(map(str, tags))}\n' for name, tags in sets.items()]

    return f"{len(sets)}\n" + "".join(lines)


def _mfem_v13(mesh) -> str:
    elements = list(mesh.Elements3D())
    boundaries = list(mesh.Elements2D())
    vertices = mesh.Points()

    domains = [(n, mesh.GetMaterial(n) or f"Body::{n}") for n in range(1, mesh.GetNDomains() + 1)]

    # Boundary elements carry the 1-based face descriptor position as attribute; only
    # emit names for attributes that are actually used by a boundary element.
    used = {b.index for b in boundaries}
    faces = [
        (tag, face.bcname or f"Boundary::{tag}")
        for tag, face in enumerate(mesh.FaceDescriptors(), start=1)
        if tag in used
    ]

    vertex_lines = "".join(" ".join(map(str, v)) + "\n" for v in vertices)

    return f"""\
MFEM mesh v1.3

dimension
3

elements
{len(elements)}
{_element_lines(elements, _VOLUME_ELEMENTS)}

attribute_sets
{_attribute_sets(domains)}

boundary
{len(boundaries)}
{_element_lines(boundaries, _SURFACE_ELEMENTS)}

bdr_attribute_sets
{_attribute_sets(faces)}

vertices
{len(vertices)}
3
{vertex_lines}

mfem_mesh_end
"""
