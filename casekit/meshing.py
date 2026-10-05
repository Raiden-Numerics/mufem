"""Mesh generation helpers for the cases' `build_geometry()` / `generate_mesh()`.

Name the bodies and faces of a netgen OCC geometry, write it as STEP, then mesh the
STEP file and write a gzipped MFEM v1.3 mesh whose attribute sets carry the names
that cases refer to as markers ("Plate" @ Vol, "Plate::Insulated" @ Bnd, ...).

    from netgen.occ import Box, Glue, X
    from casekit.meshing import color_nice_green, mesh_and_save, name_body

    plate = Box((0, 0, 0), (0.6, 1.0, 0.01))
    name_body(plate, "Plate", color=color_nice_green)
    plate.faces.Min(X).name = "Plate::Insulated"

    Glue([plate]).WriteStep("geometry.step")

    mesh_and_save("geometry.step", basesize=0.02)

Requires netgen (netgen-mesher, a dependency of this package), which is only needed to
regenerate a mesh; the cases themselves load the committed geometry.mesh.
"""

import gzip
import tempfile
from pathlib import Path
from typing import Optional, Tuple, Union

from netgen.occ import Glue, OCCGeometry

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


def mesh_and_save(
    step_path: Union[str, Path],
    basesize: float,
    path: Union[str, Path] = "geometry.mesh",
    second_order: bool = False,
    **kwargs,
):
    """Mesh the STEP file `step_path` with netgen and write it gzipped.

    Body and face names written by `WriteStep` are read back and become the mesh's
    attribute set names. A first-order mesh is written as MFEM v1.3; a second-order
    (curved) mesh as Gmsh 2.2, since the MFEM v1.3 format has no curved elements.
    """
    # The STEP file holds the bodies as separate solids; glue them again so that
    # touching bodies share their interface faces and the mesh is conforming.
    shape = OCCGeometry(str(step_path)).shape
    geometry = Glue(shape.solids)

    unnamed = [face.center for face in geometry.faces if not face.name]
    if unnamed:
        print(
            f"Warning: {len(unnamed)} face(s) without a name in {step_path}, e.g. at {unnamed[0]}"
        )

    mesh = OCCGeometry(geometry).GenerateMesh(maxh=basesize, **kwargs)

    if second_order:
        mesh.SecondOrder()

    with gzip.open(path, "wt") as file:
        file.write(_gmsh22(mesh) if second_order else _mfem_v13(mesh))

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


def _gmsh22(mesh) -> str:
    """Gmsh 2.2 export of netgen with the body and face names as physical names.

    netgen tags volume elements with 100000 + domain index and boundary elements with
    the surface number; the names are added as a $PhysicalNames section.
    """
    with tempfile.TemporaryDirectory() as directory:
        file_path = Path(directory) / "geometry.msh"
        mesh.Export(str(file_path), "Gmsh2 Format")
        lines = file_path.read_text().splitlines(keepends=True)

    names = [
        (2, face.surfnr, face.bcname or f"Boundary::{face.surfnr}")
        for face in mesh.FaceDescriptors()
    ]
    names += [
        (3, 100000 + n, mesh.GetMaterial(n) or f"Body::{n}")
        for n in range(1, mesh.GetNDomains() + 1)
    ]

    physical_names = (
        ["$PhysicalNames\n", f"{len(names)}\n"]
        + [f'{dim} {tag} "{name}"\n' for dim, tag, name in names]
        + ["$EndPhysicalNames\n"]
    )

    # netgen writes "$MeshFormat", its version line and "$EndMeshFormat" first.
    header = ["$MeshFormat\n", "2.2 0 8\n", "$EndMeshFormat\n"]

    return "".join(header + physical_names + lines[3:])
