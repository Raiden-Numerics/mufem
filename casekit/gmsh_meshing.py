"""Mesh generation with gmsh for the cases' `generate_mesh()`.

gmsh does not write names into a STEP file, so a gmsh case's `build_geometry()`
builds the geometry with gmsh (default entity tags), writes geometry.step and keeps
its physical groups as {name: (dimension, entity tags)}. `mesh_and_save` imports the
STEP file, where gmsh numbers the entities the same way, adds the groups, meshes and
writes a Gmsh 2.2 mesh to `path`. gmsh picks the format from the extension, so a gmsh
case overrides `mesh_path` with a .msh file:

    def generate_mesh(self):
        from casekit.gmsh_meshing import mesh_and_save

        mesh_and_save(
            self.step_path,
            self.physical_groups,
            path=self.mesh_path,
            options={"Mesh.MeshSizeMax": 4e-3, "Mesh.ElementOrder": 2},
        )

gmsh writes no colors into a STEP file either; `color_step` adds them for the geometry image
(casekit.netgen_image), at the end of `build_geometry()`:

        color_step(self.step_path, self.physical_groups, {"Walls": color_steel})
"""

import math
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import gmsh


def _import(step_path: Union[str, Path]) -> None:
    """Import the STEP file into the current gmsh model, numbering its entities as the
    physical groups of a case do."""
    gmsh.model.occ.importShapes(str(step_path), highestDimOnly=False)
    gmsh.model.occ.synchronize()

    # A face inside a solid (e.g. a lumped port) is lost in a STEP file, so it is written
    # as a separate face and embedded here again.
    free_faces = [
        (2, tag)
        for _, tag in gmsh.model.getEntities(2)
        if len(gmsh.model.getAdjacencies(2, tag)[0]) == 0
    ]
    if free_faces:
        gmsh.model.occ.fragment(gmsh.model.getEntities(3), free_faces)
        gmsh.model.occ.synchronize()


def mesh_and_save(
    step_path: Union[str, Path],
    physical_groups: Dict[str, Tuple[int, List[int]]],
    path: Union[str, Path] = "geometry.msh",
    options: Optional[Dict[str, float]] = None,
) -> None:
    """Mesh the STEP file with gmsh and write it as Gmsh 2.2 to `path` (a .msh file).

    Physical groups are numbered from 1 per dimension in the given order.
    """
    gmsh.initialize()
    _import(step_path)

    next_tag = defaultdict(lambda: 1)
    for name, (dim, tags) in physical_groups.items():
        gmsh.model.addPhysicalGroup(dim, tags, name=name, tag=next_tag[dim])
        next_tag[dim] += 1

    for option, value in (options or {}).items():
        gmsh.option.setNumber(option, value)

    gmsh.model.mesh.generate(3)

    gmsh.option.setNumber("Mesh.MshFileVersion", 2.2)
    gmsh.write(str(path))

    gmsh.finalize()


def _point_on(tag: int) -> List[float]:
    """A point on the face `tag` of the current model, searched in its parameter domain: the
    middle can lie in a hole (e.g. of an annulus)."""
    low, high = gmsh.model.getParametrizationBounds(2, tag)
    for fu in (0.5, 0.25, 0.75, 0.1, 0.9):
        for fv in (0.5, 0.25, 0.75, 0.1, 0.9):
            uv = [low[0] + fu * (high[0] - low[0]), low[1] + fv * (high[1] - low[1])]
            point = list(gmsh.model.getValue(2, tag, uv))
            if gmsh.model.isInside(2, tag, point):
                return point
    raise ValueError(f"no point found on face {tag}")


def color_step(
    step_path: Union[str, Path],
    physical_groups: Dict[str, Tuple[int, List[int]]],
    colors: Dict[str, Tuple[float, ...]],
) -> None:
    """Give the faces of the physical groups (of a volume group: all its faces) their color,
    RGB or RGBA, in the STEP file; later groups override earlier ones.

    The groups number the faces as mesh_and_save imports the file, which can differ from
    their order in the file (e.g. after embedding a port face). So each face of a group is
    found in the file by a point on it; netgen reads the file, its faces in that order, and
    writes it again with the colors, which gmsh ignores.
    """
    from netgen.occ import OCCGeometry

    gmsh.initialize()
    gmsh.model.add("written")
    gmsh.model.occ.importShapes(str(step_path), highestDimOnly=False)
    gmsh.model.occ.synchronize()
    written = [tag for _, tag in gmsh.model.getEntities(2)]
    gmsh.model.add("imported")
    _import(step_path)

    def written_faces(dim: int, tags: List[int]) -> List[int]:
        """The indices in the file of the faces of the imported entities `tags`."""
        gmsh.model.setCurrent("imported")
        if dim == 3:
            boundary = gmsh.model.getBoundary([(3, tag) for tag in tags], combined=False)
            tags = sorted({abs(tag) for _, tag in boundary})
        points = [_point_on(tag) for tag in tags]
        gmsh.model.setCurrent("written")
        return [
            min(
                (i for i, face in enumerate(written) if gmsh.model.isInside(2, face, point)),
                key=lambda i: math.dist(
                    point, gmsh.model.getClosestPoint(2, written[i], point)[0]
                ),
            )
            for point in points
        ]

    faces = {name: written_faces(*physical_groups[name]) for name in colors}
    gmsh.finalize()

    shape = OCCGeometry(str(step_path)).shape
    for name, color in colors.items():
        for index in faces[name]:
            shape.faces[index].col = color
    shape.WriteStep(str(step_path))
