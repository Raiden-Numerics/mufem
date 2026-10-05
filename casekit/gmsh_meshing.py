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
"""

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import gmsh


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
