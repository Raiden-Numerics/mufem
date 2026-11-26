import sys

import gmsh

L = 0.1  # cube edge length [m]

gmsh.initialize()
gmsh.model.add("Charged Cube")

# Geometry: a single box from (0, 0, 0) to (L, L, L)
gmsh.model.occ.addBox(0, 0, 0, L, L, L)
gmsh.model.occ.synchronize()


def faces_at_z(z, eps=1e-6):
    box = (-eps, -eps, z - eps, L + eps, L + eps, z + eps)
    return [tag for _, tag in gmsh.model.getEntitiesInBoundingBox(*box, dim=2)]


# Named regions, referenced in case.py as "Cube" @ Vol, "Anode" @ Bnd, "Cathode" @ Bnd
gmsh.model.addPhysicalGroup(3, [1], name="Cube")
gmsh.model.addPhysicalGroup(2, faces_at_z(L), name="Anode")
gmsh.model.addPhysicalGroup(2, faces_at_z(0.0), name="Cathode")

# Tetrahedral mesh with six elements along each edge
gmsh.option.setNumber("Mesh.MeshSizeMax", L / 6)
gmsh.model.mesh.generate(3)
gmsh.write("cube.msh")
gmsh.write("cube.step")  # geometry for CAD tools

# Show geometry and mesh in the gmsh GUI (skip with: python setup.py -nopopup)
if "-nopopup" not in sys.argv:
    gmsh.option.setNumber("Mesh.SurfaceFaces", 1)
    gmsh.option.setNumber("Mesh.VolumeEdges", 0)
    gmsh.fltk.run()
gmsh.finalize()
