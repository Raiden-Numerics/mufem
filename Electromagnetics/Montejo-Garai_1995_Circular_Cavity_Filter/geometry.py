import gmsh

gmsh.initialize()

gmsh.model.add("geometry")


# **************************************************************************************
# Dimensions
# **************************************************************************************
# WR75 waveguide:
wr75_width = 19.05e-3
wr75_height = 9.525e-3
wr75_length = 20e-3

# Coupling iris:
iris_width = 9.7e-3
iris_height = 3e-3
iris_length = 1e-3

# Circular cavity:
cavity_radius = 12e-3
cavity_length = 100e-3


# **************************************************************************************
# Create geometry
# **************************************************************************************
z = 0

# input WR75 waveguide:
gmsh.model.occ.addBox(0, 0, 0, wr75_width, wr75_height, wr75_length, 101)
gmsh.model.occ.translate([(3, 101)], -wr75_width / 2, -wr75_height / 2, z)
z = z + wr75_length

# Input coupling iris:
gmsh.model.occ.addBox(0, 0, 0, iris_width, iris_height, iris_length, 102)
gmsh.model.occ.translate([(3, 102)], -iris_width / 2, -iris_height / 2, z)
z = z + iris_length

# Circular cavity:
gmsh.model.occ.addCylinder(0, 0, 0, 0, 0, cavity_length, cavity_radius, 103)
gmsh.model.occ.translate([(3, 103)], 0, 0, z)
z = z + cavity_length

# Output coupling iris:
gmsh.model.occ.addBox(0, 0, 0, iris_width, iris_height, iris_length, 104)
gmsh.model.occ.translate([(3, 104)], -iris_width / 2, -iris_height / 2, z)
z = z + iris_length

# Output WR75 waveguide:
gmsh.model.occ.addBox(0, 0, 0, wr75_width, wr75_height, wr75_length, 105)
gmsh.model.occ.translate([(3, 105)], -wr75_width / 2, -wr75_height / 2, z)
z = z + wr75_length

# Fuse all parts together:
gmsh.model.occ.fuse([(3, 101)], [(3, 102), (3, 103), (3, 104), (3, 105)], 100)
gmsh.model.occ.synchronize()


# **************************************************************************************
# Assign attributes
# **************************************************************************************
eps = 0.1e-3

ov = gmsh.model.getEntitiesInBoundingBox(
    -wr75_width / 2 - eps,
    -wr75_height / 2 - eps,
    -eps,
    +wr75_width / 2 + eps,
    +wr75_height / 2 + eps,
    +eps,
    2,
)
input_port = ov[0]

ov = gmsh.model.getEntitiesInBoundingBox(
    -wr75_width / 2 - eps,
    -wr75_height / 2 - eps,
    z - eps,
    +wr75_width / 2 + eps,
    +wr75_height / 2 + eps,
    z + eps,
    2,
)
output_port = ov[0]

walls = [ov for ov in gmsh.model.getEntities(dim=2) if ov not in [input_port, output_port]]

ov = gmsh.model.getEntities(3)
domain = ov[0]

gmsh.model.addPhysicalGroup(2, [input_port[1]], name="InputPort")
gmsh.model.addPhysicalGroup(2, [output_port[1]], name="OutputPort")
gmsh.model.addPhysicalGroup(2, [ov[1] for ov in walls], name="Walls")
gmsh.model.addPhysicalGroup(3, [domain[1]], name="Domain", tag=1)
# @todo(SFW-47): Here we force the tag of the domain to be 1. This is done since MFEM
# creates the array of markers with the length based on the maximum tag number rather
# than the number of tags.


# **************************************************************************************
# Adjust the view
# **************************************************************************************
# gmsh.model.setColor([domain], 113, 121, 126, recursive=True)
gmsh.model.setColor(walls, 170, 177, 183, recursive=True)
gmsh.model.setColor([input_port], 255, 183, 157)
gmsh.model.setColor([output_port], 255, 183, 157)
gmsh.model.setColor(gmsh.model.getEntities(1), 85, 88, 91)

gmsh.option.setNumber("General.BackgroundGradient", 0)

gmsh.option.setNumber("General.Light0", 1)
gmsh.option.setNumber("General.Light0X", 0.25)
gmsh.option.setNumber("General.Light0Y", 0.65)
gmsh.option.setNumber("General.Light0Z", 1)

gmsh.option.setNumber("General.Trackball", 0)
gmsh.option.setNumber("General.RotationX", 15)
gmsh.option.setNumber("General.RotationY", 135)

gmsh.option.setNumber("General.ScaleX", 0.25)
gmsh.option.setNumber("General.ScaleY", 0.25)
gmsh.option.setNumber("General.ScaleZ", 0.25)

gmsh.option.setNumber("Mesh.Lines", 0)
gmsh.option.setNumber("Mesh.SurfaceEdges", 0)
gmsh.option.setNumber("Mesh.SurfaceFaces", 1)
gmsh.option.setNumber("Mesh.VolumeEdges", 0)
gmsh.option.setNumber("Mesh.VolumeFaces", 0)

gmsh.option.setNumber("General.Clip0A", 1)
gmsh.option.setNumber("Mesh.Clip", 1)

gmsh.option.setNumber("General.SmallAxes", 0)


# **************************************************************************************
# Generate mesh
# **************************************************************************************
gmsh.option.setNumber("Mesh.MeshSizeMax", 4e-3)
gmsh.option.setNumber("Mesh.MeshSizeFromCurvature", 10)

gmsh.option.setNumber("Mesh.ElementOrder", 2)
gmsh.option.setNumber("Mesh.HighOrderOptimize", 2)

gmsh.model.mesh.generate(3)

gmsh.option.setNumber("Mesh.MshFileVersion", 2.2)
gmsh.write("geometry.msh")

# Save to image file:
gmsh.fltk.initialize()
gmsh.graphics.draw()
gmsh.option.setNumber("Print.Width", 2000)
gmsh.option.setNumber("Print.Height", 1500)
gmsh.write("Geometry.png")
gmsh.fltk.finalize()

gmsh.fltk.run()

gmsh.finalize()
