import numpy as np
import gmsh

gmsh.initialize()

gmsh.model.add("geometry")


# **************************************************************************************
# Create geometry
# **************************************************************************************
wavelength = 4.0
arm_length = wavelength / 4
arm_radius = arm_length / 20
gap_size = arm_length / 100
outer_boundary_radius = 1.5 * wavelength

kernel = gmsh.model.occ

outer_boundary = kernel.addSphere(0, 0, 0, outer_boundary_radius)
top_arm = kernel.addCylinder(0, 0, gap_size / 2, 0, 0, arm_length, arm_radius)
bot_arm = kernel.addCylinder(0, 0, -gap_size / 2, 0, 0, -arm_length, arm_radius)

gap_rectangle = kernel.addRectangle(-arm_radius, -gap_size / 2, 0, 2 * arm_radius, gap_size)
kernel.rotate([(2, gap_rectangle)], 0, 0, 0, 1, 0, 0, np.pi / 2)

kernel.cut([(3, outer_boundary)], [(3, top_arm), (3, bot_arm)])
kernel.fragment([(3, 1)], [(2, gap_rectangle)])

kernel.synchronize()


# **************************************************************************************
# Assign attributes
# **************************************************************************************
print("3D: ", gmsh.model.getEntities(3))
print("2D: ", gmsh.model.getEntities(2))

domain = [(3, 1)]
boundary_top_arm = [(2, 14), (2, 15), (2, 16), (2, 17)]
boundary_bot_arm = [(2, 10), (2, 11), (2, 12), (2, 13)]
boundary_port = [(2, 8)]
boundary_outer = [(2, 9)]

gmsh.model.addPhysicalGroup(3, [dimTag[1] for dimTag in domain], name="Domain", tag=1)
gmsh.model.addPhysicalGroup(
    2, [dimTag[1] for dimTag in boundary_top_arm], name="BoundaryTopArm", tag=1
)
gmsh.model.addPhysicalGroup(
    2, [dimTag[1] for dimTag in boundary_bot_arm], name="BoundaryBotArm", tag=2
)
gmsh.model.addPhysicalGroup(2, [dimTag[1] for dimTag in boundary_port], name="Port", tag=3)
gmsh.model.addPhysicalGroup(
    2, [dimTag[1] for dimTag in boundary_outer], name="BoundaryOuter", tag=4
)


# **************************************************************************************
# Generate mesh
# **************************************************************************************
gmsh.option.setNumber("Mesh.MeshSizeMax", wavelength / 5)

gmsh.option.setNumber("Mesh.ElementOrder", 2)
gmsh.option.setNumber("Mesh.HighOrderOptimize", 2)
gmsh.option.setNumber("Mesh.MeshSizeFromCurvature", 12)

gmsh.model.mesh.generate(3)


# **************************************************************************************
# Adjust the view
# **************************************************************************************
gmsh.model.setColor(gmsh.model.getEntities(3), 0, 255, 0, recursive=True)

# gmsh.model.setColor(domain, 100, 100, 255)
gmsh.model.setColor(boundary_top_arm, 100, 100, 100, recursive=True)
gmsh.model.setColor(boundary_bot_arm, 200, 200, 200, recursive=True)
gmsh.model.setColor(boundary_port, 255, 100, 100, recursive=True)
gmsh.model.setColor(boundary_outer, 100, 100, 255, recursive=True)

gmsh.option.setNumber("General.BackgroundGradient", 0)

gmsh.option.setNumber("General.Trackball", 0)
gmsh.option.setNumber("General.RotationX", -85)
gmsh.option.setNumber("General.RotationZ", 30)

gmsh.option.setNumber("General.ScaleX", 1.2)
gmsh.option.setNumber("General.ScaleY", 1.2)
gmsh.option.setNumber("General.ScaleZ", 1.2)

gmsh.option.setNumber("Mesh.SurfaceFaces", 1)
gmsh.option.setNumber("Mesh.VolumeEdges", 0)
gmsh.option.setNumber("Mesh.VolumeFaces", 0)

gmsh.option.setNumber("General.Clip0A", 1)
gmsh.option.setNumber("General.Clip0D", 0.025)
gmsh.option.setNumber("Mesh.Clip", 1)


# **************************************************************************************
# Export to mesh file
# **************************************************************************************
gmsh.option.setNumber("Mesh.MshFileVersion", 2.2)
gmsh.write("geometry.msh")

gmsh.fltk.run()

gmsh.finalize()
