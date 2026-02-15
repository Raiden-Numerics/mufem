import gmsh

from mufem import (
    Bnd,
    Vol,
    Everywhere,
    Simulation,
    SteadyRunner,
    RefinementModel,
    VolumeIntegralReport,
)
from mufem.electromagnetics.electrostatics import (
    ElectricPotentialCondition,
    ElectrostaticMaterial,
    ElectrostaticsModel,
)


def create_geometry(xshift, mesh_file="geometry.msh"):
    gmsh.initialize()

    # Create geometry ------------------------------------------------------------------
    u = 1  # unit of spatial dimensions

    def tooth(x, y, z):
        return gmsh.model.occ.addBox(x, y, z, 15 * u, 4 * u, 4 * u)

    # Comb 1:
    tag_tooth1 = tooth(0, 0, 0)
    tag_tooth2 = tooth(0, 0, 10 * u)
    tag_tooth3 = tooth(0, 0, 20 * u)
    tag_tooth4 = tooth(0, 0, 30 * u)
    tag_base = gmsh.model.occ.addBox(0, 0, 0, 5 * u, 4 * u, 34 * u)

    ov = gmsh.model.occ.fuse(
        [(3, tag_base)],
        [(3, tag_tooth1), (3, tag_tooth2), (3, tag_tooth3), (3, tag_tooth4)],
    )
    comb1 = ov[0][0]

    gmsh.model.occ.translate([comb1], -xshift / 2, 0, 0)

    # Comb 2:
    tag_tooth1 = tooth(7 * u, 0, 5 * u)
    tag_tooth1 = tooth(7 * u, 0, 5 * u + 10 * u)
    tag_tooth1 = tooth(7 * u, 0, 5 * u + 20 * u)
    tag_base = gmsh.model.occ.addBox(17 * u, 0, 0, 5 * u, 4 * u, 34 * u)

    ov = gmsh.model.occ.fuse(
        [(3, tag_base)], [(3, tag_tooth1), (3, tag_tooth2), (3, tag_tooth3)]
    )
    comb2 = ov[0][0]

    gmsh.model.occ.translate([comb2], +xshift / 2, 0, 0)

    # Domain box:
    wx = 88 * u
    wy = 44 * u
    wz = 88 * u
    tag_domain = gmsh.model.occ.addBox(
        11 * u - wx / 2, -6 * u, 17 * u - wz / 2, wx, wy, wz
    )

    ov = gmsh.model.occ.cut([(3, tag_domain)], [comb1, comb2])
    domain = ov[0][0]

    gmsh.model.occ.synchronize()

    # Assign attributes ----------------------------------------------------------------
    print("3D: ", gmsh.model.getEntities(3))
    print("2D: ", gmsh.model.getEntities(2))

    comb1 = [(2, i) for i in range(1, 19)]
    comb2 = [(2, i) for i in range(19, 37)]
    ground = [(2, 38)]
    domain = [(3, 3)]

    gmsh.model.addPhysicalGroup(2, [dimTag[1] for dimTag in comb1], name="Comb1", tag=1)
    gmsh.model.addPhysicalGroup(2, [dimTag[1] for dimTag in comb2], name="Comb2", tag=2)
    gmsh.model.addPhysicalGroup(
        2, [dimTag[1] for dimTag in ground], name="Ground", tag=3
    )
    gmsh.model.addPhysicalGroup(
        3, [dimTag[1] for dimTag in domain], name="Domain", tag=1
    )

    # Generate mesh --------------------------------------------------------------------
    maxh = 4 * u
    gmsh.option.setNumber("Mesh.MeshSizeMax", maxh)

    gmsh.model.mesh.generate(3)

    gmsh.option.setNumber("Mesh.MshFileVersion", 2.2)
    gmsh.write(mesh_file)

    gmsh.finalize()


sim = Simulation.New(name="Ren_2014_MEMS_Comb_Drive")

runner = SteadyRunner(total_iterations=2)
sim.set_runner(runner)


# Mesh ---------------------------------------------------------------------------------
xshifts = [0, 0.5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5, 5.5, 6, 6.5, 7, 7.5, 8]

if sim.get_machine().is_main_process():
    create_geometry(xshifts[0])

sim.get_domain().load_mesh("geometry.msh")
sim.get_domain().get_mesh().scale(1e-6)

refinement_model = RefinementModel()
sim.get_model_manager().add_model(refinement_model)


# Model --------------------------------------------------------------------------------
order = 2  # finite element polynomial degree
model = ElectrostaticsModel(Everywhere @ Vol, order)
sim.get_model_manager().add_model(model)

mesh_refiner = model.get_mesh_refiner()
mesh_refiner.set_refinement_fraction(0.3)


# Materials ----------------------------------------------------------------------------
material = ElectrostaticMaterial("Air", Everywhere @ Vol, electric_permittivity=1.0)
model.add_material(material)


# Boundary conditions ------------------------------------------------------------------
voltage = 1  # [V]

condition_comb1 = ElectricPotentialCondition(
    name="Comb1", marker="Comb1" @ Bnd, electric_potential=0.0
)

condition_comb2 = ElectricPotentialCondition(
    name="Comb2", marker="Comb2" @ Bnd, electric_potential=voltage
)

condition_ground = ElectricPotentialCondition(
    name="Ground", marker="Ground" @ Bnd, electric_potential=0.0
)

model.add_conditions([condition_comb1, condition_comb2, condition_ground])


# Reports ------------------------------------------------------------------------------
report = VolumeIntegralReport(
    name="Electric Energy Density Report",
    cff_name="Electric Energy Density",
)
sim.get_report_manager().add_report(report)


# Run the simulation -------------------------------------------------------------------
max_iterations = 10  # maximum number of iterations for each mesh file

max_ncells = 1e5  # maximum number of cells

with open("results/Capacitance.csv", "w") as fp:
    fp.write("# xshift [um], ncells, capacitance [F]\n")

vis = sim.get_field_exporter()
vis.add_field_output("Electric Potential")

for xshift in xshifts:
    if sim.get_machine().is_main_process():
        create_geometry(xshift)

    sim.get_domain().load_mesh("geometry.msh")
    sim.get_domain().get_mesh().scale(1e-6)

    for i in range(max_iterations):
        runner.advance(2)

        if i == 0:
            vis.save(order=2)

        ncells = sim.get_domain().get_mesh().get_total_number_cells()
        energy = report.evaluate()
        capacitance = 2 * energy / voltage**2  # [F]

        if sim.get_machine().is_main_process():
            with open("results/Capacitance.csv", "a") as fp:
                fp.write(f"{xshift:.1f}, {ncells}, {capacitance}\n")

        if ncells >= max_ncells:
            break
        else:
            refinement_model.refine_mesh()

    else:
        raise RuntimeError(
            "Maximum number of iterations reached without reaching max_ncells."
        )

    vis.save(order=2)
