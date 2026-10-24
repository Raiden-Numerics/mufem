import mufem
import mufem.electromagnetics.electrostatics as estat
from mufem import Vol, Bnd

sim = mufem.Simulation.New(name="Charged Cube", mesh_path="cube.msh")
sim.set_runner(mufem.SteadyRunner(total_iterations=1))

# Electrostatics model, with air filling the tagged "Cube" volume
model = estat.ElectrostaticsModel(order=2)
sim.get_model_manager().add_model(model)
model.add_material(estat.ElectrostaticMaterial(name="Air", marker="Cube" @ Vol))

# Apply 1 V across the cube: anode at 1 V, cathode grounded
model.add_conditions(
    [
        estat.ElectricPotentialCondition(
            name="Anode", marker="Anode" @ Bnd, electric_potential=1.0
        ),
        estat.ElectricPotentialCondition(
            name="Cathode", marker="Cathode" @ Bnd, electric_potential=0.0
        ),
    ]
)

# Report the stored electric energy
report = mufem.VolumeIntegralReport(name="Energy", cff_name="Electric Energy Density")
sim.get_report_manager().add_report(report)

sim.run()
print("Electric energy:", report.evaluate(), "J")

# Export the fields for visualization (ParaView / VTK)
vis = sim.get_field_exporter()
vis.set_output_directory("ChargedCubeOutput")
vis.add_field_output("Electric Potential")
vis.add_field_output("Electric Field")
vis.save()
