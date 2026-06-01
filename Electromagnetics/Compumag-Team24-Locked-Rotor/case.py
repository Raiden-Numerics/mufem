import matplotlib.pyplot as plt
import numpy
from pathlib import Path

import mufem

from mufem import Bnd, Vol
from mufem.electromagnetics.coil import (
    CoilExcitationVoltage,
    CoilSpecification,
    CoilTopologyOpen,
    CoilTypeStranded,
    ExcitationCoilCurrentReport,
    ExcitationCoilModel,
    MagneticInductanceReport,
    ResistanceReport,
)
from mufem.electromagnetics.timedomainmagnetic import (
    MagneticTorqueReport,
    TangentialMagneticFluxBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)

# Enable this to output the data per time step for animation
# make sure that the directory vis exists.
output_for_animation = False


dir_path = Path(__file__).resolve().parent

sim = mufem.Simulation.New(name="Team-24", mesh_path=f"{dir_path}/geometry.mesh")

unsteady_runner = mufem.UnsteadyRunner(
    total_time=0.15, time_step_size=0.005, total_inner_iterations=6
)
sim.set_runner(unsteady_runner)


magnetic_model = TimeDomainMagneticModel(order=1)
sim.get_model_manager().add_model(magnetic_model)


# Define the materials
air_material = TimeDomainMagneticGeneralMaterial(
    name="Air",
    marker="Air" @ Vol,
)

copper_material = TimeDomainMagneticGeneralMaterial(
    name="Copper",
    marker=["Upper Coil", "Lower Coil"] @ Vol,
    electric_conductivity=5.8e7,
    has_eddy_currents=False,
)

bh = numpy.loadtxt(
    f"{dir_path}/data/tables/Updated_BH_curve.csv", delimiter=",", comments="#"
)


iron_material = TimeDomainMagneticGeneralMaterial(
    name="Iron",
    marker=["Rotor", "Stator"] @ Vol,
    magnetic_permeability=(bh[:, 0], bh[:, 1]),
    electric_conductivity=4.54e6,
)

magnetic_model.add_materials([air_material, copper_material, iron_material])

# Setup Boundaries
boundary_marker = [
    "Stator::TangentialFlux",
    "Rotor::TangentialFlux",
    "Air::TangentialFlux",
    "Upper Coil::In",
    "Upper Coil::Out",
    "Lower Coil::In",
    "Lower Coil::Out",
] @ Bnd

tangential_magnetic_flux_bc = TangentialMagneticFluxBoundaryCondition(
    name="TangentialFlux", marker=boundary_marker
)
magnetic_model.add_condition(tangential_magnetic_flux_bc)

# Setup Coil
coil_model = ExcitationCoilModel()
sim.get_model_manager().add_model(coil_model)

for coil in ["Upper", "Lower"]:

    coil_topology = CoilTopologyOpen(
        in_marker=f"{coil} Coil::In" @ Bnd, out_marker=f"{coil} Coil::Out" @ Bnd
    )

    # 0.25 factor as we have two coils to which the voltage is applied and we have a symmetry plane
    symmetry = 0.25

    coil_type = CoilTypeStranded(number_of_turns=350)

    coil_excitation = CoilExcitationVoltage(
        voltage=23.1 * symmetry, resistance=3.09 * symmetry
    )

    coil = CoilSpecification(
        name=f"{coil} Coil",
        marker=f"{coil} Coil" @ Vol,
        topology=coil_topology,
        type=coil_type,
        excitation=coil_excitation,
    )
    coil_model.add_coil_specification(coil)

# Setup Reports
magnetic_torque_report = MagneticTorqueReport(name="Rotor Torque", marker="Rotor" @ Vol)
sim.get_report_manager().add_report(magnetic_torque_report)

magnetic_torque_monitor = mufem.ReportMonitor(
    name="Rotor Torque Monitor", report_name="Rotor Torque"
)
sim.get_monitor_manager().add_monitor(magnetic_torque_monitor)


coil_current_report = ExcitationCoilCurrentReport(name="Coil Current", coil_index=0)
sim.get_report_manager().add_report(coil_current_report)

coil_current_monitor = mufem.ReportMonitor(
    name="Coil Current Monitor", report_name="Coil Current"
)
sim.get_monitor_manager().add_monitor(coil_current_monitor)


# Run the simulation

sim.initialize()

inductance_report = MagneticInductanceReport(name="Coil Inductance")

print("Inductance Report:", inductance_report.evaluate())

coil_resistance_report = ResistanceReport(name="Coil Resistance", coil_index=0)

print("Coil Resistance Value:", coil_resistance_report.evaluate())


if output_for_animation:

    refinement_model = mufem.RefinementModel()
    sim.get_model_manager().add_model(refinement_model)

    # We save a few fields so we can visualize with paraview
    field_exporter = sim.get_field_exporter()
    field_exporter.add_field_output("Electric Current Density")
    field_exporter.add_field_output("Magnetic Flux Density")
    field_exporter.add_field_output("Magnetic Vector Potential")
    field_exporter.add_field_output("Element Type")
    field_exporter.add_field_output("Cell Volume")

    field_exporter.save()

    for i in range(30):
        unsteady_runner.advance(1)

        # Save the fields for visualization
        field_exporter.save()

else:

    sim.run()


# Plot the results


symmetry_factor = 2.0


def xy_plot(values, reference, xlabel, ylabel, xlim, ylim, xticks, filename):

    # flake8: noqa: FKA100

    plt.clf()
    plt.plot(reference[:, 0], reference[:, 1], "ko", label="Reference")
    plt.plot(
        *zip(*values),
        "r-",
        linewidth=2.5,
        markersize=5.0,
        label="$\\mu$fem",
        markerfacecolor="none",
        markeredgecolor="r",
    )
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xlim(xlim)
    plt.ylim(ylim)
    plt.xticks(xticks)

    plt.legend(loc="best").draw_frame(False)
    plt.savefig(filename, bbox_inches="tight")


coil_current_ref = numpy.loadtxt(
    f"{dir_path}/data/tables/Table_3_Coil_Current.csv", delimiter=",", skiprows=1
)

current_values = coil_current_monitor.get_values()

symmetry_factor = 2.0

# Current monitor values
monitor_values = magnetic_torque_monitor.get_values()

torque_values = [(value[0], symmetry_factor * value[1].z) for value in monitor_values]

torque_ref = numpy.loadtxt(
    f"{dir_path}/data/tables/Table_4_Torque.csv", delimiter=",", skiprows=1
)

if output_for_animation:

    for i in range(31):

        xy_plot(
            values=current_values[: i + 1],
            reference=coil_current_ref,
            xlabel="Time [s]",
            ylabel="Coil Current [A]",
            xlim=(0, 0.15),
            ylim=(0.0, 8.0),
            xticks=[0.0, 0.05, 0.1, 0.15],
            filename=f"{dir_path}/vis/Coil_Current_vs_Time_{i:03d}.png",
        )

        xy_plot(
            values=torque_values[: i + 1],
            reference=torque_ref,
            xlabel="Time [s]",
            ylabel="Rotor Torque [Nm]",
            xlim=(0, 0.15),
            ylim=(0.0, 3.5),
            xticks=[0.0, 0.05, 0.1, 0.15],
            filename=f"{dir_path}/vis/Rotor_Torque_vs_Time_{i:03d}.png",
        )


xy_plot(
    values=current_values,
    reference=coil_current_ref,
    xlabel="Time [s]",
    ylabel="Coil Current [A]",
    xlim=(0, 0.15),
    ylim=(0.0, 8.0),
    xticks=[0.0, 0.05, 0.1, 0.15],
    filename=f"{dir_path}/results/Coil_Current_vs_Time.png",
)


xy_plot(
    values=torque_values,
    reference=torque_ref,
    xlabel="Time [s]",
    ylabel="Rotor Torque [Nm]",
    xlim=(0, 0.15),
    ylim=(0.0, 3.5),
    xticks=[0.0, 0.05, 0.1, 0.15],
    filename=f"{dir_path}/results/Rotor_Torque_vs_Time.png",
)
