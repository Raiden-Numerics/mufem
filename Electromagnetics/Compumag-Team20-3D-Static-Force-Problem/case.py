import matplotlib.pyplot as plt
import numpy

from mufem import Bnd, Vol, SteadyRunner, CffConstantScalar, Simulation
from mufem.electromagnetics.coil import (
    CoilExcitationCurrent,
    CoilSpecification,
    CoilTopologyOpen,
    CoilTypeStranded,
    ExcitationCoilModel,
    MagneticInductanceReport,
    ResistanceReport,
)
from mufem.electromagnetics.timedomainmagnetic import (
    MagneticForceReport,
    TangentialMagneticFluxBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)

from typing import List

from pathlib import Path

dir_path = Path(__file__).resolve().parent


sim = Simulation.New(
    name="Compumag-Team20-3D-Static-Force-Problem",
    mesh_path=f"{dir_path}/geometry.mesh",
)


# Setup Problem
steady_runner = SteadyRunner(total_iterations=0)

magnetic_model = TimeDomainMagneticModel(order=1)

air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

copper_material = TimeDomainMagneticGeneralMaterial(
    name="Copper", marker="Coil" @ Vol, electric_conductivity=1.0e7
)

bh = numpy.loadtxt(f"{dir_path}/data/Table_1_BH_Curve.csv", delimiter=",", comments="#")

iron_material = TimeDomainMagneticGeneralMaterial(
    name="Iron",
    marker=["Yoke", "Pole"] @ Vol,
    magnetic_permeability=(bh[:, 1], bh[:, 0]),
    has_eddy_currents=False,
)

magnetic_model.add_materials([air_material, copper_material, iron_material])

# Boundaries
tangential_magnetic_flux_bc = TangentialMagneticFluxBoundaryCondition(
    name="TangentialFlux",
    marker=[
        "Yoke::TangentialFlux",
        "Pole::TangentialFlux",
        "Coil::In",
        "Coil::Out",
        "Air::TangentialFlux",
    ]
    @ Bnd,
)
magnetic_model.add_condition(tangential_magnetic_flux_bc)

# Coil
coil_model = ExcitationCoilModel()
sim.get_model_manager().add_model(coil_model)

coil_topology = CoilTopologyOpen(
    in_marker="Coil::In" @ Bnd, out_marker="Coil::Out" @ Bnd
)
coil_type = CoilTypeStranded(number_of_turns=1000)

coil_drive_current = CffConstantScalar(1.0)
coil_excitation = CoilExcitationCurrent(current=coil_drive_current)

coil = CoilSpecification(
    name="Coil",
    marker="Coil" @ Vol,
    topology=coil_topology,
    type=coil_type,
    excitation=coil_excitation,
)
coil_model.add_coil_specification(coil)

magnetic_force_report_1 = MagneticForceReport(name="Pole Force", marker="Pole" @ Vol)
sim.get_report_manager().add_report(magnetic_force_report_1)

inductance_report = MagneticInductanceReport(name="Coil Inductance")
sim.get_report_manager().add_report(inductance_report)

coil_resistance_report = ResistanceReport(name="Coil Resistance", coil_index=0)
sim.get_report_manager().add_report(coil_resistance_report)


# Run the scan

center_piece_force_list: List[float] = []

for coil_current in numpy.linspace(0.0, 5.0, 11):

    coil_drive_current.set_value(coil_current)

    steady_runner.advance(5)

    force_z = magnetic_force_report_1.evaluate().z

    center_piece_force_list.append((coil_current, force_z))


# Plot the results

plt.clf()

symmetry_factor = 4.0

calculated = numpy.array(center_piece_force_list)

reference = numpy.loadtxt(
    f"{dir_path}/data/ReferenceForce.csv", delimiter=",", comments="#"
)

plt.plot(reference[:, 0], reference[:, 1], "ko", label="Reference")

plt.plot(
    calculated[:, 0],
    symmetry_factor * calculated[:, 1],
    "ro-",
    linewidth=2.5,
    markersize=5.0,
    label="$\\mu$fem",
    markerfacecolor="none",
    markeredgecolor="r",
)

plt.xlabel("Coil Current [A]")
plt.ylabel("Pole Force [N]")

plt.legend(loc="best").draw_frame(False)

plt.xlim(0.0, 5.4)
plt.ylim(0, 90)

plt.savefig(f"{dir_path}/results/Force_vs_Current.png", bbox_inches="tight")


# Finally, we save a few fields so we can visualize with paraview
vis = sim.get_field_exporter()
vis.add_field_output("Magnetic Flux Density")
vis.add_field_output("Electric Current Density")

vis.save(order=1)
