import numpy

import mufem
from mufem.electromagnetics.coil import (
    CoilExcitationCurrent,
    CoilSpecification,
    CoilTopologyClosed,
    CoilTypeStranded,
    ExcitationCoilModel,
)
from mufem.electromagnetics.timedomainmagnetic import (
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
    TangentialMagneticFluxBoundaryCondition,
)

from pathlib import Path
import matplotlib.pyplot as plt

dir_path = Path(__file__).resolve().parent


sim = mufem.Simulation.New(name="Team-13", mesh_path=f"{dir_path}/geometry.mesh")


is_main_process = sim.get_machine().is_main_process()

# Setup Problem
steady_runner = mufem.SteadyRunner(total_iterations=12)
sim.set_runner(steady_runner)

magnetic_domain = [
    "Center Plate",
    "Outer Plate 1",
    "Outer Plate 2",
    "Coil",
    "Air",
] @ mufem.Vol

magnetic_model = TimeDomainMagneticModel(marker=magnetic_domain, order=2)
sim.get_model_manager().add_model(magnetic_model)

# Materials
air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ mufem.Vol)

copper_material = TimeDomainMagneticGeneralMaterial(
    name="Cu",
    marker="Coil" @ mufem.Vol,
    electric_conductivity=1.0e7,
    has_eddy_currents=False,
)

bh = numpy.loadtxt(f"{dir_path}/data/bh_table.csv", delimiter=",", comments="#")


iron_material = TimeDomainMagneticGeneralMaterial(
    name="Iron",
    marker=["Center Plate", "Outer Plate 1", "Outer Plate 2"] @ mufem.Vol,
    magnetic_permeability=(bh[:, 1], bh[:, 0]),
)
magnetic_model.add_materials([air_material, copper_material, iron_material])

# Boundaries (all normal)
tangential_magnetic_flux_bc = TangentialMagneticFluxBoundaryCondition(
    name="TangentialFlux",
    marker="Air::Tangential Flux" @ mufem.Bnd,
)
magnetic_model.add_condition(tangential_magnetic_flux_bc)

# Coil
coil_model = ExcitationCoilModel()
sim.get_model_manager().add_model(coil_model)

coil_topology = CoilTopologyClosed(x=0.09, y=0.0, z=0.001, dx=0.0, dy=1.0, dz=0.0)
coil_type = CoilTypeStranded(number_of_turns=500)

coil_excitation = CoilExcitationCurrent.Constant(3.0)

coil = CoilSpecification(
    name="Coil",
    marker="Coil" @ mufem.Vol,
    topology=coil_topology,
    type=coil_type,
    excitation=coil_excitation,
)

coil_model.add_coil_specification(coil)


sim.run()

vis = sim.get_field_exporter()
vis.add_field_output("Magnetic Flux Density")
vis.add_field_output("Electric Current Density")

vis.save(order=2)


# Plot Results
# flake8: noqa: FKA100


x_vals = numpy.linspace(0.01, 0.11, 23, endpoint=True)
b_vals = []


for x in x_vals:

    probe_report = mufem.ProbeReport.SinglePoint(
        "B", "Magnetic Flux Density", x=x, y=0.02, z=0.055
    )

    b = probe_report.evaluate().mag

    b_vals.append(b)


res = numpy.column_stack((x_vals, b_vals))
ref = numpy.loadtxt(
    f"{dir_path}/data/Table7_FluxDensity.csv", delimiter=",", comments="#"
)


T_to_mT = 1000.0
m_to_mm = 1000.0


plt.plot(ref[:, 0] * m_to_mm, ref[:, 1] * T_to_mT, "k-", label="Reference")
plt.plot(res[:, 0] * m_to_mm, res[:, 1] * T_to_mT, "ro-", label="$\\mu$fem")


plt.xlabel("x [mm]")
plt.ylabel("B [mT]")

plt.xlim((0, 120))

plt.legend(loc="best", frameon=False)

plt.savefig(
    f"{dir_path}/results/Magnetic_Flux_Density_Line_Air.png",
    bbox_inches="tight",
)
