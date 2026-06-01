import matplotlib.pyplot as plt
import numpy

import mufem

from mufem import Bnd, Vol
from mufem.electromagnetics.timedomainmagnetic import (
    TangentialMagneticFieldBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)

from pathlib import Path

dir_path = Path(__file__).resolve().parent


sim = mufem.Simulation.New(
    name="Compumag Team1b: Felix Cylinder", mesh_path=f"{dir_path}/geometry.mesh"
)

# Setup Problem
mufem.UnsteadyRunner(total_time=0.02, time_step_size=0.001, total_inner_iterations=3)

magnetic_model = TimeDomainMagneticModel(order=1, magnetostatic_initialization=True)

# Setup Materials
air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

copper_material = TimeDomainMagneticGeneralMaterial(
    name="Al", marker="Cylinder" @ Vol, electric_conductivity=25380710.659898475
)
magnetic_model.add_materials([air_material, copper_material])

# Setup Boundary Conditions
cff_magnetic_field = mufem.CffExpressionVector(
    "[0, 79577.488101574*exp(-{Time}/0.0069), 0]"
)

tangential_magnetic_field_bc = TangentialMagneticFieldBoundaryCondition(
    name="ExternalField",
    marker="Air::Boundary" @ Bnd,
    tangential_magnetic_field=cff_magnetic_field,
)
magnetic_model.add_condition(tangential_magnetic_field_bc)

# Setup Reports
ohmic_heating_report = mufem.VolumeIntegralReport(
    name="Ohmic Heating", marker="Cylinder" @ Vol, cff_name="Ohmic Heating"
)
sim.get_report_manager().add_report(ohmic_heating_report)


ohmic_heating_monitor = mufem.ReportMonitor(
    name="Ohmic Heating Monitor", report_name="Ohmic Heating"
)
sim.get_monitor_manager().add_monitor(ohmic_heating_monitor)


sim.run()

vis = sim.get_field_exporter()
vis.add_field_output("Magnetic Flux Density")
vis.add_field_output("Electric Current Density")
vis.save()

# Plot the losses

plt.clf()

ref_power_loss_time, ref_power_loss_value = numpy.loadtxt(
    f"{dir_path}/data/PowerLoss.csv", delimiter=",", unpack=True
)

plt.plot(  # noqa: FKA100 - false positive, wants x=, y= but not available
    ref_power_loss_time,
    ref_power_loss_value,
    color="k",
    linestyle="-",
    label="Davey (1988)",
    linewidth=2.5,
    markersize=6.5,
)

monitor_values = ohmic_heating_monitor.get_values()


plt.plot(
    *zip(*monitor_values),
    color="r",
    linestyle="-",
    marker=".",
    label="$\\mu$fem",
    markersize=6.5,
    linewidth=2.0,
)

plt.xlabel("Time [s]")
plt.ylabel("Ohmic Heating Loss [W]")
plt.xlim(left=0, right=0.02)
plt.xticks([0, 0.01, 0.02])
plt.ylim(bottom=0, top=600)
plt.legend(loc="best").set_frame_on(False)

plt.savefig(f"{dir_path}/results/OhmicHeating.png", bbox_inches="tight")
