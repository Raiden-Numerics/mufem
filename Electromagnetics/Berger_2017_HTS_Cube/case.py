import matplotlib.pyplot as plt
import numpy

import mufem

from mufem import Bnd, Vol
from mufem.electromagnetics.module.superconductor import SuperconductorMagneticMaterial
from mufem.electromagnetics.timedomainmagnetic import (
    LineSearchStrategy,
    TangentialMagneticFieldBoundaryCondition,
    TangentialMagneticFluxBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)

from pathlib import Path

dir_path = Path(__file__).resolve().parent


sim = mufem.Simulation.New(
    name="Berger (2017): High-Temperature Superconductor Cube",
    mesh_path=f"{dir_path}/geometry.mesh",
)

# Setup Problem
frequency = 50.0
period = 1.0 / frequency
time_step_size = period / 50.0
total_time = 1.0 * period

mufem.UnsteadyRunner(
    total_time=total_time,
    time_step_size=time_step_size,
    total_inner_iterations=10,
)

magnetic_model = TimeDomainMagneticModel(order=1, magnetostatic_initialization=False)

# Line search stabilises Newton's iteration on the n=25 power-law nonlinearity.
line_search = magnetic_model.get_solver().get_line_search()
line_search.set_active(True)
line_search.set_strategy(LineSearchStrategy.ThreePointQuadratic)
line_search.set_iteration_window(min_iter=0, max_iter=100000000)
line_search.set_residual_skip_threshold(1.0e-10)
line_search.set_max_alpha(1.0)

# Setup Materials
air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

# n=25, Jc=2.5e6 A/m^2, Ec=1e-4 V/m are characteristic of commercial Bi-2223
# (1G HTS tape) at 77 K self-field, matching Berger 2017 §II.B.
hts_material = SuperconductorMagneticMaterial(
    name="Bi-2223",
    marker="Cube" @ Vol,
    Ec=1.0e-4,
    Jc=2.5e6,
    n=25,
)

magnetic_model.add_materials([air_material, hts_material])

# Setup Boundary Conditions
# Applied field: B_a(t) = B_max sin(2 pi f t) along y.
# B_max = 20 mT > B_p = mu0 * Jc * d / 2 ~ 15.7 mT places the case in the
# full-penetration regime.
b_max = 20.0e-3
h_max = b_max / (4.0e-7 * numpy.pi)

cff_applied_field = mufem.CffExpressionVector(
    f"[0, {h_max}*sin(2*pi*{frequency}*{{Time}}), 0]"
)

applied_field_bc = TangentialMagneticFieldBoundaryCondition(
    name="Applied Field",
    marker="Air::Outer" @ Bnd,
    tangential_magnetic_field=cff_applied_field,
)

# 1/8-symmetry: x=0 and z=0 are B-tangential planes (Tangential-A=0).
symmetry_bc = TangentialMagneticFluxBoundaryCondition(
    name="Symmetry Plane",
    marker=[
        "Cube::TangentialFlux::X",
        "Cube::TangentialFlux::Z",
        "Air::TangentialFlux::X",
        "Air::TangentialFlux::Z",
    ]
    @ Bnd,
)

magnetic_model.add_conditions([applied_field_bc, symmetry_bc])

# Setup Reports
ohmic_heating_report = mufem.VolumeIntegralReport(
    name="Ohmic Heating", marker="Cube" @ Vol, cff_name="Ohmic Heating"
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

# Plot the AC losses against the Berger (2017) reference.
# The octant model integrates 1/8 of the cube; multiply by 8 to recover the
# full-cube instantaneous loss. Convert time to ms and loss to mW.

plt.clf()

ref_time_ms, ref_loss_mw = numpy.loadtxt(
    f"{dir_path}/data/AC_Losses_B20mT.csv", delimiter=",", unpack=True
)

plt.plot(  # noqa: FKA100 - false positive, wants x=, y= but not available
    ref_time_ms,
    ref_loss_mw,
    color="k",
    linestyle="-",
    label="Berger (2017)",
    linewidth=2.5,
    markersize=6.5,
)

monitor_values = ohmic_heating_monitor.get_values()
times_s, losses_w = zip(*monitor_values)
times_ms = numpy.asarray(times_s) * 1.0e3
losses_mw = numpy.asarray(losses_w) * 8.0e3

plt.plot(
    times_ms,
    losses_mw,
    color="r",
    linestyle="-",
    marker=".",
    label="$\\mu$fem",
    markersize=6.5,
    linewidth=2.0,
)

plt.xlabel("Time [ms]")
plt.ylabel("Ohmic Heating [mW]")
plt.xlim(left=0, right=1.0e3 * period)
plt.ylim(bottom=0)
plt.legend(loc="best").set_frame_on(False)

plt.savefig(f"{dir_path}/results/Ohmic_Heating.png", bbox_inches="tight")
