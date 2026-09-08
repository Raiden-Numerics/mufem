import matplotlib.pyplot as plt
import numpy

import mufem
import mufem.methods as method
from mufem.electromagnetics.coil import (
    CoilExcitationCurrent,
    CoilSpecification,
    CoilTopologyOpen,
    CoilTypeStranded,
    ExcitationCoilModel,
)
from mufem.electromagnetics.timeharmonicmagnetic import (
    MagneticPermeabilityMethodTemperatureTableSusceptibility,
    RelaxationType as MagneticRelaxationType,
    TangentialMagneticFluxBoundaryCondition,
    TimeHarmonicMagneticGeneralMaterial,
    TimeHarmonicMagneticModel,
)
from mufem.thermal import (
    ConvectionBoundaryCondition,
    RadiationBoundaryCondition,
    RelaxationType as ThermalRelaxationType,
    SolidTemperatureMaterial,
    SolidTemperatureModel,
)


def load_csv(file_name):
    return numpy.loadtxt(f"data/{file_name}", delimiter=",", comments="#")


# Problem setup ------------------------------------------------------------------------
sim = mufem.Simulation.New(name="Compumag Team 36: Induction Heating Device")

# De-refinement (used by the adaptive strategy) requires a nonconforming mesh.
nonconforming_options = mufem.NonConformingOption(
    is_nonconforming=True, simplicies_nonconforming=True
)
sim.get_domain().load_mesh("geometry.mesh", nonconforming=nonconforming_options)

# Regions are referred to by the names assigned during meshing.
billet_marker = "Billet" @ mufem.Vol
air_marker = "Air" @ mufem.Vol

runner = mufem.UnsteadyRunner(
    total_time=100.0,
    time_step_size=5.0,
    total_inner_iterations=8,
)
sim.set_runner(runner)

# Time-Harmonic Magnetic model ---------------------------------------------------------
magnetic_model = TimeHarmonicMagneticModel(frequency=2000.0, order=1)
sim.get_model_manager().add_model(magnetic_model)

magnetic_solver = magnetic_model.get_solver()
magnetic_solver.set_under_relaxation_factor(0.7)
magnetic_solver.set_relaxation_type(MagneticRelaxationType.Aitken)
magnetic_solver.set_verbose(False)

air_material = TimeHarmonicMagneticGeneralMaterial("Air", air_marker)

copper_material = TimeHarmonicMagneticGeneralMaterial(
    "Copper",
    mufem.Vol("Coil::.*"),
    electric_conductivity=5.998e7,
    has_eddy_currents=True,
)

# Temperature-dependent steel properties.
rho_T = load_csv("Steel_ElectricResistivity.csv")
h_b = load_csv("Steel_BHCurve.csv")
xi_T = load_csv("Steel_MagneticSusceptibility.csv")

permeability_method = MagneticPermeabilityMethodTemperatureTableSusceptibility(
    h_b[:, 0], h_b[:, 1], xi_T[:, 0] + 273.15, xi_T[:, 1]
)

billet_material = TimeHarmonicMagneticGeneralMaterial(
    "Billet",
    billet_marker,
    permeability_method,
    electric_conductivity=method.TemperatureTable(
        rho_T[:, 0] + 273.15, 1.0 / rho_T[:, 1]
    ),
    has_eddy_currents=True,
)

magnetic_model.add_materials([air_material, copper_material, billet_material])

# Tangential-flux (symmetry) boundaries, plus every coil terminal face.
tangential_flux_boundary_marker = mufem.Bnd(
    [".*::TangentialFlux", "Coil::.*::In", "Coil::.*::Out"]
)
magnetic_model.add_condition(
    TangentialMagneticFluxBoundaryCondition(
        "TangentialFlux", tangential_flux_boundary_marker
    )
)

# Excitation coils ---------------------------------------------------------------------
coil_model = ExcitationCoilModel()
sim.get_model_manager().add_model(coil_model)

for n in range(10):
    coil_topology = CoilTopologyOpen(
        f"Coil::{n}::In" @ mufem.Bnd, f"Coil::{n}::Out" @ mufem.Bnd
    )
    coil_type = CoilTypeStranded(1)
    coil_excitation = CoilExcitationCurrent(current=3500.0 * numpy.sqrt(2))  # RMS
    coil = CoilSpecification(
        "Coil", f"Coil::{n}" @ mufem.Vol, coil_topology, coil_type, coil_excitation
    )
    coil_model.add_coil_specification(coil)

# Thermal model ------------------------------------------------------------------------
thermal_model = SolidTemperatureModel(billet_marker, 1)
sim.get_model_manager().add_model(thermal_model)
thermal_model.get_initial_condition().set_constant(25.0 + 273.15)

lambda_T = load_csv("Steel_ThermalConductivity.csv")
cp_T = load_csv("Steel_SpecificHeatCapacity.csv")

thermal_billet_material = SolidTemperatureMaterial(
    name="Billet",
    marker=billet_marker,
    thermal_conductivity=method.TemperatureTable(
        lambda_T[:, 0] + 273.15, lambda_T[:, 1]
    ),
    specific_heat_capacity=method.TemperatureTable(cp_T[:, 0] + 273.15, cp_T[:, 1]),
    density=7800,
)
thermal_model.add_materials([thermal_billet_material])

# Lateral surface: convection + radiation at 70 °C ambient.
lateral_surface_marker = "Billet::2::LatteralSurface" @ mufem.Bnd
thermal_model.add_conditions(
    [
        ConvectionBoundaryCondition(
            "Lateral Surface Convection", lateral_surface_marker, 7.0, 273.0 + 70.0
        ),
        RadiationBoundaryCondition(
            "Lateral Surface Radiation", lateral_surface_marker, 0.8, 273.0 + 70.0
        ),
    ]
)

# End surface: convection + radiation at 25 °C ambient.
end_surface_marker = "Billet::EndSurface" @ mufem.Bnd
thermal_model.add_conditions(
    [
        ConvectionBoundaryCondition(
            "End Surface Convection", end_surface_marker, 7.0, 273.0 + 25.0
        ),
        RadiationBoundaryCondition(
            "End Surface Radiation", end_surface_marker, 0.8, 273.0 + 25.0
        ),
    ]
)

thermal_solver = thermal_model.get_solver()
thermal_solver.set_under_relaxation_factor(0.7)
thermal_solver.set_relaxation_type(ThermalRelaxationType.Aitken)

# Reports and monitors -----------------------------------------------------------------
ohmic_heating_report = mufem.VolumeIntegralReport(
    name="OhmicHeatingReport", marker=billet_marker, cff_name="Ohmic Heating"
)
sim.get_report_manager().add_report(ohmic_heating_report)
ohmic_heating_monitor = mufem.ReportMonitor(
    "Ohmic Heating Monitor", "OhmicHeatingReport"
)
sim.get_monitor_manager().add_monitor(ohmic_heating_monitor)

eps = 1.0e-6
for name, point in [("Center", (eps, eps, 0.0)), ("Surface", (0.03 - eps, eps, 0.0))]:
    probe = mufem.ProbeReport.SinglePoint(
        name=name, cff_name="Temperature", x=point[0], y=point[1], z=point[2]
    )
    sim.get_report_manager().add_report(probe)
    sim.get_monitor_manager().add_monitor(mufem.ReportMonitor(name, name))

refinement_model = mufem.RefinementModel()
sim.get_model_manager().add_model(refinement_model)

# Run the simulation -------------------------------------------------------------------
vis = sim.get_field_exporter()
vis.add_field_output("Temperature")
vis.add_field_output("Magnetic Flux Density-Real")
vis.add_field_output("Magnetic Flux Density-Imag")
vis.add_field_output("Ohmic Heating")

sim.initialize()
vis.save()

# dt = 5 s, T_end = 100 s -> 20 steps. Refine once at t = 45 s (step 9).
for _ in range(9):
    runner.advance(1)
    vis.save()

refinement_model.refine_mesh()
vis.save()

for _ in range(11):
    runner.advance(1)
    vis.save()

# Ohmic heating ------------------------------------------------------------------------
symmetry_factor = 2 * (360.0 / 30.0)  # 30-degree periodic sector

ohmic = ohmic_heating_monitor.get_values()
ref_t, ref_p = load_csv("Fig6a_Ohmic_Heating_Power.csv").T

plt.clf()
plt.plot(ref_t, ref_p * 1e-3, "ko", label="Di Barba (2017)")
plt.plot(
    *zip(*[(t, p * symmetry_factor * 1e-3) for t, p in ohmic]),
    color="r",
    marker=".",
    linestyle="-",
    label="$\\mu$fem",
)
plt.xlabel("Time t [s]")
plt.ylabel("Ohmic Heating [kW]")
plt.xlim(0, 80)
plt.legend(loc="best").set_frame_on(False)
plt.savefig("results/Ohmic_Heating.png", bbox_inches="tight")

# Temperature evolution at centre and surface ------------------------------------------
for probe_name, reference_file, output in [
    ("Center", "Fig8a_Temperature_vs_Time_0cm.csv", "results/Temperature_Center.png"),
    ("Surface", "Fig8a_Temperature_vs_Time_3cm.csv", "results/Temperature_Surface.png"),
]:
    values = sim.get_monitor_manager().get_monitor(probe_name).get_values()
    temperature = [(t, T - 273.15) for t, T in values]
    ref_t, ref_T = load_csv(reference_file).T

    plt.clf()
    plt.plot(ref_t, ref_T, "ko", label="Di Barba (2018)")
    plt.plot(
        *zip(*temperature),
        color="r",
        marker=".",
        linestyle="-",
        label="$\\mu$fem",
    )
    plt.xlabel("Time [s]")
    plt.ylabel("Temperature [°C]")
    plt.xlim(0, 100)
    plt.legend(loc="best").set_frame_on(False)
    plt.savefig(output, bbox_inches="tight")
