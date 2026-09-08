import math

import matplotlib.pyplot as plt
import numpy

import mufem
from mufem import Vol
from mufem.methods import TemperatureTable
from mufem.thermal import (
    SolidTemperatureMaterial,
    SolidTemperatureModel,
    VolumetricHeatSourceCondition,
)


def make_goldak_double_ellipsoid(
    *,
    Q: float,
    v: float,
    tau: float,
    a: float,
    b: float,
    c_f: float,
    c_r: float,
    f_f: float,
    f_r: float,
    x0: float = 0.0,
    y0: float = 0.0,
    z0: float = 0.0,
):
    """Goldak double-ellipsoidal moving heat source as a μfem coefficient expression."""

    def pre(f, c):
        return (6.0 * math.sqrt(3.0) * f * Q) / (
            a * b * c * math.pi * math.sqrt(math.pi)
        )

    expr = f"""
    var x_ := {{Position}}.X - {x0};
    var y_ := {{Position}}.Y - {y0};
    var z_ := {{Position}}.Z - {z0};

    var xi := z_ - {v} * ({{Time}} - {tau});

    var front := {pre(f_f, c_f)} * exp( -3*x_^2/{a}^2 - 3*y_^2/{b}^2 - 3*xi^2/{c_f}^2 );
    var rear  := {pre(f_r, c_r)} * exp( -3*x_^2/{a}^2 - 3*y_^2/{b}^2 - 3*xi^2/{c_r}^2 );

    if (xi >= 0, front, rear)
    """

    return mufem.CffExpressionScalar(expr)


# Problem setup ------------------------------------------------------------------------
sim = mufem.Simulation.New(
    name="Goldak 1984: Welding Heat Source",
    mesh_path="geometry.mesh",
)

runner = mufem.UnsteadyRunner(
    total_time=21.5,
    time_step_size=0.25,
    total_inner_iterations=10,
)
sim.set_runner(runner)

# Model --------------------------------------------------------------------------------
model = SolidTemperatureModel(order=2)
sim.get_model_manager().add_model(model)
model.get_initial_condition().set_constant(293.15)

# Materials (temperature-dependent) ----------------------------------------------------
thermal_conductivity_table = numpy.loadtxt(
    "data/Thermal_Conductivity.csv", delimiter=","
)
volumetric_heat_capacity_table = numpy.loadtxt(
    "data/Volumetric_Heat_Capacity.csv", delimiter=","
)

# Convert volumetric to specific heat capacity: [J/mm^3/K] / [kg/mm^3] = [J/kg/K]
to_specific_heat_capacity = 1.0 / 7.850e-6

steel = SolidTemperatureMaterial(
    name="Steel",
    marker="Piece" @ Vol,
    thermal_conductivity=TemperatureTable(
        thermal_conductivity_table[:, 0] + 273.15,
        thermal_conductivity_table[:, 1],
    ),
    specific_heat_capacity=TemperatureTable(
        volumetric_heat_capacity_table[:, 0] + 273.15,
        volumetric_heat_capacity_table[:, 1] * to_specific_heat_capacity,
    ),
    density=7850.0,
)
model.add_materials([steel])

# Conditions ---------------------------------------------------------------------------
# Goldak source parameters from Table 2 of [1].
cff_q = make_goldak_double_ellipsoid(
    Q=36538.35,
    v=5.0e-3,
    tau=0.0,
    a=0.02,
    b=0.02,
    c_f=0.015,
    c_r=0.030,
    f_f=0.6,
    f_r=1.4,
    z0=0.1,
)
sim.get_coefficient_manager().register_user("VolumetricHeatSource", cff_q)

heat_source_condition = VolumetricHeatSourceCondition(
    name="Goldak Heat Source",
    marker="Piece" @ Vol,
    heat_power_density=cff_q,
)

# Latent heat of fusion via a mushy-zone (enthalpy) formulation.
mushy_zone_condition = mufem.thermal.MushyZoneCondition(
    name="Fusion latent heat",
    marker="Piece" @ Vol,
    latent_heat=2.1e9 / 7850.0,  # [J/kg] = [J/m^3] / [kg/m^3]
    temperature_solidus=1480.0 - 50.0 + 273.15,
    temperature_liquidus=1480.0 + 50.0 + 273.15,
)

# Radiative/convective loss on the top surface.
heat_flux_condition = mufem.thermal.HeatFluxBoundaryCondition(
    name="Convective Loss",
    marker="Piece::Top" @ mufem.Bnd,
    normal_heat_flux="-24.1e-4 * 0.9 * max({Temperature} - 293.15, 0.0)^1.61",
    normal_heat_flux_linearization="-24.1e-4 * 0.9 * 1.61 * max({Temperature} - 293.15, 0.0)^0.61",
)

model.add_conditions([heat_source_condition, mushy_zone_condition, heat_flux_condition])

# Run the simulation -------------------------------------------------------------------
vis = sim.get_field_exporter()
vis.add_field_output("Temperature")
vis.add_field_output("VolumetricHeatSource")

runner.run()
vis.save(order=2)

# Temperature across the weld at the measuring line z = 0.15 m --------------------------
probe_report = mufem.ProbeReport.Line(
    name="T",
    cff_name="Temperature",
    start=(0.0, 0.0, 0.15),
    end=(0.03, 0.0, 0.15),
    number_points=101,
)
temperature = [(p.x, T - 273.15) for p, T in probe_report.evaluate_all()]  # K -> °C

ref_x, ref_T = numpy.loadtxt(
    "data/Temperature_vs_Position.csv", delimiter=",", unpack=True
)

plt.clf()
plt.plot(ref_x * 1e3, ref_T, "k-", label="Goldak (1984)", linewidth=2.5)
plt.plot(
    *zip(*[(x * 1e3, T) for x, T in temperature]),
    color="r",
    marker=".",
    linestyle="-",
    label="$\\mu$fem",
    markersize=6,
)
plt.xlabel("Position [mm]")
plt.ylabel("Temperature [°C]")
plt.legend(loc="best").set_frame_on(False)
plt.savefig("results/Temperature_vs_Position.png", bbox_inches="tight")
