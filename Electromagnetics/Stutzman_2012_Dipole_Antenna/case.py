import numpy as np

import mufem
from mufem import Bnd, Vol
from mufem.electromagnetics.timeharmonicmaxwell import (
    AbsorbingBoundaryCondition,
    FarFieldRadiationSensor,
    LumpedPortCondition,
    PerfectElectricConductorCondition,
    TimeHarmonicMaxwellGeneralMaterial,
    TimeHarmonicMaxwellModel,
)

# **************************************************************************************
# Problem setup
# **************************************************************************************
sim = mufem.Simulation.New(
    name="Stutzman 2012: Dipole Antenna",
    mesh_path="geometry.msh",
)

runner = mufem.SteadyRunner(total_iterations=1)
sim.set_runner(runner)


# **************************************************************************************
# Model
# **************************************************************************************
model = TimeHarmonicMaxwellModel(
    frequency=0.0749e9,  # [Hz]
    order=2,  # finite element polynomial degree
)
sim.get_model_manager().add_model(model)


# **************************************************************************************
# Materials
# **************************************************************************************
material = TimeHarmonicMaxwellGeneralMaterial.Constant(
    name="Air",
    marker="Domain" @ Vol,
)
model.add_material(material)


# **************************************************************************************
# Boundary conditions
# **************************************************************************************
condition_outer = AbsorbingBoundaryCondition(
    name="AirBoundary", marker="BoundaryOuter" @ Bnd
)

condition_arms = PerfectElectricConductorCondition(
    name="PEC",
    marker=["BoundaryTopArm", "BoundaryBotArm"] @ Bnd,
)

w = 0.10  # [m] port width
length = 0.04  # [m] port length
R = 50  # [Ohm] transmission line resistance
Z = R  # [Ohm] transmission line impedance: 1/Z = 1/R + 1/(j*w*L) + j*w*C
Zs = Z * w / length  # [Ohm] surface impedance
condition_port = LumpedPortCondition(
    name="Port",
    marker="Port" @ Bnd,
    surface_impedance=Zs,
    incident_electric_field_vector=(0, 0, 1),
)

model.add_conditions([condition_outer, condition_arms, condition_port])


# **************************************************************************************
# Run the simulation
# **************************************************************************************
sim.run()

# Export ParaView data:
vis = sim.get_field_exporter()
vis.add_field_output("Electric Field-Real")
vis.add_field_output("Electric Field-Imag")
vis.add_field_output("Magnetic Field-Real")
vis.add_field_output("Magnetic Field-Imag")
vis.save(order=2)


# **************************************************************************************
# Export 3D far-field radiation pattern
# **************************************************************************************
if sim.get_machine().is_main_process():
    print("\nExport 3D far-field radiation pattern...")

sensor = FarFieldRadiationSensor(
    "FarFieldRadiationSensor",
    polar_start=0.0,
    polar_stop=180.0,
    polar_step=6.0,
    azimuthal_start=0.0,
    azimuthal_stop=360.0,
    azimuthal_step=6.0,
)
thetas = np.array(sensor.get_polar_angles())
phis = np.array(sensor.get_azimuthal_angles())
radiation_pattern = np.array(sensor.get_radiation_pattern())
radiation_pattern = radiation_pattern / np.max(radiation_pattern)

np.savez(
    "results/Far_Field_3D.npz",
    thetas=thetas,
    phis=phis,
    radiation_pattern=radiation_pattern,
)
