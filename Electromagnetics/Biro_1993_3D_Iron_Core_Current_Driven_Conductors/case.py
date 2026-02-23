import numpy

import mufem


from mufem.electromagnetics.timeharmonicmagnetic import (
    TimeHarmonicMagneticGeneralMaterial,
    TimeHarmonicMagneticModel,
    TangentialMagneticFluxBoundaryCondition,
)

from mufem.electromagnetics.coil import (
    CoilSpecification,
    CoilTopologyOpen,
    ExcitationCoilModel,
    CoilExcitationCurrent,
    CoilTypeSolid,
)

from mufem import Vol, Bnd


from pathlib import Path

dir_path = Path(__file__).resolve().parent


sim = mufem.Simulation.New(
    name="Biro 1993: 3D Iron Core Current Driven Conductors",
    mesh_path=f"{dir_path}/geometry.mesh",
)


is_main_process = sim.get_machine().is_main_process()

# Setup Problem
steady_runner = mufem.SteadyRunner(total_iterations=1)
sim.set_runner(steady_runner)

# Magnetic Model
magnetic_model = TimeHarmonicMagneticModel(Vol.Everywhere, 5000, 2)
sim.get_model_manager().add_model(magnetic_model)

magnetic_solver = magnetic_model.get_solver()
magnetic_solver.set_verbose(True)
magnetic_solver.set_iteration_number(150)
magnetic_solver.set_tolerance_threshold(1.0e-6)

# Material

air_material = TimeHarmonicMagneticGeneralMaterial(
    "Air", "Air" @ Vol, has_eddy_currents=False
)

core_material = TimeHarmonicMagneticGeneralMaterial(
    "Iron",
    Vol("Core.*"),
    magnetic_permeability=1000.0,
    has_eddy_currents=False,
)

copper_material = TimeHarmonicMagneticGeneralMaterial(
    "Copper",
    Vol("Coil.*"),
    electric_conductivity=5.6e7,
    has_eddy_currents=True,
)

magnetic_model.add_materials([air_material, core_material, copper_material])

# Boundaries
tangential_magnetic_flux_bc = TangentialMagneticFluxBoundaryCondition(
    "Tangential Flux",
    Bnd(".*Front") + Bnd(".*Back") + "Air::TangentialFlux" @ Bnd,
)

magnetic_model.add_condition(tangential_magnetic_flux_bc)

# Coil
coil_model = ExcitationCoilModel()
sim.get_model_manager().add_model(coil_model)

for n in range(25):

    coil_topology = CoilTopologyOpen(
        f"Coil {n+1}::Back" @ Bnd, f"Coil {n+1}::Front" @ Bnd
    )
    coil_type = CoilTypeSolid()
    # @todo: should be in constructor
    coil_type.drive_method = CoilTypeSolid.DriveMethod.Source

    coil_excitation = CoilExcitationCurrent.Harmonic(
        current_magnitude=10, current_phase=0.0
    )

    coil = CoilSpecification(
        f"Coil {n+1}",
        Vol(f"Coil {n+1}"),
        coil_topology,
        coil_type,
        coil_excitation,
    )
    coil_model.add_coil_specification(coil)


sim.run()


vis = sim.get_field_exporter()
vis.add_field_output("Magnetic Flux Density-Real")
vis.add_field_output("Magnetic Flux Density-Imag")
vis.add_field_output("Electric Current Density-Real")
vis.add_field_output("Electric Current Density-Imag")

vis.save(order=2)


# Compare with reference

reference = numpy.loadtxt(f"{dir_path}/data/Ohmic_Loss.csv", delimiter=",", unpack=True)

for n in range(25):

    report = mufem.VolumeIntegralReport(
        "Ohmic Heating", f"Coil {n+1}" @ Vol, "Ohmic Heating"
    )

    report_value = report.evaluate() * 4  # due to symmetry

    reference_value = reference[2, n]  # 0-based index, column 3 in file

    if is_main_process:
        print(
            f"Coil {n+1}: Ohmic Heating = {report_value:.4f} W, "
            f"Reference = {reference_value:.4f} W"
        )
