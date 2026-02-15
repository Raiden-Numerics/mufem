import mufem
from mufem.electromagnetics.coil import (
    CoilExcitationCurrent,
    CoilSpecification,
    CoilTopologyClosed,
    CoilTypeStranded,
    ExcitationCoilModel,
)
from mufem.electromagnetics.timeharmonicmagnetic import (
    TimeHarmonicMagneticGeneralMaterial,
    TimeHarmonicMagneticModel,
)

from mufem import Vol

import matplotlib.pyplot as plt
import numpy
from pathlib import Path

dir_path = Path(__file__).resolve().parent


sim = mufem.Simulation.New(name="Team-7", mesh_path=f"{dir_path}/geometry.mesh")

# Setup Problem
steady_runner = mufem.SteadyRunner(total_iterations=1)
sim.set_runner(steady_runner)

magnetic_model = TimeHarmonicMagneticModel(Vol.Everywhere, frequency=50, order=3)
sim.get_model_manager().add_model(magnetic_model)

# Define the materials
air_material = TimeHarmonicMagneticGeneralMaterial(
    name="Air", marker="Air" @ Vol, has_eddy_currents=False
)

copper_material = TimeHarmonicMagneticGeneralMaterial(
    name="Copper", marker="Coil" @ Vol, has_eddy_currents=False
)

alu_material = TimeHarmonicMagneticGeneralMaterial(
    name="Alu",
    marker="Plate" @ Vol,
    magnetic_permeability=1.0,
    electric_conductivity=3.526e7,
)

magnetic_model.add_materials([air_material, copper_material, alu_material])

# Coil
coil_model = ExcitationCoilModel()
sim.get_model_manager().add_model(coil_model)

coil_topology = CoilTopologyClosed(x=0.2, y=0.01, z=0.07, dx=1.0, dy=0.0, dz=0.0)
coil_type = CoilTypeStranded(number_of_turns=2742)
coil_excitation = CoilExcitationCurrent.Harmonic(current_magnitude=1.0, current_phase=0)

coil = CoilSpecification(
    name="Coil",
    marker="Coil" @ Vol,
    topology=coil_topology,
    type=coil_type,
    excitation=coil_excitation,
)
coil_model.add_coil_specification(coil)

# Run the code and output fields

sim.run()

vis = sim.get_field_exporter()

vis.add_field_output("Magnetic Flux Density-Real")
vis.add_field_output("Magnetic Flux Density-Imag")
vis.add_field_output("Electric Current Density-Real")
vis.add_field_output("Electric Current Density-Imag")

vis.save(order=3)

# Post Process Results
probe_reports = [("A1-B1", 0.072), ("A2-B2", 0.144)]
x_values = numpy.linspace(start=0.0, stop=0.288, num=128)


for probe in probe_reports:

    b_values = []

    for x in x_values:

        magnetic_flux_density_real_report = mufem.ProbeReport.SinglePoint(
            name="MagneticFluxDensityRealReport",
            cff_name="Magnetic Flux Density-Real",
            x=x,
            y=probe[1],
            z=0.034,
        )

        magnetic_flux_density_imag_report = mufem.ProbeReport.SinglePoint(
            name="MagneticFluxDensityImagReport",
            cff_name="Magnetic Flux Density-Imag",
            x=x,
            y=probe[1],
            z=0.034,
        )

        b_real = magnetic_flux_density_real_report.evaluate()
        b_imag = magnetic_flux_density_imag_report.evaluate()

        # We multiply by 1e3 to convert from T to mT
        # and by 1e3 to convert from m to mm
        b_values.append((1e3 * x, 1e3 * (-b_real.z + 1j * b_imag.z)))

    # Plot
    # flake8: noqa: FKA100

    plt.clf()

    ref = numpy.loadtxt(
        f"{dir_path}/data/Bz_{probe[0]}.csv", delimiter=",", comments="#"
    )

    plt.plot(
        ref[:, 1],
        1.0e-1 * ref[:, 2],
        "ko-",
        markersize=6.0,
        linewidth=2.0,
    )
    plt.plot(
        ref[:, 1],
        1.0e-1 * ref[:, 3],
        "ko-",
        label="Reference",
        markersize=6.0,
        linewidth=2.0,
    )

    plt.plot(
        [x_value for x_value, _ in b_values],
        [numpy.real(b_value) for _, b_value in b_values],
        label=f"$\\mu$fem (Real)",
        color="r",
        linewidth=3.0,
    )

    plt.plot(
        [x_value for x_value, _ in b_values],
        [numpy.imag(b_value) for _, b_value in b_values],
        label=f"$\\mu$fem (Imag)",
        color="b",
        linewidth=3.0,
    )

    plt.xlabel("Position [mm]")
    plt.ylabel("Magnetic Flux Density [mT]")
    plt.title(f"Magnetic Flux Density at {probe[0]}")

    plt.xlim((0, 288))
    plt.xticks([0, 72, 144, 216, 288])

    plt.legend(loc="best").draw_frame(False)

    plt.savefig(
        f"{dir_path}/results/Magnetic_Flux_Density-{probe[0]}.png",
        bbox_inches="tight",
    )

    numpy.savetxt(
        f"{dir_path}/results/Bz_{probe[0]}_mufem.csv",
        numpy.c_[
            [x for x, _ in b_values],
            [v.real for _, v in b_values],
            [v.imag for _, v in b_values],
        ],
        delimiter=",",
        header="x [mm], Bz [mT]",
    )
