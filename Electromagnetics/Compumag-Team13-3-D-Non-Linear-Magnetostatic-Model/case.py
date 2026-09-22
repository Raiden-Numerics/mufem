import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root: validation_case

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
)

from pathlib import Path
from plots import xy_plot, PlotStyle

dir_path = Path(__file__).resolve().parent


from validation_case import ValidationCase


class Team13NonLinearMagnetostatic(ValidationCase):
    tags = {"moderate"}

    def run(self):
        sim = mufem.Simulation.New(name="Team-13", mesh_path=f"{dir_path}/geometry.mesh")

        # Setup Problem
        steady_runner = mufem.SteadyRunner(total_iterations=12)
        sim.set_runner(steady_runner)

        magnetic_model = TimeDomainMagneticModel(order=2)
        sim.get_model_manager().add_model(magnetic_model)

        line_search = magnetic_model.get_solver().get_line_search()
        line_search.set_active(True)
        line_search.set_iteration_window(min_iter=0, max_iter=6)

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
            electric_conductivity=0.0,
        )
        magnetic_model.add_materials([air_material, copper_material, iron_material])

        # Coil
        coil_model = ExcitationCoilModel()
        sim.get_model_manager().add_model(coil_model)

        coil_topology = CoilTopologyClosed(x=0.09, y=0.0, z=0.001, dx=0.0, dy=1.0, dz=0.0)
        coil_type = CoilTypeStranded(number_of_turns=500)

        coil_excitation = CoilExcitationCurrent(current=3.0)

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

        probe_report = mufem.ProbeReport.Line(
            "B",
            "Magnetic Flux Density",
            start=(0.01, 0.02, 0.055),
            end=(0.11, 0.02, 0.055),
            number_points=23,
        )

        xy_values = [(p.x, v.mag) for p, v in probe_report.evaluate_all()]

        xy_plot(
            values=xy_values,
            xscale=1000.0,  # m -> mm
            yscale=1000.0,  # T -> mT
            style=PlotStyle.LINE_AND_POINTS,
            reference_file=f"{dir_path}/data/Table7_FluxDensity.csv",
            reference_xscale=1000.0,
            reference_yscale=1000.0,
            reference_style=PlotStyle.POINTS,
            reference_label="Nakata & Fujiwara (1992)",
            xlabel="x [mm]",
            ylabel="B [mT]",
            xlim=(0.0, 120.0),
            path=f"{dir_path}/results/Magnetic_Flux_Density_Line_Air.png",
        )


if __name__ == "__main__":
    Team13NonLinearMagnetostatic().run()
