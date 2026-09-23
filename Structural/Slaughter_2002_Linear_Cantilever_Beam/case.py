import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root: validation_case

import numpy

import mufem

from plots import xy_plot, PlotStyle
from mufem import Vol
from mufem.structural import (
    FixedDisplacementBoundaryCondition,
    LinearElasticMaterial,
    StructuralModel,
    TractionBoundaryCondition,
)

# Problem setup ------------------------------------------------------------------------
from validation_case import ValidationCase


class Slaughter2002CantileverBeam(ValidationCase):
    tags = {"moderate"}

    def run(self):
        sim = mufem.Simulation.New(
            name="Slaughter 2002: Linear Cantilever Beam",
            mesh_path="geometry.mesh",
        )

        runner = mufem.SteadyRunner(total_iterations=1)
        sim.set_runner(runner)

        # Model --------------------------------------------------------------------------------
        model = StructuralModel(order=2)
        sim.get_model_manager().add_model(model)

        # Materials ----------------------------------------------------------------------------
        material = LinearElasticMaterial(
            name="Steel",
            marker=Vol.Everywhere,
            youngs_modulus=210.0e6,
            poissons_ratio=0.3,
        )
        model.add_materials([material])

        # Boundary conditions ------------------------------------------------------------------
        fixed_cond = FixedDisplacementBoundaryCondition(
            name="Clamped",
            marker="Beam::Clamped" @ mufem.Bnd,
        )

        traction_cond = TractionBoundaryCondition(
            name="Load",
            marker="Beam::Loaded" @ mufem.Bnd,
            traction=(0.0, -1000.0, 0.0),
        )

        model.add_conditions([fixed_cond, traction_cond])

        # Run the simulation -------------------------------------------------------------------
        sim.run()

        # Displacement along the beam axis -----------------------------------------------------
        displacement_report = mufem.ProbeReport.Line(
            name="DisplacementReport",
            cff_name="Displacement",
            start=(0.0, 0.0, 0.0),
            end=(1.0, 0.0, 0.0),
            number_points=30,
        )
        displacement = [(p.x, d.y) for p, d in displacement_report.evaluate_all()]

        ref_disp_x, ref_disp_y = numpy.loadtxt(
            "data/Displacement_vs_Position.csv", delimiter=",", unpack=True
        )

        xy_plot(
            values=displacement,
            yscale=1e3,
            style=PlotStyle.LINE_AND_POINTS,
            reference_values=list(zip(ref_disp_x, ref_disp_y * 1e3)),
            reference_style=PlotStyle.LINE,
            reference_label="Slaughter (2002)",
            xlabel="Position [m]",
            ylabel="Displacement [mm]",
            xlim=(0.0, 1.0),
            path="results/Displacement_vs_Position.png",
        )

        # Von Mises stress along the beam ------------------------------------------------------
        vm_stress_report = mufem.ProbeReport.Line(
            name="VonMisesStressReport",
            cff_name="Von Mises Stress",
            start=(0.0, 0.0499, 0.0),
            end=(1.0, 0.0499, 0.0),
            number_points=30,
        )
        vm_stress = [(p.x, s) for p, s in vm_stress_report.evaluate_all()]

        ref_vm_x, ref_vm_y = numpy.loadtxt(
            "data/Von_Mises_Stress_vs_Position.csv", delimiter=",", unpack=True
        )

        xy_plot(
            values=vm_stress,
            yscale=1e-3,
            style=PlotStyle.LINE_AND_POINTS,
            reference_values=list(zip(ref_vm_x, ref_vm_y * 1e-3)),
            reference_style=PlotStyle.LINE,
            reference_label="Slaughter (2002)",
            xlabel="Position [m]",
            ylabel="Stress [kPa]",
            xlim=(0.0, 1.0),
            path="results/Von_Mises_Stress_vs_Position.png",
        )

        # Export ParaView data -----------------------------------------------------------------
        vis = sim.get_field_exporter()
        vis.add_field_output("Displacement")
        vis.add_field_output("Von Mises Stress")
        vis.save(order=1)


if __name__ == "__main__":
    Slaughter2002CantileverBeam().run()
