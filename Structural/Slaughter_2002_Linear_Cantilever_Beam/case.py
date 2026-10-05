from casekit import PlotStyle, ValidationCase, expect, xy_plot

import numpy

import mufem
from mufem import Bnd, Vol
from mufem.structural import (
    FixedDisplacementBoundaryCondition,
    LinearElasticMaterial,
    StructuralModel,
    TractionBoundaryCondition,
)


class Slaughter2002CantileverBeam(ValidationCase):
    name = "Slaughter 2002: Linear Cantilever Beam"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import Box, Glue, X

        from casekit.netgen_geometry import color_iron, name_body

        # Length 1.0 m, height 0.1 m, width 0.2 m.
        beam_body = Box((0.0, -0.05, -0.1), (1.0, 0.05, 0.10))

        name_body(beam_body, "Beam", color=color_iron, individual_names=False)

        beam_body.faces.Min(X).name = "Beam::Clamped"  # x = 0
        beam_body.faces.Max(X).name = "Beam::Loaded"  # x = L

        geometry = Glue([beam_body])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=5.0e-2, path=self.mesh_path)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        runner = mufem.SteadyRunner(total_iterations=1)
        sim.set_runner(runner)

        # Model ------------------------------------------------------------------------
        model = StructuralModel(order=2)
        sim.get_model_manager().add_model(model)

        # Materials --------------------------------------------------------------------
        material = LinearElasticMaterial(
            name="Steel",
            marker=Vol.Everywhere,
            youngs_modulus=210.0e6,
            poissons_ratio=0.3,
        )
        model.add_materials([material])

        # Boundary conditions ----------------------------------------------------------
        fixed_cond = FixedDisplacementBoundaryCondition(
            name="Clamped",
            marker="Beam::Clamped" @ Bnd,
        )

        traction_cond = TractionBoundaryCondition(
            name="Load",
            marker="Beam::Loaded" @ Bnd,
            traction=(0.0, -1000.0, 0.0),
        )

        model.add_conditions([fixed_cond, traction_cond])

        return sim

    def validate(self):
        # Displacement along the beam axis.
        displacement_report = mufem.ProbeReport.Line(
            name="DisplacementReport",
            cff_name="Displacement",
            start=(0.0, 0.0, 0.0),
            end=(1.0, 0.0, 0.0),
            number_points=30,
        )
        self.displacement = [(p.x, d.y) for p, d in displacement_report.evaluate_all()]

        # Von Mises stress along the top fiber.
        vm_stress_report = mufem.ProbeReport.Line(
            name="VonMisesStressReport",
            cff_name="Von Mises Stress",
            start=(0.0, 0.0499, 0.0),
            end=(1.0, 0.0499, 0.0),
            number_points=30,
        )
        self.vm_stress = [(p.x, s) for p, s in vm_stress_report.evaluate_all()]

        # Euler-Bernoulli: tip deflection F L^3 / (3 E I) and top-fiber stress
        # F (L - x) (h / 2) / I, with F = 20 N, L = 1 m, h = 0.1 m, I = 1/60000 m^4.
        # The 3D solid is about 1% stiffer than the beam theory at the tip.
        expect(
            self.displacement[-1][1],
            -1.9047619e-3,
            rel_tol=2e-2,
            label="tip displacement [m]",
        )
        x_mid, stress_mid = self.vm_stress[15]
        expect(
            stress_mid,
            60000.0 * (1.0 - x_mid),
            rel_tol=1e-2,
            label=f"von Mises stress at x = {x_mid:.3f} m [Pa]",
        )

    def postprocess(self):
        if self.is_main():
            ref_disp_x, ref_disp_y = numpy.loadtxt(
                self.dir_path / "data" / "Displacement_vs_Position.csv",
                delimiter=",",
                unpack=True,
            )

            xy_plot(
                values=self.displacement,
                yscale=1e3,
                style=PlotStyle.LINE_AND_POINTS,
                reference_values=list(zip(ref_disp_x, ref_disp_y * 1e3)),
                reference_style=PlotStyle.LINE,
                reference_label="Slaughter (2002)",
                xlabel="Position [m]",
                ylabel="Displacement [mm]",
                xlim=(0.0, 1.0),
                path=f"{self.results_path / 'Displacement_vs_Position.png'}",
            )

            ref_vm_x, ref_vm_y = numpy.loadtxt(
                self.dir_path / "data" / "Von_Mises_Stress_vs_Position.csv",
                delimiter=",",
                unpack=True,
            )

            xy_plot(
                values=self.vm_stress,
                yscale=1e-3,
                style=PlotStyle.LINE_AND_POINTS,
                reference_values=list(zip(ref_vm_x, ref_vm_y * 1e-3)),
                reference_style=PlotStyle.LINE,
                reference_label="Slaughter (2002)",
                xlabel="Position [m]",
                ylabel="Stress [kPa]",
                xlim=(0.0, 1.0),
                path=f"{self.results_path / 'Von_Mises_Stress_vs_Position.png'}",
            )

        # ParaView export (collective) ------------------------------------------------
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Displacement")
        vis.add_field_output("Von Mises Stress")
        vis.save(order=1)


if __name__ == "__main__":
    Slaughter2002CantileverBeam().run()
