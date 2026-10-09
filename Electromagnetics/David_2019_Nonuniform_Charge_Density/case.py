from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot

import math

import numpy as np

import mufem
import mufem.electromagnetics.electrostatics as estat


class David2019ChargeDensity(ValidationCase):
    name = "David 2019: Nonuniform Charge Density"
    tags = {"moderate"}

    # [m] radius of the spherical domain, large enough to approximate free space
    sphere_radius = 10.0
    # Gaussian charge density Q / (4 pi) exp(-r^2 / (2 a^2)): amplitude Q [C/m^3] and
    # radius a [m]; the total charge is sqrt(pi / 2) a^3 Q.
    charge = 1.0
    charge_radius = 0.5

    def build_geometry(self):
        from netgen.occ import Glue, Pnt, Sphere

        from casekit.netgen_geometry import color_air, name_body

        domain = Sphere(Pnt(0, 0, 0), self.sphere_radius)
        name_body(domain, "Domain", color=color_air, individual_names=False)

        geometry = Glue([domain])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=0.5, path=self.mesh_path)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        runner = mufem.SteadyRunner(total_iterations=3)
        sim.set_runner(runner)

        # Model and material -----------------------------------------------------------
        domain_marker = "Domain" @ mufem.Vol

        model = estat.ElectrostaticsModel(order=2)
        sim.get_model_manager().add_model(model)

        material = estat.ElectrostaticMaterial(name="Air", marker=domain_marker)
        model.add_material(material)

        # Conditions -------------------------------------------------------------------
        charge_expr = f"""
            var r := sqrt({{Position}}.X^2 + {{Position}}.Y^2 + {{Position}}.Z^2);
            var Q := {self.charge};
            var a := {self.charge_radius};

            Q / (4 * pi) * exp(-r^2 / (2 * a^2))
        """

        charge_density_condition = estat.ChargeDensityCondition(
            name="Volume Charge", marker=domain_marker, charge_density=charge_expr
        )

        boundary_marker = "Domain::Boundary" @ mufem.Bnd
        potential_condition = estat.ElectricPotentialCondition(
            name="Potential = 0V", marker=boundary_marker, electric_potential=0
        )

        model.add_conditions([charge_density_condition, potential_condition])

        return sim

    def electric_field_theory(self, r):
        """Radial electric field of the Gaussian charge distribution from Gauss's law."""
        Q, a = self.charge, self.charge_radius

        eps0 = 8.8541878188e-12  # [F/m] vacuum permittivity
        factor = Q / (4 * np.pi * eps0 * r**2)
        term1 = np.sqrt(np.pi / 2) * a**3 * math.erf(r / (np.sqrt(2) * a))
        term2 = a**2 * r * np.exp(-(r**2) / (2 * a**2))
        return factor * (term1 - term2)

    def electric_field_x(self, x):
        report = mufem.ProbeReport.SinglePoint(
            name="Electric Field Report", cff_name="Electric Field", x=x, y=0, z=0
        )
        return report.evaluate().x

    def validate(self):
        # Electric field along the x-axis across the whole sphere.
        R = self.sphere_radius
        self.positions = np.linspace(-R + 0.01, R - 0.01, 500)
        self.e_mufem = [self.electric_field_x(x) for x in self.positions]

        # Near the maximum of the field and far outside the charge distribution. The
        # mesh size (0.5 m) equals the width a of the charge, which limits the accuracy
        # near the maximum to a few percent.
        for r in [1.0, 5.0]:
            expect(
                self.electric_field_x(r),
                self.electric_field_theory(r),
                rel_tol=5e-2,
                label=f"electric field at r = {r} m [V/m]",
            )

    def postprocess(self):
        if self.is_main():
            e_theory = [self.electric_field_theory(x) for x in self.positions]

            xy_plot(
                values=list(zip(self.positions, np.array(self.e_mufem) / 1e9)),
                style=PlotStyle.LINE_AND_POINTS,
                reference_values=list(zip(self.positions, np.array(e_theory) / 1e9)),
                reference_style=PlotStyle.LINE,
                reference_label="Theory",
                xlabel="Distance $r$ [m]",
                ylabel="Electric field $E$ [GV/m]",
                path=f"{self.results_path / 'Electric_Field.png'}",
            )

        # Export the electric field data to a VTK file (collective).
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Electric Field")
        vis.add_field_output("Electric Potential")
        vis.save(order=2)


if __name__ == "__main__":
    run_case(David2019ChargeDensity)
