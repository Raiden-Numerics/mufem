from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot

import mufem
from mufem import Bnd, Vol
from mufem.thermal import (
    AdiabaticBoundaryCondition,
    ConvectionBoundaryCondition,
    SolidTemperatureMaterial,
    SolidTemperatureModel,
    TemperatureCondition,
)


class Cameron1986(ValidationCase):
    name = "Cameron 1986: Heat Transfer With Convection"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import Box, Glue, X, Y

        from casekit.netgen_geometry import color_nice_green, name_body

        plate_body = Box((0, 0, 0), (0.6, 1.0, 0.01))

        name_body(plate_body, "Plate", color=color_nice_green)

        plate_body.faces.Min(X).name = "Plate::Insulated"
        plate_body.faces.Max(X).name = "Plate::AmbientTemperature"

        plate_body.faces.Min(Y).name = "Plate::FixedTemperature"
        plate_body.faces.Max(Y).name = "Plate::AmbientTemperature"

        geometry = Glue([plate_body])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=0.02, path=self.mesh_path)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        runner = mufem.SteadyRunner(total_iterations=3)
        sim.set_runner(runner)

        # Model ------------------------------------------------------------------------
        model = SolidTemperatureModel(marker="Plate" @ Vol)
        sim.get_model_manager().add_model(model)

        # Materials --------------------------------------------------------------------
        material = SolidTemperatureMaterial(
            name="Material",
            marker="Plate" @ Vol,
            thermal_conductivity=52.0,
            specific_heat_capacity=1.0,
            density=1.0,
        )
        model.add_material(material)

        # Boundary conditions ----------------------------------------------------------
        bc_adiabatic = AdiabaticBoundaryCondition(
            name="Insulated",
            marker="Plate::Insulated" @ Bnd,
        )

        bc_ambient = ConvectionBoundaryCondition(
            name="Natural Convection",
            marker="Plate::AmbientTemperature" @ Bnd,
            convection_efficiency=750.0,
            temperature_medium=273.15,
        )

        bc_fixed = TemperatureCondition(
            name="Fixed Temperature",
            marker="Plate::FixedTemperature" @ Bnd,
            temperature=373.15,
        )

        model.add_conditions([bc_fixed, bc_ambient, bc_adiabatic])

        return sim

    def validate(self):
        # NAFEMS T4 target temperature at point E on the right edge, 0.2 m above the bottom
        # (Cameron et al. (1986)).
        report = mufem.ProbeReport.SinglePoint(
            name="TemperatureReport",
            cff_name="Temperature",
            x=0.6,
            y=0.2,
            z=0.005,
        )
        expect(report.evaluate() - 273.15, 18.3, rel_tol=1e-2, label="temperature at point E [°C]")

        # Temperature profile along y = 0.5 m for the plot.
        profile = mufem.ProbeReport.Line(
            name="Probe Report",
            cff_name="Temperature",
            start=(0.0, 0.5, 0.005),
            end=(0.6, 0.5, 0.005),
            number_points=23,
        )
        self.temperature_profile = [(p.x, T - 273.15) for p, T in profile.evaluate_all()]

    def postprocess(self):
        if self.is_main():
            xy_plot(
                values=self.temperature_profile,
                style=PlotStyle.LINE_AND_POINTS,
                xlabel="Position [m]",
                ylabel="Temperature [°C]",
                path=f"{self.results_path}/Temperature.png",
            )

        # ParaView export (collective) ------------------------------------------------
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Temperature")
        vis.save()


if __name__ == "__main__":
    run_case(Cameron1986)
