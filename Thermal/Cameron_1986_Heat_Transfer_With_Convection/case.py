import mufem
from mufem import Bnd, Vol
from mufem.thermal import (
    AdiabaticBoundaryCondition,
    ConvectionBoundaryCondition,
    SolidTemperatureMaterial,
    SolidTemperatureModel,
    TemperatureCondition,
)

from validation_case import ValidationCase
from plots import xy_plot, PlotStyle


class Cameron1986(ValidationCase):
    name = "Cameron 1986: Heat Transfer With Convection"
    tags = {"moderate"}

    def build(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.dir_path}/geometry.mesh",
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
        bc_Adiabatic = AdiabaticBoundaryCondition(
            name="Insulated",
            marker="Plate::Insulated" @ Bnd,
        )

        bc_TAmbient = ConvectionBoundaryCondition(
            name="Natural Convection",
            marker="Plate::AmbientTemperature" @ Bnd,
            convection_efficiency=750.0,
            temperature_medium=273.15,
        )

        bc_TFixed = TemperatureCondition(
            name="Fixed Temperature",
            marker="Plate::FixedTemperature" @ Bnd,
            temperature=373.15,
        )

        model.add_conditions([bc_TFixed, bc_TAmbient, bc_Adiabatic])

        return sim

    def validate(self, sim):
        # NAFEMS T4 reference temperature on the right edge, 0.2 m above the bottom.
        report = mufem.ProbeReport.SinglePoint(
            name="TemperatureReport",
            cff_name="Temperature",
            x=0.6,
            y=0.2,
            z=0.005,
        )
        self.expect(report.evaluate(), 291.45, rel_tol=1e-3, label="probe temperature [K]")

        # Temperature profile along y = 0.5, checked against the stored baseline.
        profile = mufem.ProbeReport.Line(
            name="Probe Report",
            cff_name="Temperature",
            start=(0.0, 0.5, 0.005),
            end=(0.6, 0.5, 0.005),
            number_points=23,
        )
        self.temperature_profile = [(p.x, T) for p, T in profile.evaluate_all()]
        self.expect_baseline(
            sim,
            "Temperature",
            self.temperature_profile,
            header="Position [m], Temperature [K]",
        )

    def visualize(self, sim):
        if self.is_main(sim):
            xy_plot(
                values=self.temperature_profile,
                style=PlotStyle.LINE_AND_POINTS,
                xlabel="Position [m]",
                ylabel="Temperature [K]",
                path=f"{self.results_path}/Temperature.png",
            )

        # ParaView export (collective) ------------------------------------------------
        vis = sim.get_field_exporter()
        vis.add_field_output("Temperature")
        vis.save()


if __name__ == "__main__":
    Cameron1986().run()
