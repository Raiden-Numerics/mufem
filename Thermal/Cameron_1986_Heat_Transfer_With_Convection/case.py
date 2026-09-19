import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root: validation_case

import matplotlib.pyplot as plt
import numpy

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
        report = mufem.ProbeReport.SinglePoint(
            name="TemperatureReport",
            cff_name="Temperature",
            x=0.6,
            y=0.2,
            z=0.005,
        )
        Tprobe = report.evaluate()
        self.expect(Tprobe, 291.45, rel_tol=1e-2, label="probe temperature [K]")

    def visualize(self, sim):
        # Temperature profile along y = 0.5. evaluate() is collective, so the
        # loop runs on all ranks; only the matplotlib write is main-rank-local.
        x_vals = numpy.linspace(0, 0.6, 23, endpoint=True)
        T_vals = []
        for x in x_vals:
            report = mufem.ProbeReport.SinglePoint(
                name="Probe Report",
                cff_name="Temperature",
                x=x,
                y=0.5,
                z=0.005,
            )
            T_vals.append(report.evaluate())

        if self.is_main(sim):
            plt.plot(x_vals, T_vals, color="red")
            plt.xlabel("Position [m]")
            plt.ylabel("Temperature [K]")
            plt.savefig("results/Temperature.png", bbox_inches="tight")

        # ParaView export (collective) ------------------------------------------------
        vis = sim.get_field_exporter()
        vis.add_field_output("Temperature")
        vis.save()


if __name__ == "__main__":
    Cameron1986().run()
