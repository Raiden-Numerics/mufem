import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root: validation_case

import numpy

import mufem
from mufem import Bnd, Vol
from mufem.thermal import (
    ConvectionBoundaryCondition,
    HeatFluxBoundaryCondition,
    SolidTemperatureMaterial,
    SolidTemperatureModel,
)

# Problem setup ------------------------------------------------------------------------
from validation_case import ValidationCase
from plots import xy_plot, PlotStyle


class Bruce2012ElectronicDesign(ValidationCase):
    tags = {"moderate"}

    def run(self):
        sim = mufem.Simulation.New(
            name="Bruce 2012: Heat Transfer in Electronic Design",
            mesh_path="geometry.mesh",
        )

        runner = mufem.UnsteadyRunner(
            total_time=10.0, time_step_size=0.1, total_inner_iterations=3
        )
        sim.set_runner(runner)

        # Model --------------------------------------------------------------------------------
        model = SolidTemperatureModel(
            marker=["Die", "TIM1", "Lid", "TIM2", "Heat Sink"] @ Vol,
        )
        sim.get_model_manager().add_model(model)
        model.get_initial_condition().set_constant(273.15)

        # Materials ----------------------------------------------------------------------------
        silicon_material = SolidTemperatureMaterial(
            name="Silicon",
            marker="Die" @ Vol,
            thermal_conductivity=111.0,
            specific_heat_capacity=668.0,
            density=2330,
        )
        ag_epoxy_material = SolidTemperatureMaterial(
            name="Ag-Epoxy",
            marker="TIM1" @ Vol,
            thermal_conductivity=2.0,
            specific_heat_capacity=400.0,
            density=4400,
        )
        copper_material = SolidTemperatureMaterial(
            name="Copper",
            marker=["Lid", "Heat Sink"] @ Vol,
            thermal_conductivity=390,
            specific_heat_capacity=385,
            density=8890,
        )
        alu_filler_material = SolidTemperatureMaterial(
            name="Grease Aluminium Filler Particle",
            marker="TIM2" @ Vol,
            thermal_conductivity=1.0,
            specific_heat_capacity=900,
            density=2500,
        )
        model.add_materials(
            [silicon_material, ag_epoxy_material, copper_material, alu_filler_material]
        )

        # Boundary conditions ------------------------------------------------------------------
        heat_flux_bc = HeatFluxBoundaryCondition(
            name="Heat Flux",
            marker="Die::SurfaceHeatFlux" @ Bnd,
            normal_heat_flux=5917.1598,
        )
        conv_flux_bc = ConvectionBoundaryCondition(
            name="Convective Heat Flux",
            marker="Heat Sink::ConvectiveHeatFlux" @ Bnd,
            convection_efficiency=20000.0,
            temperature_medium=273.15,
        )
        model.add_conditions([heat_flux_bc, conv_flux_bc])

        # Reports and monitors -----------------------------------------------------------------
        report_die = mufem.ProbeReport.SinglePoint(
            name="DieTemperatureReport", cff_name="Temperature", x=0.0, y=0.25e-3, z=0.0
        )
        sim.get_report_manager().add_report(report_die)
        monitor_die = mufem.ReportMonitor("Die Temperature Monitor", "DieTemperatureReport")
        sim.get_monitor_manager().add_monitor(monitor_die)

        report_lid = mufem.ProbeReport.SinglePoint(
            name="LidTemperatureReport", cff_name="Temperature", x=0.0, y=0.85e-3, z=0.0
        )
        sim.get_report_manager().add_report(report_lid)
        monitor_lid = mufem.ReportMonitor("Lid Temperature Monitor", "LidTemperatureReport")
        sim.get_monitor_manager().add_monitor(monitor_lid)

        # Run the simulation -------------------------------------------------------------------
        vis = sim.get_field_exporter()
        vis.add_field_output("Temperature")
        vis.add_field_output("Density")
        vis.add_field_output("Thermal Conductivity")
        vis.add_field_output("Specific Heat Capacity")

        sim.run()
        vis.save()


        # Temperature evolution plots ----------------------------------------------------------
        def plot_evolution(monitor, reference_file, ylabel, output):
            evolution = [(t, T - 273.15) for t, T in monitor.get_values()]  # K -> °C
            ref_t, ref_T = numpy.loadtxt(reference_file, delimiter=",", unpack=True)

            xy_plot(
                values=evolution,
                style=PlotStyle.LINE,
                reference_values=list(zip(ref_t, ref_T - 273.15)),
                reference_style=PlotStyle.LINE,
                reference_label="Li (2020)",
                xlabel="Time [s]",
                ylabel=ylabel,
                xlim=(0.0, 10.0),
                path=output,
            )


        plot_evolution(
            monitor_die,
            "data/Die_Temperature_Reference.csv",
            "Die Temperature [°C]",
            "results/Die_Temperature_Evolution.png",
        )
        plot_evolution(
            monitor_lid,
            "data/Lid_Temperature_Reference.csv",
            "Lid Temperature [°C]",
            "results/Lid_Temperature_Evolution.png",
        )


if __name__ == "__main__":
    Bruce2012ElectronicDesign().run()
