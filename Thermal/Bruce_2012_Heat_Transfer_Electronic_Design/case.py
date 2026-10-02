from validation_tools import PlotStyle, ValidationCase, expect, xy_plot

import numpy

import mufem
from mufem import Bnd, Vol
from mufem.thermal import (
    ConvectionBoundaryCondition,
    HeatFluxBoundaryCondition,
    SolidTemperatureMaterial,
    SolidTemperatureModel,
)


class Bruce2012ElectronicDesign(ValidationCase):
    name = "Bruce 2012: Heat Transfer in Electronic Design"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import Box, Glue, Y

        from validation_tools.meshing import hex_to_float, name_body

        # Name, thickness [mm], color
        parts = [
            ("Die", 0.5, "7f8d9b"),
            ("TIM1", 0.1, "b1b159"),
            ("Lid", 0.5, "b55b00"),
            ("TIM2", 0.05, "27386d"),
            ("Heat Sink", 6.0, "627862"),
        ]

        width = 13.0e-3
        length = 13.0e-3

        bodies = []
        offset = 0.0

        for name, thickness, color in parts:
            new_offset = offset + thickness * 1.0e-3

            body = Box((-width / 2, offset, -length / 2), (width / 2, new_offset, length / 2))

            name_body(body, name, color=hex_to_float(color))

            bodies.append(body)

            offset = new_offset

        bodies[0].faces.Max(Y).name = "Die::SurfaceHeatFlux"
        bodies[4].faces.Max(Y).name = "Heat Sink::ConvectiveHeatFlux"

        geometry = Glue(bodies)

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from validation_tools.meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=1.0, path=self.mesh_path)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        runner = mufem.UnsteadyRunner(
            total_time=10.0, time_step_size=0.1, total_inner_iterations=3
        )
        sim.set_runner(runner)

        # Model ------------------------------------------------------------------------
        model = SolidTemperatureModel(
            marker=["Die", "TIM1", "Lid", "TIM2", "Heat Sink"] @ Vol,
        )
        sim.get_model_manager().add_model(model)
        model.get_initial_condition().set_constant(273.15)

        # Materials --------------------------------------------------------------------
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

        # Boundary conditions ----------------------------------------------------------
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

        # Reports and monitors ---------------------------------------------------------
        self.report_die = mufem.ProbeReport.SinglePoint(
            name="DieTemperatureReport", cff_name="Temperature", x=0.0, y=0.25e-3, z=0.0
        )
        sim.get_report_manager().add_report(self.report_die)
        self.monitor_die = mufem.ReportMonitor("Die Temperature Monitor", "DieTemperatureReport")
        sim.get_monitor_manager().add_monitor(self.monitor_die)

        self.report_lid = mufem.ProbeReport.SinglePoint(
            name="LidTemperatureReport", cff_name="Temperature", x=0.0, y=0.85e-3, z=0.0
        )
        sim.get_report_manager().add_report(self.report_lid)
        self.monitor_lid = mufem.ReportMonitor("Lid Temperature Monitor", "LidTemperatureReport")
        sim.get_monitor_manager().add_monitor(self.monitor_lid)

        return sim

    def validate(self):
        # Temperatures at t = 10 s; the temperature rise is about 1 K, so the
        # tolerance is absolute.
        expect(
            self.report_die.evaluate(),
            274.13588784085783,
            rel_tol=0.0,
            abs_tol=1e-2,
            label="die temperature [K]",
        )
        expect(
            self.report_lid.evaluate(),
            273.8362471408524,
            rel_tol=0.0,
            abs_tol=1e-2,
            label="lid temperature [K]",
        )

    def postprocess(self):
        if self.is_main():
            self.plot_evolution(
                self.monitor_die,
                "Die_Temperature_Reference.csv",
                "Die Temperature [°C]",
                "Die_Temperature_Evolution.png",
            )
            self.plot_evolution(
                self.monitor_lid,
                "Lid_Temperature_Reference.csv",
                "Lid Temperature [°C]",
                "Lid_Temperature_Evolution.png",
            )

        # ParaView export (collective) ------------------------------------------------
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Temperature")
        vis.add_field_output("Density")
        vis.add_field_output("Thermal Conductivity")
        vis.add_field_output("Specific Heat Capacity")
        vis.save()

    def plot_evolution(self, monitor, reference_file, ylabel, output):
        evolution = [(t, T - 273.15) for t, T in monitor.get_values()]  # K -> °C
        ref_t, ref_T = numpy.loadtxt(
            self.dir_path / "data" / reference_file, delimiter=",", unpack=True
        )

        xy_plot(
            values=evolution,
            style=PlotStyle.LINE_AND_POINTS,
            reference_values=list(zip(ref_t, ref_T - 273.15)),
            reference_style=PlotStyle.POINTS,
            reference_label="Li (2020)",
            xlabel="Time [s]",
            ylabel=ylabel,
            xlim=(0.0, 10.0),
            path=f"{self.results_path / output}",
        )


if __name__ == "__main__":
    Bruce2012ElectronicDesign().run()
