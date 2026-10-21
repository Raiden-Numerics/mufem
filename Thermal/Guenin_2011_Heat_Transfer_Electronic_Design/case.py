from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot

import numpy

import mufem
from mufem import Bnd, Vol
from mufem.thermal import (
    ConvectionBoundaryCondition,
    HeatFluxBoundaryCondition,
    SolidTemperatureMaterial,
    SolidTemperatureModel,
)


class Guenin2011ElectronicDesign(ValidationCase):
    name = "Guenin 2011: Heat Transfer in Electronic Design"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import Box, Glue, Y

        from casekit.netgen_geometry import hex_to_float, name_body

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
        from casekit.netgen_meshing import mesh_and_save

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
            name="Grease Aluminum Filler Particle",
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
        # The heat flux covers the whole cross-section and the sides are adiabatic, so the
        # heat flow is one-dimensional: at steady state the temperature rise follows from the
        # thermal resistances t / (k A) of the layers and 1 / (h A) of the convection. The die
        # is isothermal (no heat flows into it) and the lid probe is at the middle of the lid.
        area = 13.0e-3**2
        power = 5917.1598 * area  # [W] 1 W

        def resistance(thickness, conductivity):
            return thickness / (conductivity * area)

        r_tim1 = resistance(0.1e-3, 2.0)
        r_lid = resistance(0.5e-3, 390.0)
        r_tim2 = resistance(0.05e-3, 1.0)
        r_sink = resistance(6.0e-3, 390.0)
        r_convection = 1.0 / (20000.0 * area)

        steady_rise = {
            "die": power * (r_tim1 + r_lid + r_tim2 + r_sink + r_convection),
            "lid": power * (r_lid / 2 + r_tim2 + r_sink + r_convection),
        }

        # At t = 10 s the package is within 0.1 % of its steady state.
        expect(
            self.report_die.evaluate() - 273.15,
            steady_rise["die"],
            rel_tol=1e-2,
            label="die temperature rise [K]",
        )
        expect(
            self.report_lid.evaluate() - 273.15,
            steady_rise["lid"],
            rel_tol=1e-2,
            label="lid temperature rise [K]",
        )

        # Transient: temperature rise at t = 1 s against Fig. 3.3 of Li (2020).
        for monitor, name in [(self.monitor_die, "Die"), (self.monitor_lid, "Lid")]:
            time, temperature = numpy.array(monitor.get_values()).T
            ref_t, ref_T = numpy.loadtxt(
                self.dir_path / "data" / f"{name}_Temperature_Reference.csv",
                delimiter=",",
                unpack=True,
            )
            expect(
                numpy.interp(1.0, time, temperature) - 273.15,
                numpy.interp(1.0, ref_t, ref_T) - 273.15,
                rel_tol=3e-2,
                label=f"{name.lower()} temperature rise at t = 1 s [K]",
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

        # Field export for the scenes of create_scenes() (collective)
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Temperature")
        vis.add_field_output("Density")
        vis.add_field_output("Thermal Conductivity")
        vis.add_field_output("Specific Heat Capacity")
        vis.save()

    def create_scenes(self):
        # All images use the isometric view along (1, 1, 1) with the stacking direction of the
        # layers (y) up, as data/Geometry.png.
        import pyvista as pv

        from casekit.pyvista_scene import FieldExportReader, add_colorbar, create_scene

        bodies = FieldExportReader(self.dir_path).read()
        for body in bodies:
            body["Temperature Rise"] = body["Temperature"] - 273.15

        for array, title, clim, n_labels, label_format, name in [
            ("Temperature Rise", "Temperature Rise [K]", (0.0, 1.0), 6, "%.1f", "Temperature"),
            (
                "Specific Heat Capacity",
                "Specific Heat Capacity [J/(kg K)]",
                (300.0, 900.0),
                4,
                "%.0f",
                "Heat_Capacity",
            ),
            ("Density", "Density [kg/m³]", (0.0, 9000.0), 4, "%.0f", "Density"),
            (
                "Thermal Conductivity",
                "Thermal Conductivity [W/(m K)]",
                (0.0, 400.0),
                5,
                "%.0f",
                "Thermal_Conductivity",
            ),
        ]:
            scene = create_scene((1000, 1100))
            actor = scene.add_mesh(bodies, scalars=array, clim=clim)
            scene.view_vector((1, 1, 1), viewup=(0, 1, 0))
            # Room for the color bar below: the camera moves down along its up direction.
            shift = -1.5e-3 * numpy.array(scene.camera.up)
            scene.camera.focal_point += shift
            scene.camera.position += shift
            add_colorbar(
                scene,
                actor,
                title,
                n_labels=n_labels,
                label_format=label_format,
                location="bottom",
            )
            scene.show(screenshot=self.results_path / f"Scene_{name}.png")

        # The mesh: the layers in their colors of data/Geometry.png with the edges in black, at
        # the size and position of the package there (930 px wide from 20 px on the left,
        # centered vertically in the 1300 x 852 px image), so that both images of Figure 1 show
        # the package at the same scale.
        scene = create_scene((1300, 852))
        for name, color in [
            ("Die", "7f8d9b"),
            ("TIM1", "b1b159"),
            ("Lid", "b55b00"),
            ("TIM2", "27386d"),
            ("Heat Sink", "627862"),
        ]:
            scene.add_mesh(bodies[name], color=pv.Color(f"#{color}"), show_edges=True)
        focal_point = numpy.array([1.115e-3, 2.383e-3, -3.498e-3])
        scene.camera_position = [focal_point + 0.1, focal_point, (0, 1, 0)]
        scene.camera.parallel_scale = 8.421e-3  # half the image height in meters
        scene.show(screenshot=self.dir_path / "data" / "Mesh.png")

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
    run_case(Guenin2011ElectronicDesign)
