from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot

import math

import numpy

import mufem
from mufem import Bnd, Vol
from mufem.electromagnetics.timedomainmagnetic import (
    TangentialMagneticFieldBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)


class Team1bFelixCylinder(ValidationCase):
    name = "Compumag TEAM 1b: The FELIX Short Cylinder"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import Box, Cylinder, Glue, Pnt, Z, gp_Ax2

        from casekit.colors import color_air, color_copper
        from casekit.netgen_geometry import name_body

        cylinder_length = 0.20
        cylinder_inner_radius = 0.05715
        cylinder_outer_radius = 0.06985

        air_box_half_length = cylinder_length

        # Cylinder ---------------------------------------------------------------------
        axis_z = gp_Ax2((0, 0, -cylinder_length / 2), Z)

        cylinder_outer = Cylinder(axis_z, cylinder_outer_radius, cylinder_length)
        cylinder_inner = Cylinder(axis_z, cylinder_inner_radius, cylinder_length)

        cylinder_body = cylinder_outer - cylinder_inner

        name_body(cylinder_body, "Cylinder", color=color_copper)

        # Air --------------------------------------------------------------------------
        air_pnt0 = Pnt(-air_box_half_length, -air_box_half_length, -air_box_half_length)
        air_pnt1 = Pnt(air_box_half_length, air_box_half_length, air_box_half_length)

        air_body = Box(air_pnt0, air_pnt1)
        name_body(air_body, "Air", color=color_air, individual_names=False)

        air_body = air_body - cylinder_body

        air_body.faces.maxh = 0.05
        cylinder_body.faces.maxh = 0.008

        geometry = Glue([cylinder_body, air_body])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=5.0e-2, path=self.mesh_path)

    def create_geometry_image(self):
        # The view of the scene of create_scenes(), horizontal along (-1, 0, 1) so that the
        # applied field (y) stays vertical; three arrows show the applied field.
        from netgen.occ import OCCGeometry

        from casekit.netgen_image import Labels, snapshot, trim

        solids = OCCGeometry(f"{self.step_path}").shape.solids
        image = trim(image=snapshot(shapes=solids, direction=(-1, 0, 1), up=(0, 1, 0)))

        # The applied field B_y(t): three arrows along -y with a label.
        labels = Labels(image=image)
        x, top, length = 90, 360, 200
        for dx in (0, 45, 90):
            labels.arrow(
                start=(x + dx, top),
                end=(x + dx, top + length + 10),
                width=9,
                head=26,
                spread=0.46,
            )
        labels.formula(position=(x - 10, top - 75), tex="$B_y(t)$")

        image.save(self.dir_path / "data" / "Geometry.png")

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        self.runner = mufem.UnsteadyRunner(
            total_time=0.02, time_step_size=0.001, total_inner_iterations=3
        )
        sim.set_runner(self.runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeDomainMagneticModel(order=1, magnetostatic_initialization=True)
        sim.get_model_manager().add_model(magnetic_model)

        # Materials --------------------------------------------------------------------
        air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

        aluminum_material = TimeDomainMagneticGeneralMaterial(
            name="Al", marker="Cylinder" @ Vol, electric_conductivity=25380710.659898475
        )
        magnetic_model.add_materials([air_material, aluminum_material])

        # Boundary conditions ----------------------------------------------------------
        cff_magnetic_field = mufem.CffExpressionVector(
            "[0, 79577.488101574*exp(-{Time}/0.0069), 0]"
        )

        tangential_magnetic_field_bc = TangentialMagneticFieldBoundaryCondition(
            name="ExternalField",
            marker="Air::Boundary" @ Bnd,
            tangential_magnetic_field=cff_magnetic_field,
        )
        magnetic_model.add_condition(tangential_magnetic_field_bc)

        # Reports ----------------------------------------------------------------------
        self.ohmic_heating_report = mufem.VolumeIntegralReport(
            name="Ohmic Heating", marker="Cylinder" @ Vol, cff_name="Ohmic Heating"
        )
        sim.get_report_manager().add_report(self.ohmic_heating_report)

        self.ohmic_heating_monitor = mufem.ReportMonitor(
            name="Ohmic Heating Monitor", report_name="Ohmic Heating"
        )
        sim.get_monitor_manager().add_monitor(self.ohmic_heating_monitor)

        # Magnetic flux density at the center of the cylinder.
        center_field_report = mufem.ProbeReport.SinglePoint(
            name="Center Field", cff_name="Magnetic Flux Density", x=0.0, y=0.0, z=0.0
        )
        sim.get_report_manager().add_report(center_field_report)

        self.center_field_monitor = mufem.ReportMonitor(
            name="Center Field Monitor", report_name="Center Field"
        )
        sim.get_monitor_manager().add_monitor(self.center_field_monitor)

        return sim

    def solve(self):
        # The fields of every time step for the scenes of create_scenes() (collective).
        exporter = self.sim.get_field_exporter()
        exporter.set_output_directory(self.dir_path / "VisualizationOutput")
        exporter.add_field_outputs(["Magnetic Flux Density", "Electric Current Density"])

        self.sim.initialize()
        exporter.save()

        for _ in range(20):
            self.runner.advance(1)
            exporter.save()

    def validate(self):
        def at(monitor, time):
            return min(monitor.get_values(), key=lambda sample: abs(sample[0] - time))[1]

        # Power loss against the median of the eight codes of Table 4 of Davey (1988).
        for time, loss in [(0.004, 430.5), (0.008, 534.5), (0.010, 484.0)]:
            expect(
                at(self.ohmic_heating_monitor, time),
                loss,
                rel_tol=5e-2,
                label=f"power loss at t = {1e3 * time:.0f} ms [W]",
            )

        # Induced field at the center (total minus applied) against the measurement of Table 3 of
        # Davey (1988); most codes there are also 5-10 % below it at 4 and 8 ms.
        for time, induced_field in [(0.004, 0.035), (0.008, 0.042), (0.010, 0.0375)]:
            applied_field = 0.1 * math.exp(-time / 0.0069)
            expect(
                abs(at(self.center_field_monitor, time).y) - applied_field,
                induced_field,
                rel_tol=1e-1,
                label=f"induced field at the center at t = {1e3 * time:.0f} ms [T]",
            )

    def loss_plot(self, loss):
        """The arguments of xy_plot / xy_chart for the Ohmic loss over time, shared by the plot
        of postprocess() and the animation of create_scenes()."""
        return dict(
            values=loss,
            style=PlotStyle.LINE_AND_POINTS,
            reference_values=numpy.loadtxt(
                self.dir_path / "data" / "PowerLoss.csv", delimiter=",", comments="#"
            ),
            reference_style=PlotStyle.POINTS,
            reference_label="Davey (1988)",
            xlabel="Time [s]",
            ylabel="Ohmic Heating Loss [W]",
            xlim=(0.0, 0.02),
            xticks=[0, 0.01, 0.02],
            ylim=(0.0, 600.0),
        )

    def postprocess(self):
        if not self.is_main():
            return

        loss = numpy.array(self.ohmic_heating_monitor.get_values())

        # The input of the animation of create_scenes().
        numpy.savez(self.scene_data_path, loss=loss)

        xy_plot(path=f"{self.results_path / 'OhmicHeating.png'}", **self.loss_plot(loss))

    def create_scenes(self):
        # The eddy currents in the cylinder as arrows, in the horizontal view along (-1, 0, 1)
        # with y up of data/Geometry.png: at the final time, and over time in an animation with
        # the Ohmic loss up to the time step in a chart on the right.
        from casekit.pyvista_scene import (
            FieldExportReader,
            add_colorbar,
            create_scene,
            gif,
            update_curve,
            xy_chart,
        )

        reader = FieldExportReader(self.dir_path)
        cylinder_color = (0.69, 0.69, 0.69)
        # The glyphs keep the current density as GlyphVector.
        field = dict(scalars="GlyphVector", clim=(0.0, 3.0e6), name="field")

        def arrows(time_step):
            cylinder = reader.read(time_step)["Cylinder"]
            # Arrows 3 cm long at 3e6 A/m² and above: the early current density is far higher.
            return cylinder, cylinder.glyph(
                orient="Electric Current Density",
                scale="Electric Current Density",
                factor=0.03,
                clamping=True,
                rng=(0.0, 3.0e6),
            )

        cylinder, current = arrows(reader.number_time_steps - 1)
        scene = create_scene((1300, 1100))
        scene.add_mesh(cylinder, color=cylinder_color)
        actor = scene.add_mesh(current, **field)
        scene.view_vector((-1, 0, 1), viewup=(0, 1, 0))
        scene.camera.zoom(1.35)
        scene.camera.SetWindowCenter(0.0, -0.18)  # room for the color bar below
        add_colorbar(
            scene,
            actor,
            "Electric Current Density [10⁶ A/m²]",
            n_labels=4,
            label_format="%.0f",
            location="bottom",
            scale=1e-6,
        )
        scene.show(screenshot=self.results_path / "Scene_Electric_Current_Density.png")

        loss = numpy.load(self.scene_data_path)["loss"]
        scene = create_scene((1600, 800), shape="1|1", border=False)
        chart, curve, _ = xy_chart(**self.loss_plot(loss))
        scene.subplot(1)
        scene.add_chart(chart)
        scene.subplot(0)

        scene.add_mesh(cylinder, color=cylinder_color)
        actor = scene.add_mesh(current, **field)
        scene.view_vector((-1, 0, 1), viewup=(0, 1, 0))
        scene.camera.zoom(0.95)
        scene.camera.SetWindowCenter(0.2, 0.0)  # room for the color bar on the right
        add_colorbar(
            scene,
            actor,
            "Current Density [10⁶ A/m²]",
            n_labels=4,
            label_format="%.0f",
            font_size=19,
            scale=1e-6,
        )

        with gif(
            scene, self.results_path / "Animation_Electric_Current_Density.gif", fps=4
        ) as write_frame:
            for time_step in range(reader.number_time_steps):
                scene.add_mesh(arrows(time_step)[1], **field)
                update_curve(curve, loss[: time_step + 1])
                write_frame()


if __name__ == "__main__":
    run_case(Team1bFelixCylinder)
