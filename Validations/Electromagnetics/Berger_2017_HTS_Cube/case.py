from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot

# numpy must be imported before mufem (see casekit/plots.py).
import numpy

import mufem
from mufem import Bnd, Vol
from mufem.electromagnetics.module.superconductor import SuperconductorMagneticMaterial
from mufem.electromagnetics.timedomainmagnetic import (
    LineSearchStrategy,
    TangentialMagneticFieldBoundaryCondition,
    TangentialMagneticFluxBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)


class Berger2017HtsCube(ValidationCase):
    name = "Berger 2017: High-Temperature Superconductor Cube"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import Box, Glue, Sphere, X, Y, Z

        from casekit.colors import color_air, color_hts
        from casekit.netgen_geometry import name_body

        length_cube = 0.01
        # The 100 mm air radius matches the paper's air box and keeps the dipole
        # perturbation at the outer boundary negligible.
        radius_air = 0.1

        # 1/8 of the cube (positive octant). The field is along Y: X = 0 and Z = 0 are
        # B-tangential symmetry planes, Y = 0 is the B-normal plane.
        cube = Box((0, 0, 0), (length_cube / 2, length_cube / 2, length_cube / 2))
        name_body(cube, "Cube", color=color_hts)

        cube.faces.Min(X).name = "Cube::TangentialFlux::X"
        cube.faces.Min(Z).name = "Cube::TangentialFlux::Z"
        cube.faces.Min(Y).name = "Cube::NormalField"
        cube.faces.Max(X).name = "Cube::AirInterface::X"
        cube.faces.Max(Y).name = "Cube::AirInterface::Y"
        cube.faces.Max(Z).name = "Cube::AirInterface::Z"
        cube.maxh = 0.0005

        # 1/8 of the air ball with the cube cut out.
        air_box = Box((0, 0, 0), (radius_air, radius_air, radius_air))
        air_sphere = Sphere((0, 0, 0), radius_air)
        air = (air_sphere * air_box) - cube
        name_body(air, "Air", color=color_air)

        air.faces.Min(X).name = "Air::TangentialFlux::X"
        air.faces.Min(Z).name = "Air::TangentialFlux::Z"
        air.faces.Min(Y).name = "Air::NormalField"
        air.faces[0].name = "Air::Outer"  # spherical surface where the field is applied

        geometry = Glue([cube, air])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=5.0e-2, path=self.mesh_path)

    def create_geometry_image(self):
        # The cube enlarged six times for visibility; the view looks onto the symmetry planes
        # x = 0 and z = 0.
        import math

        from netgen.occ import Glue, OCCGeometry, Pnt

        from casekit.netgen_image import snapshot, trim

        solids = OCCGeometry(f"{self.step_path}").shape.solids

        # The 5 mm cube is tiny in the 100 mm air ball: enlarge it for the image.
        cube = next(solid for solid in solids if solid.name == "Cube").Scale(Pnt(0, 0, 0), 6)
        air = next(solid for solid in solids if solid.name == "Air") - cube
        shape = Glue([cube, air])

        # Draw the faces between cube and air in the cube color, not the translucent air color.
        for face in shape.solids[0].faces:
            face.col = cube.faces[0].col

        # The isometric view along (-1, 1, -1), turned by -15 deg about y, with the applied
        # field (y) up: x' = x cos + z sin, z' = z cos - x sin.
        turn = math.radians(-15.0)
        direction = (-math.cos(turn) - math.sin(turn), 1.0, math.sin(turn) - math.cos(turn))
        image = snapshot(shapes=shape.solids, direction=direction, up=(0, 1, 0))
        trim(image=image).save(self.dir_path / "data" / "Geometry.png")

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        # One period of the 50 Hz applied field.
        frequency = 50.0
        self.period = 1.0 / frequency

        runner = mufem.UnsteadyRunner(
            total_time=self.period,
            time_step_size=self.period / 50.0,
            total_inner_iterations=10,
        )
        sim.set_runner(runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeDomainMagneticModel(order=1, magnetostatic_initialization=False)
        sim.get_model_manager().add_model(magnetic_model)

        # Line search stabilizes Newton's iteration on the n=25 power-law nonlinearity.
        line_search = magnetic_model.get_solver().get_line_search()
        line_search.set_active(True)
        line_search.set_strategy(LineSearchStrategy.ThreePointQuadratic)
        line_search.set_iteration_window(min_iter=0, max_iter=100000000)
        line_search.set_residual_skip_threshold(1.0e-10)
        line_search.set_max_alpha(1.0)

        # Materials --------------------------------------------------------------------
        air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

        # n=25, Jc=2.5e6 A/m^2, Ec=1e-4 V/m, close to measurements on cylindrical Bi-2223
        # samples, Berger (2017), §II.B.
        hts_material = SuperconductorMagneticMaterial(
            name="Bi-2223",
            marker="Cube" @ Vol,
            Ec=1.0e-4,
            Jc=2.5e6,
            n=25,
        )

        magnetic_model.add_materials([air_material, hts_material])

        # Boundary conditions ----------------------------------------------------------
        # Applied field: B_a(t) = B_max sin(2 pi f t) along y.
        # B_max = 20 mT > B_p = mu0 * Jc * d / 2 ~ 15.7 mT places the case in the
        # full-penetration regime.
        b_max = 20.0e-3
        h_max = b_max / (4.0e-7 * numpy.pi)

        cff_applied_field = mufem.CffExpressionVector(
            f"[0, {h_max}*sin(2*pi*{frequency}*{{Time}}), 0]"
        )

        applied_field_bc = TangentialMagneticFieldBoundaryCondition(
            name="Applied Field",
            marker="Air::Outer" @ Bnd,
            tangential_magnetic_field=cff_applied_field,
        )

        # 1/8-symmetry: x=0 and z=0 are B-tangential planes (Tangential-A=0).
        symmetry_bc = TangentialMagneticFluxBoundaryCondition(
            name="Symmetry Plane",
            marker=[
                "Cube::TangentialFlux::X",
                "Cube::TangentialFlux::Z",
                "Air::TangentialFlux::X",
                "Air::TangentialFlux::Z",
            ]
            @ Bnd,
        )

        magnetic_model.add_conditions([applied_field_bc, symmetry_bc])

        # Reports ----------------------------------------------------------------------
        ohmic_heating_report = mufem.VolumeIntegralReport(
            name="Ohmic Heating", marker="Cube" @ Vol, cff_name="Ohmic Heating"
        )
        sim.get_report_manager().add_report(ohmic_heating_report)

        self.ohmic_heating_monitor = mufem.ReportMonitor(
            name="Ohmic Heating Monitor", report_name="Ohmic Heating"
        )
        sim.get_monitor_manager().add_monitor(self.ohmic_heating_monitor)

        # The fields at the start and after every time step for the scenes of create_scenes().
        exporter = sim.get_field_exporter()
        exporter.set_output_directory(self.dir_path / "VisualizationOutput")
        exporter.add_field_outputs(["Magnetic Flux Density", "Electric Current Density"])
        exporter.set_events([mufem.Event.Initialization, mufem.Event.TimeStep])

        return sim

    def validate(self):
        # The octant model integrates 1/8 of the cube.
        time, loss = numpy.array(self.ohmic_heating_monitor.get_values()).T
        loss = 8.0 * loss

        expect(loss.max(), 0.02983, rel_tol=1e-2, label="peak AC loss [W]")

        # Steady-state average loss over the second half-period, Eq. (3) of Berger (2017),
        # against model (B.3) of Table III; the six models spread by up to 10.2 % around it.
        half = numpy.argmin(abs(time - self.period / 2))
        average_loss = 2.0 / self.period * numpy.trapezoid(loss[half:], time[half:])
        expect(average_loss, 13.009e-3, rel_tol=0.12, label="average AC loss [W]")

    def loss_plot(self, loss):
        """The arguments of xy_plot / xy_chart for the full-cube loss [mW] over time [ms],
        shared by the plot of postprocess() and the animation of create_scenes()."""
        return dict(
            values=loss,
            style=PlotStyle.LINE_AND_POINTS,
            reference_values=numpy.loadtxt(
                self.dir_path / "data" / "AC_Losses_B20mT.csv", delimiter=",", comments="#"
            ),
            reference_style=PlotStyle.POINTS,
            reference_label="Berger (2017)",
            xlabel="Time [ms]",
            ylabel="Ohmic Heating [mW]",
            xlim=(0.0, 20.0),
            ylim=(0.0, 35.0),
        )

    def postprocess(self):
        if not self.is_main():
            return

        # The octant model integrates 1/8 of the cube: s -> ms, octant W -> full-cube mW.
        time, loss = numpy.array(self.ohmic_heating_monitor.get_values()).T
        loss = numpy.column_stack([1.0e3 * time, 8.0e3 * loss])

        # The input of the animation of create_scenes().
        numpy.savez(self.scene_data_path, loss=loss)

        xy_plot(path=f"{self.results_path / 'Ohmic_Heating.png'}", **self.loss_plot(loss))

    def create_scenes(self):
        # Animation: the shielding current circulating about the applied field (y), in the full
        # cube mirrored from the octant with the octant toward the camera cut away; the loss up
        # to the time step in a chart on the right. |J| is close to Jc nearly everywhere in the
        # full-penetration regime, but the circulation reverses with every half-cycle.
        from casekit.pyvista_scene import (
            FieldExportReader,
            add_colorbar,
            create_scene,
            gif,
            update_curve,
            xy_chart,
        )

        reader = FieldExportReader(self.dir_path)

        def mirrored_cube(time_step):
            # J_phi = (J_x z - J_z x) / r is even about all three symmetry planes, so the
            # mirrored copies keep it as it is.
            octant = reader.read(time_step, hide=["Air"])["Cube"]
            x, z = octant.points[:, 0], octant.points[:, 2]
            current_density = octant["Electric Current Density"]
            octant["J_phi"] = (
                current_density[:, 0] * z - current_density[:, 2] * x
            ) / numpy.maximum(numpy.hypot(x, z), 1.0e-9)
            return [
                octant.scale((sx, sy, sz), inplace=False)
                for sx in (1, -1)
                for sy in (1, -1)
                for sz in (1, -1)
                if (sx, sy, sz) != (1, 1, 1)
            ]

        loss = numpy.load(self.scene_data_path)["loss"]
        scene = create_scene((1600, 800), shape="1|1", border=False)
        chart, curve, _ = xy_chart(**self.loss_plot(loss))
        scene.subplot(1)
        scene.add_chart(chart)
        scene.subplot(0)

        field = dict(scalars="J_phi", clim=(-3.0e6, 3.0e6))

        def add_cube(time_step):
            actors = [
                scene.add_mesh(part, name=f"field{i}", **field)
                for i, part in enumerate(mirrored_cube(time_step))
            ]
            return actors[0]

        actor = add_cube(0)
        scene.view_vector((1, 1, 1), viewup=(0, 1, 0))
        scene.camera.SetWindowCenter(0.2, 0.0)  # room for the color bar on the right
        scene.camera.zoom(0.9)
        add_colorbar(
            scene,
            actor,
            "Azimuthal Current Density [10⁶ A/m²]",
            n_labels=7,
            label_format="%.0f",
            font_size=19,
            scale=1e-6,
        )

        with gif(
            scene, self.results_path / "Animation_Electric_Current_Density.gif"
        ) as write_frame:
            for time_step in range(reader.number_time_steps):
                add_cube(time_step)
                update_curve(curve, loss[: time_step + 1])
                write_frame()


if __name__ == "__main__":
    run_case(Berger2017HtsCube)
