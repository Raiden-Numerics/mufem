from casekit import ValidationCase, expect, run_case

# numpy MUST be imported before mufem: on the Windows wheel, loading numpy's
# OpenBLAS after mufem corrupts mufem's mesh read (Simulation.New).
import matplotlib.pyplot as plt
import numpy

import mufem
from mufem import Vol
from mufem.electromagnetics.coil import (
    CoilExcitationCurrent,
    CoilSpecification,
    CoilTopologyClosed,
    CoilTypeStranded,
    ExcitationCoilModel,
)
from mufem.electromagnetics.timeharmonicmagnetic import (
    TimeHarmonicMagneticGeneralMaterial,
    TimeHarmonicMagneticModel,
)


class Team7AsymmetricalConductor(ValidationCase):
    name = "Compumag TEAM 7: Asymmetrical Conductor with a Hole"
    tags = {"moderate"}

    # Solved in this order, so that the exported fields belong to 50 Hz.
    frequencies = (200, 50)

    # Measurement lines of B_z at z = 34 mm (Fujiwara (1990), Table 4): name, y [m].
    flux_density_lines = (("A1-B1", 0.072), ("A2-B2", 0.144))

    # Tolerance of the relative L2 error of B_z against the measurement per frequency.
    flux_density_tolerance = {50: 0.06, 200: 0.10}

    def build_geometry(self):
        from netgen.occ import Axes, Box, Glue, Pnt, WorkPlane, X, Y, Z

        from casekit.netgen_geometry import color_air, color_aluminum, color_copper, name_body

        # Plate with an off-center hole --------------------------------------------------
        wp_plate = WorkPlane(Axes((0, 0, 0), Z, X))
        face = (
            wp_plate.Rectangle(0.294, 0.294)
            .MoveTo(0.018, 0.018)
            .Rectangle(0.108, 0.108)
            .Reverse()
            .Face()
        )
        plate = face.Extrude(0.019)
        plate.faces.maxh = 0.04

        name_body(plate, "Plate", color=color_aluminum)

        # Racetrack coil -----------------------------------------------------------------
        wp_coil = WorkPlane(Axes(p=(0.294, 0.000, 0.049), n=Z, h=Y))

        coil_inner = wp_coil.MoveTo(0.100, 0.100).RectangleC(0.100, 0.100).Offset(0.025).Face()
        coil_outer = wp_coil.MoveTo(0.100, 0.100).RectangleC(0.100, 0.100).Offset(0.050).Face()

        coil = (coil_outer - coil_inner).Extrude(0.100)

        name_body(coil, "Coil", color=color_copper)

        # Air ----------------------------------------------------------------------------
        air = Box(Pnt(-0.2, -0.2, -0.2), Pnt(0.5, 0.5, 0.5))
        name_body(air, "Air", color=color_air)

        air = air - coil - plate

        geometry = Glue([plate, coil, air])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=1.0, path=self.mesh_path, second_order=True)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        self.runner = mufem.SteadyRunner(total_iterations=3)
        sim.set_runner(self.runner)

        # Model ------------------------------------------------------------------------
        self.magnetic_model = TimeHarmonicMagneticModel(frequency=self.frequencies[0], order=3)
        sim.get_model_manager().add_model(self.magnetic_model)

        # Materials --------------------------------------------------------------------
        air_material = TimeHarmonicMagneticGeneralMaterial(
            name="Air", marker="Air" @ Vol, has_eddy_currents=False
        )

        copper_material = TimeHarmonicMagneticGeneralMaterial(
            name="Copper", marker="Coil" @ Vol, has_eddy_currents=False
        )

        alu_material = TimeHarmonicMagneticGeneralMaterial(
            name="Alu",
            marker="Plate" @ Vol,
            magnetic_permeability=1.0,
            electric_conductivity=3.526e7,
            has_eddy_currents=True,
        )

        self.magnetic_model.add_materials([air_material, copper_material, alu_material])

        # Coil -------------------------------------------------------------------------
        coil_model = ExcitationCoilModel()
        sim.get_model_manager().add_model(coil_model)

        # 2742 ampere turns (peak), maximum at wt = 0, flowing in +x at (0.2, 0.01, 0.07),
        # i.e. anticlockwise seen from +z as in the TEAM 7 description.
        coil_topology = CoilTopologyClosed(x=0.2, y=0.01, z=0.07, dx=1.0, dy=0.0, dz=0.0)
        coil_type = CoilTypeStranded(number_of_turns=2742)
        coil_excitation = CoilExcitationCurrent(current=(1.0, 0))

        coil = CoilSpecification(
            name="Coil",
            marker="Coil" @ Vol,
            topology=coil_topology,
            type=coil_type,
            excitation=coil_excitation,
        )
        coil_model.add_coil_specification(coil)

        return sim

    def solve(self):
        self.sim.initialize()

        self.results = {}
        for frequency in self.frequencies:
            self.magnetic_model.set_frequency(frequency)
            self.runner.advance(self.runner.get_total_iterations())
            self.results[frequency] = self.evaluate_lines()

    @staticmethod
    def probe(field, x, y, z):
        """Complex vector of `field` at (x, y, z)."""
        real, imag = (
            mufem.ProbeReport.SinglePoint(
                name=f"{field}-{part}", cff_name=f"{field}-{part}", x=x, y=y, z=z
            ).evaluate()
            for part in ("Real", "Imag")
        )
        return numpy.array([real.x, real.y, real.z]) + 1j * numpy.array([imag.x, imag.y, imag.z])

    def evaluate_lines(self):
        """B_z [mT] on A1-B1 and A2-B2, and J_y [A/mm^2] just below the top surface of the plate.

        The real and imaginary parts compare with the measured values at wt = 0 and 90 deg:
        conj(B_z) for the flux density, and -1j * J_y for the eddy current density, as in the
        NGSolve TEAM-7 reference.
        """
        x_values = numpy.linspace(0.0, 0.288, 97)
        lines = {
            name: [
                (1e3 * x, 1e3 * numpy.conj(self.probe("Magnetic Flux Density", x, y, 0.034)[2]))
                for x in x_values
            ]
            for name, y in self.flux_density_lines
        }

        # Keep the probes inside the aluminum at the plate edge and the hole edges.
        eps = 1.0e-5
        x_plate = numpy.concatenate(
            ([eps], numpy.linspace(0.003, 0.018 - eps, 6), numpy.linspace(0.126 + eps, 0.288, 55))
        )
        lines["Top"] = [
            (1e3 * x, -1e-6j * self.probe("Electric Current Density", x, 0.072, 0.019 - eps)[1])
            for x in x_plate
        ]
        return lines

    def validate(self):
        # Relative L2 error over both phases at the measured points of each line.
        self.errors = {}
        for frequency, lines in self.results.items():
            for name, _ in self.flux_density_lines:
                x, b = numpy.array(lines[name]).T
                ref = self.load_csv(f"Bz_{name}.csv")
                column = 2 if frequency == 50 else 4
                measured = 0.1 * (ref[:, column] + 1j * ref[:, column + 1])
                computed = numpy.interp(ref[:, 1], x.real, b.real) + 1j * numpy.interp(
                    ref[:, 1], x.real, b.imag
                )
                error = numpy.linalg.norm(computed - measured) / numpy.linalg.norm(measured)
                self.errors[(frequency, name)] = error
                expect(
                    error,
                    0.0,
                    abs_tol=self.flux_density_tolerance[frequency],
                    label=f"Bz error on {name} at {frequency} Hz",
                )

    def postprocess(self):
        if self.is_main():
            for frequency, lines in self.results.items():
                for name, _ in self.flux_density_lines:
                    self.plot_flux_density(frequency, name, lines[name])
                self.plot_current_density(frequency, lines["Top"])

            # The input of the animation of create_scenes(): B_z [mT] along A1-B1 at 50 Hz,
            # over x [mm], as compared with the measurement (conjugated, see evaluate_lines).
            x, b = numpy.array(self.results[50]["A1-B1"]).T
            numpy.savez(self.scene_data_path, x=x.real, bz=b)

        # Field export for the animation of create_scenes() (collective)
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Magnetic Flux Density-Real")
        vis.add_field_output("Magnetic Flux Density-Imag")
        vis.add_field_output("Electric Current Density-Real")
        vis.add_field_output("Electric Current Density-Imag")
        vis.save(order=3)

    def plot_line(self, x, values, ref_x, ref_values, ylabel, title, path):
        plt.clf()
        plt.plot(
            ref_x, ref_values.real, "ko", markersize=6, label="Fujiwara (1990), $\\omega t = 0°$"
        )
        plt.plot(
            ref_x, ref_values.imag, "ks", markersize=6, label="Fujiwara (1990), $\\omega t = 90°$"
        )
        plt.plot(x, values.real, color="r", linewidth=3.0, label="$\\mu$fem, $\\omega t = 0°$")
        plt.plot(x, values.imag, color="b", linewidth=3.0, label="$\\mu$fem, $\\omega t = 90°$")
        plt.xlabel("Position x [mm]")
        plt.ylabel(ylabel)
        plt.title(title)
        plt.xlim((0, 288))
        plt.xticks([0, 72, 144, 216, 288])
        plt.legend(loc="best").draw_frame(False)
        plt.savefig(path, bbox_inches="tight")

    def plot_flux_density(self, frequency, name, values):
        x, b = numpy.array(values).T
        ref = self.load_csv(f"Bz_{name}.csv")
        column = 2 if frequency == 50 else 4
        self.plot_line(
            x.real,
            b,
            ref[:, 1],
            0.1 * (ref[:, column] + 1j * ref[:, column + 1]),
            "Magnetic Flux Density $B_z$ [mT]",
            f"$B_z$ along {name} at {frequency} Hz",
            self.results_path / f"Magnetic_Flux_Density-{name}-{frequency}Hz.png",
        )

    def plot_current_density(self, frequency, values):
        x, j = numpy.array(values).T
        # No eddy currents in the hole (18 mm < x < 126 mm): break the line there.
        gap = numpy.searchsorted(x.real, 0.018 * 1e3)
        x = numpy.insert(x.real, gap, numpy.nan)
        j = numpy.insert(j, gap, numpy.nan)
        ref = self.load_csv("Jy_Top.csv")
        column = 2 if frequency == 50 else 4
        self.plot_line(
            x,
            j,
            ref[:, 1],
            ref[:, column] + 1j * ref[:, column + 1],
            "Eddy Current Density $J_y$ [A/mm$^2$]",
            f"$J_y$ on the top surface (y = 72 mm) at {frequency} Hz",
            self.results_path / f"Electric_Current_Density-Top-{frequency}Hz.png",
        )

    def load_csv(self, file_name):
        return numpy.loadtxt(self.dir_path / "data" / file_name, delimiter=",", comments="#")

    def create_scenes(self):
        # The current density J(t) = J_r cos(wt) - J_i sin(wt) in the coil and the plate at
        # 50 Hz over one period as arrows, next to the coil current and B_z along A1-B1 at the
        # same time.
        import pyvista as pv

        from casekit import PlotStyle
        from casekit.pyvista_scene import (
            FieldExportReader,
            add_colorbar,
            at_phase,
            create_scene,
            gif,
            update_curve,
            xy_chart,
        )

        frames_per_period = 40
        period_ms = 1e3 / 50

        # B_z along A1-B1 as in postprocess(): x [mm] and the complex B_z [mT], which holds Re
        # and -Im of the solution, and x, wt = 0 and 90 deg of the measurement [G], so that
        # B_z(t) = Re cos(wt) + Im sin(wt) for both.
        computed = numpy.load(self.scene_data_path)
        measured = numpy.loadtxt(self.dir_path / "data" / "Bz_A1-B1.csv", delimiter=",")

        def flux_density(phase):
            measured_bz = 0.1 * measured[:, 2:4] @ (numpy.cos(phase), numpy.sin(phase))
            computed_bz = (computed["bz"] * numpy.exp(-1j * phase)).real
            return numpy.c_[measured[:, 1], measured_bz], numpy.c_[computed["x"], computed_bz]

        scene = create_scene((1600, 800), shape="1|2", splitting_position=0.6, border=False)

        # The coil current cos(wt) over the period, with the current time marked.
        t = numpy.linspace(0.0, period_ms, 200)
        current_chart, current_point, _ = xy_chart(
            values=[(0.0, 1.0)],
            label="Current Time",
            style=PlotStyle.POINTS,
            reference_values=numpy.c_[t, numpy.cos(2 * numpy.pi * t / period_ms)],
            reference_label="Applied Current",
            reference_style=PlotStyle.LINE,
            xlabel="Cycle Time [ms]",
            ylabel="Coil Current [A]",
            xlim=(0, period_ms),
            ylim=(-1.1, 1.1),
            xticks=[0, 5, 10, 15, 20],
            yticks=[-1, 0, 1],
            legend_loc="lower left",
        )
        measured_bz, computed_bz = flux_density(0.0)
        flux_chart, computed_curve, measured_curve = xy_chart(
            values=computed_bz,
            style=PlotStyle.LINE,
            reference_values=measured_bz,
            reference_label="Fujiwara (1990)",
            reference_style=PlotStyle.LINE_AND_POINTS,
            xlabel="Position [mm]",
            ylabel="Bz along A1-B1 [mT]",
            xlim=(0, 288),
            ylim=(-9, 9),
            xticks=[0, 72, 144, 216, 288],
            yticks=[-9, -6, -3, 0, 3, 6, 9],
        )
        for subplot, chart in ((1, current_chart), (2, flux_chart)):
            scene.subplot(subplot)
            scene.add_chart(chart)
        scene.subplot(0)

        bodies = FieldExportReader(self.dir_path).read(hide=["Air"])
        arrow = pv.Arrow(
            shaft_radius=0.07,
            shaft_resolution=16,
            tip_radius=0.12,
            tip_length=0.15,
            tip_resolution=16,
        )

        def arrows(phase_deg):
            conductors = at_phase(bodies, "Electric Current Density", phase_deg).combine()
            field = "Electric Current Density"
            return conductors.glyph(orient=field, scale=field, factor=2e-8, geom=arrow)

        scene.add_mesh(bodies, color=(0.9, 0.9, 0.9))
        # The glyphs keep the current density as GlyphVector.
        field = dict(scalars="GlyphVector", clim=(0.0, 2.0e6), name="arrows")
        actor = scene.add_mesh(arrows(0.0), **field)
        # The direction of the view of data/Geometry.png, fitted to the coil and the plate.
        scene.view_vector((-0.0656, 0.0281, 0.0254), viewup=(0, 0, 1))
        scene.camera.zoom(1.25)
        scene.camera.SetWindowCenter(0.0, -0.15)  # room for the color bar below
        add_colorbar(
            scene,
            actor,
            "Electric Current Density [10⁶ A/m²]",
            n_labels=3,
            label_format="%.0f",
            location="bottom",
            font_size=19,
            scale=1e-6,
        )

        with gif(scene, self.results_path / "Team7_Animation.gif") as write_frame:
            for i in range(frames_per_period):
                phase = 2 * numpy.pi * i / frames_per_period
                scene.add_mesh(arrows(numpy.degrees(phase)), **field)
                update_curve(
                    current_point, [(period_ms * i / frames_per_period, numpy.cos(phase))]
                )
                measured_bz, computed_bz = flux_density(phase)
                update_curve(measured_curve, measured_bz)
                update_curve(computed_curve, computed_bz)
                write_frame()


if __name__ == "__main__":
    run_case(Team7AsymmetricalConductor)
