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

    # Measurement lines of B_z at z = 34 mm (Fujiwara and Nakata (1990), Table 4): name, y [m].
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

        # 2742 ampere turns (peak), maximum at wt = 0. The current runs against the given
        # direction, i.e. clockwise seen from +z instead of anticlockwise as in the
        # TEAM 7 description; the probes below flip the sign of the field to compensate.
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
        -conj(B_z) for the flux density (the minus sign undoes the reversed coil current), and
        1j * J_y for the eddy current density, as in the NGSolve TEAM-7 reference.
        """
        x_values = numpy.linspace(0.0, 0.288, 97)
        lines = {
            name: [
                (1e3 * x, -1e3 * numpy.conj(self.probe("Magnetic Flux Density", x, y, 0.034)[2]))
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
            (1e3 * x, 1e-6 * 1j * self.probe("Electric Current Density", x, 0.072, 0.019 - eps)[1])
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

            # Used by create_scene.py for the animation (50 Hz).
            for name, _ in self.flux_density_lines:
                x, b = numpy.array(self.results[50][name]).T
                numpy.savetxt(
                    self.results_path / f"Bz_{name}_mufem.csv",
                    numpy.c_[x.real, b.real, b.imag],
                    delimiter=",",
                    header="x [mm], Re Bz [mT], Im Bz [mT]",
                )

        # ParaView export (collective) ------------------------------------------------
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Magnetic Flux Density-Real")
        vis.add_field_output("Magnetic Flux Density-Imag")
        vis.add_field_output("Electric Current Density-Real")
        vis.add_field_output("Electric Current Density-Imag")
        vis.save(order=3)

    def plot_line(self, x, values, ref_x, ref_values, ylabel, title, path):
        plt.clf()
        plt.plot(ref_x, ref_values.real, "ko", markersize=6, label="Measured ($\\omega t = 0°$)")
        plt.plot(ref_x, ref_values.imag, "ks", markersize=6, label="Measured ($\\omega t = 90°$)")
        plt.plot(x, values.real, color="r", linewidth=3.0, label="$\\mu$fem ($\\omega t = 0°$)")
        plt.plot(x, values.imag, color="b", linewidth=3.0, label="$\\mu$fem ($\\omega t = 90°$)")
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


if __name__ == "__main__":
    run_case(Team7AsymmetricalConductor)
