from validation_tools import ValidationCase, expect

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
    name = "Compumag Team 7: Asymmetrical Conductor with a Hole"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import Axes, Box, Glue, Pnt, WorkPlane, X, Y, Z

        from validation_tools.meshing import color_air, color_aluminum, color_copper, name_body

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
        from validation_tools.meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=1.0, path=self.mesh_path, second_order=True)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        runner = mufem.SteadyRunner(total_iterations=3)
        sim.set_runner(runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeHarmonicMagneticModel(frequency=50, order=3)
        sim.get_model_manager().add_model(magnetic_model)

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

        magnetic_model.add_materials([air_material, copper_material, alu_material])

        # Coil -------------------------------------------------------------------------
        coil_model = ExcitationCoilModel()
        sim.get_model_manager().add_model(coil_model)

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

    def magnetic_flux_density_z(self, x, y):
        """Complex B_z [mT] at (x, y, 0.034); the sign of the real part follows [1]."""
        b_real = mufem.ProbeReport.SinglePoint(
            name="MagneticFluxDensityRealReport",
            cff_name="Magnetic Flux Density-Real",
            x=x,
            y=y,
            z=0.034,
        ).evaluate()
        b_imag = mufem.ProbeReport.SinglePoint(
            name="MagneticFluxDensityImagReport",
            cff_name="Magnetic Flux Density-Imag",
            x=x,
            y=y,
            z=0.034,
        ).evaluate()

        return 1e3 * (-b_real.z + 1j * b_imag.z)

    def validate(self):
        # B_z along the measurement lines at z = 34 mm: (name, y [m]); x in mm, B_z in mT.
        probe_lines = [("A1-B1", 0.072), ("A2-B2", 0.144)]
        x_values = numpy.linspace(start=0.0, stop=0.288, num=128)
        self.b_lines = {
            name: [(1e3 * x, self.magnetic_flux_density_z(x, y)) for x in x_values]
            for name, y in probe_lines
        }

        # Peak of the measured B_z on A1-B1 at x = 126 mm: 78.11 x 0.1 mT.
        b_peak = self.magnetic_flux_density_z(0.126, 0.072)
        expect(b_peak.real, 7.811, rel_tol=5e-2, label="Bz at x = 126 mm on A1-B1 [mT]")

    def postprocess(self):
        if self.is_main():
            for name, b_values in self.b_lines.items():
                self.plot_line(name, b_values)

        # ParaView export (collective) ------------------------------------------------
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Magnetic Flux Density-Real")
        vis.add_field_output("Magnetic Flux Density-Imag")
        vis.add_field_output("Electric Current Density-Real")
        vis.add_field_output("Electric Current Density-Imag")
        vis.save(order=3)

    def plot_line(self, name, b_values):
        x = [x_value for x_value, _ in b_values]
        b = numpy.array([b_value for _, b_value in b_values])

        # Measured values in units of 0.1 mT at wt = 0 and wt = 90 degrees.
        ref = numpy.loadtxt(self.dir_path / "data" / f"Bz_{name}.csv", delimiter=",", comments="#")

        plt.clf()
        plt.plot(ref[:, 1], 1.0e-1 * ref[:, 2], "ko-", markersize=6.0, linewidth=2.0)
        plt.plot(
            ref[:, 1], 1.0e-1 * ref[:, 3], "ko-", label="Reference", markersize=6.0, linewidth=2.0
        )
        plt.plot(x, b.real, label="$\\mu$fem (Real)", color="r", linewidth=3.0)
        plt.plot(x, b.imag, label="$\\mu$fem (Imag)", color="b", linewidth=3.0)

        plt.xlabel("Position [mm]")
        plt.ylabel("Magnetic Flux Density [mT]")
        plt.title(f"Magnetic Flux Density at {name}")
        plt.xlim((0, 288))
        plt.xticks([0, 72, 144, 216, 288])
        plt.legend(loc="best").draw_frame(False)

        plt.savefig(self.results_path / f"Magnetic_Flux_Density-{name}.png", bbox_inches="tight")

        # Used by create_scene.py for the animation.
        numpy.savetxt(
            self.results_path / f"Bz_{name}_mufem.csv",
            numpy.c_[x, b.real, b.imag],
            delimiter=",",
            header="x [mm], Bz [mT]",
        )


if __name__ == "__main__":
    Team7AsymmetricalConductor().run()
