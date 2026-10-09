from casekit import ValidationCase, expect, run_case

# numpy must be imported before mufem (see casekit/plots.py).
import matplotlib.pyplot as plt
import numpy

from mufem import Bnd, Simulation, SteadyRunner, Vol
from mufem.electromagnetics.timeharmonicmaxwell import (
    PerfectElectricConductorCondition,
    SParametersReport,
    TimeHarmonicMaxwellGeneralMaterial,
    TimeHarmonicMaxwellModel,
    WaveguideInputPortCondition,
    WaveguideOutputPortCondition,
)


class MontejoGarai1995CavityFilter(ValidationCase):
    name = "Montejo-Garai 1995: Circular Cavity Filter"
    tags = {"moderate", "mumps"}  # TimeHarmonicMaxwell needs a direct solver

    # True scans 501 frequencies and regenerates data/S21_precalculated.csv; the default
    # run solves only the frequencies of the checks and the two at which the field is
    # visualized.
    precalculate = False

    # [Hz] frequencies at which the field is visualized
    visualized_frequencies = (12e9, 14e9)

    # Measured passband points of Montejo-Garai and Zapata (1995), Fig. 2, checked
    # against the computed |S21|.
    checked_frequencies = (13.637e9, 13.841e9, 14.038e9, 14.240e9, 14.441e9)

    @property
    def mesh_path(self):
        # gmsh picks the output format from the file extension.
        return self.dir_path / "geometry.msh"

    def build_geometry(self):
        import gmsh

        gmsh.initialize()

        # WR75 waveguide:
        wr75_width = 19.05e-3
        wr75_height = 9.525e-3
        wr75_length = 20e-3

        # Coupling iris:
        iris_width = 9.7e-3
        iris_height = 3e-3
        iris_length = 1e-3

        # Circular cavity:
        cavity_radius = 12e-3
        cavity_length = 100e-3

        # Waveguide, iris, cavity, iris, waveguide along z, fused into one volume ------
        occ = gmsh.model.occ
        z = 0

        input_waveguide = occ.addBox(0, 0, 0, wr75_width, wr75_height, wr75_length)
        occ.translate([(3, input_waveguide)], -wr75_width / 2, -wr75_height / 2, z)
        z = z + wr75_length

        input_iris = occ.addBox(0, 0, 0, iris_width, iris_height, iris_length)
        occ.translate([(3, input_iris)], -iris_width / 2, -iris_height / 2, z)
        z = z + iris_length

        cavity = occ.addCylinder(0, 0, 0, 0, 0, cavity_length, cavity_radius)
        occ.translate([(3, cavity)], 0, 0, z)
        z = z + cavity_length

        output_iris = occ.addBox(0, 0, 0, iris_width, iris_height, iris_length)
        occ.translate([(3, output_iris)], -iris_width / 2, -iris_height / 2, z)
        z = z + iris_length

        output_waveguide = occ.addBox(0, 0, 0, wr75_width, wr75_height, wr75_length)
        occ.translate([(3, output_waveguide)], -wr75_width / 2, -wr75_height / 2, z)
        z = z + wr75_length

        occ.fuse(
            [(3, input_waveguide)],
            [(3, input_iris), (3, cavity), (3, output_iris), (3, output_waveguide)],
        )
        occ.synchronize()

        gmsh.write(f"{self.step_path}")

        # The port faces at z = 0 and z = end; all other faces are walls ----------------
        eps = 0.1e-3

        def port_at(z_port):
            return gmsh.model.getEntitiesInBoundingBox(
                -wr75_width / 2 - eps,
                -wr75_height / 2 - eps,
                z_port - eps,
                +wr75_width / 2 + eps,
                +wr75_height / 2 + eps,
                z_port + eps,
                2,
            )[0][1]

        input_port = port_at(0.0)
        output_port = port_at(z)
        walls = [
            tag for _, tag in gmsh.model.getEntities(2) if tag not in [input_port, output_port]
        ]

        self.physical_groups = {
            "InputPort": (2, [input_port]),
            "OutputPort": (2, [output_port]),
            "Walls": (2, walls),
            "Domain": (3, [tag for _, tag in gmsh.model.getEntities(3)]),
        }

        gmsh.finalize()

    def generate_mesh(self):
        from casekit.gmsh_meshing import mesh_and_save

        mesh_and_save(
            self.step_path,
            self.physical_groups,
            path=self.mesh_path,
            options={
                "Mesh.MeshSizeMax": 4e-3,
                "Mesh.MeshSizeFromCurvature": 10,
                "Mesh.ElementOrder": 2,
                # Optimize the curved elements without the elastic step (value 2): that
                # step uses the PETSc built into gmsh, which clashes with mufem's MPI.
                "Mesh.HighOrderOptimize": 1,
            },
        )

    def setup_case(self):
        sim = Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        self.runner = SteadyRunner(total_iterations=0)
        sim.set_runner(self.runner)

        # Model and material -----------------------------------------------------------
        self.model = TimeHarmonicMaxwellModel(
            marker="Domain" @ Vol,
            frequency=14.5e9,  # [Hz] radiation frequency
            order=2,  # finite element polynomial degree
        )
        sim.get_model_manager().add_model(self.model)

        material_air = TimeHarmonicMaxwellGeneralMaterial.Constant(
            name="Air",
            marker="Domain" @ Vol,
        )
        self.model.add_material(material_air)

        # Boundary conditions ----------------------------------------------------------
        condition_pec = PerfectElectricConductorCondition(
            name="PEC",
            marker="Walls" @ Bnd,
        )

        condition_input_port = WaveguideInputPortCondition(
            name="Input",
            marker="InputPort" @ Bnd,
            mode_index=0,  # index of the mode that will be launched from the input port
        )

        condition_output_port = WaveguideOutputPortCondition(
            name="Output",
            marker="OutputPort" @ Bnd,
        )

        self.model.add_conditions([condition_pec, condition_input_port, condition_output_port])

        # Reports ----------------------------------------------------------------------
        self.report_s_parameters = SParametersReport(
            name="S-parameters",
            condition=condition_output_port,
            nmodes=1,  # number of modes to be calculated for the report
        )
        sim.get_report_manager().add_report(self.report_s_parameters)

        return sim

    def solve(self):
        if self.precalculate:
            self.frequencies = numpy.linspace(10e9, 15e9, 501)  # [Hz]
        else:
            self.frequencies = numpy.array(
                sorted(self.visualized_frequencies + self.checked_frequencies)
            )
            vis = self.sim.get_field_exporter()
            vis.add_field_output("Electric Field-Real")

        self.s21 = numpy.zeros(len(self.frequencies), dtype=complex)

        for i, frequency in enumerate(self.frequencies):
            if self.is_main():
                print(f"\nFrequency {i + 1}/{len(self.frequencies)}: {frequency / 1e9:.3f}GHz")

            self.model.set_frequency(frequency)
            self.runner.advance(1)

            if not self.precalculate and frequency in self.visualized_frequencies:
                vis.save(order=2)

            self.s21[i] = self.report_s_parameters.evaluate().to_numpy()[0, 0]

    def validate(self):
        if self.precalculate:
            return

        # |S21| in the passband against the measurement of Montejo-Garai and Zapata (1995).
        # In the stopband the computed transmission lies 1-3 dB below the measurement, as
        # does the finite element result of Liu et al. (2002).
        measured = numpy.loadtxt(
            self.dir_path / "data" / "Montejo-Garai_1995.csv", delimiter=",", comments="#"
        )
        for frequency in self.checked_frequencies:
            s21 = self.s21[list(self.frequencies).index(frequency)]
            expect(
                20 * numpy.log10(abs(s21)),
                measured[numpy.argmin(abs(measured[:, 0] - frequency / 1e9)), 1],
                abs_tol=0.5,
                label=f"|S21| at {frequency / 1e9:.3f} GHz [dB]",
            )

    def postprocess(self):
        if not self.is_main():
            return

        if self.precalculate:
            numpy.savetxt(
                self.dir_path / "data" / "S21_precalculated.csv",
                numpy.column_stack((self.frequencies, self.s21.real, self.s21.imag)),
                delimiter=", ",
                comments="# ",
                header="Frequency [Hz], Real(S21), Imag(S21)",
            )

        plt.clf()

        # Reference data:
        data = numpy.loadtxt(self.dir_path / "data" / "Montejo-Garai_1995.csv", delimiter=",")
        plt.plot(
            data[:, 0], data[:, 1], "k^", label="Montejo-Garai 1995 (measured)", markersize=10
        )

        # Precalculated spectrum:
        precalculated = self.load_precalculated()
        s21_dB = 10 * numpy.log10(numpy.abs(precalculated[:, 1] + 1j * precalculated[:, 2]) ** 2)
        plt.plot(precalculated[:, 0] / 1e9, s21_dB, label="$\\mu$fem (precalculated)", color="red")

        # Simulated data:
        s21_dB = 10 * numpy.log10(numpy.abs(self.s21) ** 2)
        plt.plot(
            self.frequencies / 1e9, s21_dB, "*", label="$\\mu$fem", color="blue", markersize=12
        )

        plt.legend(loc="best", frameon=False)
        plt.xlabel("Frequency [GHz]")
        plt.ylabel("|S21|$^2$ [dB]")
        plt.savefig(self.results_path / "S21_vs_frequency.png", bbox_inches="tight")

    def load_precalculated(self):
        return numpy.loadtxt(
            self.dir_path / "data" / "S21_precalculated.csv", delimiter=",", comments="#"
        )


if __name__ == "__main__":
    run_case(MontejoGarai1995CavityFilter)
