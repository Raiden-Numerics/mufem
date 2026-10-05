from casekit import ValidationCase, expect

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

    # True scans 251 frequencies and regenerates data/S21_precalculated.csv; the default
    # run solves only the two frequencies at which the field is visualized.
    precalculate = False

    @property
    def mesh_path(self):
        # gmsh picks the output format from the file extension.
        return self.dir_path / "geometry.msh"

    def generate_mesh(self):
        # Built and meshed with gmsh in one step: gmsh does not keep the names of the
        # ports and walls in the STEP file.
        import gmsh

        gmsh.initialize()
        gmsh.model.add("geometry")

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

        # Geometry: waveguide, iris, cavity, iris, waveguide along z ----------------------
        occ = gmsh.model.occ
        z = 0

        occ.addBox(0, 0, 0, wr75_width, wr75_height, wr75_length, 101)
        occ.translate([(3, 101)], -wr75_width / 2, -wr75_height / 2, z)
        z += wr75_length

        occ.addBox(0, 0, 0, iris_width, iris_height, iris_length, 102)
        occ.translate([(3, 102)], -iris_width / 2, -iris_height / 2, z)
        z += iris_length

        occ.addCylinder(0, 0, 0, 0, 0, cavity_length, cavity_radius, 103)
        occ.translate([(3, 103)], 0, 0, z)
        z += cavity_length

        occ.addBox(0, 0, 0, iris_width, iris_height, iris_length, 104)
        occ.translate([(3, 104)], -iris_width / 2, -iris_height / 2, z)
        z += iris_length

        occ.addBox(0, 0, 0, wr75_width, wr75_height, wr75_length, 105)
        occ.translate([(3, 105)], -wr75_width / 2, -wr75_height / 2, z)
        z += wr75_length

        occ.fuse([(3, 101)], [(3, 102), (3, 103), (3, 104), (3, 105)], 100)
        occ.synchronize()

        gmsh.write(f"{self.step_path}")

        # Physical groups: the two port faces at z = 0 and z = end, the rest are walls ---
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
            )[0]

        input_port = port_at(0.0)
        output_port = port_at(z)
        walls = [
            face for face in gmsh.model.getEntities(dim=2) if face not in [input_port, output_port]
        ]
        domain = gmsh.model.getEntities(3)[0]

        gmsh.model.addPhysicalGroup(2, [input_port[1]], name="InputPort", tag=1)
        gmsh.model.addPhysicalGroup(2, [output_port[1]], name="OutputPort", tag=2)
        gmsh.model.addPhysicalGroup(2, [face[1] for face in walls], name="Walls", tag=3)
        gmsh.model.addPhysicalGroup(3, [domain[1]], name="Domain", tag=1)

        # Second-order mesh ----------------------------------------------------------------
        gmsh.option.setNumber("Mesh.MeshSizeMax", 4e-3)
        gmsh.option.setNumber("Mesh.MeshSizeFromCurvature", 10)
        gmsh.option.setNumber("Mesh.ElementOrder", 2)
        # Optimize the curved elements without the elastic step (value 2): that step
        # uses PETSc, which clashes with mufem's PETSc in the same process.
        gmsh.option.setNumber("Mesh.HighOrderOptimize", 1)

        gmsh.model.mesh.generate(3)

        gmsh.option.setNumber("Mesh.MshFileVersion", 2.2)
        gmsh.write(f"{self.mesh_path}")

        gmsh.finalize()

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
            self.frequencies = numpy.linspace(10e9, 15e9, 251)  # [Hz]
        else:
            self.frequencies = numpy.array([12e9, 14e9])  # [Hz] frequencies to visualize
            vis = self.sim.get_field_exporter()
            vis.add_field_output("Electric Field-Real")

        self.s21 = numpy.zeros(len(self.frequencies), dtype=complex)

        for i, frequency in enumerate(self.frequencies):
            if self.is_main():
                print(f"\nFrequency {i + 1}/{len(self.frequencies)}: {frequency / 1e9:.3f}GHz")

            self.model.set_frequency(frequency)
            self.runner.advance(1)

            if not self.precalculate:
                vis.save(order=2)

            self.s21[i] = self.report_s_parameters.evaluate().to_numpy()[0, 0]

    def validate(self):
        if self.precalculate:
            return

        # |S21| against the precalculated spectrum: in the stopband (12 GHz) and the
        # passband (14 GHz) of the filter.
        precalculated = self.load_precalculated()
        for frequency, s21 in zip(self.frequencies, self.s21):
            expected = precalculated[numpy.argmin(numpy.abs(precalculated[:, 0] - frequency))]
            expect(
                abs(s21),
                abs(expected[1] + 1j * expected[2]),
                rel_tol=5e-2,
                label=f"|S21| at {frequency / 1e9:.0f} GHz",
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
        plt.plot(data[:, 0], data[:, 1], "k^", label="Montejo-Garai 1995", markersize=10)

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
        return numpy.loadtxt(self.dir_path / "data" / "S21_precalculated.csv", delimiter=",")


if __name__ == "__main__":
    MontejoGarai1995CavityFilter().run()
