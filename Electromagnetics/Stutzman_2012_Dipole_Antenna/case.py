from casekit import ValidationCase, expect, run_case

# numpy must be imported before mufem (see casekit/plots.py).
import matplotlib.pyplot as plt
import numpy

from mufem import Bnd, Simulation, SteadyRunner, Vol
from mufem.electromagnetics.timeharmonicmaxwell import (
    AbsorbingBoundaryCondition,
    FarFieldRadiationSensor,
    LumpedPortCondition,
    PerfectElectricConductorCondition,
    TimeHarmonicMaxwellGeneralMaterial,
    TimeHarmonicMaxwellModel,
)


class Stutzman2012DipoleAntenna(ValidationCase):
    name = "Stutzman 2012: Dipole Antenna"
    tags = {"moderate", "mumps"}  # TimeHarmonicMaxwell needs a direct solver

    wavelength = 4.0  # [m]

    @property
    def mesh_path(self):
        # gmsh picks the output format from the file extension.
        return self.dir_path / "geometry.msh"

    def build_geometry(self):
        import gmsh

        gmsh.initialize()

        arm_length = self.wavelength / 4
        arm_radius = arm_length / 20
        gap_size = arm_length / 100
        outer_boundary_radius = 1.5 * self.wavelength

        # Air sphere without the two arms, with the port strip in the gap --------------
        occ = gmsh.model.occ

        air = occ.addSphere(0, 0, 0, outer_boundary_radius)
        top_arm = occ.addCylinder(0, 0, gap_size / 2, 0, 0, arm_length, arm_radius)
        bot_arm = occ.addCylinder(0, 0, -gap_size / 2, 0, 0, -arm_length, arm_radius)

        port = occ.addRectangle(-arm_radius, -gap_size / 2, 0, 2 * arm_radius, gap_size)
        occ.rotate([(2, port)], 0, 0, 0, 1, 0, 0, numpy.pi / 2)

        domain, _ = occ.cut([(3, air)], [(3, top_arm), (3, bot_arm)])
        occ.synchronize()

        # The port strip is written as a separate face: embedded in the solid it would be
        # lost in the STEP file. mesh_and_save embeds it again like the fragment below.
        gmsh.write(f"{self.step_path}")

        occ.fragment(domain, [(2, port)])
        occ.synchronize()

        # Classify the faces by their bounding boxes -----------------------------------
        eps = 1e-3 * gap_size
        groups = {"BoundaryTopArm": [], "BoundaryBotArm": [], "Port": [], "BoundaryOuter": []}

        for _, tag in gmsh.model.getEntities(2):
            _, _, z_min, _, _, z_max = gmsh.model.getBoundingBox(2, tag)
            if z_max - z_min > 2 * arm_length:
                groups["BoundaryOuter"].append(tag)
            elif z_min > gap_size / 2 - eps:
                groups["BoundaryTopArm"].append(tag)
            elif z_max < -gap_size / 2 + eps:
                groups["BoundaryBotArm"].append(tag)
            else:
                groups["Port"].append(tag)

        self.physical_groups = {
            "Domain": (3, [tag for _, tag in gmsh.model.getEntities(3)]),
            **{name: (2, tags) for name, tags in groups.items()},
        }

        gmsh.finalize()

    def generate_mesh(self):
        from casekit.gmsh_meshing import mesh_and_save

        mesh_and_save(
            self.step_path,
            self.physical_groups,
            path=self.mesh_path,
            options={
                "Mesh.MeshSizeMax": self.wavelength / 5,
                "Mesh.MeshSizeFromCurvature": 12,
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

        sim.set_runner(SteadyRunner(total_iterations=1))

        # Model and material -----------------------------------------------------------
        model = TimeHarmonicMaxwellModel(
            marker="Domain" @ Vol,
            frequency=0.0749e9,  # [Hz]
            order=2,  # finite element polynomial degree
        )
        sim.get_model_manager().add_model(model)

        material_air = TimeHarmonicMaxwellGeneralMaterial.Constant(
            name="Air",
            marker="Domain" @ Vol,
        )
        model.add_material(material_air)

        # Boundary conditions ----------------------------------------------------------
        condition_outer = AbsorbingBoundaryCondition(
            name="AirBoundary",
            marker="BoundaryOuter" @ Bnd,
        )

        condition_arms = PerfectElectricConductorCondition(
            name="PEC",
            marker=["BoundaryTopArm", "BoundaryBotArm"] @ Bnd,
        )

        port_width = 0.10  # [m]
        port_length = 0.04  # [m]
        impedance = 50  # [Ohm] transmission line impedance
        condition_port = LumpedPortCondition(
            name="Port",
            marker="Port" @ Bnd,
            surface_impedance=impedance * port_width / port_length,  # [Ohm]
            incident_electric_field_vector=(0, 0, 1),
        )

        model.add_conditions([condition_outer, condition_arms, condition_port])

        # Field output -----------------------------------------------------------------
        vis = sim.get_field_exporter()
        vis.add_field_output("Electric Field-Real")
        vis.add_field_output("Electric Field-Imag")
        vis.add_field_output("Magnetic Field-Real")
        vis.add_field_output("Magnetic Field-Imag")

        return sim

    def solve(self):
        self.sim.run()
        self.sim.get_field_exporter().save(order=2)

        sensor = FarFieldRadiationSensor(
            "FarFieldRadiationSensor",
            polar_start=0.0,
            polar_stop=180.0,
            polar_step=6.0,
            azimuthal_start=0.0,
            azimuthal_stop=360.0,
            azimuthal_step=6.0,
        )
        self.thetas = numpy.array(sensor.get_polar_angles())
        self.phis = numpy.array(sensor.get_azimuthal_angles())
        radiation_pattern = numpy.array(sensor.get_radiation_pattern())
        self.radiation_pattern = radiation_pattern / numpy.max(radiation_pattern)

        # E-plane (phi = 0) and H-plane (theta = 90 deg) cross-sections, each normalized.
        eplane = self.radiation_pattern[:, numpy.argmin(numpy.abs(self.phis))]
        hplane = self.radiation_pattern[numpy.argmin(numpy.abs(self.thetas - numpy.pi / 2)), :]
        self.eplane = eplane / numpy.max(eplane)
        self.hplane = hplane / numpy.max(hplane)

    def eplane_analytic(self, thetas):
        """Half-wave dipole far field |cos(pi/2 cos(theta)) / sin(theta)| [3]."""
        sin = numpy.maximum(numpy.sin(thetas), 1e-6)  # the pattern vanishes along the arms
        return numpy.abs(numpy.cos(numpy.pi / 2 * numpy.cos(thetas)) / sin)

    def validate(self):
        # E-plane against the analytical pattern of a thin dipole, away from the nulls
        # along the arms. The thick arms (radius L/20) lower the pattern towards the
        # arms, by about 6% at 30 and 150 deg.
        for theta_deg in [30, 60, 90, 120, 150]:
            i = numpy.argmin(numpy.abs(self.thetas - numpy.radians(theta_deg)))
            expect(
                self.eplane[i],
                float(self.eplane_analytic(self.thetas[i])),
                rel_tol=1e-1,
                label=f"E-plane pattern at theta = {theta_deg} deg",
            )

        # The H-plane pattern of the dipole is uniform; the port strip breaks the
        # rotational symmetry by about 2%.
        expect(numpy.min(self.hplane), 1.0, rel_tol=5e-2, label="H-plane pattern minimum")

    def postprocess(self):
        if not self.is_main():
            return

        # 3D pattern for paraview_radiation_pattern.py.
        numpy.savez(
            self.results_path / "Far_Field_3D.npz",
            thetas=self.thetas,
            phis=self.phis,
            radiation_pattern=self.radiation_pattern,
        )

        def to_db(value):
            # 20 log10 for the field amplitude, clipped at -200 dB.
            value = numpy.maximum(value, numpy.max(value) * 1e-10)
            value_db = 20 * numpy.log10(value)
            return value_db - numpy.max(value_db)

        # The E-plane over the full circle: theta in [0, pi] and its mirror image.
        thetas_full = numpy.concatenate((self.thetas, self.thetas + numpy.pi))
        eplane_full = numpy.concatenate((self.eplane, self.eplane[::-1]))
        eplane_analytic = self.eplane_analytic(self.thetas)
        eplane_analytic_full = numpy.concatenate((eplane_analytic, eplane_analytic[::-1]))

        cross_sections = [
            ("E-plane", thetas_full, eplane_analytic_full, eplane_full),
            ("H-plane", self.phis, numpy.ones(len(self.phis)), self.hplane),
        ]

        for title, angles, analytic, simulated in cross_sections:
            fig, ax = plt.subplots(subplot_kw={"projection": "polar"})
            ax.set_theta_zero_location("N")
            ax.set_theta_direction(-1)
            ax.plot(angles, to_db(analytic), "k-", label="Analytic")
            ax.plot(angles, to_db(simulated), "r-", label="$\\mu$fem")
            ax.set_ylim(-12, 2)
            ax.set_yticks([-10, -8, -6, -4, -2, 0])
            ax.legend(loc="lower center", bbox_to_anchor=(0.5, 0.12))
            ax.set_title(title, fontweight="bold")
            fig.savefig(self.results_path / f"Far_Field_{title}.png", bbox_inches="tight")
            plt.close(fig)


if __name__ == "__main__":
    run_case(Stutzman2012DipoleAntenna)
