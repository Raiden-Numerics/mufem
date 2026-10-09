from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot

# numpy must be imported before mufem (see casekit/plots.py).
import matplotlib.pyplot as plt
import numpy

from mufem import (
    Bnd,
    Everywhere,
    RefinementModel,
    Simulation,
    SteadyRunner,
    Vol,
    VolumeIntegralReport,
)
from mufem.electromagnetics.electrostatics import (
    ElectricPotentialCondition,
    ElectrostaticMaterial,
    ElectrostaticsModel,
)


class Ren2014MemsCombDrive(ValidationCase):
    name = "Ren 2014: MEMS Comb Drive"
    # The meshes of all shifts (about 22 MB) are not shipped: they must be built first
    # with --rebuild-mesh.
    tags = {"long", "rebuild_mesh"}

    # [um] shifts of the combs apart from each other, one mesh each
    xshifts = [0.5 * k for k in range(17)]

    voltage = 1.0  # [V]

    def step_path_for(self, xshift):
        return self.dir_path / f"geometry_xshift={xshift:.1f}.step"

    def mesh_path_for(self, xshift):
        return self.dir_path / f"geometry_xshift={xshift:.1f}.msh"

    def build_geometry(self):
        import gmsh

        self.physical_groups = {}

        for xshift in self.xshifts:
            gmsh.initialize()
            occ = gmsh.model.occ

            # Air box around the combs; its bottom face is the ground plate -------------
            ground_y = -6
            air = occ.addBox(11 - 44, ground_y, 17 - 44, 88, 44, 88)

            def comb(boxes, dx):
                tags = [occ.addBox(x + dx, y, z, lx, ly, lz) for x, y, z, lx, ly, lz in boxes]
                return occ.fuse([(3, tags[0])], [(3, tag) for tag in tags[1:]])[0]

            # Comb 1 with four teeth and comb 2 with three, shifted apart by xshift.
            comb1 = comb(
                [(0, 0, 0, 5, 4, 34)] + [(0, 0, 10 * k, 15, 4, 4) for k in range(4)], -xshift / 2
            )
            comb2 = comb(
                [(17, 0, 0, 5, 4, 34)] + [(7, 0, 5 + 10 * k, 15, 4, 4) for k in range(3)],
                +xshift / 2,
            )
            occ.synchronize()

            # The cut keeps the comb faces, so they are recognized by their bounding boxes.
            def bounding_boxes(volume):
                return [
                    gmsh.model.getBoundingBox(*face) for face in gmsh.model.getBoundary(volume)
                ]

            comb_faces = {"Comb1": bounding_boxes(comb1), "Comb2": bounding_boxes(comb2)}

            occ.cut([(3, air)], comb1 + comb2)
            occ.synchronize()

            gmsh.write(f"{self.step_path_for(xshift)}")

            # Classify the faces as mesh_and_save numbers them: the STEP import renumbers
            # the faces left after the cut.
            gmsh.clear()
            occ.importShapes(f"{self.step_path_for(xshift)}")
            occ.synchronize()

            eps = 1e-6
            groups = {"Comb1": [], "Comb2": [], "Ground": []}

            for _, tag in gmsh.model.getEntities(2):
                box = gmsh.model.getBoundingBox(2, tag)
                for name, boxes in comb_faces.items():
                    if any(numpy.allclose(box, other, atol=eps) for other in boxes):
                        groups[name].append(tag)
                if box[4] < ground_y + eps:
                    groups["Ground"].append(tag)

            self.physical_groups[xshift] = {
                **{name: (2, tags) for name, tags in groups.items()},
                "Domain": (3, [tag for _, tag in gmsh.model.getEntities(3)]),
            }

            gmsh.finalize()

    def generate_mesh(self):
        from casekit.gmsh_meshing import mesh_and_save

        for xshift in self.xshifts:
            mesh_and_save(
                self.step_path_for(xshift),
                self.physical_groups[xshift],
                path=self.mesh_path_for(xshift),
                options={"Mesh.MeshSizeMax": 4},  # [um]; refined adaptively at run time
            )

    def setup_case(self):
        missing = [
            self.mesh_path_for(x) for x in self.xshifts if not self.mesh_path_for(x).exists()
        ]
        if missing:
            raise FileNotFoundError(
                f"{missing[0].name} and {len(missing) - 1} more meshes are missing: build "
                "them with pymufem case.py --rebuild-mesh"
            )

        sim = Simulation.New(name=self.name)

        self.runner = SteadyRunner(total_iterations=2)
        sim.set_runner(self.runner)

        sim.get_domain().load_mesh(f"{self.mesh_path_for(self.xshifts[0])}")
        sim.get_domain().get_mesh().scale(1e-6)  # [um] -> [m]

        self.refinement_model = RefinementModel()
        sim.get_model_manager().add_model(self.refinement_model)

        # Model and material -----------------------------------------------------------
        model = ElectrostaticsModel(order=2)
        sim.get_model_manager().add_model(model)

        # Refine the 30% of the cells with the largest error estimate.
        model.get_mesh_refiner().set_refinement_fraction(0.3)

        material = ElectrostaticMaterial("Air", Everywhere @ Vol, electric_permittivity=1.0)
        model.add_material(material)

        # Boundary conditions: 1 V on the three-tooth comb, 0 V on the four-tooth comb and
        # the ground plate, as in Fig. 3 of [1] ------------------------------------------
        condition_comb1 = ElectricPotentialCondition(
            name="Comb1", marker="Comb1" @ Bnd, electric_potential=0.0
        )

        condition_comb2 = ElectricPotentialCondition(
            name="Comb2", marker="Comb2" @ Bnd, electric_potential=self.voltage
        )

        condition_ground = ElectricPotentialCondition(
            name="Ground", marker="Ground" @ Bnd, electric_potential=0.0
        )

        model.add_conditions([condition_comb1, condition_comb2, condition_ground])

        # Reports ----------------------------------------------------------------------
        self.report = VolumeIntegralReport(
            name="Electric Energy Density Report",
            cff_name="Electric Energy Density",
        )
        sim.get_report_manager().add_report(self.report)

        return sim

    def solve(self):
        max_refinements = 10
        max_ncells = 1e5

        vis = self.sim.get_field_exporter()
        vis.add_field_output("Electric Potential")

        # (xshift [um], number of cells, capacitance [F]) for every refinement step
        self.capacitances = []

        for xshift in self.xshifts:
            self.sim.get_domain().load_mesh(f"{self.mesh_path_for(xshift)}")
            self.sim.get_domain().get_mesh().scale(1e-6)

            for i in range(max_refinements):
                self.runner.advance(2)

                if i == 0:
                    vis.save(order=2)

                ncells = self.sim.get_domain().get_mesh().get_total_number_cells()
                capacitance = 2 * self.report.evaluate() / self.voltage**2  # C = 2 W / V^2
                self.capacitances.append((xshift, ncells, capacitance))

                if ncells >= max_ncells:
                    break

                self.refinement_model.refine_mesh()
            else:
                raise RuntimeError(
                    f"No {max_ncells:.0e} cells after {max_refinements} refinements."
                )

            vis.save(order=2)

        self.capacitances = numpy.array(self.capacitances)

    def final_capacitances(self):
        """Capacitance [F] on the finest mesh of each shift."""
        return numpy.array(
            [self.capacitances[self.capacitances[:, 0] == x][-1, 2] for x in self.xshifts]
        )

    def load_reference(self):
        """Elements [10^3] and the primal and dual FEM capacitances [fF] of [1], Fig. 4."""
        return numpy.loadtxt(
            self.dir_path / "data" / "Ren_2014_Capacitance.csv", delimiter=",", comments="#"
        )

    def validate(self):
        # The capacitance of the unshifted combs must lie between the lower (dual FEM) and
        # upper (primal FEM) bound of [1] on its finest mesh of 152k elements.
        _, upper, lower = self.load_reference()[-1]
        expect(
            self.final_capacitances()[0] / 1e-15,
            (upper + lower) / 2,
            abs_tol=(upper - lower) / 2,
            label="capacitance at xshift = 0 [fF]",
        )

    def postprocess(self):
        if not self.is_main():
            return

        numpy.savetxt(
            self.results_path / "Capacitance.csv",
            self.capacitances,
            delimiter=", ",
            fmt=["%.1f", "%d", "%.10e"],
            header="xshift [um], ncells, capacitance [F]",
        )

        # Capacitance versus the number of cells for a few shifts ------------------------
        plt.clf()
        reference = self.load_reference()
        for column, marker, method in [(1, "k^--", "primal"), (2, "kv--", "dual")]:
            plt.plot(
                reference[:, 0],
                reference[:, column],
                marker,
                label=f"Ren 2014, {method} FEM (xshift = 0)",
            )

        for xshift in [0, 2, 4, 6, 8]:
            data = self.capacitances[self.capacitances[:, 0] == xshift]
            plt.plot(data[:, 1] / 1e3, data[:, 2] / 1e-15, "o-", label=f"xshift = {xshift:.1f} μm")

        plt.legend(loc="best", frameon=False)
        plt.xlabel("Number of cells [10³]")
        plt.ylabel("Capacitance [fF]")
        plt.savefig(self.results_path / "Capacitance_Vs_Ncells.png", bbox_inches="tight")

        # Capacitance versus the shift; its slope gives the comb drive force -------------
        x = numpy.array(self.xshifts) * 1e-6  # [m]
        capacitance = self.final_capacitances()

        dcdx, c0 = numpy.polyfit(x, capacitance, 1)
        force = 0.5 * dcdx * self.voltage**2  # F = 1/2 dC/dx V^2
        print(f"dC/dx = {dcdx:.3e} F/m, comb drive force F = {force / 1e-9:.3f} nN")

        xy_plot(
            values=list(zip(x / 1e-6, capacitance / 1e-15)),
            style=PlotStyle.POINTS,
            reference_values=numpy.column_stack((x / 1e-6, (dcdx * x + c0) / 1e-15)),
            reference_style=PlotStyle.LINE,
            reference_label="linear fit",
            xlabel="Shift [μm]",
            ylabel="Capacitance [fF]",
            path=f"{self.results_path / 'Capacitance_Vs_Xshift.png'}",
        )


if __name__ == "__main__":
    run_case(Ren2014MemsCombDrive)
