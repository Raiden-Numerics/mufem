from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot

import numpy

import mufem
from mufem import Bnd, Vol
from mufem.electromagnetics.coil import (
    CoilExcitationCurrent,
    CoilSpecification,
    CoilTopologyOpen,
    CoilTypeStranded,
    ExcitationCoilModel,
)
from mufem.electromagnetics.timedomainmagnetic import (
    MagneticForceReport,
    TangentialMagneticFluxBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)


class Team20StaticForce(ValidationCase):
    name = "Compumag TEAM 20: 3-D Static Force Problem"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import ArcOfCircle, Box, Face, Glue, Pnt, Segment, Vec, Wire, X, Y, Z

        from casekit.colors import color_air, color_copper, color_iron
        from casekit.netgen_geometry import name_body, polygon_face

        # Quarter model: X = 0 and Y = 0 are symmetry planes.

        # Yoke -------------------------------------------------------------------------
        yoke_face = polygon_face(
            [
                (0.0, 0.0, 0.0),
                (0.0635, 0.0, 0.0),
                (0.0635, 0.0, 0.150),
                (0.0135, 0.0, 0.150),
                (0.0135, 0.0, 0.125),
                (0.0385, 0.0, 0.125),
                (0.0385, 0.0, 0.025),
                (0.0, 0.0, 0.025),
            ]
        )
        yoke = yoke_face.Extrude(0.025 / 2, Y)

        name_body(yoke, "Yoke", color=color_iron, individual_names=False)
        yoke.faces.Min(Y).name = "Yoke::TangentialFlux"
        yoke.faces.Min(X).name = "Yoke::TangentialFlux"

        # Pole -------------------------------------------------------------------------
        z_pole = 0.025 + 0.0015
        pole_face = polygon_face(
            [
                (0.0, 0.0, z_pole),
                (0.0125, 0.0, z_pole),
                (0.0125, 0.0, z_pole + 0.0985),
                (0.0, 0.0, z_pole + 0.0985),
            ]
        )
        pole = pole_face.Extrude(0.010 / 2, Y)

        name_body(pole, "Pole", color=color_iron, individual_names=False)
        pole.faces.Min(Y).name = "Pole::TangentialFlux"
        pole.faces.Min(X).name = "Pole::TangentialFlux"

        # Coil (quarter of a rounded square annulus) -----------------------------------
        # Extrude the outer and inner quarter squares before subtracting: the top face of
        # an extruded face with arcs loses its name in WriteStep.
        coil_height = 0.100 - 2 * 0.0017

        def rounded_quarter_square(size, radius):
            pnt0 = Pnt(0, 0, 0)
            pnt1 = Pnt(size, 0, 0)
            pnt2 = Pnt(size, size - radius, 0)
            pnt3 = Pnt(size - radius, size, 0)
            pnt4 = Pnt(0, size, 0)

            wire = Wire(
                [
                    Segment(pnt0, pnt1),
                    Segment(pnt1, pnt2),
                    ArcOfCircle(pnt2, Vec(0, 1, 0), pnt3),
                    Segment(pnt3, pnt4),
                    Segment(pnt4, pnt0),
                ]
            )
            return Face(wire).Extrude(coil_height, Z)

        coil = rounded_quarter_square(0.075 / 2.0, 0.023) - rounded_quarter_square(
            0.039 / 2.0, 0.005
        )
        coil = coil.Move((0.025 + 0.0017) * Z)

        name_body(coil, "Coil", color=color_copper, individual_names=False)
        coil.faces.Min(Y).name = "Coil::In"
        coil.faces.Min(X).name = "Coil::Out"

        # Air --------------------------------------------------------------------------
        air = Box(Pnt(0, 0, -0.1), Pnt(0.2, 0.25, 0.25))
        name_body(air, "Air", color=color_air, individual_names=False)

        air = air - yoke - pole - coil

        air.faces.Min(Y).name = "Air::TangentialFlux"
        air.faces.Min(X).name = "Air::TangentialFlux"

        # Mesh sizes -------------------------------------------------------------------
        pole.faces.maxh = 0.001
        yoke.faces.maxh = 0.0025
        coil.faces.maxh = 0.0025

        geometry = Glue([air, yoke, pole, coil])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=5.0e-2, path=self.mesh_path)

    def create_geometry_image(self):
        # The isometric view of create_scenes() onto the symmetry planes x = 0 and y = 0, with
        # the bodies labeled.
        from netgen.occ import OCCGeometry

        from casekit.netgen_image import Labels, snapshot, trim

        solids = OCCGeometry(f"{self.step_path}").shape.solids
        image = trim(image=snapshot(shapes=solids, direction=(-1, -1, 1), up=(0, 0, 1)))

        labels = Labels(image=image)
        labels.text(position=(200, 300), text="Air")
        for text, position, anchor, start, end in [
            ("Coil", (280, 690), "rm", (290, 690), (352, 690)),
            ("Yoke", (590, 600), "lm", (580, 600), (512, 620)),
            ("Pole", (625, 880), "lm", (615, 875), (420, 760)),
        ]:
            labels.text(position=position, text=text, anchor=anchor)
            labels.arrow(start=start, end=end)

        image.save(self.dir_path / "data" / "Geometry.png")

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        self.runner = mufem.SteadyRunner(total_iterations=0)
        sim.set_runner(self.runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeDomainMagneticModel(order=1)
        sim.get_model_manager().add_model(magnetic_model)

        # Materials --------------------------------------------------------------------
        air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

        copper_material = TimeDomainMagneticGeneralMaterial(
            name="Copper", marker="Coil" @ Vol, electric_conductivity=1.0e7
        )

        bh = numpy.loadtxt(
            self.dir_path / "data" / "Table_1_BH_Curve.csv", delimiter=",", comments="#"
        )

        iron_material = TimeDomainMagneticGeneralMaterial(
            name="Iron",
            marker=["Yoke", "Pole"] @ Vol,
            magnetic_permeability=(bh[:, 1], bh[:, 0]),
            has_eddy_currents=False,
        )

        magnetic_model.add_materials([air_material, copper_material, iron_material])

        # Boundary conditions ----------------------------------------------------------
        tangential_magnetic_flux_bc = TangentialMagneticFluxBoundaryCondition(
            name="TangentialFlux",
            marker=[
                "Yoke::TangentialFlux",
                "Pole::TangentialFlux",
                "Coil::In",
                "Coil::Out",
                "Air::TangentialFlux",
            ]
            @ Bnd,
        )
        magnetic_model.add_condition(tangential_magnetic_flux_bc)

        # Coil -------------------------------------------------------------------------
        coil_model = ExcitationCoilModel()
        sim.get_model_manager().add_model(coil_model)

        coil_topology = CoilTopologyOpen(in_marker="Coil::In" @ Bnd, out_marker="Coil::Out" @ Bnd)
        coil_type = CoilTypeStranded(number_of_turns=1000)

        self.coil_drive_current = mufem.CffConstantScalar(1.0)
        coil_excitation = CoilExcitationCurrent(current=self.coil_drive_current)

        coil = CoilSpecification(
            name="Coil",
            marker="Coil" @ Vol,
            topology=coil_topology,
            type=coil_type,
            excitation=coil_excitation,
        )
        coil_model.add_coil_specification(coil)

        # Reports ----------------------------------------------------------------------
        self.pole_force_report = MagneticForceReport(name="Pole Force", marker="Pole" @ Vol)
        sim.get_report_manager().add_report(self.pole_force_report)

        # Flux density in the gap below the pole: mid-point P1 and edge P2 of
        # Takahashi (1995).
        self.gap_field_reports = {
            name: mufem.ProbeReport.SinglePoint(
                f"Gap Field {name}", "Magnetic Flux Density", x=x, y=y, z=0.02575
            )
            for name, x, y in [("P1", 0.0, 0.0), ("P2", 0.0125, 0.005)]
        }

        # Field export, saved at the end of solve(), for the scenes of create_scenes()
        field_exporter = sim.get_field_exporter()
        field_exporter.add_field_output("Magnetic Flux Density")
        field_exporter.add_field_output("Electric Current Density")
        field_exporter.set_order(1)

        return sim

    def solve(self):
        # Current scan; the quarter model gives a quarter of the (attractive, -z) force.
        self.pole_force = []
        self.gap_field = []

        for coil_current in numpy.linspace(0.0, 5.0, 11):
            self.coil_drive_current.set_value(coil_current)

            self.runner.advance(5)

            self.pole_force.append((coil_current, -4.0 * self.pole_force_report.evaluate().z))
            self.gap_field.append(
                {name: report.evaluate().z for name, report in self.gap_field_reports.items()}
            )

        # The runner is advanced by hand, so no Event.RunCompletion fires: the fields at the
        # end of the run for the scenes of create_scenes() (collective).
        if self.field_export:
            self.sim.get_field_exporter().save()

    def validate(self):
        force = dict(self.pole_force)

        # Measured force (Takahashi (1995), Table 6); 1000 turns, so the current in A is the
        # AT / 1000.
        for coil_current, measured_force in [(1.0, 8.1), (3.0, 54.4), (4.5, 75.0), (5.0, 80.1)]:
            expect(
                force[coil_current],
                measured_force,
                rel_tol=5e-2,
                label=f"pole force at {1000 * coil_current:.0f} AT [N]",
            )

        # Measured Bz in the gap at 5000 AT (Takahashi (1995), Table 4); at the edge P2,
        # where the field changes abruptly, calculation and measurement are less accurate.
        expect(self.gap_field[-1]["P1"], 1.03, rel_tol=5e-2, label="Bz at P1 at 5000 AT [T]")
        expect(self.gap_field[-1]["P2"], 0.74, rel_tol=1e-1, label="Bz at P2 at 5000 AT [T]")

    def postprocess(self):
        if self.is_main():
            xy_plot(
                values=self.pole_force,
                style=PlotStyle.LINE_AND_POINTS,
                reference_file=f"{self.dir_path}/data/ReferenceForce.csv",
                reference_style=PlotStyle.POINTS,
                reference_label="Takahashi (1994)",
                xlabel="Coil Current [A]",
                ylabel="Pole Force [N]",
                xlim=(0.0, 5.4),
                ylim=(0, 90),
                yticks=[0, 20, 40, 60, 80],
                path=f"{self.results_path / 'Force_vs_Current.png'}",
            )

    def create_scenes(self):
        # Both images use the isometric view along (-1, -1, 1) onto the symmetry planes x = 0
        # and y = 0, with z up, as data/Geometry.png.
        from casekit.pyvista_scene import FieldExportReader, add_colorbar, create_scene

        reader = FieldExportReader(self.dir_path)
        bodies = reader.read()

        # Mesh of all bodies.
        scene = create_scene((1100, 1600))
        iron, copper, air = (0.6, 0.6, 0.6), (0.72, 0.45, 0.2), (0.96, 0.89, 0.83)
        for name, color in {"Air": air, "Yoke": iron, "Pole": iron, "Coil": copper}.items():
            scene.add_mesh(bodies[name], color=color, show_edges=True)
        scene.view_vector((-1, -1, 1), viewup=(0, 0, 1))
        scene.camera.zoom(1.4)  # the default fit leaves room for any rotation
        scene.show(screenshot=self.results_path / "Scene_Mesh.png")

        # Magnetic flux density in the yoke, the pole and the coil.
        # The window leaves room on both sides, for the color bar on the right.
        scene = create_scene((1100, 1200))
        bodies = reader.read(hide=["Air"])
        actor = scene.add_mesh(bodies, scalars="Magnetic Flux Density", clim=(0.0, 2.5))
        scene.view_vector((-1, -1, 1), viewup=(0, 0, 1))
        add_colorbar(scene, actor, "Magnetic Flux Density [T]", n_labels=6)
        scene.show(screenshot=self.results_path / "Scene_Magnetic_Flux_Density.png")


if __name__ == "__main__":
    run_case(Team20StaticForce)
