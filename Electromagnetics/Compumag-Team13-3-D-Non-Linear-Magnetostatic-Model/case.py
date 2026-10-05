from casekit import PlotStyle, ValidationCase, expect, xy_plot

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
from mufem.electromagnetics.timedomainmagnetic import (
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)


class Team13NonLinearMagnetostatic(ValidationCase):
    name = "Compumag Team 13: 3-D Non-Linear Magnetostatic Model"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import Axis, Box, Glue, Pnt, Vec, X, Y, Z

        from casekit.netgen_geometry import (
            color_air,
            color_copper,
            color_steel,
            name_body,
            racetrack_face,
        )

        # The plates use a 5 mm face mesh size: coarser elements at the plate edges
        # under-resolve B in the air gap along the measurement line.

        # Center plate -------------------------------------------------------------------
        center_plate = Box(Pnt(-0.0016, -0.025, 0), Pnt(+0.0016, 0.025, 0.1264 / 2))
        name_body(center_plate, "Center Plate", color=color_steel, individual_names=False)
        center_plate.faces.maxh = 0.005

        # Outer (L-shaped) plates --------------------------------------------------------
        plate_1 = Box(
            Pnt(0.0021, 0.015, 0.1264 / 2.0),
            Pnt(0.0021 + 0.12, 0.015 + 0.050, 0.1264 / 2.0 - 0.0032),
        )
        plate_2 = Box(
            Pnt(0.0021 + 0.120 - 0.0032, 0.015, 0),
            Pnt(0.0021 + 0.120, 0.015 + 0.05, 0.1264 / 2.0 - 0.0032),
        )

        outer_plate_1 = plate_1 + plate_2
        name_body(outer_plate_1, "Outer Plate 1", color=color_steel, individual_names=False)
        outer_plate_1.faces.maxh = 0.005

        outer_plate_2 = outer_plate_1.Rotate(Axis(Pnt(0, 0, 0), Vec(0, 0, 1)), 180)
        name_body(outer_plate_2, "Outer Plate 2", color=color_steel, individual_names=False)
        outer_plate_2.faces.maxh = 0.005

        # Racetrack coil -----------------------------------------------------------------
        r25 = 0.025
        r50 = 0.05

        # Extrude both racetracks before subtracting: an extruded face shares its
        # underlying shape with the base face, and WriteStep keeps only one name.
        outer_coil = racetrack_face(0.094, 0.294, 0.0, 0.2, r50).Extrude(Vec(0, 0, 0.05))
        inner_coil = racetrack_face(0.094 + r25, 0.294 - r25, r25, 0.2 - r25, r25).Extrude(
            Vec(0, 0, 0.05)
        )

        coil = outer_coil - inner_coil
        coil = coil.Move(Vec(-0.094 - 0.1, -0.1, 0))

        name_body(coil, "Coil", color=color_copper, individual_names=False)
        coil.faces.maxh = 0.02

        # Air ----------------------------------------------------------------------------
        air = Box(Pnt(0.225, -0.225, 0), Pnt(-0.225, 0.225, 0.2))
        name_body(air, "Air", color=color_air, individual_names=False)

        air = air - center_plate - outer_plate_1 - coil

        air.faces.Max(Z).name = "Air::Tangential Flux"
        air.faces.Min(X).name = "Air::Tangential Flux"
        air.faces.Max(X).name = "Air::Tangential Flux"
        air.faces.Min(Y).name = "Air::Tangential Flux"
        air.faces.Max(Y).name = "Air::Tangential Flux"

        geometry = Glue([center_plate, outer_plate_1, outer_plate_2, coil, air])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=2.5e-1, path=self.mesh_path, second_order=True)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        runner = mufem.SteadyRunner(total_iterations=12)
        sim.set_runner(runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeDomainMagneticModel(order=2)
        sim.get_model_manager().add_model(magnetic_model)

        line_search = magnetic_model.get_solver().get_line_search()
        line_search.set_active(True)
        line_search.set_iteration_window(min_iter=0, max_iter=6)

        # Materials --------------------------------------------------------------------
        air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

        copper_material = TimeDomainMagneticGeneralMaterial(
            name="Cu",
            marker="Coil" @ Vol,
            electric_conductivity=1.0e7,
            has_eddy_currents=False,
        )

        bh = numpy.loadtxt(self.dir_path / "data" / "bh_table.csv", delimiter=",", comments="#")

        iron_material = TimeDomainMagneticGeneralMaterial(
            name="Iron",
            marker=["Center Plate", "Outer Plate 1", "Outer Plate 2"] @ Vol,
            magnetic_permeability=(bh[:, 1], bh[:, 0]),
            electric_conductivity=0.0,
        )
        magnetic_model.add_materials([air_material, copper_material, iron_material])

        # Coil -------------------------------------------------------------------------
        coil_model = ExcitationCoilModel()
        sim.get_model_manager().add_model(coil_model)

        coil_topology = CoilTopologyClosed(x=0.09, y=0.0, z=0.001, dx=0.0, dy=1.0, dz=0.0)
        coil_type = CoilTypeStranded(number_of_turns=500)
        coil_excitation = CoilExcitationCurrent(current=3.0)

        coil = CoilSpecification(
            name="Coil",
            marker="Coil" @ Vol,
            topology=coil_topology,
            type=coil_type,
            excitation=coil_excitation,
        )
        coil_model.add_coil_specification(coil)

        return sim

    def validate(self):
        # |B| along the measurement line in the air gap.
        probe_report = mufem.ProbeReport.Line(
            "B",
            "Magnetic Flux Density",
            start=(0.01, 0.02, 0.055),
            end=(0.11, 0.02, 0.055),
            number_points=23,
        )
        self.flux_density = [(p.x, v.mag) for p, v in probe_report.evaluate_all()]

        # Measured |B| at x = 50 mm (Nakata & Fujiwara, Table 7).
        center_report = mufem.ProbeReport.SinglePoint(
            "Center B", "Magnetic Flux Density", x=0.05, y=0.02, z=0.055
        )
        expect(
            center_report.evaluate().mag,
            0.0283,
            rel_tol=1e-1,
            label="|B| at x = 50 mm [T]",
        )

    def postprocess(self):
        if self.is_main():
            xy_plot(
                values=self.flux_density,
                xscale=1000.0,  # m -> mm
                yscale=1000.0,  # T -> mT
                style=PlotStyle.LINE_AND_POINTS,
                reference_file=f"{self.dir_path}/data/Table7_FluxDensity.csv",
                reference_xscale=1000.0,
                reference_yscale=1000.0,
                reference_style=PlotStyle.POINTS,
                reference_label="Nakata & Fujiwara (1992)",
                xlabel="x [mm]",
                ylabel="B [mT]",
                xlim=(0.0, 120.0),
                path=f"{self.results_path / 'Magnetic_Flux_Density_Line_Air.png'}",
            )

        # ParaView export (collective) ------------------------------------------------
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Magnetic Flux Density")
        vis.add_field_output("Electric Current Density")
        vis.save(order=2)


if __name__ == "__main__":
    Team13NonLinearMagnetostatic().run()
