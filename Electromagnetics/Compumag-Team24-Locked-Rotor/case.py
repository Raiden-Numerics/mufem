from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot

import numpy

import mufem
from mufem import Bnd, Vol
from mufem.electromagnetics.coil import (
    CoilExcitationVoltage,
    CoilSpecification,
    CoilTopologyOpen,
    CoilTypeStranded,
    ExcitationCoilCurrentReport,
    ExcitationCoilModel,
)
from mufem.electromagnetics.timedomainmagnetic import (
    MagneticTorqueReport,
    TangentialMagneticFluxBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)


class Team24LockedRotor(ValidationCase):
    name = "Compumag Team 24: Locked Rotor"
    tags = {"moderate"}

    # write fields and plots for every time step to vis/ (see paraview_gif.py)
    output_for_animation = False

    def build_geometry(self):
        from netgen.occ import Box, Cylinder, Glue, X, Y, Z, gp_Ax1, gp_Ax2, gp_Dir, gp_Pnt

        from casekit.netgen_geometry import color_air, color_copper, color_iron, name_body

        # Half model: Z = 0 is a symmetry plane.
        axis_length = 0.0254 / 2.0

        origin = gp_Pnt(0, 0, 0)
        ax_z = gp_Ax2(origin, gp_Dir(0, 0, 1))

        # Stator (outer ring with two poles) ---------------------------------------------
        outer_ring_radius = 0.209 / 2.0
        outer_ring_width = 0.0214

        outer_ring = Cylinder(ax_z, outer_ring_radius, axis_length) - Cylinder(
            ax_z, outer_ring_radius - outer_ring_width, axis_length
        )

        box = Box(gp_Pnt(-0.0278 / 2.0, -0.09, 0), gp_Pnt(0.0278 / 2.0, 0.09, axis_length))
        outer_ring = outer_ring + (box - Cylinder(ax_z, 0.1075 / 2, axis_length))

        outer_ring = outer_ring.MakeFillet([outer_ring.edges[n] for n in [23, 27, 29, 31]], 4.5e-3)
        outer_ring.faces.maxh = 0.005

        name_body(outer_ring, "Stator", color=color_iron, individual_names=False)
        outer_ring.faces.Min(Z).name = "Stator::TangentialFlux"

        # Rotor (inner ring with two poles), rotated by 22 degrees -----------------------
        inner_ring_radius = 0.0508 / 2.0
        inner_ring_width = 0.0127

        inner_ring = Cylinder(ax_z, inner_ring_radius + inner_ring_width, axis_length) - Cylinder(
            ax_z, inner_ring_radius, axis_length
        )

        box = Box(gp_Pnt(-0.0254 / 2.0, -0.06, 0), gp_Pnt(0.0254 / 2.0, 0.06, axis_length))
        bar = box * Cylinder(ax_z, 0.1021 / 2.0, axis_length) - Cylinder(ax_z, 0.03, axis_length)
        inner_ring = inner_ring + bar

        name_body(inner_ring, "Rotor", color=color_iron, individual_names=False)
        inner_ring.faces.Min(Z).name = "Rotor::TangentialFlux"

        inner_ring = inner_ring.Rotate(gp_Ax1(origin, Z), 22.0)
        inner_ring.faces.maxh = 0.005

        # Coils ----------------------------------------------------------------------------
        coil = Box(
            (-0.034 / 2 - 0.024, -0.017 / 2, -0.031 / 2 - 0.024),
            (0.034 / 2 + 0.024, 0.017 / 2, 0.031 / 2 + 0.024),
        )
        coil = coil.MakeFillet([coil.edges[n] for n in [1, 5, 3, 7]], 24.0e-3)
        coil_sub = Box((-0.034 / 2, -0.017 / 2, -0.031 / 2), (0.034 / 2, 0.017 / 2, 0.031 / 2))
        coil = coil - coil_sub - Box((-0.1, -0.1, 0), (0.1, 0.1, -0.1))

        coil1 = coil.Move((0, 0.063, 0))
        coil1.faces.maxh = 0.005
        name_body(coil1, "Upper Coil", color=color_copper, individual_names=False)

        for face in coil1.faces:
            if face.center[2] < 1.0e-8:
                face.name = "Upper Coil::In" if face.center[0] < 0 else "Upper Coil::Out"

        coil2 = coil.Move((0, -0.063, 0))
        coil2.faces.maxh = 0.005
        name_body(coil2, "Lower Coil", color=color_copper, individual_names=False)

        for face in coil2.faces:
            if face.center[2] < 1.0e-8:
                face.name = "Lower Coil::Out" if face.center[0] > 0 else "Lower Coil::In"

        # Air ------------------------------------------------------------------------------
        air = Box((-0.2, -0.2, 0), (0.2, 0.2, 0.2))
        name_body(air, "Air", color=color_air, individual_names=False)

        air = air - outer_ring - inner_ring - coil1 - coil2

        for face in air.faces:
            if face.center[2] < 1.0e-8:
                face.name = "Air::TangentialFlux"

        for side in [X, Y, Z]:
            air.faces.Max(side).name = "Air::TangentialFlux"
            air.faces.Min(side).name = "Air::TangentialFlux"

        geometry = Glue([outer_ring, inner_ring, coil1, coil2, air])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from netgen.meshing import BoundaryLayerParameters

        from casekit.netgen_meshing import mesh_and_save

        # Prism boundary layers resolve the eddy currents at the iron surfaces.
        boundary_layers = [
            BoundaryLayerParameters(
                boundary=f"{body}::Boundary",
                thickness=[0.00025, 0.0005, 0.001, 0.002],
                new_material=None,
                limit_growth_vectors=True,
                domain=body,
                sides_keep_surfaceindex=True,
            )
            for body in ["Stator", "Rotor"]
        ]

        mesh_and_save(
            self.step_path, basesize=1.0, path=self.mesh_path, boundary_layers=boundary_layers
        )

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        self.runner = mufem.UnsteadyRunner(
            total_time=0.15, time_step_size=0.005, total_inner_iterations=6
        )
        sim.set_runner(self.runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeDomainMagneticModel(order=1)
        sim.get_model_manager().add_model(magnetic_model)

        # Materials --------------------------------------------------------------------
        air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

        copper_material = TimeDomainMagneticGeneralMaterial(
            name="Copper",
            marker=["Upper Coil", "Lower Coil"] @ Vol,
            electric_conductivity=5.8e7,
            has_eddy_currents=False,
        )

        bh = numpy.loadtxt(
            self.dir_path / "data" / "tables" / "Updated_BH_curve.csv", delimiter=",", comments="#"
        )

        iron_material = TimeDomainMagneticGeneralMaterial(
            name="Iron",
            marker=["Rotor", "Stator"] @ Vol,
            magnetic_permeability=(bh[:, 0], bh[:, 1]),
            electric_conductivity=4.54e6,
        )

        magnetic_model.add_materials([air_material, copper_material, iron_material])

        # Boundary conditions ----------------------------------------------------------
        tangential_magnetic_flux_bc = TangentialMagneticFluxBoundaryCondition(
            name="TangentialFlux",
            marker=[
                "Stator::TangentialFlux",
                "Rotor::TangentialFlux",
                "Air::TangentialFlux",
                "Upper Coil::In",
                "Upper Coil::Out",
                "Lower Coil::In",
                "Lower Coil::Out",
            ]
            @ Bnd,
        )
        magnetic_model.add_condition(tangential_magnetic_flux_bc)

        # Coils ------------------------------------------------------------------------
        coil_model = ExcitationCoilModel()
        sim.get_model_manager().add_model(coil_model)

        # The two coils share the applied voltage, and the model is a half: 0.25.
        symmetry = 0.25

        for coil in ["Upper", "Lower"]:
            coil_specification = CoilSpecification(
                name=f"{coil} Coil",
                marker=f"{coil} Coil" @ Vol,
                topology=CoilTopologyOpen(
                    in_marker=f"{coil} Coil::In" @ Bnd, out_marker=f"{coil} Coil::Out" @ Bnd
                ),
                type=CoilTypeStranded(number_of_turns=350),
                excitation=CoilExcitationVoltage(
                    voltage=23.1 * symmetry, resistance=3.09 * symmetry
                ),
            )
            coil_model.add_coil_specification(coil_specification)

        # Reports and monitors ---------------------------------------------------------
        torque_report = MagneticTorqueReport(name="Rotor Torque", marker="Rotor" @ Vol)
        sim.get_report_manager().add_report(torque_report)

        self.torque_monitor = mufem.ReportMonitor(
            name="Rotor Torque Monitor", report_name="Rotor Torque"
        )
        sim.get_monitor_manager().add_monitor(self.torque_monitor)

        coil_current_report = ExcitationCoilCurrentReport(name="Coil Current", coil_index=0)
        sim.get_report_manager().add_report(coil_current_report)

        self.current_monitor = mufem.ReportMonitor(
            name="Coil Current Monitor", report_name="Coil Current"
        )
        sim.get_monitor_manager().add_monitor(self.current_monitor)

        return sim

    def solve(self):
        if not self.output_for_animation:
            self.sim.run()
            return

        field_exporter = self.sim.get_field_exporter()
        field_exporter.add_field_output("Electric Current Density")
        field_exporter.add_field_output("Magnetic Flux Density")
        field_exporter.add_field_output("Magnetic Vector Potential")
        field_exporter.add_field_output("Element Type")
        field_exporter.add_field_output("Cell Volume")

        self.sim.initialize()
        field_exporter.save()

        for _ in range(30):
            self.runner.advance(1)
            field_exporter.save()

    def validate(self):
        self.coil_current = self.current_monitor.get_values()
        # Half model: twice the torque on the rotor half; it acts along -z.
        self.rotor_torque = [
            (t, -2.0 * torque.z) for t, torque in self.torque_monitor.get_values()
        ]

        # Measured values at t = 0.15 s (Rodger et al., 1994), interpolated between
        # 0.14 s and 0.16 s.
        expect(self.coil_current[-1][1], 7.37, rel_tol=5e-2, label="coil current [A]")
        expect(self.rotor_torque[-1][1], 3.18, rel_tol=5e-2, label="rotor torque [Nm]")

    def postprocess(self):
        if not self.is_main():
            return

        tables = self.dir_path / "data" / "tables"
        current_ref = numpy.loadtxt(tables / "Table_3_Coil_Current.csv", delimiter=",", skiprows=1)
        torque_ref = numpy.loadtxt(tables / "Table_4_Torque.csv", delimiter=",", skiprows=1)

        if self.output_for_animation:
            for i in range(len(self.coil_current)):
                self.plot(
                    self.coil_current[: i + 1],
                    self.rotor_torque[: i + 1],
                    current_ref,
                    torque_ref,
                    self.dir_path / "vis",
                    f"_{i:03d}",
                )

        self.plot(
            self.coil_current, self.rotor_torque, current_ref, torque_ref, self.results_path, ""
        )

    @staticmethod
    def plot(current, torque, current_ref, torque_ref, directory, suffix):
        common = dict(
            style=PlotStyle.LINE_AND_POINTS,
            reference_style=PlotStyle.POINTS,
            reference_label="Rodger et al. (1994)",
            xlabel="Time [s]",
            xlim=(0.0, 0.15),
            xticks=[0.0, 0.05, 0.1, 0.15],
        )

        xy_plot(
            values=current,
            reference_values=current_ref,
            ylabel="Coil Current [A]",
            ylim=(0.0, 8.0),
            path=f"{directory}/Coil_Current_vs_Time{suffix}.png",
            **common,
        )
        xy_plot(
            values=torque,
            reference_values=torque_ref,
            ylabel="Rotor Torque [Nm]",
            ylim=(0.0, 3.5),
            path=f"{directory}/Rotor_Torque_vs_Time{suffix}.png",
            **common,
        )


if __name__ == "__main__":
    run_case(Team24LockedRotor)
