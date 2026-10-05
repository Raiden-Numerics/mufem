from casekit import PlotStyle, ValidationCase, expect, xy_plot

import matplotlib.pyplot as plt
import numpy

import mufem
from mufem import RigidBodyMotionModel, UnsteadyRunner, Vol
from mufem.electromagnetics.timedomainmagnetic import (
    MagneticTorqueReport,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)
from mufem.motion import MeshMotionPartialRemeshing, RotatingMotion


class Lubin2015EddyCurrentBrake(ValidationCase):
    name = "Lubin 2015: Axial-Flux Eddy Current Brake"
    tags = {"eternal"}

    # 2 p = 10 sector magnets (grade N40) on the magnet-side back iron
    number_of_magnets = 10

    # write fields and torque frames for every time step to vis/ (see create_animation.py)
    output_for_animation = False

    def build_geometry(self):
        from netgen.occ import Axis, Cylinder, Glue, Pnt, Vec, Z

        from casekit.netgen_geometry import (
            annular_sector,
            color_air,
            color_copper,
            color_iron,
            color_nice_blue,
            color_nice_red,
            name_body,
        )

        # Dimensions of Table I in [1].
        inner_radius_magnets = 30e-3  # R1
        outer_radius_magnets = 60e-3  # R2
        inner_radius_plate = 15e-3  # R0
        outer_radius_plate = 75e-3

        magnet_side_iron_thickness = 10e-3  # a
        magnet_thickness = 10e-3  # b
        air_gap_length = 3e-3  # c
        plate_thickness = 5e-3  # d
        plate_side_iron_thickness = 8e-3  # e

        # Magnets span alpha = 0.9 of the pole pitch.
        pole_angle = 0.9 * 360.0 / self.number_of_magnets

        z = 0.0
        parts = []

        # Magnet side: back iron and magnets ---------------------------------------------
        back_iron_magnet_side = Cylinder(
            Pnt(0, 0, z), Z, r=outer_radius_magnets, h=magnet_side_iron_thickness
        )
        name_body(
            back_iron_magnet_side,
            "Back Iron::Magnet Side",
            color=color_iron,
            individual_names=False,
        )
        parts.append(back_iron_magnet_side)
        z += magnet_side_iron_thickness

        for k in range(self.number_of_magnets):
            magnet = annular_sector(
                r_in=inner_radius_magnets,
                r_out=outer_radius_magnets,
                h=magnet_thickness,
                angle_deg=pole_angle,
            )
            magnet = magnet.Rotate(Axis(Pnt(0, 0, 0), Z), k * 360.0 / self.number_of_magnets)
            magnet = magnet.Move(Vec(0, 0, z))

            color = color_nice_red if k % 2 == 0 else color_nice_blue
            name_body(magnet, f"Magnet::{k}", color=color, individual_names=False)
            magnet.faces.maxh = 3.0e-3
            parts.append(magnet)

        z += magnet_thickness + air_gap_length

        # Copper side: plate and back iron ------------------------------------------------
        copper = Cylinder(Pnt(0, 0, z), Z, r=outer_radius_plate, h=plate_thickness) - Cylinder(
            Pnt(0, 0, z), Z, r=inner_radius_plate, h=plate_thickness
        )
        name_body(copper, "Copper Plate", color=color_copper, individual_names=False)
        copper.faces.maxh = 3.0e-3
        parts.append(copper)
        z += plate_thickness

        back_iron_copper_side = Cylinder(
            Pnt(0, 0, z), Z, r=outer_radius_plate, h=plate_side_iron_thickness
        ) - Cylinder(Pnt(0, 0, z), Z, r=inner_radius_plate, h=plate_side_iron_thickness)
        name_body(
            back_iron_copper_side,
            "Back Iron::Copper Side",
            color=color_iron,
            individual_names=False,
        )
        parts.append(back_iron_copper_side)

        # Surrounding air ------------------------------------------------------------------
        air = Cylinder(Pnt(0, 0, -0.03), Z, r=0.15, h=z + 0.08)
        name_body(air, "Air", color=color_air, individual_names=False)
        air.faces.maxh = 1.0

        for part in parts:
            air = air - part
        parts.append(air)

        geometry = Glue(parts)

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=5e-3, path=self.mesh_path)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        self.runner = UnsteadyRunner(
            total_time=0.005, time_step_size=5.0e-4, total_inner_iterations=2
        )
        sim.set_runner(self.runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeDomainMagneticModel(order=1, magnetostatic_initialization=True)
        sim.get_model_manager().add_model(magnetic_model)

        # Materials --------------------------------------------------------------------
        air_material = TimeDomainMagneticGeneralMaterial(
            "Air", "Air" @ Vol, has_eddy_currents=False
        )

        copper_material = TimeDomainMagneticGeneralMaterial(
            name="Copper",
            marker="Copper Plate" @ Vol,
            electric_conductivity=5.7e7,
            has_eddy_currents=True,
        )

        iron_material = TimeDomainMagneticGeneralMaterial(
            name="AISI-1010 Carbon Steel",
            marker=["Back Iron::Magnet Side", "Back Iron::Copper Side"] @ Vol,
            magnetic_permeability=1000.0,
            has_eddy_currents=False,
        )

        # Magnets with alternating axial magnetization.
        magnets = [f"Magnet::{k}" for k in range(self.number_of_magnets)]

        magnet_material_ns = TimeDomainMagneticGeneralMaterial(
            name="NdFeB N40",
            marker=magnets[0::2] @ Vol,
            magnetic_permeability=1.0,
            remanent_flux_density=[0.0, 0.0, 1.25],
            has_eddy_currents=False,
        )

        magnet_material_sn = TimeDomainMagneticGeneralMaterial(
            name="NdFeB N40",
            marker=magnets[1::2] @ Vol,
            magnetic_permeability=1.0,
            remanent_flux_density=[0.0, 0.0, -1.25],
            has_eddy_currents=False,
        )

        magnetic_model.add_materials(
            [copper_material, magnet_material_ns, magnet_material_sn, air_material, iron_material]
        )

        # Rotation of the magnet side; the air is partially remeshed --------------------
        rbm_model = RigidBodyMotionModel(
            mesh_motion_strategy=MeshMotionPartialRemeshing("Air" @ Vol)
        )

        self.motion = RotatingMotion(
            name="Rotation",
            marker=["Back Iron::Magnet Side", *magnets] @ Vol,
            origin=[0.0, 0.0, 0.0],
            axis=[0.0, 0.0, -1.0],
            rotation_rate=0,
        )
        rbm_model.add_motion(self.motion)
        sim.get_model_manager().add_model(rbm_model)

        # Reports ----------------------------------------------------------------------
        self.torque_report = MagneticTorqueReport(
            "Plate Torque", ["Copper Plate", "Back Iron::Copper Side"] @ Vol
        )
        sim.get_report_manager().add_report(self.torque_report)

        self.torque_monitor = mufem.ReportMonitor("Plate Torque", "Plate Torque")
        sim.get_monitor_manager().add_monitor(self.torque_monitor)

        return sim

    def plate_torque(self):
        """Braking torque on the plate; the magnets rotate about -z and drag it along."""
        return -self.torque_report.evaluate().z

    def solve(self):
        if self.output_for_animation:
            field_exporter = self.sim.get_field_exporter()
            field_exporter.add_field_output("Electric Current Density")
            field_exporter.add_field_output("Magnetic Flux Density")

        self.sim.initialize()

        self.torque_vs_rpm = []
        self.torque_vs_rpm_step = []

        for rpm in [500, 1000, 2000]:
            self.motion.set_rotation_rate(rpm / 60.0)  # rpm -> Hz

            if self.output_for_animation:
                for _ in range(30):
                    self.runner.advance(1)
                    field_exporter.save()
                    self.torque_vs_rpm_step.append((rpm, self.plate_torque()))
            else:
                self.runner.advance(20)

            self.torque_vs_rpm.append((rpm, self.plate_torque()))

    def validate(self):
        # Torque at the end of each speed step, against the analytical model of [1]; the
        # short transients (20 steps per speed) stay within about 8% of it.
        reference = numpy.loadtxt(
            self.dir_path / "data" / "Torque_Vs_Slip_speed.csv", delimiter=",", skiprows=1
        )

        for rpm, torque in self.torque_vs_rpm:
            expect(
                torque,
                float(numpy.interp(rpm, reference[:, 0], reference[:, 1])),
                rel_tol=0.15,
                label=f"plate torque at {rpm} rpm [Nm]",
            )

    def postprocess(self):
        if not self.is_main():
            return

        time_torque = [(t, -torque.z) for t, torque in self.torque_monitor.get_values()]

        xy_plot(
            values=time_torque,
            style=PlotStyle.LINE_AND_POINTS,
            xlabel="Time [s]",
            ylabel="Torque [Nm]",
            xlim=(0, max(t for t, _ in time_torque)),
            ylim=(0, 35),
            path=f"{self.results_path / 'Torque_vs_Time.png'}",
        )

        reference = numpy.loadtxt(
            self.dir_path / "data" / "Torque_Vs_Slip_speed.csv", delimiter=",", skiprows=1
        )

        xy_plot(
            values=self.torque_vs_rpm,
            style=PlotStyle.LINE_AND_POINTS,
            reference_values=reference,
            reference_style=PlotStyle.LINE,
            reference_label="Lubin & Rezzoug (2015)",
            xlabel="Slip Speed [rpm]",
            ylabel="Torque [Nm]",
            xlim=(0, 3000),
            ylim=(0, 35),
            path=f"{self.results_path / 'Torque_vs_RPM.png'}",
        )

        if self.output_for_animation:
            for n, (rpm, _) in enumerate(self.torque_vs_rpm_step):
                self.plot_animation_frame(reference, rpm, n)

    def plot_animation_frame(self, reference, rpm, n):
        """Torque vs slip speed with an arrow at the current speed."""
        plt.clf()

        plt.plot(
            reference[:, 0], reference[:, 1], "k-", label="Lubin & Rezzoug (2015)", linewidth=3.0
        )
        plt.plot(*zip(*self.torque_vs_rpm), "ro", label="$\\mu$fem", markersize=10.0)

        plt.xlabel("Slip Speed [rpm]", fontsize=16)
        plt.ylabel("Torque [Nm]", fontsize=16)
        plt.xlim((0, 3000))
        plt.ylim((0, 35))

        ax = plt.gca()
        ax.tick_params(axis="both", labelsize=14)
        ax.legend(loc="best", fontsize=16).get_frame().set_linewidth(2.0)

        arrow_height = 6.0
        ax.annotate(
            "",
            xy=(rpm, 0.1 + arrow_height),
            xytext=(rpm, 0.1),
            arrowprops=dict(arrowstyle="->", linewidth=2.5, color="k"),
            clip_on=False,
        )

        plt.gcf().set_size_inches(7.5, 5.5)
        plt.savefig(self.dir_path / "vis" / f"Torque_vs_RPM_{n:03d}.png", dpi=200)


if __name__ == "__main__":
    Lubin2015EddyCurrentBrake().run()
