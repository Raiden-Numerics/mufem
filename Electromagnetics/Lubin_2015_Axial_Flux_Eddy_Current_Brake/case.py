import numpy
from mufem.electromagnetics.timedomainmagnetic import (
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
    MagneticTorqueReport,
)

from mufem import (
    Vol,
    RigidBodyMotionModel,
    UnsteadyRunner,
)

from mufem.motion import RotatingMotion, MeshMotionPartialRemeshing

import mufem

from pathlib import Path
import matplotlib.pyplot as plt


import argparse

# add near the existing `output_for_animation = True`
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--output_for_animation", action="store_true")
args, _ = parser.parse_known_args()
output_for_animation = args.output_for_animation


def create_report_and_monitor(sim, report, report_name: str, *args):

    import mufem

    my_report = report(report_name, *args)

    sim.get_report_manager().add_report(my_report)

    my_monitor = mufem.ReportMonitor(report_name, report_name)

    sim.get_monitor_manager().add_monitor(my_monitor)

    return my_report, my_monitor


dir_path = Path(__file__).resolve().parent

sim = mufem.Simulation.New(
    name="Lubin 2015: Axial-Flux Eddy Current Brake",
    mesh_path=f"{dir_path}/geometry.mesh",
)

is_main_process = sim.get_machine().is_main_process()

unsteady_runner = UnsteadyRunner(
    total_time=0.005, time_step_size=5.0e-4, total_inner_iterations=2
)

sim.set_runner(unsteady_runner)
magnetic_model = TimeDomainMagneticModel(order=1, magnetostatic_initialization=True)
sim.get_model_manager().add_model(magnetic_model)

# Material
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

# The eddy-current coupling is made with 10 sector type NdFeB magnets (grade N40) glued
# on the soft-magnetic yoke
magnet_material_ns = TimeDomainMagneticGeneralMaterial(
    name="NdFeB N40",
    marker=["Magnet::0", "Magnet::2", "Magnet::4", "Magnet::6", "Magnet::8"] @ Vol,
    magnetic_permeability=1.0,
    remanent_flux_density=[0.0, 0.0, 1.25],
    has_eddy_currents=False,
)

magnet_material_sn = TimeDomainMagneticGeneralMaterial(
    name="NdFeB N40",
    marker=["Magnet::1", "Magnet::3", "Magnet::5", "Magnet::7", "Magnet::9"] @ Vol,
    magnetic_permeability=1.0,
    remanent_flux_density=[0.0, 0.0, -1.25],
    has_eddy_currents=False,
)

magnetic_model.add_materials(
    [
        copper_material,
        magnet_material_ns,
        magnet_material_sn,
        air_material,
        iron_material,
    ]
)

rbm_model = RigidBodyMotionModel(
    mesh_motion_strategy=MeshMotionPartialRemeshing("Air" @ Vol)
)


# We can either rotate the copper plate or the magnets. Here we rotate the magnets
# as rotation is more obvious this way.
rotate_copper_plate = False


if rotate_copper_plate:

    motion = RotatingMotion(
        name="Rotation",
        marker=["Copper Plate", "Back Iron::Copper Side"] @ Vol,
        origin=[0.0, 0.0, 0.0],
        axis=[0.0, 0.0, 1.0],
        rotation_rate=0,
    )
else:

    motion = RotatingMotion(
        name="Rotation",
        marker=[
            "Back Iron::Magnet Side",
            "Magnet::0",
            "Magnet::2",
            "Magnet::4",
            "Magnet::6",
            "Magnet::8",
            "Magnet::1",
            "Magnet::3",
            "Magnet::5",
            "Magnet::7",
            "Magnet::9",
        ]
        @ Vol,
        origin=[0.0, 0.0, 0.0],
        axis=[0.0, 0.0, -1.0],
        rotation_rate=0,
    )

rbm_model.add_motion(motion)
sim.get_model_manager().add_model(rbm_model)


#
plate_torque_report, plate_torque_monitor = create_report_and_monitor(
    sim,
    MagneticTorqueReport,
    "Plate Torque",
    ["Copper Plate", "Back Iron::Copper Side"] @ Vol,
)


torque_vs_rpm = []
torque_vs_rpm_step = []


if output_for_animation:

    # We save a few fields so we can visualize with focus-viewer/paraview
    field_exporter = sim.get_field_exporter()
    field_exporter.add_field_output("Electric Current Density")
    field_exporter.add_field_output("Magnetic Flux Density")


sim.initialize()

for rpm in [500, 1000, 2000]:

    motion.set_rotation_rate(rpm / 60.0)  # Convert RPM to Hz

    if output_for_animation:
        for i in range(30):
            unsteady_runner.advance(1)

            # Save the fields for visualization
            field_exporter.save()
            torque_vs_rpm_step.append((rpm, plate_torque_report.evaluate().z))

    else:

        unsteady_runner.advance(20)

    torque_vs_rpm.append((rpm, plate_torque_report.evaluate().z))


time_torque = sim.get_monitor_manager().get_monitor("Plate Torque").get_values()


# Show Torque vs Time


plt.clf()
plt.plot([t for t, T in time_torque], [T.z for t, T in time_torque])
plt.xlabel("Time [s]")
plt.ylabel("Torque [Nm]")

plt.xlim((0, max([t for t, T in time_torque])))
plt.ylim((0, 35))

plt.savefig(f"{dir_path}/results/Torque_vs_Time.png", bbox_inches="tight")


# Show Torque vs Slip Speed

plt.clf()

ref = numpy.loadtxt(
    f"{dir_path}/data/Torque_Vs_Slip_speed.csv", delimiter=",", skiprows=1
)

plt.plot(ref[:, 0], ref[:, 1], "k-", label="Reference", linewidth=3.0)
plt.plot(*zip(*torque_vs_rpm), "ro", label="$\\mu$fem", markersize=10.0)

plt.xlabel("Slip Speed [rpm]", fontsize=16)
plt.ylabel("Torque [Nm]", fontsize=16)

plt.xlim((0, 3000))
plt.ylim((0, 35))

ax = plt.gca()

ax.tick_params(axis="both", labelsize=14)


leg = ax.legend(
    loc="best",
    fontsize=16,
)
leg.get_frame().set_linewidth(2.0)


plt.gcf().set_size_inches(7.5, 5.5)  # larger canvas

plt.savefig(f"{dir_path}/results/Torque_vs_RPM.png", dpi=200)


# For animation: show the torque vs slip speed with an arrow indicating the current rpm

if output_for_animation:
    # flake8: noqa: FKA100

    for n, (rpm, torque) in enumerate(torque_vs_rpm_step):

        plt.clf()

        ref = numpy.loadtxt(
            f"{dir_path}/data/Torque_Vs_Slip_speed.csv", delimiter=",", skiprows=1
        )

        plt.plot(ref[:, 0], ref[:, 1], "k-", label="Reference", linewidth=3.0)
        plt.plot(*zip(*torque_vs_rpm), "ro", label="$\\mu$fem", markersize=10.0)

        plt.xlabel("Slip Speed [rpm]", fontsize=16)
        plt.ylabel("Torque [Nm]", fontsize=16)

        plt.xlim((0, 3000))
        plt.ylim((0, 35))

        ax = plt.gca()

        ax.tick_params(axis="both", labelsize=14)

        leg = ax.legend(
            loc="best",
            fontsize=16,
        )
        leg.get_frame().set_linewidth(2.0)

        arrow_height = 6.0
        text_offset = 1.0

        ax.annotate(
            "",
            xy=(rpm, 0.1 + arrow_height),
            xytext=(rpm, 0.1),
            arrowprops=dict(
                arrowstyle="->",
                linewidth=2.5,
                color="k",
            ),
            clip_on=False,
        )

        plt.gcf().set_size_inches(7.5, 5.5)

        plt.savefig(f"{dir_path}/vis/Torque_vs_RPM_{n:03d}.png", dpi=200)
