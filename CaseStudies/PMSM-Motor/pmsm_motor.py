"""Step skew in a hairpin IPM traction motor: the full machine in 3D at its operating point.

The Time-Domain Magnetic model in the field-conforming (T-Omega) formulation: non-linear iron with
the material-state Newton stabilization, the magnets of each skew step and pole turning with the
rotor, a sliding rotor-stator interface, and the hairpin winding as 6 solid conductors, one per
parallel path, each driven by its current between its two terminal faces. A magnetostatic
initialization is followed by the time steps.

    mpirun -np 8 python pmsm_motor.py --machine skewed --steps 30 --out results_skewed
    mpirun -np 32 python pmsm_motor.py --machine skewed --steps 30 --eddy --out results_skewed_eddy

--eddy makes the copper conducting, with eddy currents in the whole winding, and reports its Ohmic
loss. The meshes (Geometry_Skewed.msh, Geometry_Unskewed.msh, about 13 million tetrahedra each) are
not part of the repository; see the README. Requires mufem 0.8 or newer.
"""

import argparse
import csv
import json
import math
import os

import mufem
from mufem import Bnd, RigidBodyMotionModel, Vol
from mufem.electromagnetics.coil import (
    CoilExcitationCurrent,
    CoilSpecification,
    CoilTopologyOpen,
    CoilTypeSolid,
    ExcitationCoilModel,
    MagneticFluxLinkageReport,
)
from mufem.electromagnetics.timedomainmagnetic import (
    Formulation,
    LineSearchStrategy,
    MagneticTorqueReport,
    MagnetizationMethodVariable,
    NonlinearStabilization,
    NonMatchingCoupling,
    NonMatchingInterfaceCondition,
    TangentialMagneticFluxBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)
from mufem.motion import CffBodyFrameVector, MeshMotionSlidingInterface, RotatingMotion

HERE = os.path.dirname(os.path.abspath(__file__))

# Operating point: 550 A peak at beta = 40 deg from the q-axis (maximum torque per ampere),
# 4030 rpm.
CURRENT = 550.0  # [A] peak phase current
BETA_DEG = 40.0  # [deg el] current angle from the q-axis
SPEED = 422.0  # [rad/s]
THETA0_DEG = 52.5  # [deg mech] rotor angle of the d-axis on the axis of phase A

# 0.5 deg mech per time step; 30 steps cover 15 deg mech, one period of the 6th torque harmonic.
TIME_STEP = math.radians(0.5) / SPEED

COPPER_CONDUCTIVITY = 5.8e7  # [S/m]


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--machine", choices=["skewed", "unskewed"], default="skewed")
    ap.add_argument("--mesh", help="gmsh mesh in mm (default data/Geometry_<Machine>.msh)")
    ap.add_argument("--steps", type=int, default=30, help="time steps of 0.5 deg mech")
    ap.add_argument("--order", type=int, default=1, help="finite element order")
    ap.add_argument(
        "--eddy", action="store_true", help="conducting copper: eddy currents and the winding loss"
    )
    ap.add_argument("--out", default=os.path.join(HERE, "results_run"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    name = args.machine.capitalize()
    with open(os.path.join(HERE, "data", f"Winding_{name}.json")) as f:
        table = json.load(f)
    mesh_path = args.mesh or os.path.join(HERE, "data", f"Geometry_{name}.msh")

    # Phase currents of the dq excitation i_d = -I sin(beta), i_q = I cos(beta):
    # i_k = I sin(omega t + phi_k).
    pole_pairs = table["pole_pairs"]
    frequency = pole_pairs * SPEED / (2.0 * math.pi)
    phi_a = -pole_pairs * THETA0_DEG + BETA_DEG + 180.0
    phase_deg = {phase: phi_a - 120.0 * k for k, phase in enumerate("ABC")}

    sim = mufem.Simulation.New("PMSM step skew")
    sliding = mufem.NonMatchingInterface(
        name="Sliding", marker0="interface_rotor", marker1="interface_stator"
    )
    sim.get_domain().load_mesh(
        mesh_path, interfaces=[sliding], partitioning=mufem.Partitioning.Balanced
    )
    sim.get_domain().get_mesh().scale(1e-3)
    sim.set_runner(
        mufem.UnsteadyRunner(
            total_time=args.steps * TIME_STEP, time_step_size=TIME_STEP, total_inner_iterations=20
        )
    )

    model = TimeDomainMagneticModel(
        order=args.order,
        magnetostatic_initialization=True,
        formulation=Formulation.FieldConforming,
    )
    solver = model.get_solver()
    solver.set_nonlinear_stabilization(NonlinearStabilization.MaterialState)
    solver.get_line_search().set_strategy(LineSearchStrategy.EnergyBacktracking)
    sim.get_model_manager().add_model(model)

    rotor = Vol("air_rotor|rotor_core|shaft|magnet_.*")
    motion = RotatingMotion(
        name="Rotation",
        marker=rotor,
        origin=[0.0, 0.0, 0.0],
        axis=[0.0, 0.0, 1.0],
        rotation_rate=SPEED / (2 * math.pi),
    )

    # Materials: air, the HF-10X B-H curve in the laminations and the shaft, copper, and one
    # material per magnet group (skew step and pole), its remanence along the pole axis in the
    # frame of the rotor.
    with open(os.path.join(HERE, "data", "HF10X_BH.csv")) as f:
        rows = list(csv.DictReader(f))
    bh = ([float(r["H"]) for r in rows], [float(r["B"]) for r in rows])
    materials = [
        TimeDomainMagneticGeneralMaterial("Air", Vol("air_rotor|air_stator")),
        TimeDomainMagneticGeneralMaterial(
            "Iron", Vol("rotor_core|stator_core|shaft"), magnetic_permeability=bh
        ),
        TimeDomainMagneticGeneralMaterial(
            "Cu",
            Vol("winding_.*"),
            electric_conductivity=COPPER_CONDUCTIVITY,
            has_eddy_currents=args.eddy,
        ),
    ]
    magnets = table["magnets"]
    for group, direction in magnets["groups"].items():
        remanence = [magnets["remanence_T"] * c for c in direction]
        materials.append(
            TimeDomainMagneticGeneralMaterial(
                group,
                group @ Vol,
                magnetic_permeability=magnets["relative_permeability"],
                remanent_flux_density=MagnetizationMethodVariable(
                    CffBodyFrameVector(body_vector=remanence, motion=motion)
                ),
            )
        )
    model.add_materials(materials)

    model.add_condition(
        TangentialMagneticFluxBoundaryCondition(
            "Tangential Flux", Bnd("outer_boundary|terminal_.*")
        )
    )
    model.add_condition(
        NonMatchingInterfaceCondition(
            "Sliding",
            marker="Sliding" @ mufem.Interface,
            coupling=NonMatchingCoupling.CONSERVATIVE,
        )
    )
    motion_model = RigidBodyMotionModel(mesh_motion_strategy=MeshMotionSlidingInterface())
    motion_model.add_motion(motion)
    sim.get_model_manager().add_model(motion_model)

    # Winding: each parallel path is one solid conductor from its in to its out terminal and
    # carries I / a. A path of polarity -1 enters in a slot of negative current, so its current is
    # reversed.
    coils = ExcitationCoilModel()
    sim.get_model_manager().add_model(coils)
    path_current = CURRENT / table["parallel_paths"]
    for path in table["paths"]:
        p = path["name"]
        phase = phase_deg[path["phase"]] + (0.0 if path["polarity"] > 0 else 180.0)
        coils.add_coil_specification(
            CoilSpecification(
                f"Path {p}",
                Vol(f"winding_{p}"),
                CoilTopologyOpen(Bnd(f"terminal_{p}_in"), Bnd(f"terminal_{p}_out")),
                CoilTypeSolid(),
                CoilExcitationCurrent(current=mufem.CffSinusoidal(path_current, frequency, phase)),
            )
        )

    # Reports: rotor torque, flux linkage of each path, and the loss of conducting copper.
    reports = sim.get_report_manager()
    monitors = sim.get_monitor_manager()
    torque = MagneticTorqueReport("Rotor Torque", rotor)
    reports.add_report(torque)
    torque_monitor = mufem.ReportMonitor("Rotor Torque", "Rotor Torque")
    monitors.add_monitor(torque_monitor)
    flux_monitors = {}
    for k, path in enumerate(table["paths"]):
        label = f"Flux {path['name']}"
        reports.add_report(MagneticFluxLinkageReport(label, k))
        flux_monitors[path["name"]] = mufem.ReportMonitor(label, label)
        monitors.add_monitor(flux_monitors[path["name"]])
    loss_monitor = None
    if args.eddy:
        reports.add_report(
            mufem.VolumeIntegralReport("Winding Loss", Vol("winding_.*"), cff_name="Ohmic Heating")
        )
        loss_monitor = mufem.ReportMonitor("Winding Loss", "Winding Loss")
        monitors.add_monitor(loss_monitor)
    sim.get_runner().add_convergence_criterion(
        mufem.ReportConvergenceCriterion(
            "dTorque",
            torque,
            tolerance=1e-5,
            absolute_tolerance=1e-6,
            component=mufem.VectorComponent.Z,
        )
    )

    exporter = sim.get_field_exporter()
    exporter.add_field_outputs(
        ["Magnetic Flux Density", "Electric Current Density"]
        + (["Ohmic Heating"] if args.eddy else [])
    )
    exporter.set_output_directory(os.path.join(args.out, "fields"))
    exporter.set_events(events=[mufem.Event.RunCompletion])
    exporter.set_active(True)

    sim.run()

    if not sim.get_machine().is_main_process():
        return
    with open(os.path.join(args.out, "torque.csv"), "w") as f:
        f.write("time_s,torque_z_Nm\n")
        f.writelines(f"{t:.9g},{value.z:.9g}\n" for t, value in torque_monitor.get_values())
    with open(os.path.join(args.out, "flux_linkage.csv"), "w") as f:
        f.write("path,time_s,psi_Wb\n")
        for p, monitor in flux_monitors.items():
            f.writelines(f"{p},{t:.9g},{value:.9g}\n" for t, value in monitor.get_values())
    if loss_monitor is not None:
        with open(os.path.join(args.out, "winding_loss.csv"), "w") as f:
            f.write("time_s,loss_W\n")
            f.writelines(f"{t:.9g},{value:.9g}\n" for t, value in loss_monitor.get_values())


if __name__ == "__main__":
    main()
