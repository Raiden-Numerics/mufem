from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot

import numpy

import mufem
from mufem import Bnd, RigidBodyMotionModel, Vol
from mufem.electromagnetics.coil import (
    CoilExcitationCurrent,
    CoilSpecification,
    CoilTopologyOpen,
    CoilTypeStranded,
    ExcitationCoilModel,
    MagneticFluxLinkageReport,
)
from mufem.electromagnetics.timedomainmagnetic import (
    Formulation,
    InterfaceSymmetry,
    LineSearchOption,
    LineSearchStrategy,
    MagneticTorqueReport,
    MagnetizationMethodVariable,
    MatchingInterfaceCondition,
    NonlinearStabilization,
    NonMatchingCoupling,
    NonMatchingInterfaceCondition,
    TangentialMagneticFluxBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)
from mufem.motion import CffBodyFrameVector, MeshMotionSlidingInterface, RotatingMotion

# One pole pitch of the 4-pole machine is modeled, and the half z >= 0 of its stack.
FULL_MODEL_SCALE = 8.0

# 50 Hz drive of 2 pole pairs: 25 rev/s = 1500 rpm. One electrical period is simulated.
FREQUENCY = 50.0
POLE_PAIRS = 2
STEPS_PER_PERIOD = 120

# Rated load: phase current [A rms] and advance of the current vector from the q-axis [deg].
I_RMS = 3.0
BETA_DEG = 25.0

# Electrical angle of the d-axis from the axis of phase U at t = 0, theta_e = omega t + THETA_E0.
# Phase U has its axis at mech 105 deg, the d-axis of the magnet is at mech 45 deg.
THETA_E0_DEG = 2.0 * (45.0 - 105.0)

# The rotation that maps the cut face at 90 deg onto the cut face at 0 deg.
ROTATION_MINUS_90_Z = [
    [0.0, 1.0, 0.0],
    [-1.0, 0.0, 0.0],
    [0.0, 0.0, 1.0],
]

PHASES = ("U", "V", "W")


class IpmMotorModelD(ValidationCase):
    name = "IEEJ 2009: IPM Motor Model D"
    tags = {"long"}

    def build_geometry(self):
        import math

        from netgen.meshing import IdentificationType
        from netgen.occ import (
            ArcOfCircle,
            Axis,
            Box,
            Compound,
            Cylinder,
            Face,
            Glue,
            Pnt,
            Rotation,
            Segment,
            Vec,
            Wire,
            Z,
        )

        from casekit.colors import color_air, color_blue, color_copper, color_iron
        from casekit.netgen_geometry import name_body

        sector_deg = (0.0, 90.0)
        z_axis = Axis(Pnt(0, 0, 0), Vec(0, 0, 1))

        # Half of the axial length: z = 0 is the midplane. The coils extend beyond the stack.
        stator_height = 0.030
        rotor_height = 0.03375
        magnet_height = 0.0325
        air_height = stator_height + 0.015

        # Stator (data/Dmodel_CAD.dxf) ----------------------------------------------------
        stator_inner_radius = 0.028
        stator_outer_radius = 0.0561
        slot_inner_radius = 0.0289

        def build_slot():
            """Slot on the +y axis: sides parallel to the neighboring teeth, round bottom."""
            half_tooth = 0.00165
            bottom_center = 0.038478
            bottom_radius = 0.0033725

            def side_point(s, sign):
                a = math.radians(90.0 - sign * 7.5)  # the axis of the neighboring tooth
                return Pnt(
                    s * math.cos(a) - sign * half_tooth * math.sin(a),
                    s * math.sin(a) + sign * half_tooth * math.cos(a),
                    0,
                )

            # The sides are tangent to the bottom circle.
            s_tangent = bottom_center * math.cos(math.radians(7.5))
            s_inner = 0.9 * slot_inner_radius
            right_inner, right_tangent = side_point(s_inner, 1), side_point(s_tangent, 1)
            left_inner, left_tangent = side_point(s_inner, -1), side_point(s_tangent, -1)
            wire = Wire(
                [
                    Segment(right_inner, right_tangent),
                    ArcOfCircle(
                        right_tangent, Pnt(0, bottom_center + bottom_radius, 0), left_tangent
                    ),
                    Segment(left_tangent, left_inner),
                    Segment(left_inner, right_inner),
                ]
            )
            cut = Cylinder((0, 0, 0), Z, r=slot_inner_radius, h=air_height)
            return Face(wire).Extrude(air_height * Z) - cut

        slot = build_slot()
        # The opening of the slot towards the air gap, 2 mm wide.
        slot_with_opening = slot + Box(
            Pnt(-0.001, 0, 0), Pnt(0.001, slot_inner_radius, stator_height)
        )

        stator = Cylinder((0, 0, 0), Z, r=stator_outer_radius, h=stator_height) - Cylinder(
            (0, 0, 0), Z, r=stator_inner_radius, h=stator_height
        )
        for n in range(24):
            stator = stator - slot_with_opening.Rotate(z_axis, 7.5 + 15.0 * n - 90.0)

        name_body(stator, "Stator", color=color_iron, individual_names=False)
        stator.faces.Min(Z).name = "Stator::TangentialFlux"

        # Coils in the six slots of the sector, q = 2 single-layer full-pitch winding ---------
        coils = []
        for n, winding in enumerate(["-W", "+V", "+V", "-U", "-U", "+W"]):
            coil = slot.Rotate(z_axis, 7.5 + 15.0 * n - 90.0)
            coil_name = f"Coil::{winding}::{n}"
            name_body(coil, coil_name, color=color_copper, individual_names=False)
            coil.faces.Min(Z).name = f"{coil_name}::In"
            coil.faces.Max(Z).name = f"{coil_name}::Out"
            coils.append(coil)

        # Rotor ----------------------------------------------------------------------------
        # The parts of a pole are built with the pole on +y and turned to their position; the
        # pole of the magnet in the sector is at 45 deg. The shaft is non-magnetic (air).
        rotor_outer_radius = 0.0275
        rotor = Cylinder((0, 0, 0), Z, r=rotor_outer_radius, h=rotor_height) - Cylinder(
            (0, 0, 0), Z, r=0.008, h=rotor_height
        )

        # Bolt holes (plastic bolts, air): 4 mm at r = 22 mm on the pole axis, 3 mm at r = 11.5 mm
        # at +-30 deg.
        hole_x = 0.0115 * math.sin(math.radians(30.0))
        hole_y = 0.0115 * math.cos(math.radians(30.0))
        holes = [
            Cylinder((0, 0.022, 0), Z, r=0.002, h=rotor_height),
            Cylinder((hole_x, hole_y, 0), Z, r=0.0015, h=rotor_height),
            Cylinder((-hole_x, hole_y, 0), Z, r=0.0015, h=rotor_height),
        ]

        # Magnet pocket (20.78 x 2.5 mm, r = 13 ... 15.5 mm) with its flux barriers. Each barrier
        # runs parallel to the q-axis at 0.75 ... 3.25 mm from it and ends on the arc r = 27 mm
        # (0.5 mm bridge).
        sin45 = math.sin(math.radians(45.0))

        def barrier_end(offset):
            along = math.sqrt(0.027**2 - offset**2)
            return Pnt((along - offset) * sin45, (along + offset) * sin45, 0)

        def mirror(point):
            return Pnt(-point[0], point[1], 0)

        p4 = Pnt(0.0135 - 0.00075 / sin45, 0.0135, 0)
        p5, p56, p6 = barrier_end(0.00075), barrier_end(0.002), barrier_end(0.00325)
        points = [
            Pnt(-0.01039, 0.013, 0),
            Pnt(0.01039, 0.013, 0),
            Pnt(0.01039, 0.0135, 0),
            p4,
            p5,
            p6,
            Pnt(0.010905, 0.0155, 0),
            Pnt(-0.010905, 0.0155, 0),
            mirror(p6),
            mirror(p5),
            mirror(p4),
            Pnt(-0.01039, 0.0135, 0),
        ]
        arcs = {4: p56, 8: mirror(p56)}  # the ends of the barriers
        pocket = Face(
            Wire(
                [
                    (
                        ArcOfCircle(points[i], arcs[i], points[i + 1])
                        if i in arcs
                        else Segment(points[i], points[(i + 1) % len(points)])
                    )
                    for i in range(len(points))
                ]
            )
        ).Extrude(rotor_height * Z)

        for n in range(4):
            angle = 90.0 * n - 45.0
            for hole in holes:
                rotor = rotor - hole.Rotate(z_axis, angle)
        for n in range(4):
            rotor = rotor - pocket.Rotate(z_axis, 90.0 * n - 45.0)

        name_body(rotor, "Rotor", color=color_iron, individual_names=False)
        rotor.faces.Min(Z).name = "Rotor::TangentialFlux"

        # The magnet (20.53 x 2.39 mm) sits in the center of its pocket.
        magnet = Box((-0.010265, 0.013055, 0), (0.010265, 0.015445, magnet_height)).Rotate(
            z_axis, -45.0
        )
        name_body(magnet, "Magnet::0", color=color_blue, individual_names=False)
        magnet.faces.Min(Z).name = "Magnet::TangentialFlux"

        # Air ------------------------------------------------------------------------------
        # A cylinder in the middle of the air gap separates the air turning with the rotor from
        # the outer air. Each side has its own cylinder, so that the two faces stay separate and
        # the sides can slide along them.
        sliding_radius = 0.02775

        air_rotor = Cylinder((0, 0, 0), Z, r=sliding_radius, h=air_height)
        name_body(air_rotor, "Air-Rotor", color=color_air, individual_names=False)
        air_rotor.faces.name = "Air-Rotor::TangentialFlux"
        air_rotor = air_rotor - rotor - magnet

        air = Cylinder((0, 0, 0), Z, r=0.1, h=air_height)
        name_body(air, "Air", color=color_air, individual_names=False)
        air.faces.name = "Air::TangentialFlux"
        air.faces.maxh = 1.0
        air = air - Cylinder((0, 0, 0), Z, r=sliding_radius, h=air_height) - stator
        for coil in coils:
            air = air - coil

        # Cut to the sector ----------------------------------------------------------------
        half_space = Box(Pnt(-1, 0, -1), Pnt(1, 1, 1))
        sector = half_space.Rotate(z_axis, sector_deg[0]) * half_space.Rotate(
            z_axis, sector_deg[1] - 180.0
        )
        stator = stator * sector
        air = air * sector
        rotor = rotor * sector
        air_rotor = air_rotor * sector

        def name_cut_faces(body, prefix):
            for face in body.faces:
                x, y, _ = face.center
                if math.hypot(x, y) < 1e-9:
                    continue
                for side, angle in enumerate(sector_deg):
                    delta = (math.degrees(math.atan2(y, x)) - angle + 180.0) % 360.0 - 180.0
                    if abs(delta) < 1e-6:
                        face.name = f"{prefix}::{side}"

        for body in (stator, air):
            name_cut_faces(body, "Periodic::Stator")
        for body in (rotor, air_rotor):
            name_cut_faces(body, "Periodic::Rotor")

        # The sliding cylinder ---------------------------------------------------------------
        # Seams with different counts on the two sides pin their mesh columns, so that the two
        # meshes never coincide while the rotor turns.
        def split_cylinder(body, number_pieces):
            piece_angle = math.radians(sector_deg[1] - sector_deg[0]) / number_pieces
            seams = []
            for k in range(1, number_pieces):
                x = sliding_radius * math.cos(k * piece_angle)
                y = sliding_radius * math.sin(k * piece_angle)
                seams.append(Segment(Pnt(x, y, 0.0), Pnt(x, y, air_height)))
            body = Glue([body] + seams)

            piece_area = piece_angle * sliding_radius * air_height
            # The radius of the centroid of a cylindrical strip.
            centroid = sliding_radius * math.sin(0.5 * piece_angle) / (0.5 * piece_angle)
            pieces = [
                face
                for face in body.faces
                if abs(math.hypot(face.center[0], face.center[1]) - centroid)
                < 1e-3 * sliding_radius
                and abs(face.center[2] - 0.5 * air_height) < 1e-6
                and abs(face.mass - piece_area) < 1e-3 * piece_area
            ]
            if len(pieces) != number_pieces:
                raise RuntimeError(f"{len(pieces)} sliding pieces, expected {number_pieces}")
            return body, pieces

        air_rotor, rotor_pieces = split_cylinder(air_rotor, 30)
        air, stator_pieces = split_cylinder(air, 25)
        for face in rotor_pieces:
            face.name = "AirRotor::Cylinder"
        for face in stator_pieces:
            face.name = "Air::Cylinder"

        # Mesh sizes -----------------------------------------------------------------------
        rotor.faces.maxh = 0.003
        stator.faces.maxh = 0.003

        airgap_maxh = 0.65e-3
        rotor_arc_area = math.radians(90.0) * rotor_outer_radius * rotor_height
        for face in rotor.faces:
            if (
                abs(face.center[2] - 0.5 * rotor_height) < 1e-3
                and abs(face.mass - rotor_arc_area) / rotor_arc_area < 0.05
            ):
                face.maxh = airgap_maxh
        for face in stator.faces:
            radius = math.hypot(face.center[0], face.center[1])
            if (
                abs(radius - stator_inner_radius) < 5e-3
                and abs(face.center[2] - 0.5 * stator_height) < 1e-3
            ):
                face.maxh = airgap_maxh

        # Each side is glued on its own and the sides are only put together, so that the faces of
        # the sliding cylinder stay separate.
        geometry = Compound(
            [Glue([rotor, magnet, air_rotor]), Glue([stator] + coils + [air])], False
        )

        # Periodic surface meshes on the cut faces.
        for prefix in ("Periodic::Stator", "Periodic::Rotor"):
            side0 = [face for face in geometry.faces if face.name == f"{prefix}::0"]
            side1 = [face for face in geometry.faces if face.name == f"{prefix}::1"]
            if len(side0) != len(side1) or not side0:
                raise RuntimeError(f"{prefix}: {len(side0)} vs {len(side1)} cut faces")
            for face1 in side1:
                # The image of the center under the rotation by -90 deg.
                x, y, z = face1.center
                image = (y, -x, z)
                face0 = min(side0, key=lambda face: math.dist(face.center, image))
                if math.dist(face0.center, image) > 1e-6:
                    raise RuntimeError(f"{prefix}: no cut face matches {face1.center}")
                face1.Identify(face0, prefix, IdentificationType.PERIODIC, Rotation(z_axis, -90.0))

        geometry.WriteStep(f"{self.step_path}")

        # For generate_mesh(): the identifications and the separate sliding faces are not in the
        # STEP file.
        self.geometry = geometry

    def generate_mesh(self):
        from netgen.meshing import MeshingParameters
        from netgen.occ import OCCGeometry

        from casekit.netgen_meshing import save_mesh

        basesize = 0.5
        mesh = OCCGeometry(self.geometry).GenerateMesh(maxh=basesize)
        mesh.OptimizeVolumeMesh(
            MeshingParameters(maxh=basesize, optimize3d="cmdmustmmmm", optsteps3d=5)
        )
        save_mesh(mesh, self.mesh_path)

    def create_geometry_image(self):
        from netgen.occ import OCCGeometry

        from casekit.netgen_image import Labels, snapshot, trim

        solids = [
            solid
            for solid in OCCGeometry(f"{self.step_path}").shape.solids
            if not solid.name.startswith("Air")
        ]
        # The named cut faces lost their color in the STEP file.
        for solid in solids:
            color = next(face.col for face in solid.faces if face.col is not None)
            for face in solid.faces:
                if face.col is None:
                    face.col = color

        image = snapshot(
            shapes=solids, direction=(0, 0, 1), up=(0, 1, 0), zoom=-40, size=(1600, 1400)
        )
        image = trim(image=image)
        labels = Labels(image=image, font_size=38)
        labels.text(position=(650, 250), text="Stator")
        # The coils from 7.5 deg counter-clockwise, at the centers of their top faces.
        for text, position in [
            ("W-", (853, 1224)),
            ("V+", (791, 1006)),
            ("V+", (675, 811)),
            ("U-", (513, 650)),
            ("U-", (315, 535)),
            ("W+", (95, 475)),
        ]:
            labels.draw.text(position, text, font=labels.font, fill="darkgray", anchor="mm")
        labels.text(position=(270, 810), text="Rotor")
        labels.text(position=(480, 1125), text="Magnet", anchor="lm")
        labels.arrow(start=(470, 1125), end=(345, 1125), head=22)
        image.save(self.dir_path / "data" / "Geometry.png")

        image = snapshot(
            shapes=solids, direction=(0.3, -1, 0.25), up=(0, 0, 1), zoom=-36, size=(1600, 1400)
        )
        image = trim(image=image)
        labels = Labels(image=image, font_size=38)
        labels.text(position=(760, 750), text="Stator")
        labels.text(position=(285, 650), text="Rotor")
        labels.text(position=(600, 280), text="Coil")
        labels.arrow(start=(950, 260), end=(950, 120), head=22)
        labels.text(position=(985, 130), text="z")
        image.save(self.dir_path / "data" / "Geometry_Side.png")

    def setup_case(self):
        sim = mufem.Simulation.New(name=self.name, mesh_path=f"{self.mesh_path}")

        dt = 1.0 / (FREQUENCY * STEPS_PER_PERIOD)
        runner = mufem.UnsteadyRunner(
            total_time=STEPS_PER_PERIOD * dt, time_step_size=dt, total_inner_iterations=20
        )
        sim.set_runner(runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeDomainMagneticModel(order=1, formulation=Formulation.FieldConforming)
        sim.get_model_manager().add_model(magnetic_model)

        # In the saturated rotor bridges a Newton step overshoots far past the energy minimum;
        # the stabilization and the line search on the energy keep the iteration converging.
        solver = magnetic_model.get_solver()
        solver.set_magnetostatic_initialization(LineSearchOption())
        solver.set_nonlinear_stabilization(NonlinearStabilization.MaterialState)
        line_search = solver.get_line_search()
        line_search.set_active(True)
        line_search.set_strategy(LineSearchStrategy.EnergyBacktracking)

        # Motion -----------------------------------------------------------------------
        # Rotor, magnet and rotor-side air turn as one rigid body.
        rotor_marker = "Rotor|Air-Rotor|Magnet::.*"
        motion = RotatingMotion(
            name="Rotation",
            marker=Vol(rotor_marker),
            origin=[0.0, 0.0, 0.0],
            axis=[0.0, 0.0, 1.0],
            rotation_rate=FREQUENCY / POLE_PAIRS,
        )
        rbm_model = RigidBodyMotionModel(mesh_motion_strategy=MeshMotionSlidingInterface())
        rbm_model.add_motion(motion)
        sim.get_model_manager().add_model(rbm_model)

        # Materials --------------------------------------------------------------------
        air_material = TimeDomainMagneticGeneralMaterial(
            name="Air", marker=["Air", "Air-Rotor"] @ Vol
        )

        bh = numpy.loadtxt(
            self.dir_path / "data" / "JIS50A350_BH.csv", delimiter=",", comments="#"
        )
        iron_material = TimeDomainMagneticGeneralMaterial(
            name="Iron",
            marker=["Rotor", "Stator"] @ Vol,
            magnetic_permeability=(bh[:, 1], bh[:, 0]),
            has_eddy_currents=False,
        )

        copper_material = TimeDomainMagneticGeneralMaterial(
            name="Copper",
            marker=Vol("Coil::.*"),
            electric_conductivity=5.8e7,
            has_eddy_currents=False,
        )

        # The magnetization along the pole axis at 45 deg, held in the frame of the rotor.
        br = 1.25 * numpy.sqrt(0.5)
        magnet_material = TimeDomainMagneticGeneralMaterial(
            name="Magnet",
            marker="Magnet::0" @ Vol,
            magnetic_permeability=1.05,
            remanent_flux_density=MagnetizationMethodVariable(
                CffBodyFrameVector(body_vector=[br, br, 0.0], motion=motion)
            ),
            electric_conductivity=6.944e5,
            has_eddy_currents=False,
        )

        magnetic_model.add_materials(
            [air_material, iron_material, copper_material, magnet_material]
        )

        # Boundary and interface conditions --------------------------------------------
        magnetic_model.add_condition(
            TangentialMagneticFluxBoundaryCondition(
                name="TangentialFlux", marker=Bnd("Coil::.*(In|Out)|.*TangentialFlux")
            )
        )

        for side in ("Rotor", "Stator"):
            magnetic_model.add_condition(
                MatchingInterfaceCondition(
                    name=f"Periodic {side}",
                    marker0=f"Periodic::{side}::0" @ Bnd,
                    marker1=f"Periodic::{side}::1" @ Bnd,
                    symmetry=InterfaceSymmetry.ANTI_PERIODIC,
                    rotation=ROTATION_MINUS_90_Z,
                )
            )

        # Where the rotor arc has turned past the end of the stator arc, it couples to the
        # anti-periodic image of the stator.
        magnetic_model.add_condition(
            NonMatchingInterfaceCondition(
                "AirRotor<->Air sliding",
                "AirRotor::Cylinder" @ Bnd,
                "Air::Cylinder" @ Bnd,
                symmetry=InterfaceSymmetry.ANTI_PERIODIC,
                rotation=ROTATION_MINUS_90_Z,
                coupling=NonMatchingCoupling.CONSERVATIVE,
            )
        )

        # Coils ------------------------------------------------------------------------
        coil_model = ExcitationCoilModel()
        sim.get_model_manager().add_model(coil_model)

        # i_d = -I sin(beta), i_q = I cos(beta):
        # i_k = I cos(theta_e + beta + 90 - 120 k) = I sin(omega t + THETA_E0 + beta + 180 - 120 k)
        phase_offset = THETA_E0_DEG + BETA_DEG + 180.0

        self.flux_monitors = {}
        for index, phase in enumerate(PHASES):
            coil_model.add_coil_specification(
                CoilSpecification(
                    name=f"Coil {phase}",
                    marker=Vol(rf"Coil::[+-]{phase}::.*"),
                    topology=CoilTopologyOpen(
                        in_marker=Bnd(rf"Coil::[+-]{phase}::.*::In"),
                        out_marker=Bnd(rf"Coil::[+-]{phase}::.*::Out"),
                    ),
                    type=CoilTypeStranded(number_of_turns=35),
                    excitation=CoilExcitationCurrent(
                        current=mufem.CffSinusoidal(
                            I_RMS * numpy.sqrt(2.0), FREQUENCY, phase_offset - 120.0 * index
                        )
                    ),
                    reverse_direction=Vol(rf"Coil::\-{phase}::.*"),
                )
            )

            report_name = f"Flux Linkage {phase}"
            sim.get_report_manager().add_report(MagneticFluxLinkageReport(report_name, index))
            self.flux_monitors[phase] = mufem.ReportMonitor(
                name=f"{report_name} Monitor", report_name=report_name
            )
            sim.get_monitor_manager().add_monitor(self.flux_monitors[phase])

        # Torque -----------------------------------------------------------------------
        torque_report = MagneticTorqueReport(name="Rotor Torque", marker=Vol(rotor_marker))
        sim.get_report_manager().add_report(torque_report)
        self.torque_monitor = mufem.ReportMonitor(
            name="Rotor Torque Monitor", report_name="Rotor Torque"
        )
        sim.get_monitor_manager().add_monitor(self.torque_monitor)

        # A time step ends once the torque has settled, at the latest after the inner iterations
        # of the runner. At a tolerance of 1e-4 the flux linkages still change by a few percent.
        runner.add_convergence_criterion(
            mufem.ReportConvergenceCriterion(
                "Delta Torque",
                torque_report,
                tolerance=1.0e-5,
                absolute_tolerance=1.0e-6,
                component=mufem.VectorComponent.Z,
            )
        )

        # The fields of every time step for the scenes of create_scenes().
        field_exporter = sim.get_field_exporter()
        field_exporter.set_output_directory(self.dir_path / "VisualizationOutput")
        field_exporter.add_field_outputs(["Magnetic Flux Density"])
        field_exporter.set_events([mufem.Event.Initialization, mufem.Event.TimeStep])

        return sim

    def validate(self):
        # The full machine.
        self.rotor_torque = [
            (t, FULL_MODEL_SCALE * torque.z) for t, torque in self.torque_monitor.get_values()
        ]
        self.flux_linkage = {
            phase: [(t, FULL_MODEL_SCALE * flux) for t, flux in monitor.get_values()]
            for phase, monitor in self.flux_monitors.items()
        }
        # Without the magnetostatic start at t = 0: the period counts each rotor position once.
        period = -STEPS_PER_PERIOD
        torque = numpy.array(self.rotor_torque)[period:, 1]
        time = numpy.array(self.flux_linkage["U"])[period:, 0]
        flux = numpy.array(self.flux_linkage["U"])[period:, 1]
        fundamental = 2.0 * numpy.mean(flux * numpy.exp(2j * numpy.pi * FREQUENCY * time))

        # IEEJ TR 1244, Fig. 3.36, 3D FEA: mean of the digitised waveform.
        expect(torque.mean(), 1.941, rel_tol=5e-2, label="mean torque, IEEJ 3D FEA [Nm]")
        # IEEJ portal, Dmodel_T-beta.csv. All published analyses lie 5-13 % above the measurement.
        expect(torque.mean(), 1.746, rel_tol=15e-2, label="mean torque, measured [Nm]")
        # The fundamental of the flux linkage from the 2D reference of data/. The field-conforming
        # formulation lies about 6 % above it, see the README.
        expect(abs(fundamental), 0.1538, rel_tol=10e-2, label="flux linkage, rfmkit 2D [Wb]")

    def torque_plot(self, rotor_torque):
        """The arguments of xy_plot / xy_chart for the rotor torque over time, shared by the plot
        of postprocess() and the animation of create_scenes()."""
        reference = numpy.loadtxt(
            self.dir_path / "data" / "Reference_IEEJ_Fig3_36_Torque.csv",
            delimiter=",",
            comments="#",
        )
        return dict(
            values=[(1e3 * t, torque) for t, torque in rotor_torque],
            style=PlotStyle.LINE,
            reference_values=[(1e3 * row[0], row[2]) for row in reference],
            reference_style=PlotStyle.LINE,
            reference_label="IEEJ 3D FEA (TR 1244)",
            xlabel="Time [ms]",
            ylabel="Rotor Torque [Nm]",
            xlim=(0.0, 20.0),
            xticks=[0.0, 5.0, 10.0, 15.0, 20.0],
            ylim=(1.0, 2.8),
        )

    def postprocess(self):
        if not self.is_main():
            return

        # The input of the animation of create_scenes().
        numpy.savez(self.scene_data_path, rotor_torque=numpy.array(self.rotor_torque))

        xy_plot(
            path=f"{self.results_path / 'Rotor_Torque_vs_Time.png'}",
            **self.torque_plot(self.rotor_torque),
        )

        common = dict(
            style=PlotStyle.LINE,
            xlabel="Time [ms]",
            xscale=1e3,
            xlim=(0.0, 20.0),
            xticks=[0.0, 5.0, 10.0, 15.0, 20.0],
            reference_label="rfmkit (2D)",
            reference_style=PlotStyle.LINE,
        )

        reference_file = f"{self.dir_path / 'data' / 'Reference_rfmkit_2D_Load.csv'}"
        for column, phase in enumerate(PHASES, start=2):
            xy_plot(
                values=self.flux_linkage[phase],
                reference_file=reference_file,
                reference_xscale=1e3,
                reference_y_column=column,
                ylabel=f"Flux Linkage {phase} [Wb]",
                ylim=(-0.2, 0.2),
                path=f"{self.results_path / f'Flux_Linkage_{phase}_vs_Time.png'}",
                **common,
            )

    def create_scenes(self):
        import pyvista as pv
        from matplotlib.colors import LinearSegmentedColormap

        from casekit.colors import color_copper
        from casekit.pyvista_scene import (
            FieldExportReader,
            add_colorbar,
            create_scene,
            gif,
            update_curve,
            xy_chart,
        )

        reader = FieldExportReader(self.dir_path)

        def full_machine(body):
            """The surface of `body` in all eight modeled parts: four sectors, mirrored at z = 0.
            |B| is the same in all of them."""
            surface = body.clean().extract_surface(algorithm=None, nonlinear_subdivision=0)
            parts = []
            for n in range(4):
                part = surface.rotate_z(90.0 * n, point=(0.0, 0.0, 0.0))
                parts += [part, part.reflect((0.0, 0.0, 1.0), point=(0.0, 0.0, 0.0))]
            return pv.MultiBlock(parts).combine(merge_points=False)

        # The "Fast" color map of ParaView.
        fast = LinearSegmentedColormap.from_list(
            "fast",
            [
                (0.0, (0.0564, 0.0564, 0.47)),
                (0.1716, (0.243, 0.4604, 0.81)),
                (0.2985, (0.3568, 0.745, 0.9544)),
                (0.4321, (0.6882, 0.93, 0.9179)),
                (0.5, (0.8995, 0.9446, 0.7687)),
                (0.6007, (0.9571, 0.8338, 0.5089)),
                (0.7084, (0.9275, 0.6214, 0.3154)),
                (0.8496, (0.8, 0.352, 0.16)),
                (1.0, (0.59, 0.0767, 0.1195)),
            ],
        )
        field = dict(scalars="Magnetic Flux Density", clim=(0.0, 2.0), cmap=fast)
        bodies = ["Stator", "Rotor", "Magnet::0"]

        rotor_torque = numpy.load(self.scene_data_path)["rotor_torque"]
        arguments = self.torque_plot(rotor_torque)

        scene = create_scene((1100, 600), shape=(1, 2), col_weights=[0.54, 0.46], border=False)
        chart, curve, _ = xy_chart(**arguments)
        chart.size, chart.loc = (0.97, 0.9), (0.0, 0.05)
        scene.subplot(0, 1)
        scene.add_chart(chart)
        scene.subplot(0, 0)

        first = reader.read()
        coils = pv.MultiBlock([first[name] for name in first.keys() if name.startswith("Coil")])
        scene.add_mesh(full_machine(coils.combine(merge_points=False)), color=color_copper)
        for name in bodies:
            actor = scene.add_mesh(full_machine(first[name]), name=name, **field)

        scene.camera_position = [(0.17, -0.17, 0.2), (0.0, 0.0, 0.0), (0, 0, 1)]
        scene.camera.parallel_scale = 0.075
        scene.camera.SetWindowCenter(-0.17, 0.0)  # room for the color bar on the left
        add_colorbar(
            scene, actor, "Magnetic Flux Density [T]", n_labels=5, location="left", font_size=15
        )

        # Every second time step keeps the size of the animation down.
        with gif(scene, self.results_path / "Animation_Magnetic_Flux_Density.gif") as write_frame:
            for time_step in range(0, reader.number_time_steps, 2):
                fields = reader.read(time_step)
                for name in bodies:
                    scene.add_mesh(full_machine(fields[name]), name=name, **field)
                update_curve(curve, arguments["values"][: time_step + 1])
                write_frame()


if __name__ == "__main__":
    run_case(IpmMotorModelD)
