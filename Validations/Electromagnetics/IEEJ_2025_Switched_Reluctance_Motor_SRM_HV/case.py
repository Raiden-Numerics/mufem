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
    MagneticTorqueReport,
    MatchingInterfaceCondition,
    NonlinearStabilization,
    NonMatchingCoupling,
    NonMatchingInterfaceCondition,
    TangentialMagneticFluxBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)
from mufem.motion import MeshMotionSlidingInterface, RotatingMotion

# One 60 deg sector of the 18/12 machine is modeled, and the half z >= 0 of its stack: 6 sectors,
# times 2 for the mirror at z = 0.
FULL_MODEL_SCALE = 12.0

# The rotation that maps the cut face at +60 deg onto the cut face at 0 deg.
ROTATION_MINUS_60_Z = [
    [0.5, 0.8660254037844386, 0.0],
    [-0.8660254037844386, 0.5, 0.0],
    [0.0, 0.0, 1.0],
]

PHASES = ("U", "V", "W")
TURNS_PER_COIL = 17
PEAK_CURRENT = 250.0

# The rotor is built in the unaligned position of phase U; half a rotor pole pitch further it is
# aligned. The rotor repeats every 30 deg.
UNALIGNED_TO_ALIGNED_DEG = 15.0
ROTOR_POLE_PITCH_DEG = 30.0
POSITIONS_PER_DEG = 2

# The unaligned position of each phase, from that of U: the pole of V is 20 deg ahead of that of
# U, so the rotor reaches it 20 - 30 = -10 deg after U; W is 20 deg behind, 10 deg after U.
PHASE_UNALIGNED_DEG = {"U": 0.0, "V": -10.0, "W": 10.0}

# Each phase conducts over the middle 10 deg of its 15 deg stroke: V to U at 2.5 deg, U to W at
# 12.5 deg, W to V at 22.5 deg, the switching of the portal's commutated torque. At each switching
# the current crosses over linearly within +-1 deg (a modification of the ideal commutation).
CONDUCTION_START_DEG = 2.5
CONDUCTION_DEG = ROTOR_POLE_PITCH_DEG / len(PHASES)
SWITCHING_RAMP_DEG = 2.0

# The drive starts where the stroke ends (15 deg, inside the conduction of W) and is reported over
# one rotor pole pitch from the next switching, V on at 22.5 deg.
DRIVE_LEAD_DEG = 7.5
PERIOD_START_DEG = UNALIGNED_TO_ALIGNED_DEG + DRIVE_LEAD_DEG
DRIVE_END_DEG = PERIOD_START_DEG + ROTOR_POLE_PITCH_DEG

# The time scale is arbitrary (no eddy currents): 15 deg per second.
DEGREES_PER_SECOND = 15.0

# The portal torque is that of its half-machine model: twice it is the co-energy torque of its own
# flux linkage table (see the README).
PORTAL_TORQUE_SCALE = 2.0

# Phase colors of the animation; the color map of the iron holds none of them.
PHASE_COLORS = {"U": "#e03131", "V": "#2f9e44", "W": "#1c7ed6"}


def conduction(phase, angle):
    """The fraction of the current that `phase` carries at the rotor angle `angle` [deg] from the
    unaligned position of U: 1 within its conduction, with a linear ramp centered on each
    switching angle."""
    pitch, ramp = ROTOR_POLE_PITCH_DEG, SWITCHING_RAMP_DEG
    offset = (
        angle - PHASE_UNALIGNED_DEG[phase] - CONDUCTION_START_DEG + 0.5 * pitch
    ) % pitch - 0.5 * pitch
    rise = (offset + 0.5 * ramp) / ramp
    fall = (CONDUCTION_DEG + 0.5 * ramp - offset) / ramp
    return min(max(min(rise, fall), 0.0), 1.0)


def phase_current(phase, angle):
    """The current of `phase` [A] at the rotor angle `angle` [deg]: during the stroke only U, then
    the commutated drive. The drive begins half a position after the stroke ends, so that the
    aligned position still belongs to the stroke."""
    if angle <= UNALIGNED_TO_ALIGNED_DEG + 0.5 / POSITIONS_PER_DEG:
        return PEAK_CURRENT if phase == "U" else 0.0
    return PEAK_CURRENT * conduction(phase, angle)


def current_table(phase):
    """`phase_current` as a time table: the corners of the switching ramps, and a step between the
    two positions where the drive begins."""
    drive_start = UNALIGNED_TO_ALIGNED_DEG + 0.5 / POSITIONS_PER_DEG
    step = 1.0e-6
    angles = {0.0, DRIVE_END_DEG, drive_start - step, drive_start + step}
    switching = CONDUCTION_START_DEG + PHASE_UNALIGNED_DEG[phase]
    for k in range(-1, int(DRIVE_END_DEG // ROTOR_POLE_PITCH_DEG) + 2):
        for edge in (switching, switching + CONDUCTION_DEG):
            for side in (-0.5, 0.5):
                angle = edge + side * SWITCHING_RAMP_DEG + k * ROTOR_POLE_PITCH_DEG
                if drive_start < angle < DRIVE_END_DEG:
                    angles.add(angle)
    angles = sorted(angles)
    return mufem.CffTimeTable(
        [angle / DEGREES_PER_SECOND for angle in angles],
        [phase_current(phase, angle) for angle in angles],
    )


class SwitchedReluctanceMotorSrmHv(ValidationCase):
    name = "IEEJ 2025: Switched Reluctance Motor SRM_HV"
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

        from casekit.colors import color_air, color_copper, color_iron
        from casekit.netgen_geometry import name_body

        z_axis = Axis(Pnt(0, 0, 0), Vec(0, 0, 1))

        # The frame of the drawing data/SRM2_CAD.dxf: stator poles on 20 deg n (W at 0 deg, U at
        # 20 deg, V at 40 deg), slots on 10 deg + 20 deg n. The stator sector is cut through the
        # slot centers at 10 and 70 deg, so that it holds the whole coils of the poles at 20 deg
        # (U), 40 deg (V) and 60 deg (W). The rotor is built in the unaligned position of phase U,
        # poles on 5 deg + 30 deg n, and cut through the interpolar gaps.
        stator_sector_deg = (10.0, 70.0)
        rotor_sector_deg = (-10.0, 50.0)

        shaft_radius = 0.035
        rotor_yoke_radius = 0.070
        rotor_radius = 0.089
        stator_inner_radius = 0.0895
        slot_bottom_radius = 0.116
        stator_outer_radius = 0.1345
        coil_inner_radius = 0.0905
        sliding_radius = 0.5 * (rotor_radius + stator_inner_radius)

        # Half of the axial length: z = 0 is the midplane. The coil sides run 10 mm beyond the
        # stack; the end turn joins them over the end of the pole, 2 mm clear of the iron. The air
        # reaches 60 mm beyond the stack.
        stack_height = 0.0675
        coil_height = stack_height + 0.010
        end_turn_clearance = 0.002
        air_height = stack_height + 0.060

        # The two coil sides of a slot are kept 2 x 0.5 mm apart, so that the cut planes through
        # the slot centers run through air: the source field of a coil lives on the coil only and
        # cannot meet another coil across a periodic face.
        slot_half_width = 0.007445
        separator_half_width = 0.0005

        def polar(radius, angle_deg):
            angle = math.radians(angle_deg)
            return Pnt(radius * math.cos(angle), radius * math.sin(angle), 0)

        def angle_of(point):
            return math.degrees(math.atan2(point[1], point[0])) % 360.0

        def on_angle(point, angle_deg):
            return abs((angle_of(point) - angle_deg + 180.0) % 360.0 - 180.0) < 1e-6

        def sector(first_deg, last_deg):
            half_space = Box(Pnt(-1, 0, -1), Pnt(1, 1, 1))
            return half_space.Rotate(z_axis, first_deg) * half_space.Rotate(
                z_axis, last_deg - 180.0
            )

        def slot_strip(center_deg, half_width, height):
            """The parallel-sided strip of a slot, from the axis out past the slot bottom."""
            strip = Box(Pnt(0, -half_width, 0), Pnt(1.2 * slot_bottom_radius, half_width, height))
            return strip.Rotate(z_axis, center_deg)

        # Stator: yoke and 18 poles; the parallel-sided slots are cut out of the ring ------------
        slot_body = Cylinder((0, 0, 0), Z, r=slot_bottom_radius, h=coil_height)
        stator = Cylinder((0, 0, 0), Z, r=stator_outer_radius, h=stack_height) - Cylinder(
            (0, 0, 0), Z, r=stator_inner_radius, h=stack_height
        )
        for n in range(18):
            stator = (
                stator - slot_strip(10.0 + 20.0 * n, slot_half_width, stack_height) * slot_body
            )

        name_body(stator, "Stator", color=color_iron, individual_names=False)
        stator.faces.Min(Z).name = "Stator::TangentialFlux"

        # Coils: one per stator pole of the sector ------------------------------------------------
        # The + side lies in the upper half of the slot below the pole, the - side in the lower
        # half of the slot above, and the end turn over the pole. The current enters and leaves at
        # the midplane; with the mirror image the coil is a closed turn. The pole at 60 deg (W) is
        # reversed to the one at 0 deg (portal winding), so its current enters at the - side.
        coil_ring = slot_body - Cylinder((0, 0, 0), Z, r=coil_inner_radius, h=coil_height)
        end_turn_ring = coil_ring * Box(
            Pnt(-1, -1, stack_height + end_turn_clearance), Pnt(1, 1, coil_height)
        )

        def coil_side(slot_deg, upper):
            """The half of a slot above (`upper`) or below its center line, off the separator."""
            sign = 1.0 if upper else -1.0
            inner, outer = sign * separator_half_width, sign * slot_half_width
            half = Box(
                Pnt(0, min(inner, outer), 0),
                Pnt(1.2 * slot_bottom_radius, max(inner, outer), coil_height),
            )
            return half.Rotate(z_axis, slot_deg) * coil_ring

        coils = []
        for pole_deg, phase, polarity in [(20.0, "U", 1), (40.0, "V", 1), (60.0, "W", -1)]:
            end_turn = (
                end_turn_ring * sector(pole_deg - 10.0, pole_deg + 10.0)
                - slot_strip(pole_deg - 10.0, separator_half_width, coil_height)
                - slot_strip(pole_deg + 10.0, separator_half_width, coil_height)
            )
            coil = (
                coil_side(pole_deg - 10.0, upper=True)
                + end_turn
                + coil_side(pole_deg + 10.0, upper=False)
            )
            coil_name = f"Coil::{phase}"
            name_body(coil, coil_name, color=color_copper, individual_names=False)
            terminals = [face for face in coil.faces if abs(face.center[2]) < 1e-9]
            if len(terminals) != 2:
                raise RuntimeError(f"{coil_name}: {len(terminals)} faces at z = 0")
            for face in terminals:
                below = angle_of(face.center) < pole_deg
                face.name = f"{coil_name}::{'In' if below == (polarity > 0) else 'Out'}"
            coils.append(coil)

        # Rotor: yoke ring around the non-magnetic shaft (air) and 12 tapered poles ---------------
        # The flanks run straight from +-7.850 deg at the yoke to +-5.514 deg at the tip, extended
        # into the yoke so that the union is clean.
        def rotor_pole(center_deg):
            base_radius = 0.95 * rotor_yoke_radius

            def flank(sign):
                p, q = polar(rotor_yoke_radius, sign * 7.850), polar(rotor_radius, sign * 5.514)
                t = (base_radius - rotor_yoke_radius) / (rotor_radius - rotor_yoke_radius)
                return Pnt(p[0] + t * (q[0] - p[0]), p[1] + t * (q[1] - p[1]), 0), q

            base_minus, tip_minus = flank(-1)
            base_plus, tip_plus = flank(+1)
            wire = Wire(
                [
                    Segment(base_minus, tip_minus),
                    ArcOfCircle(tip_minus, polar(rotor_radius, 0.0), tip_plus),
                    Segment(tip_plus, base_plus),
                    Segment(base_plus, base_minus),
                ]
            )
            return Face(wire).Extrude(stack_height * Z).Rotate(z_axis, center_deg)

        shaft = Cylinder((0, 0, 0), Z, r=shaft_radius, h=stack_height)
        rotor = Cylinder((0, 0, 0), Z, r=rotor_yoke_radius, h=stack_height)
        for n in range(12):
            rotor = rotor + rotor_pole(5.0 + 30.0 * n)
        rotor = rotor - shaft
        name_body(rotor, "Rotor", color=color_iron, individual_names=False)
        rotor.faces.Min(Z).name = "Rotor::TangentialFlux"

        # Air ---------------------------------------------------------------------------------
        # A cylinder in the middle of the air gap separates the air turning with the rotor from
        # the outer air.
        air_rotor = Cylinder((0, 0, 0), Z, r=sliding_radius, h=air_height)
        name_body(air_rotor, "Air-Rotor", color=color_air, individual_names=False)
        air_rotor.faces.name = "Air-Rotor::TangentialFlux"
        air_rotor = air_rotor - rotor

        air = Cylinder((0, 0, 0), Z, r=0.180, h=air_height)
        name_body(air, "Air", color=color_air, individual_names=False)
        air.faces.name = "Air::TangentialFlux"
        air.faces.maxh = 0.02
        air = air - Cylinder((0, 0, 0), Z, r=sliding_radius, h=air_height) - stator
        for coil in coils:
            air = air - coil

        # Cut to the sector ---------------------------------------------------------------------
        stator = stator * sector(*stator_sector_deg)
        air = air * sector(*stator_sector_deg)
        rotor = rotor * sector(*rotor_sector_deg)
        air_rotor = air_rotor * sector(*rotor_sector_deg)

        def name_cut_faces(body, sector_deg, prefix):
            for face in body.faces:
                if math.hypot(face.center[0], face.center[1]) < 1e-9:
                    continue
                for side, angle in enumerate(sector_deg):
                    if on_angle(face.center, angle):
                        face.name = f"{prefix}::{side}"

        for body in (stator, air):
            name_cut_faces(body, stator_sector_deg, "Periodic::Stator")
        for body in (rotor, air_rotor):
            name_cut_faces(body, rotor_sector_deg, "Periodic::Rotor")
        for coil in coils:
            for face in coil.faces:
                if any(on_angle(face.center, angle) for angle in stator_sector_deg):
                    raise RuntimeError(f"A coil face lies on a cut plane at {face.center}")

        # The sliding cylinder ------------------------------------------------------------------
        # Seams with different counts on the two sides pin their mesh columns, so that the two
        # meshes never coincide while the rotor turns.
        def split_cylinder(body, sector_deg, number_pieces):
            first, last = (math.radians(angle) for angle in sector_deg)
            piece_angle = (last - first) / number_pieces
            seams = []
            for k in range(1, number_pieces):
                x = sliding_radius * math.cos(first + k * piece_angle)
                y = sliding_radius * math.sin(first + k * piece_angle)
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

        air_rotor, rotor_pieces = split_cylinder(air_rotor, rotor_sector_deg, 30)
        air, stator_pieces = split_cylinder(air, stator_sector_deg, 25)
        for face in rotor_pieces:
            face.name = "AirRotor::Cylinder"
        for face in stator_pieces:
            face.name = "Air::Cylinder"

        # Mesh sizes: the air gap of 0.5 mm, the pole tips and the bore refined -------------------
        airgap_maxh = 0.7e-3
        rotor.faces.maxh = 0.004
        stator.faces.maxh = 0.004
        for body, radius in ((rotor, rotor_radius), (stator, stator_inner_radius)):
            for face in body.faces:
                if abs(math.hypot(face.center[0], face.center[1]) - radius) < 2e-3:
                    face.maxh = airgap_maxh

        # Each side is glued on its own and the sides are only put together, so that the faces of
        # the sliding cylinder stay separate.
        geometry = Compound([Glue([rotor, air_rotor]), Glue([stator] + coils + [air])], False)

        # Periodic surface meshes on the cut faces.
        for prefix, sector_deg in (
            ("Periodic::Stator", stator_sector_deg),
            ("Periodic::Rotor", rotor_sector_deg),
        ):
            side0 = [face for face in geometry.faces if face.name == f"{prefix}::0"]
            side1 = [face for face in geometry.faces if face.name == f"{prefix}::1"]
            if len(side0) != len(side1) or not side0:
                raise RuntimeError(f"{prefix}: {len(side0)} vs {len(side1)} cut faces")
            turn = math.radians(sector_deg[0] - sector_deg[1])
            for face1 in side1:
                # The image of the center under the rotation by -60 deg.
                x, y, z = face1.center
                image = (
                    x * math.cos(turn) - y * math.sin(turn),
                    x * math.sin(turn) + y * math.cos(turn),
                    z,
                )
                face0 = min(side0, key=lambda face: math.dist(face.center, image))
                if math.dist(face0.center, image) > 1e-6:
                    raise RuntimeError(f"{prefix}: no cut face matches {face1.center}")
                face1.Identify(
                    face0,
                    prefix,
                    IdentificationType.PERIODIC,
                    Rotation(z_axis, sector_deg[0] - sector_deg[1]),
                )

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
        # The named faces lost their color in the STEP file.
        for solid in solids:
            color = next(face.col for face in solid.faces if face.col is not None)
            for face in solid.faces:
                if face.col is None:
                    face.col = color

        image = snapshot(
            shapes=solids, direction=(0, 0, 1), up=(0, 1, 0), zoom=-28, size=(1600, 1400)
        )
        image = trim(image=image)
        labels = Labels(image=image, font_size=38)
        labels.text(position=(900, 560), text="Stator")
        labels.text(position=(300, 1150), text="Rotor")
        # The coils at the centers of their end turns.
        for text, position in [("U", (740, 890)), ("V", (570, 560)), ("W", (310, 370))]:
            labels.text(position=position, text=text)
        image.save(self.dir_path / "data" / "Geometry.png")

        image = snapshot(
            shapes=solids, direction=(1, 0.2, 0.7), up=(0, 0, 1), zoom=-30, size=(1600, 1400)
        )
        image = trim(image=image)
        labels = Labels(image=image, font_size=38)
        labels.text(position=(650, 700), text="Stator")
        labels.text(position=(300, 110), text="Rotor")
        labels.text(position=(600, 45), text="End turns", anchor="mm")
        labels.arrow(start=(600, 70), end=(600, 160), head=22)
        image.save(self.dir_path / "data" / "Geometry_Side.png")

    def setup_case(self):
        # The periodic cut faces of each side are paired by the rotation by -60 deg; the two sides
        # of the sliding cylinder are meshed independently.
        interfaces = [
            mufem.MatchingInterface(
                name=f"Periodic {side}",
                marker0=f"Periodic::{side}::0",
                marker1=f"Periodic::{side}::1",
                rotation=ROTATION_MINUS_60_Z,
            )
            for side in ("Rotor", "Stator")
        ]
        interfaces.append(
            mufem.NonMatchingInterface(
                name="AirRotor<->Air sliding",
                marker0="AirRotor::Cylinder",
                marker1="Air::Cylinder",
                rotation=ROTATION_MINUS_60_Z,
            )
        )
        sim = mufem.Simulation.New(name=self.name)
        sim.get_domain().load_mesh(f"{self.mesh_path}", interfaces=interfaces)

        # Nothing conducts eddy currents: every time step is the magnetostatic field at one rotor
        # position. solve() steps through the positions.
        self.runner = mufem.UnsteadyRunner(
            total_time=DRIVE_END_DEG / DEGREES_PER_SECOND,
            time_step_size=1.0 / (DEGREES_PER_SECOND * POSITIONS_PER_DEG),
            total_inner_iterations=20,
        )
        sim.set_runner(self.runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeDomainMagneticModel(
            order=1, magnetostatic_initialization=True, formulation=Formulation.FieldConforming
        )
        sim.get_model_manager().add_model(magnetic_model)
        # At 250 A the pole tips saturate deeply.
        magnetic_model.get_solver().set_nonlinear_stabilization(
            NonlinearStabilization.MaterialState
        )

        # Motion -----------------------------------------------------------------------
        rotor_marker = "Rotor|Air-Rotor"
        motion = RotatingMotion(
            name="Rotation",
            marker=Vol(rotor_marker),
            origin=[0.0, 0.0, 0.0],
            axis=[0.0, 0.0, 1.0],
            rotation_rate=DEGREES_PER_SECOND / 360.0,
        )
        rbm_model = RigidBodyMotionModel(mesh_motion_strategy=MeshMotionSlidingInterface())
        rbm_model.add_motion(motion)
        sim.get_model_manager().add_model(rbm_model)

        # Materials --------------------------------------------------------------------
        bh = numpy.loadtxt(
            self.dir_path / "data" / "10JNEX900_BH.csv", delimiter=",", comments="#"
        )
        magnetic_model.add_materials(
            [
                TimeDomainMagneticGeneralMaterial(name="Air", marker=["Air", "Air-Rotor"] @ Vol),
                TimeDomainMagneticGeneralMaterial(
                    name="Iron",
                    marker=["Rotor", "Stator"] @ Vol,
                    magnetic_permeability=(bh[:, 1], bh[:, 0]),
                    has_eddy_currents=False,
                ),
                TimeDomainMagneticGeneralMaterial(
                    name="Copper",
                    marker=Vol("Coil::.*"),
                    electric_conductivity=5.8e7,
                    has_eddy_currents=False,
                ),
            ]
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
                    marker=f"Periodic {side}" @ mufem.Interface,
                    symmetry=InterfaceSymmetry.ANTI_PERIODIC,
                )
            )

        # Where one side of the sliding cylinder reaches past the other, it couples to the
        # anti-periodic image.
        magnetic_model.add_condition(
            NonMatchingInterfaceCondition(
                name="AirRotor<->Air sliding",
                marker="AirRotor<->Air sliding" @ mufem.Interface,
                symmetry=InterfaceSymmetry.ANTI_PERIODIC,
                coupling=NonMatchingCoupling.CONSERVATIVE,
            )
        )

        # Coils ------------------------------------------------------------------------
        # The sector holds one whole coil per phase: up the + side, over the end turn, down the
        # - side, between its two terminals at the midplane.
        coil_model = ExcitationCoilModel()
        sim.get_model_manager().add_model(coil_model)
        for phase in PHASES:
            coil_model.add_coil_specification(
                CoilSpecification(
                    name=f"Coil {phase}",
                    marker=Vol(f"Coil::{phase}"),
                    topology=CoilTopologyOpen(
                        in_marker=Bnd(f"Coil::{phase}::In"),
                        out_marker=Bnd(f"Coil::{phase}::Out"),
                    ),
                    type=CoilTypeStranded(number_of_turns=TURNS_PER_COIL),
                    excitation=CoilExcitationCurrent(current=current_table(phase)),
                )
            )

        sim.get_report_manager().add_report(MagneticFluxLinkageReport("Flux Linkage U", 0))
        self.flux_monitor = mufem.ReportMonitor(
            name="Flux Linkage U Monitor", report_name="Flux Linkage U"
        )
        sim.get_monitor_manager().add_monitor(self.flux_monitor)

        # Torque -----------------------------------------------------------------------
        torque_report = MagneticTorqueReport(name="Rotor Torque", marker=Vol(rotor_marker))
        sim.get_report_manager().add_report(torque_report)
        self.torque_monitor = mufem.ReportMonitor(
            name="Rotor Torque Monitor", report_name="Rotor Torque"
        )
        sim.get_monitor_manager().add_monitor(self.torque_monitor)

        self.runner.add_convergence_criterion(
            mufem.ReportConvergenceCriterion(
                "Delta Torque",
                torque_report,
                tolerance=1.0e-5,
                absolute_tolerance=1.0e-6,
                component=mufem.VectorComponent.Z,
            )
        )

        # The fields of the reported pole pitch for the scenes of create_scenes(), saved by
        # solve().
        self.field_exporter = sim.get_field_exporter()
        self.field_exporter.set_output_directory(self.dir_path / "VisualizationOutput")
        self.field_exporter.add_field_outputs(["Magnetic Flux Density"])
        self.field_exporter.set_events([])

        return sim

    def solve(self):
        self.sim.initialize()
        positions = int(DRIVE_END_DEG * POSITIONS_PER_DEG + 1e-9)
        for position in range(1, positions + 1):
            self.runner.advance(1)
            if self.field_export and position / POSITIONS_PER_DEG > PERIOD_START_DEG:
                self.field_exporter.save()

    @staticmethod
    def by_rotor_angle(values, first, last):
        """(Rotor angle from the unaligned position of U [deg], value of the full machine) of the
        monitor values at the positions in (first, last], with 0 deg for first = 0."""
        return [
            (DEGREES_PER_SECOND * t, FULL_MODEL_SCALE * value)
            for t, value in values
            if first < DEGREES_PER_SECOND * t <= last + 1e-6 or (first == 0.0 and t == 0.0)
        ]

    def validate(self):
        torque = [(t, value.z) for t, value in self.torque_monitor.get_values()]
        flux_linkage = self.flux_monitor.get_values()
        self.stroke_torque = self.by_rotor_angle(torque, 0.0, UNALIGNED_TO_ALIGNED_DEG)
        self.stroke_flux_linkage = self.by_rotor_angle(flux_linkage, 0.0, UNALIGNED_TO_ALIGNED_DEG)
        self.commutated_torque = self.by_rotor_angle(torque, PERIOD_START_DEG, DRIVE_END_DEG)

        stroke_torque = numpy.array(self.stroke_torque)
        commutated_torque = numpy.array(self.commutated_torque)[:, 1]
        flux_linkage = numpy.array(self.stroke_flux_linkage)

        # IEEJ portal, SRM2_T-position.csv at 250 A, times 2: the mean torque over the stroke, the
        # work per stroke over its angle (trapezoidal rule on the equidistant positions).
        values = stroke_torque[:, 1]
        stroke_mean = (values.sum() - 0.5 * (values[0] + values[-1])) / (len(values) - 1)
        expect(stroke_mean, 260.0, rel_tol=5e-2, label="mean stroke torque, IEEJ 2D [Nm]")
        # IEEJ portal, SRM2_Flux-I.csv at 250 A: the aligned flux linkage. The 3D model lies above
        # the 2D table by the end field, see the README.
        expect(
            flux_linkage[-1, 1], 0.523, rel_tol=10e-2, label="aligned flux linkage, IEEJ 2D [Wb]"
        )
        # IEEJ portal, SRM2_torque.csv: the mean of the commutated torque at 250 A.
        expect(
            commutated_torque.mean(),
            337.5,
            rel_tol=5e-2,
            label="commutated mean torque, IEEJ 2D [Nm]",
        )

    def commutated_torque_plot(self, commutated_torque):
        """The arguments of xy_plot for the commutated torque over the pole pitch from the
        switching on of V; the end of the pitch is the same state as its start, so its value
        stands at 0 deg as well."""
        reference = numpy.loadtxt(
            self.dir_path / "data" / "Reference_Commutated_Torque_250A.csv",
            delimiter=",",
            comments="#",
        )
        # The table spans one pole pitch from 0 deg; with its copy one pitch further it covers the
        # reported pitch.
        reference = numpy.vstack([reference, reference + [ROTOR_POLE_PITCH_DEG, 0.0]])
        values = [(angle - PERIOD_START_DEG, torque) for angle, torque in commutated_torque]
        return dict(
            values=[(0.0, values[-1][1])] + values,
            style=PlotStyle.LINE,
            reference_values=[
                (angle - PERIOD_START_DEG, torque)
                for angle, torque in reference
                if PERIOD_START_DEG <= angle <= DRIVE_END_DEG
            ],
            reference_style=PlotStyle.LINE,
            reference_label="IEEJ 2D FEA (TR 1589)",
            xlabel="Rotor Angle from the Switching on of V [deg]",
            ylabel="Rotor Torque [Nm]",
            xlim=(0.0, ROTOR_POLE_PITCH_DEG),
            xticks=[0.0, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0],
            ylim=(0.0, 480.0),
        )

    def postprocess(self):
        if not self.is_main():
            return

        # The input of the animation of create_scenes(): the positions of the saved fields.
        angles = numpy.array([angle for angle, _ in self.commutated_torque])
        currents = numpy.array([[phase_current(phase, a) for phase in PHASES] for a in angles])
        numpy.savez(
            self.scene_data_path,
            angles=angles,
            currents=currents,
            torque=numpy.array([torque for _, torque in self.commutated_torque]),
        )

        common = dict(
            style=PlotStyle.LINE,
            xlabel="Rotor Angle from the Unaligned Position [deg]",
            xlim=(0.0, UNALIGNED_TO_ALIGNED_DEG),
            xticks=[0.0, 3.0, 6.0, 9.0, 12.0, 15.0],
            reference_style=PlotStyle.LINE,
        )
        xy_plot(
            values=self.stroke_torque,
            reference_file=f"{self.dir_path / 'data' / 'Reference_Torque_250A.csv'}",
            reference_yscale=PORTAL_TORQUE_SCALE,
            reference_label="IEEJ 2D FEA (TR 1589), x2",
            ylabel="Rotor Torque [Nm]",
            path=f"{self.results_path / 'Rotor_Torque_vs_Angle.png'}",
            **common,
        )
        xy_plot(
            values=self.stroke_flux_linkage,
            reference_file=f"{self.dir_path / 'data' / 'Reference_Flux_Linkage_250A.csv'}",
            reference_label="IEEJ 2D FEA (TR 1589)",
            ylabel="Flux Linkage U [Wb]",
            ylim=(0.0, 0.6),
            path=f"{self.results_path / 'Flux_Linkage_U_vs_Angle.png'}",
            **common,
        )
        xy_plot(
            path=f"{self.results_path / 'Commutated_Torque_vs_Angle.png'}",
            **self.commutated_torque_plot(self.commutated_torque),
        )

    def create_scenes(self):
        """The commutated machine over a full turn: the fields of the reported pole pitch, twelve
        times, with a D-shaft turning for the eye only (the bore is air in the model)."""
        import pyvista as pv
        from PIL import Image

        from casekit.colors import color_copper
        from casekit.pyvista_scene import (
            FieldExportReader,
            _font,
            add_colorbar,
            create_scene,
            update_curve,
            xy_chart,
        )

        reader = FieldExportReader(self.dir_path)
        scene_data = numpy.load(self.scene_data_path)
        angles, currents, torque = (
            scene_data["angles"],
            scene_data["currents"],
            scene_data["torque"],
        )
        if reader.number_time_steps != len(angles):
            raise RuntimeError(
                f"{reader.number_time_steps} field outputs, {len(angles)} positions"
            )

        def full_machine(mesh):
            """The six sectors and their mirror images at the midplane z = 0. The cells of the
            field export do not share their points: merged, only the outer faces remain."""
            surface = mesh.clean().extract_surface(algorithm=None)
            copies = []
            for k in range(6):
                rotated = surface.rotate_z(60.0 * k, point=(0.0, 0.0, 0.0))
                copies += [rotated, rotated.reflect((0.0, 0.0, 1.0), point=(0.0, 0.0, 0.0))]
            return pv.merge(copies)

        def d_shaft(angle):
            """A shaft with one flat in the bore, turned with the rotor by `angle` [deg]."""
            radius, flat, stack_height = 0.0347, 0.024, 0.0675
            t = numpy.linspace(0.0, 2.0 * numpy.pi, 181)[:-1]
            xy = radius * numpy.column_stack([numpy.cos(t), numpy.sin(t)])
            xy[:, 0] = numpy.minimum(xy[:, 0], flat)
            profile = pv.PolyData(
                numpy.column_stack([xy, numpy.full(len(xy), -stack_height)]),
                faces=[len(xy), *range(len(xy))],
            )
            body = profile.extrude((0.0, 0.0, 2.0 * stack_height + 0.07), capping=True)
            return body.triangulate().rotate_z(angle, point=(0.0, 0.0, 0.0))

        machines = {}

        def machine(index):
            """The iron, the coils and the outlines of the coils at the position `index`; each
            position is shown in twelve frames, so it is built once."""
            if index not in machines:
                bodies = reader.read(index)
                iron = full_machine(pv.merge([bodies["Rotor"], bodies["Stator"]]))
                iron.point_data["B"] = numpy.linalg.norm(
                    iron.point_data["Magnetic Flux Density"], axis=1
                )
                coils = {phase: full_machine(bodies[f"Coil::{phase}"]) for phase in PHASES}
                outlines = {
                    phase: coil.extract_feature_edges(
                        30.0, boundary_edges=False, manifold_edges=False
                    ).tube(radius=0.0013, n_sides=8)
                    for phase, coil in coils.items()
                }
                machines[index] = iron, coils, outlines
            return machines[index]

        # The plots run over the angle within the pole pitch; the end of the pitch is the same
        # state as its start, so its values stand at 0 deg as well.
        torque_plot = self.commutated_torque_plot(list(zip(angles, torque)))
        plot_angle = numpy.concatenate([[0.0], angles - PERIOD_START_DEG])
        plot_currents = numpy.vstack([currents[-1:], currents])
        plot_torque = numpy.concatenate([torque[-1:], torque])

        # The machine on the left, the phase currents and the torque on the right.
        scene = create_scene(
            (1280, 720),
            shape=(2, 2),
            groups=[(numpy.s_[:], 0)],
            col_weights=[0.56, 0.44],
            row_weights=[0.45, 0.55],
            border=False,
        )

        scene.subplot(0, 1)
        current_chart = pv.Chart2D(
            x_label="Rotor Angle [deg]", y_label="Phase Current [A]", grid=False
        )
        current_chart.x_range = [0.0, ROTOR_POLE_PITCH_DEG]
        current_chart.y_range = [0.0, 300.0]
        current_curves = {}
        for phase in PHASES:
            # A phase is drawn only while it carries current, and with the zeros next to that,
            # so that a ramp starts from 0; a phase conducts at most twice within the pitch.
            current_curves[phase] = [
                current_chart.line([0.0], [0.0], color=PHASE_COLORS[phase], width=3.0, label=label)
                for label in (phase, "")
            ]
        cursor = current_chart.line([0.0, 0.0], [0.0, 300.0], color="#495057", width=1.0)
        scene.add_chart(current_chart)

        scene.subplot(1, 1)
        torque_chart, torque_curve, _ = xy_chart(
            **dict(
                torque_plot,
                values=[(0.0, plot_torque[0])],
                xlabel="Rotor Angle [deg]",
                yticks=[0.0, 100.0, 200.0, 300.0, 400.0],
                legend_loc="lower right",
            )
        )
        torque_chart.line(plot_angle, plot_torque, color=(1.0, 0.0, 0.0, 0.2), width=2.0)
        torque_dot = torque_chart.scatter([0.0], [0.0], color="black", size=12)
        scene.add_chart(torque_chart)
        for axis in (current_chart.x_axis, current_chart.y_axis):
            _font(axis.GetTitleProperties(), 20)
            _font(axis.GetLabelProperties(), 18)
        current_chart.size = (0.97, 1.0)
        current_chart.border_color = "white"
        current_chart.legend.GetPen().SetOpacity(0)
        current_chart.legend.GetBrush().SetOpacity(0)
        _font(current_chart.legend.GetLabelProperties(), 18)

        scene.subplot(0, 0)
        field = dict(
            scalars="B", cmap="viridis", n_colors=64, clim=(0.0, 2.5), show_scalar_bar=False
        )
        shading = dict(ambient=0.3, diffuse=0.7, specular=0.3, specular_power=20.0)
        iron, coils, _ = machine(0)
        actor = scene.add_mesh(iron, name="Iron", **field)
        add_colorbar(
            scene,
            actor,
            "Magnetic Flux Density [T]",
            n_labels=6,
            location="bottom",
            font_size=20,
        )
        scene.view_xy()
        scene.camera.elevation = -18.0
        scene.camera.azimuth = 15.0
        scene.reset_camera()
        scene.camera.zoom(1.0)
        scene.camera.SetWindowCenter(0.0, -0.15)  # room for the color bar below

        def show_currents(index):
            shown = slice(0, index + 2)
            for j, phase in enumerate(PHASES):
                values = plot_currents[shown, j]
                carries = values > 0.0
                near = carries.copy()
                near[1:] |= carries[:-1]
                near[:-1] |= carries[1:]
                # The runs of positions to draw, each its own curve.
                edges = numpy.flatnonzero(numpy.diff(numpy.concatenate([[0], near, [0]])))
                runs = list(zip(edges[::2], edges[1::2]))
                for k, curve in enumerate(current_curves[phase]):
                    curve.visible = k < len(runs)
                    if curve.visible:
                        first, last = runs[k]
                        update_curve(curve, list(zip(plot_angle[first:last], values[first:last])))
            angle = angles[index] - PERIOD_START_DEG
            cursor.update([angle, angle], [0.0, 300.0])

        # Every second position (1 deg per frame), ending with the last of the pitch; twelve
        # pitches make the full turn.
        frames = []
        for pitch in range(12):
            for index in range(1, len(angles), 2):
                iron, coils, outlines = machine(index)
                scene.subplot(0, 0)
                scene.add_mesh(iron, name="Iron", **field)
                # All coils copper; the conducting ones outlined in the color of their phase,
                # fading with their share of the current through the switching ramps.
                for phase in PHASES:
                    scene.add_mesh(
                        coils[phase], name=f"Coil {phase}", color=color_copper[:3], **shading
                    )
                    share = currents[index][PHASES.index(phase)] / PEAK_CURRENT
                    if share > 0.0:
                        scene.add_mesh(
                            outlines[phase],
                            name=f"Outline {phase}",
                            color=PHASE_COLORS[phase],
                            opacity=share,
                            ambient=0.4,
                            diffuse=0.6,
                        )
                    else:
                        scene.remove_actor(f"Outline {phase}")
                scene.add_mesh(
                    d_shaft(angles[index] + ROTOR_POLE_PITCH_DEG * pitch),
                    name="Shaft",
                    color="#868e96",
                    **shading,
                )
                show_currents(index)
                update_curve(torque_curve, list(zip(plot_angle[: index + 2], plot_torque)))
                update_curve(torque_dot, [(angles[index] - PERIOD_START_DEG, torque[index])])
                # The charts show the data of the previous render: render once more first.
                scene.render()
                frames.append(Image.fromarray(scene.screenshot()))
        scene.close()

        # An animated WebP: full color and a fraction of the size of a GIF. 100 ms per frame: a
        # full turn in 36 s.
        frames[0].save(
            self.results_path / "Animation_Magnetic_Flux_Density.webp",
            save_all=True,
            append_images=frames[1:],
            duration=100,
            loop=0,
            quality=85,
            method=6,
        )


if __name__ == "__main__":
    run_case(SwitchedReluctanceMotorSrmHv)
