from casekit import ValidationCase, expect, run_case

# numpy must be imported before mufem (see casekit/plots.py).
import gzip
import math
import shutil
import tempfile
from pathlib import Path

import matplotlib.pyplot as plt
import numpy

import mufem
from mufem import Bnd, Vol
from mufem.electromagnetics.timedomainmaxwell import (
    FarFieldRadiationSensor,
    LumpedPortCondition,
    PerfectElectricConductorCondition,
    TimeDomainMaxwellGeneralMaterial,
    TimeDomainMaxwellModel,
    TimeDomainMaxwellPmlMaterial,
)


class BentLaminateMesh:
    """Structured all-hex mesh of the patch antenna inside a rectangular PML box [mm].

    The laminate (ground, substrate, feed line and patch) is wrapped onto a cylinder of
    radius `radius` whose axis runs along x; `radius=None` gives the planar antenna. The
    feed line stays straight, the bend starts at the patch's leading edge (y = 0). The
    y-z section is assembled from transfinite quad blocks and extruded along x:

        +--------------------------------------------------+  z_top   top PML
        |                                                  |
        |    ========______                                |          laminate
        |                  ---___                          |
        |                        \\                         |
        |                                                  |
        +--------------------------------------------------+  z_bot   bottom PML
        y_origin                                        y_wall

    The bend rows are radial (R -> R + t), so the substrate keeps its thickness, and the
    developed length is taken at the patch surface, so the patch keeps its length. Past
    the arc the laminate runs straight along its end tangent up to a vertical cut, so it
    ends on a plane the blocks of the box can butt against.
    """

    def __init__(self, radius, t, patch_width, patch_length, feed_width, feed_offset, feed_length):
        self.planar = radius is None
        self.radius = 0.0 if self.planar else radius  # [mm] bend radius at the ground
        self.t = t  # [mm] substrate thickness
        self.patch_width = patch_width  # [mm] along x
        self.patch_length = patch_length  # [mm] along the laminate
        self.feed_width = feed_width  # [mm]
        self.feed_offset = feed_offset  # [mm] patch left edge -> feed line left edge
        self.feed_length = feed_length  # [mm] port at y = -feed_length

        margin_x = 3.0  # [mm] substrate margin left/right of the patch
        margin_y = 3.0  # [mm] substrate margin beyond the far patch edge
        air_height = 12.0  # [mm] clean air above the substrate
        self.d_cap = 2.0  # [mm] air cap, substrate edge to PML
        self.d_cap_y = 4.0  # [mm] -y air cap behind the port
        pml_thickness = 6.0  # [mm]
        self.eps = 1e-4  # [mm] geometric tolerance

        # Divisions.
        self.n_pml = 6  # cells across a PML
        self.n_pml_bot = 4  # the ground shields this side, so the floor layer is coarser
        self.n_below = 3  # cells across the air under the laminate
        self.n_air = 9  # cells across the clean air above
        self.prog_air = 1.13
        self.n_sub = 1  # cells across the substrate
        self.n_capy = 2  # cells across the -y air cap
        self.n_feed = 16  # cells along the feed line
        self.n_patch = 13  # cells along the patch
        n_marg = 1  # cells from the patch edge to the substrate end

        self.x_lo, self.x_hi = -margin_x, patch_width + margin_x
        self.y_lo, self.y_hi = -feed_length, patch_length + margin_y
        self.z_hi = t + air_height
        self.z_top = self.z_hi + pml_thickness
        self.y_origin = self.y_lo - self.d_cap_y - pml_thickness

        # x stations: PML | cap | substrate edge, patch, feed line, substrate edge | cap | PML
        self.x_co = [
            self.x_lo - self.d_cap - pml_thickness,
            self.x_lo - self.d_cap,
            self.x_lo,
            0.0,
            feed_offset,
            feed_offset + feed_width,
            patch_width,
            self.x_hi,
            self.x_hi + self.d_cap,
            self.x_hi + self.d_cap + pml_thickness,
        ]
        self.x_dv = [self.n_pml, 1, 2, 3, 3, 8, 2, 1, self.n_pml]

        # The bend: the arc angle theta makes the developed length of the arc plus the
        # tangent run come out at y_hi.
        self.neutral = self.radius + t  # [mm] radius of the patch surface
        self.d_tan = 1.0  # [mm] how far past the arc the vertical cut stands
        self.theta = 0.0
        if not self.planar:
            self.theta = self.y_hi / self.neutral
            for _ in range(60):
                self.theta = (self.y_hi - self.d_tan / math.cos(self.theta)) / self.neutral
        s_tan = 0.0 if self.planar else self.d_tan / math.cos(self.theta)

        # Stations in developed length, with a node at the patch's far edge.
        self.dev = [patch_length * i / self.n_patch for i in range(self.n_patch)] + [
            patch_length + (self.y_hi - s_tan - patch_length) * i / n_marg
            for i in range(n_marg + 1)
        ]

        if self.planar:
            self.y_cut, self.z_gnd, self.z_pch = self.y_hi, 0.0, t
        else:
            self.y_cut = self.arc(self.theta, self.neutral)[0] + self.d_tan
            self.z_gnd = self.tangent_cut(self.radius)[1]
            self.z_pch = self.tangent_cut(self.neutral)[1]

        # The enclosure is the same for every radius: the floor is set by the r = 20 mm
        # laminate, which reaches deepest, the +y wall by the planar one, which reaches
        # furthest. Every variant keeps at least its air cap.
        self.z_bot = -12.4556  # [mm] floor PML inner face
        self.y_wall_in = 21.0  # [mm] +y PML inner face
        self.z_flr = self.z_bot - pml_thickness
        self.y_wall = self.y_wall_in + pml_thickness

        # A node is matched to a laminate surface by a tolerance above the sagitta of a
        # cell's chord and well below the substrate thickness.
        self.d_surf = 0.2  # [mm]

    # --- geometry -------------------------------------------------------------------
    def arc(self, theta, rho):
        """Point (y, z) on the bend at radius rho from the cylinder axis, angle theta."""
        return (rho * math.sin(theta), rho * math.cos(theta) - self.radius)

    def tangent_cut(self, rho):
        """Where the level at radius rho, run along its end tangent, meets the cut."""
        y0, z0 = self.arc(self.theta, rho)
        y_cut = self.arc(self.theta, self.neutral)[0] + self.d_tan
        return (y_cut, z0 - (y_cut - y0) * math.tan(self.theta))

    def levels_straight(self, y):
        return (y, [self.z_flr, self.z_bot, 0.0, self.t, self.z_hi, self.z_top])

    def levels_laminate(self, dev):
        """(y_ground, y_patch, z_ground, z_patch) at developed length dev."""
        if self.planar:
            return (dev, dev, 0.0, self.t)
        theta = dev / self.neutral
        yg, zg = self.arc(theta, self.radius)
        yp, zp = self.arc(theta, self.neutral)
        return (yg, yp, zg, zp)

    def height_along(self, yc, zc):
        """Height above the ground and developed length (at the patch surface) of a point."""
        if self.planar or yc <= self.eps:
            return zc, yc
        theta = math.atan2(yc, zc + self.radius)
        if theta <= self.theta:
            return math.hypot(yc, zc + self.radius) - self.radius, theta * self.neutral
        y0, z0 = self.arc(self.theta, self.radius)
        dy, dz = yc - y0, zc - z0
        return (
            dy * math.sin(self.theta) + dz * math.cos(self.theta),
            self.theta * self.neutral + dy * math.cos(self.theta) - dz * math.sin(self.theta),
        )

    # --- blocks ---------------------------------------------------------------------
    def quad(self, corners, n_a, n_b, prog=1.0):
        """One transfinite quad from four (y, z) corners, counter-clockwise."""
        import gmsh

        geo = gmsh.model.geo
        points = [geo.addPoint(self.x_co[0], y, z) for y, z in corners]
        lines = [geo.addLine(points[i], points[(i + 1) % 4]) for i in range(4)]
        geo.mesh.setTransfiniteCurve(lines[0], n_a + 1)
        geo.mesh.setTransfiniteCurve(lines[2], n_a + 1)
        geo.mesh.setTransfiniteCurve(lines[1], n_b + 1, "Progression", prog)
        geo.mesh.setTransfiniteCurve(lines[3], n_b + 1, "Progression", 1.0 / prog)
        surface = geo.addPlaneSurface([geo.addCurveLoop(lines)])
        geo.mesh.setTransfiniteSurface(surface)
        geo.mesh.setRecombine(2, surface)
        return surface

    def column(self, lo, hi, n_a):
        """The five stacked blocks between two level lists (floor, PML top, ground,
        patch, air top, domain top)."""
        rows = (
            (self.n_pml_bot, 1.0),
            (self.n_below, 1.0),
            (self.n_sub, 1.0),
            (self.n_air, self.prog_air),
            (self.n_pml, 1.0),
        )
        return [
            self.quad(
                [
                    (lo[0], lo[1][j]),
                    (hi[0], hi[1][j]),
                    (hi[0], hi[1][j + 1]),
                    (lo[0], lo[1][j + 1]),
                ],
                n_a,
                n_b,
                prog,
            )
            for j, (n_b, prog) in enumerate(rows)
        ]

    # --- mesh -----------------------------------------------------------------------
    def write(self, path):
        import gmsh

        gmsh.initialize()
        gmsh.option.setNumber("General.Terminal", 1)
        gmsh.model.add("bent_box")

        section = []

        # The straight run: -y PML, air cap, feed line.
        for y0, y1, n in (
            (self.y_origin, self.y_lo - self.d_cap_y, self.n_pml),
            (self.y_lo - self.d_cap_y, self.y_lo, self.n_capy),
            (self.y_lo, 0.0, self.n_feed),
        ):
            section += self.column(self.levels_straight(y0), self.levels_straight(y1), n)

        # The laminate, one rib per station. The ribs below and above the laminate stand
        # on it but reach level lids, so the box stays a box and the air takes the shear.
        stations = [self.levels_laminate(d) for d in self.dev]
        if not self.planar:
            stations.append((self.y_cut, self.y_cut, self.z_gnd, self.z_pch))
        for (yga, ypa, zga, zpa), (ygb, ypb, zgb, zpb) in zip(stations, stations[1:]):
            z_flr, z_bot, z_hi, z_top = self.z_flr, self.z_bot, self.z_hi, self.z_top
            section += [
                self.quad(
                    [(yga, z_flr), (ygb, z_flr), (ygb, z_bot), (yga, z_bot)], 1, self.n_pml_bot
                ),
                self.quad([(yga, z_bot), (ygb, z_bot), (ygb, zgb), (yga, zga)], 1, self.n_below),
                self.quad([(yga, zga), (ygb, zgb), (ypb, zpb), (ypa, zpa)], 1, self.n_sub),
                self.quad(
                    [(ypa, zpa), (ypb, zpb), (ypb, z_hi), (ypa, z_hi)],
                    1,
                    self.n_air,
                    self.prog_air,
                ),
                self.quad([(ypa, z_hi), (ypb, z_hi), (ypb, z_top), (ypa, z_top)], 1, self.n_pml),
            ]

        # Beyond the laminate: air cap and the +y PML.
        cut = (
            self.y_cut,
            [self.z_flr, self.z_bot, self.z_gnd, self.z_pch, self.z_hi, self.z_top],
        )
        n_cap_y = max(1, int(round((self.y_wall_in - self.y_cut) / 2.0)))
        for y1, n in ((self.y_wall_in, n_cap_y), (self.y_wall, self.n_pml)):
            far = (y1, cut[1])
            section += self.column(cut, far, n)
            cut = far

        gmsh.model.geo.synchronize()

        # Extrude the section along x.
        tops = [(2, s) for s in section]
        for i in range(len(self.x_co) - 1):
            out = gmsh.model.geo.extrude(
                tops,
                self.x_co[i + 1] - self.x_co[i],
                0.0,
                0.0,
                numElements=[self.x_dv[i]],
                recombine=True,
            )
            tops = [out[6 * k] for k in range(len(section))]
        gmsh.model.geo.synchronize()
        gmsh.model.mesh.generate(3)

        self.add_physical_groups(rows=len(stations) - 1)

        # Gmsh 2.2, gzipped (mtime 0 keeps a rebuilt file byte-identical).
        gmsh.option.setNumber("Mesh.MshFileVersion", 2.2)
        with tempfile.TemporaryDirectory() as directory:
            plain = Path(directory) / "geometry.msh"
            gmsh.write(str(plain))
            with open(plain, "rb") as source, gzip.GzipFile(path, "wb", mtime=0) as target:
                shutil.copyfileobj(source, target)
        gmsh.finalize()

    def laminate_frame(self, dim, tag):
        """x, height above ground and developed length of every node of an entity.

        Nodes, not the bounding box: the box center of a tilted cell on the bend can sit
        far off the surface its corners lie on.
        """
        import gmsh

        nodes = gmsh.model.mesh.getNodes(dim, tag, includeBoundary=True)[1].reshape(-1, 3)
        frame = [self.height_along(y, z) for _, y, z in nodes]
        return nodes[:, 0], [h for h, _ in frame], [d for _, d in frame]

    def add_physical_groups(self, rows):
        import gmsh

        eps = self.eps
        t = self.t
        xf, wf = self.feed_offset, self.feed_width

        def band(lo, c, hi):
            return lo - eps < c < hi + eps

        def on_sheet(heights, level):
            return max(abs(h - level) for h in heights) < self.d_surf

        ground, trace, patch, port = [], [], [], []
        for dim, tag in gmsh.model.getEntities(2):
            _, heights, devs = self.laminate_frame(dim, tag)
            x0, y0, z0, x1, y1, z1 = gmsh.model.getBoundingBox(dim, tag)
            xc = 0.5 * (x0 + x1)
            # The tangent frame continues past the laminate, so every sheet test is
            # fenced by the cut plane.
            span = y1 < self.y_cut + eps and y0 > self.y_origin - eps
            if (
                (y1 - y0) < eps
                and abs(0.5 * (y0 + y1) + self.feed_length) < eps
                and band(xf, xc, xf + wf)
                and z0 > -eps
                and z1 < t + eps
            ):
                port.append(tag)
            elif span and on_sheet(heights, 0.0) and band(self.x_lo, xc, self.x_hi):
                ground.append(tag)
            elif (
                span
                and on_sheet(heights, t)
                and band(xf, xc, xf + wf)
                and band(-self.feed_length, min(devs), 0.0)
                and max(devs) < eps
            ):
                trace.append(tag)
            elif (
                span
                and on_sheet(heights, t)
                and band(0.0, xc, self.patch_width)
                and min(devs) > -eps
                and max(devs) < self.patch_length + eps
            ):
                patch.append(tag)

        substrate, air, pml = [], [], []
        for _, v in gmsh.model.getEntities(3):
            x0, y0, z0, x1, y1, z1 = gmsh.model.getBoundingBox(3, v)
            xc, yc, zc = 0.5 * (x0 + x1), 0.5 * (y0 + y1), 0.5 * (z0 + z1)
            if (
                xc < self.x_lo - self.d_cap - eps
                or xc > self.x_hi + self.d_cap + eps
                or yc < self.y_lo - self.d_cap_y - eps
                or yc > self.y_wall_in + eps
                or zc > self.z_hi + eps
                or zc < self.z_bot - eps
            ):
                pml.append(v)
                continue
            _, heights, _ = self.laminate_frame(3, v)
            if (
                band(self.x_lo, xc, self.x_hi)
                and min(heights) > -self.d_surf
                and max(heights) < t + self.d_surf
                and self.y_lo - eps < yc < self.y_cut + eps
            ):
                substrate.append(v)
            else:
                air.append(v)

        # A misclassified entity passes every geometric test and silently changes the
        # permittivity or the PEC coverage, so pin the group sizes to the divisions.
        n_x_laminate = sum(self.x_dv[2:7])
        expected = {
            "ground": (
                (2, ground),
                (self.n_pml + self.n_capy + self.n_feed + rows) * n_x_laminate,
            ),
            "trace": ((2, trace), self.n_feed * self.x_dv[4]),
            "patch": ((2, patch), self.n_patch * sum(self.x_dv[3:6])),
            "port_1": ((2, port), self.n_sub * self.x_dv[4]),
            "substrate": ((3, substrate), self.n_sub * (self.n_feed + rows) * n_x_laminate),
        }
        for name, ((dim, tags), count) in expected.items():
            got = sum(len(e) for x in tags for e in gmsh.model.mesh.getElements(dim, x)[1])
            if got != count:
                raise RuntimeError(f"{name} has {got} elements, the divisions give {count}")

        # A seam between blocks would leave a slot through the domain; check that the
        # cells fill the box.
        volume = sum(
            sum(gmsh.model.mesh.getElementQualities(e, "volume"))
            for _, v in gmsh.model.getEntities(3)
            for e in gmsh.model.mesh.getElements(3, v)[1]
        )
        box = (
            (self.x_co[-1] - self.x_co[0])
            * (self.y_wall - self.y_origin)
            * (self.z_top - self.z_flr)
        )
        if abs(volume - box) > 1e-9 * box:
            raise RuntimeError(f"the cells fill {volume:.4f} mm^3 of the {box:.4f} mm^3 box")

        gmsh.model.addPhysicalGroup(3, substrate, name="substrate", tag=1)
        gmsh.model.addPhysicalGroup(3, air, name="air", tag=10)
        gmsh.model.addPhysicalGroup(3, pml, name="pml", tag=11)
        gmsh.model.addPhysicalGroup(2, ground, name="ground", tag=2)
        gmsh.model.addPhysicalGroup(2, trace, name="trace", tag=3)
        gmsh.model.addPhysicalGroup(2, patch, name="patch", tag=4)
        gmsh.model.addPhysicalGroup(2, port, name="port_1", tag=5)

        def outer_boundary(volumes):
            dimtags = [(3, v) for v in volumes]
            return [
                s
                for dim, s in gmsh.model.getBoundary(dimtags, combined=True, oriented=False)
                if dim == 2
            ]

        gmsh.model.addPhysicalGroup(
            2, outer_boundary([v for _, v in gmsh.model.getEntities(3)]), name="pml_walls", tag=6
        )
        # The far-field (Huygens) surface is the inner face of the PML shell: the
        # boundary of air + substrate, where the interior sheets cancel. The ground
        # crosses it at -y as a zero-thickness sheet, which adds nothing to the integral.
        gmsh.model.addPhysicalGroup(2, outer_boundary(air + substrate), name="huygens", tag=7)


class Oonishi1993ConformalPatchAntenna(ValidationCase):
    name = "Oonishi 1993: Conformal Patch Antenna"
    tags = {"eternal"}

    # Bend radius of the ground [mm]: 20 or 30 as in Oonishi et al. (1993), or None for
    # the planar antenna of Sheen et al. (1990).
    radius = 20.0

    # Antenna of Sheen et al. (1990), Fig. 3 [mm]: Duroid 5880 substrate, patch, and the
    # microstrip feed line joining the patch at its 16 mm edge.
    substrate_thickness = 0.794
    substrate_permittivity = 2.2
    patch_width = 12.45
    patch_length = 16.0
    feed_width = 2.46
    feed_offset = 2.09  # patch left edge -> feed line left edge
    feed_length = 20.0  # port at y = -feed_length, patch edge at y = 0

    @property
    def variant(self):
        return "planar" if self.radius is None else f"r={self.radius:.0f}mm"

    @property
    def mesh_path(self):
        return self.dir_path / f"geometry_{self.variant}.msh"

    def generate_mesh(self):
        mesh = BentLaminateMesh(
            self.radius,
            self.substrate_thickness,
            self.patch_width,
            self.patch_length,
            self.feed_width,
            self.feed_offset,
            self.feed_length,
        )
        mesh.write(self.mesh_path)

    def setup_case(self):
        sim = mufem.Simulation.New(name=self.name, mesh_path=f"{self.mesh_path}")
        sim.get_domain().get_mesh().scale(1e-3)  # mm -> m

        t_sub = 1e-3 * self.substrate_thickness  # [m]
        w_feed = 1e-3 * self.feed_width  # [m]
        x_line = 1e-3 * (self.feed_offset + self.feed_width / 2)  # [m] feed line center
        l_feed = 1e-3 * self.feed_length  # [m]

        # Bandpass Gabor pulse, spectrum ~2-16 GHz around the 7.5 GHz resonance.
        f_center = 8.5e9  # [Hz]
        tau = 18e-12  # [s] Gaussian envelope width
        t0 = 4 * tau  # [s] pulse delay
        support = 3.2 * tau  # [s] one-sided envelope support

        # Reference plane on the feed line, at a cell center of the third line cell.
        self.y_ref = -16.875e-3  # [m]
        self.t_sub = t_sub

        # Incident/reflected gate at the reference plane: the incident pulse has passed
        # before the earliest patch reflection returns. Line phase velocity from the
        # standard microstrip effective permittivity.
        eps_r = self.substrate_permittivity
        eps_eff = (eps_r + 1) / 2 + (eps_r - 1) / 2 / numpy.sqrt(1 + 12 * t_sub / w_feed)
        v = self.speed_of_light() / numpy.sqrt(eps_eff)
        t_incident_end = t0 + (l_feed + self.y_ref) / v + support
        t_reflected_start = t0 - support + (l_feed - self.y_ref) / v
        self.t_cut = 0.5 * (t_incident_end + t_reflected_start)

        # Outer time step; the explicit scheme sub-steps it internally. The 5 ps spacing
        # of the monitors covers the FFT band below 20 GHz.
        sim.set_runner(
            mufem.UnsteadyRunner(
                total_time=3.5e-9, time_step_size=5.0e-12, total_inner_iterations=1
            )
        )

        model = TimeDomainMaxwellModel(order=2, time_stepping_scheme=mufem.RK2)
        sim.get_model_manager().add_model(model)

        # Materials --------------------------------------------------------------------
        model.add_materials(
            [
                TimeDomainMaxwellGeneralMaterial(
                    name="Substrate", marker="substrate" @ Vol, electric_permittivity=eps_r
                ),
                TimeDomainMaxwellGeneralMaterial(
                    name="Air", marker="air" @ Vol, electric_permittivity=1.0
                ),
                TimeDomainMaxwellPmlMaterial(name="Pml", marker="pml" @ Vol),
            ]
        )

        # Conditions -------------------------------------------------------------------
        drive = 0.1  # [sqrt(W)]; S11 does not depend on the amplitude
        omega = 2.0 * numpy.pi * f_center
        pulse = mufem.CffExpressionScalar(
            f"{drive:.6e} * exp(-(({{Time}}-{t0:.6e})/{tau:.6e})^2)"
            f" * sin({omega:.9e}*({{Time}}-{t0:.6e}))"
        )

        # Matched lumped sheet port across the trace-to-ground gap at y = -feed_length:
        # surface impedance Z w / t = 50 Ohm * 2.46 / 0.794 = 155 Ohm. The field points
        # from the trace to the ground, the wave is launched toward the patch.
        model.add_conditions(
            [
                PerfectElectricConductorCondition("Ground", "ground" @ Bnd),
                PerfectElectricConductorCondition("Trace", "trace" @ Bnd),
                PerfectElectricConductorCondition("Patch", "patch" @ Bnd),
                PerfectElectricConductorCondition("PmlWalls", "pml_walls" @ Bnd),
                LumpedPortCondition(
                    "Port",
                    "port_1" @ Bnd,
                    155.0,
                    field_direction=(0.0, 0.0, -1.0),
                    propagation_direction=(0.0, 1.0, 0.0),
                    field_waveform=pulse,
                ),
            ]
        )

        # Monitors ---------------------------------------------------------------------
        events = [mufem.Event.Initialization, mufem.Event.TimeStep(1)]

        # Ez on the feed line gives the line voltage; |E| in the outer PML cell of each
        # open face stays small unless the PML leaks or grows.
        for name, x, y, z in (
            ("Reference Ez", x_line, self.y_ref, t_sub / 2),
            ("WallTop E", 6.2e-3, 8.0e-3, 18.3e-3),
            ("WallSide E", 23.0e-3, 8.0e-3, 2.0e-3),
            ("WallFar E", 6.2e-3, 23.5e-3, 2.0e-3),
            ("WallBack E", x_line, -29.5e-3, 2.0e-3),
            ("WallBottom E", 6.2e-3, 8.0e-3, -17.5e-3),
        ):
            sim.get_report_manager().add_report(
                mufem.ProbeReport.SinglePoint(name, "Electric Field", x, y, z)
            )
            sim.get_monitor_manager().add_monitor(mufem.ReportMonitor(name, name, events=events))

        # Total field energy (eps |E|^2 + mu |H|^2) / 2.
        def squared(field):
            return "+".join(f"{{{field}}}.{c}^2" for c in "XYZ")

        eps0 = mufem.Constants.vacuum_permittivity
        mu0 = mufem.Constants.vacuum_permeability
        sim.get_coefficient_manager().register_user(
            "Energy Density",
            mufem.CffExpressionScalar(
                f"0.5*{eps0}*({squared('Electric Field')})"
                f" + 0.5*{mu0}*({squared('Magnetic Field')})"
            ),
        )
        sim.get_report_manager().add_report(
            mufem.VolumeIntegralReport("Energy", cff_name="Energy Density")
        )
        sim.get_monitor_manager().add_monitor(
            mufem.ReportMonitor(
                "Energy", "Energy", events=[mufem.Event.Initialization, mufem.Event.TimeStep(5)]
            )
        )

        # Far field over the whole sphere at the resonance and 300 MHz to either side.
        # The ground is finite, so the lower half radiates too.
        self.far_field = FarFieldRadiationSensor(
            name="Radiated Field",
            marker="huygens" @ Bnd,
            frequency_start=7.1e9,
            frequency_stop=7.7e9,
            frequency_step=0.3e9,
            polar_start=0.0,
            polar_stop=180.0,
            polar_step=2.5,
            azimuthal_start=0.0,
            azimuthal_stop=360.0,
            azimuthal_step=5.0,
        )
        self.far_field.set_events(events)
        sim.get_monitor_manager().add_monitor(self.far_field)

        return sim

    # --- post-processing ------------------------------------------------------------
    @staticmethod
    def speed_of_light():
        return 1.0 / math.sqrt(
            mufem.Constants.vacuum_permittivity * mufem.Constants.vacuum_permeability
        )

    def monitor_values(self, name):
        return self.sim.get_monitor_manager().get_monitor(name).get_values()

    def voltage(self):
        """Line voltage V(t) = -Ez t_sub at the reference plane."""
        values = self.monitor_values("Reference Ez")
        time = numpy.array([t for t, _ in values])
        voltage = numpy.array([-e.z * self.t_sub for _, e in values])
        return time, voltage

    def s11(self):
        """S11(f) = FFT(V_reflected) / FFT(V_incident) at the reference plane, from the
        time-gated line voltage, Sheen et al. (1990)."""
        time, voltage = self.voltage()
        incident = numpy.where(time < self.t_cut, voltage, 0.0)
        reflected = voltage - incident
        n = 1 << 17
        frequency = numpy.fft.rfftfreq(n, time[1] - time[0])
        s11 = numpy.fft.rfft(reflected, n) / numpy.fft.rfft(incident, n)
        band = (frequency > 2e9) & (frequency < 20e9)
        return frequency[band], s11[band]

    def impedance(self):
        """Input impedance at the patch edge, Sheen et al. (1990), Eq. (15): S11 moved
        from the reference plane to the patch edge along the 50 Ohm line."""
        frequency, s11 = self.s11()
        eps_eff = 1.9  # value of Sheen et al. (1990)
        k = 2.0 * numpy.pi * frequency * numpy.sqrt(eps_eff) / self.speed_of_light()
        gamma = s11 * numpy.exp(2j * k * -self.y_ref)
        return frequency, 50.0 * (1.0 + gamma) / (1.0 - gamma)

    def solve(self):
        self.sim.run()

        frequency, s11 = self.s11()
        s11_db = 20 * numpy.log10(numpy.maximum(numpy.abs(s11), 1e-8))
        window = (frequency > 6.5e9) & (frequency < 8.5e9)
        i_min = numpy.argmin(s11_db[window])
        self.resonance = frequency[window][i_min]
        self.s11_min = s11_db[window][i_min]

        frequency, z = self.impedance()
        self.resistance = numpy.interp(self.resonance, frequency, z.real)

        time, energy = [], []
        for t, e in self.monitor_values("Energy"):
            time.append(t)
            energy.append(float(e))
        time, energy = numpy.array(time), numpy.array(energy)
        settled = time > 0.5e-9  # [s] well past the pulse
        self.energy_rise = numpy.max(energy[settled]) / numpy.max(energy[~settled])

        self.wall_peaks = {
            name: max(
                numpy.sqrt(e.x**2 + e.y**2 + e.z**2) for _, e in self.monitor_values(f"{name} E")
            )
            for name in ("WallTop", "WallSide", "WallFar", "WallBack", "WallBottom")
        }

        grids = [
            self.far_field.get_radiation_pattern(i)
            for i in range(len(self.far_field.get_frequencies()))
        ]
        self.thetas = numpy.array(grids[1].get_polar_angles())
        self.phis = numpy.array(grids[1].get_azimuthal_angles())
        self.patterns = [numpy.array(g.get_values()) for g in grids]

        if self.is_main():
            print(
                f"[{self.variant}] resonance {self.resonance / 1e9:.4f} GHz, "
                f"|S11| {self.s11_min:.2f} dB, Re Z {self.resistance:.1f} Ohm, "
                f"energy late/early {self.energy_rise:.3f}, "
                f"wall peaks {', '.join(f'{p:.2f}' for p in self.wall_peaks.values())} V/m"
            )

    def validate(self):
        # Resonance = deepest |S11| dip. Oonishi et al. (1993), Sec. 5.2: calculated
        # 7.47 GHz planar and 7.48 GHz bent, measured 7.58 GHz planar and 7.60 GHz bent.
        calculated, measured = (7.47e9, 7.58e9) if self.radius is None else (7.48e9, 7.60e9)
        expect(self.resonance, calculated, rel_tol=1e-2, label="resonance vs. calculation [Hz]")
        expect(self.resonance, measured, rel_tol=3e-2, label="resonance vs. measurement [Hz]")

        # Nothing drives the domain after the pulse and every boundary absorbs, so the
        # energy must not grow, and the outer PML cells must stay quiet (~3% of the
        # ~480 V/m drive field).
        expect(self.energy_rise, 0.0, abs_tol=1.0, label="late/early energy ratio")
        for name, peak in self.wall_peaks.items():
            expect(peak, 0.0, abs_tol=15.0, label=f"{name} PML |E| peak [V/m]")

    def postprocess(self):
        if not self.is_main():
            return

        suffix = self.variant
        data = self.dir_path / "data"
        oonishi = "planar" if self.radius is None else suffix

        # Reference-plane voltage: the incident pulse, then the patch reflection.
        time, voltage = self.voltage()
        fig, ax = plt.subplots(figsize=(8.0, 5.0), layout="constrained")
        ax.plot(time * 1e9, voltage, "r-", label="$\\mu$fem")
        ax.axvline(self.t_cut * 1e9, color="k", linestyle=":", label="incident/reflected gate")
        ax.set_xlabel("Time [ns]")
        ax.set_ylabel("Voltage [V]")
        ax.set_ylim(-0.4, 0.4)
        ax.legend(frameon=False)
        fig.savefig(self.results_path / f"Reference_Voltage_{suffix}.png", dpi=200)
        plt.close(fig)

        frequency, s11 = self.s11()
        s11_db = 20 * numpy.log10(numpy.maximum(numpy.abs(s11), 1e-8))

        def s11_plot(path, references, band):
            fig, ax = plt.subplots(figsize=(8.0, 5.0), layout="constrained")
            for file, fmt, label in references:
                ref = numpy.loadtxt(data / file, delimiter=",", comments="#")
                ax.plot(ref[:, 0], ref[:, 1], fmt, linewidth=2.5, label=label)
            mask = (frequency >= band[0]) & (frequency <= band[1])
            ax.plot(frequency[mask] / 1e9, s11_db[mask], "r-", linewidth=2.0, label="$\\mu$fem")
            ax.set_xlim(band[0] / 1e9, band[1] / 1e9)
            ax.set_ylim(-50.0, 5.0)
            ax.set_xlabel("Frequency [GHz]")
            ax.set_ylabel("$|S_{11}|$ [dB]")
            ax.legend(frameon=False, loc="lower left")
            fig.savefig(self.results_path / path, dpi=200)
            plt.close(fig)

        # Resonance window against Oonishi et al. (1993), Fig. 5.
        s11_plot(
            f"S11_{suffix}.png",
            [
                (f"1993_Oonishi_S11_Calculation_{oonishi}.csv", "k-", "Oonishi (1993) calculated"),
                (f"1993_Oonishi_S11_Measurement_{oonishi}.csv", "k--", "Oonishi (1993) measured"),
            ],
            (7.0e9, 8.0e9),
        )
        # Full band against the planar antenna of Sheen et al. (1990), Fig. 5.
        s11_plot(
            f"S11_Full_{suffix}.png",
            [
                ("1990_Sheen_S11_Calculation.csv", "k-", "Sheen (1990) calculated, planar"),
                ("1990_Sheen_S11_Measurement.csv", "k--", "Sheen (1990) measured, planar"),
            ],
            (2.0e9, 20.0e9),
        )

        # Input impedance at the patch edge; Oonishi et al. (1993), Fig. 6, is digitized
        # for the planar antenna only.
        frequency, z = self.impedance()
        mask = (frequency >= 7.0e9) & (frequency <= 8.0e9)
        fig, ax = plt.subplots(figsize=(8.0, 5.0), layout="constrained")
        if self.radius is None:
            for part, fmt in (("real", "k-"), ("imag", "k--")):
                ref = numpy.loadtxt(data / f"1993_Oonishi_Zi_{part}_planar.csv", delimiter=",")
                ax.plot(ref[:, 0], ref[:, 1], fmt, linewidth=2.5, label=f"Oonishi (1993) {part}")
        ax.plot(frequency[mask] / 1e9, z.real[mask], "r-", linewidth=2.0, label="$\\mu$fem real")
        ax.plot(frequency[mask] / 1e9, z.imag[mask], "r--", linewidth=2.0, label="$\\mu$fem imag")
        ax.set_xlim(7.0, 8.0)
        ax.set_ylim(-65.0, 65.0)
        ax.set_xlabel("Frequency [GHz]")
        ax.set_ylabel("$Z_{in}$ [$\\Omega$]")
        ax.legend(frameon=False)
        fig.savefig(self.results_path / f"Impedance_{suffix}.png", dpi=200)
        plt.close(fig)

        # Principal-plane cuts over the full circle, normalized to the resonance peak;
        # the flanks share that normalization. The angle runs from broadside (+z).
        frequencies = self.far_field.get_frequencies()
        peak = self.patterns[1].max()
        azimuth_step = self.phis[1] - self.phis[0]

        def column(phi):
            return int(round(numpy.radians(phi) / azimuth_step))

        for plane, (phi_front, phi_back) in (
            ("E-plane", (0.0, 180.0)),
            ("H-plane", (90.0, 270.0)),
        ):
            fig, ax = plt.subplots(subplot_kw={"projection": "polar"})
            ax.set_theta_zero_location("N")
            ax.set_theta_direction(-1)
            angle = numpy.concatenate([-self.thetas[:0:-1], self.thetas])
            for pattern, frequency_i, color in zip(self.patterns, frequencies, ("C0", "r", "C2")):
                cut = numpy.concatenate(
                    [pattern[:0:-1, column(phi_back)], pattern[:, column(phi_front)]]
                )
                ax.plot(
                    angle, cut / peak, color=color, label=f"$\\mu$fem {frequency_i / 1e9:.1f} GHz"
                )
            ax.set_ylim(0.0, 1.1)
            ax.legend(loc="lower center", bbox_to_anchor=(0.5, -0.25), ncol=3, frameon=False)
            ax.set_title(plane, fontweight="bold")
            fig.savefig(
                self.results_path / f"Far_Field_{plane}_{suffix}.png", bbox_inches="tight", dpi=200
            )
            plt.close(fig)

        # 3D pattern at resonance for paraview_radiation_pattern.py.
        numpy.savez(
            self.results_path / f"Far_Field_3D_{suffix}.npz",
            thetas=self.thetas,
            phis=self.phis,
            radiation_pattern=self.patterns[1] / peak,
        )


if __name__ == "__main__":
    run_case(Oonishi1993ConformalPatchAntenna)
