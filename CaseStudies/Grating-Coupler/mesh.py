"""Fan grating coupler for a multimode optical pin: the platform, the designs and their mesh.

    python mesh.py --design published --resolution nominal --out results_published/mesh.msh

Meshes a design with gmsh into a gmsh 2.2 file for grating_coupler.py; "./case.sh run" runs both. The fan is cut
along its axis, a symmetry plane. Its plan view, structured in cells along the grooves and the
rays from the focus and triangulated around the wire, is extruded through the layers, from 0.5 um
of substrate through the buried oxide and the silicon to the SiO2 over-cladding and the pin's core
resin. Physical groups: the volumes Silicon, SiO2 and Resin; the faces InputPort, Symmetry, Top,
Bottom, Sides and End, and the power planes UpPlane and DownPlane.

A design is published or optimized (data/Design_Published.json, data/Design_Optimized.json) or
the path of a design JSON with the keys

    groove        groove width over the pitch
    n_periods     full-strength periods after the soft start
    r_first       distance from the focus to the first groove, on the axis [um]
    fan_angle     half angle of the fan [deg]
    pitch         grating period [um]
    ramp_grooves  soft-start grooves before the full periods, widening towards the full groove
    ramp_start    width of the first ramp groove: 0 the 70 nm minimum feature, 1 the full groove

The resolution is coarse (the optimization) or nominal (the reported results). Units throughout:
lengths in um, angles in deg. Requires gmsh.
"""

import argparse
import dataclasses
import json
import os

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- platform and pin [1-6] -----------------------------------------------------------
WAVELENGTH = 1.31  # [um]
EXIT_ANGLE = 12.7  # [deg] in air; the pin's 8 deg axis in its core
N_SI, N_SIO2, N_CORE = 3.503, 1.447, 1.585  # silicon, SiO2, pin core resin
T_SI, ETCH = 0.20, 0.07  # [um] top silicon, shallow etch
H_BOX, H_SUBSTRATE, H_OVERCLAD, H_RESIN = 2.0, 0.5, 2.0, 1.0  # [um] layers kept in the model
W_WIRE, L_WIRE = 0.35, 1.5  # [um] feed wire width, port to focus
MIN_FEATURE = 0.070  # [um] smallest groove or tooth

# ---- domain [um]: from the bottom of the substrate to the top of the resin, the power planes in the SiO2
Z_BOTTOM, Z_TOP = -H_BOX - H_SUBSTRATE, T_SI + H_OVERCLAD + H_RESIN
Z_DOWN_PLANE, Z_UP_PLANE = -0.5, T_SI + 0.5
L_AFTER, L_END, MARGIN_ANGLE, X_PORT, R_START = 0.5, 1.0, 6.0, 2.0, 5.0

# ---- mesh [um] --------------------------------------------------------------------------
RESOLUTION = {  # coarse: the optimization; nominal: the reported results
    "coarse": dict(h_taper=0.10, h_groove=0.075, h_z=0.40, z_growth=1.5),
    "nominal": dict(h_taper=0.08, h_groove=0.06, h_z=0.30, z_growth=1.3),
}
H_SI, H_CLAD, H_ARC, H_SUB, H_PLANE = 0.06, 0.30, 0.60, 0.125, 0.12
MIN_GROOVE_CELLS = 3
PLANES = {"box_low": "DownPlane", "overclad_low": "UpPlane"}  # the power plane on top of each layer


def slab_index(thickness):
    """TE0 effective index of a silicon slab in SiO2, by bisection on its resonance condition."""
    k0 = 2.0 * np.pi / WAVELENGTH
    lo, hi = N_SIO2 + 1e-9, N_SI - 1e-9
    for _ in range(200):
        n = 0.5 * (lo + hi)
        kappa, gamma = k0 * np.sqrt(N_SI**2 - n**2), k0 * np.sqrt(n**2 - N_SIO2**2)
        lo, hi = (n, hi) if kappa * thickness - 2.0 * np.arctan(gamma / kappa) > 0.0 else (lo, n)
    return 0.5 * (lo + hi)


def slab_pitch(groove):
    """First-order pitch [um] for the exit angle: the groove-weighted mean of the slab indices."""
    n_mean = (1.0 - groove) * slab_index(T_SI) + groove * slab_index(T_SI - ETCH)
    return WAVELENGTH / (n_mean - np.sin(np.radians(EXIT_ANGLE)))


DESIGN_KEYS = ("groove", "n_periods", "r_first", "fan_angle", "pitch", "ramp_grooves", "ramp_start")


def load_design(design):
    """The design @p design: published, optimized (from data/) or the path of a design JSON."""
    path = design
    if design in ("published", "optimized"):
        path = os.path.join(HERE, "data", f"Design_{design.capitalize()}.json")
    with open(path) as f:
        values = json.load(f)
    return {k: values[k] for k in DESIGN_KEYS}


@dataclasses.dataclass
class Coupler:
    """The geometry of a design. Grooves lie on the ellipses F = n_g r - sin_exit Y around the focus
    (Y = y - L_WIRE, r = sqrt(x^2 + Y^2)), which every ray from the focus crosses at the same
    grating phase; on the axis, F grows by scale = n_g - sin_exit per um."""

    groove: float
    n_periods: int
    r_first: float
    fan_angle: float
    pitch: float
    ramp_grooves: int
    ramp_start: float

    def __post_init__(self):
        # Each ramp groove's pitch is the slab model's for its width, with the full grooves' offset.
        self.pitch_offset = self.pitch - slab_pitch(self.groove)
        self.sin_exit = np.sin(np.radians(EXIT_ANGLE))
        self.n_g = WAVELENGTH / self.pitch + self.sin_exit
        self.scale = self.n_g - self.sin_exit
        self.y_wire_end = L_WIRE + 0.5 * W_WIRE / np.tan(np.radians(self.fan_angle))
        self.side_angle = self.fan_angle + MARGIN_ANGLE

        # The soft start: the ramp grooves widen linearly; each one's groove fraction is found at its
        # own pitch, fraction = width / pitch(fraction).
        full_width, n_ramp = self.groove * self.pitch, int(self.ramp_grooves)
        first_width = MIN_FEATURE + self.ramp_start * (full_width - MIN_FEATURE)
        periods = []  # (groove fraction, pitch) of each groove
        for i in range(n_ramp):
            width = first_width + (full_width - first_width) * i / n_ramp
            fraction = width / self.pitch
            for _ in range(20):
                fraction = width / (slab_pitch(fraction) + self.pitch_offset)
            periods.append((fraction, slab_pitch(fraction) + self.pitch_offset))
        periods += [(self.groove, self.pitch)] * int(self.n_periods)

        # The grooves as (F at their start, F at their end), then the end of the silicon and of the domain.
        self.grooves, level = [], self.r_first * self.scale
        for fraction, period in periods:
            self.grooves.append((level, level + fraction * period * self.scale))
            level += period * self.scale
        self.f_si_end = level + L_AFTER * self.scale
        self.f_end = self.f_si_end + L_END * self.scale
        self.f_start = R_START * self.scale

    def radius(self, f, phi):
        """Distance from the focus to the ellipse @p f along the ray at @p phi from the axis."""
        return f / (self.n_g - self.sin_exit * np.cos(np.radians(phi)))

    def point(self, f, phi):
        """(x, y) of the ellipse @p f on the ray at @p phi."""
        r = self.radius(f, phi)
        return r * np.sin(np.radians(phi)), L_WIRE + r * np.cos(np.radians(phi))

    def f_of(self, x, y):
        """The ellipse through (@p x, @p y)."""
        return self.n_g * np.hypot(x, y - L_WIRE) - self.sin_exit * (y - L_WIRE)

    def in_fan(self, x, y):
        """True on the silicon of the wire and the fan."""
        if x <= 0.5 * W_WIRE and y <= self.y_wire_end:
            return True
        return (y > L_WIRE and np.degrees(np.arctan2(x, y - L_WIRE)) <= self.fan_angle
                and self.f_of(x, y) <= self.f_si_end)

    def in_groove(self, x, y):
        """True in a groove (where it is etched)."""
        f = self.f_of(x, y)
        return any(f0 <= f <= f1 for f0, f1 in self.grooves)

    @property
    def footprint(self):
        """Plan area of the fan up to its last groove [um^2] (both halves)."""
        return np.radians(self.fan_angle) * self.radius(self.f_si_end, 0.0) ** 2

    @classmethod
    def at_area(cls, area, groove, fan_angle, taper, ramp_grooves, ramp_start, pitch_offset):
        """The design of footprint exactly @p area [um^2]: the area and the half angle set the last
        groove's radius, @p taper is the share of it before the first groove, and the grating fills
        the rest with whole periods (at least one after the ramp); r_first takes up the rounding.
        The pitch is the slab model's for the groove plus @p pitch_offset."""
        r_end = np.sqrt(area / np.radians(fan_angle))
        pitch = slab_pitch(groove) + pitch_offset

        def length(n_periods):  # the grating and the slab after it, on the axis
            c = cls(groove, n_periods, 0.0, fan_angle, pitch, ramp_grooves, ramp_start)
            return c.radius(c.f_si_end, 0.0)

        n_periods = max(1, round(((1.0 - taper) * r_end - length(0)) / pitch))
        return cls(groove, n_periods, r_end - length(n_periods), fan_angle, pitch, ramp_grooves, ramp_start)


def graded(length, h_bottom, h_top, h_max, growth):
    """Layer thicknesses filling @p length, growing from h_bottom and h_top at its ends to h_max."""
    low, high, total = [], [], 0.0
    while total < length - 1e-9:
        a, b = min(h_bottom * growth ** len(low), h_max), min(h_top * growth ** len(high), h_max)
        (low if a <= b else high).append(min(a, b))
        total += min(a, b)
    return [x * length / total for x in low + high[::-1]]


def uniform(length, h):
    """Equal layer thicknesses filling @p length, at most @p h."""
    n = max(1, int(np.ceil(length / h - 1e-9)))
    return [length / n] * n


def radial_cells(c, h):
    """The ellipses bounding the structured blocks of the fan, and the radial cells between them."""
    levels, cells = [c.f_start], []

    def add(f, size, minimum=1):
        cells.append(max(minimum, int(np.ceil((f - levels[-1]) / (size * c.scale)))))
        levels.append(f)

    add(c.r_first * c.scale, h["h_taper"])
    for f0, f1 in c.grooves:
        if f0 > levels[-1] + 1e-12:
            add(f0, h["h_groove"], MIN_GROOVE_CELLS)
        add(f1, h["h_groove"], MIN_GROOVE_CELLS)
    add(c.f_si_end, h["h_groove"])
    add(c.f_end, H_CLAD)
    return levels, cells


def plan_view(c, levels):
    """The plan view at the bottom of the substrate: the blocks between the ellipses @p levels and the
    rays at 0, fan_angle and side_angle, and the wire region; its curves and surfaces."""
    import gmsh

    occ = gmsh.model.occ
    angles = (0.0, c.fan_angle, c.side_angle)
    pts = {(i, j): occ.addPoint(*c.point(f, phi), Z_BOTTOM)
           for i, f in enumerate(levels) for j, phi in enumerate(angles)}

    def arc(i, j):
        phis = [angles[j] + (angles[j + 1] - angles[j]) * k / 8 for k in range(1, 8)]
        inner = [occ.addPoint(*c.point(levels[i], phi), Z_BOTTOM) for phi in phis]
        return occ.addSpline([pts[i, j]] + inner + [pts[i, j + 1]])

    arcs = {(i, j): arc(i, j) for i in range(len(levels)) for j in range(2)}
    rays = {(i, j): occ.addLine(pts[i, j], pts[i + 1, j]) for i in range(len(levels) - 1) for j in range(3)}
    blocks = [occ.addPlaneSurface([occ.addCurveLoop([rays[i, j], arcs[i + 1, j], -rays[i, j + 1], -arcs[i, j]])])
              for i in range(len(levels) - 1) for j in range(2)]

    # The wire, the fan up to the first ellipse, and the SiO2 beside them, in triangles.
    a, b = occ.addPoint(0, 0, Z_BOTTOM), occ.addPoint(0.5 * W_WIRE, 0, Z_BOTTOM)
    d = occ.addPoint(0.5 * W_WIRE, c.y_wire_end, Z_BOTTOM)
    e = occ.addPoint(X_PORT, 0, Z_BOTTOM)
    g = occ.addPoint(X_PORT, c.point(c.f_start, c.side_angle)[1], Z_BOTTOM)
    axis, port_si, port_ox = occ.addLine(a, pts[0, 0]), occ.addLine(a, b), occ.addLine(b, e)
    wire_side, fan_edge = occ.addLine(b, d), occ.addLine(d, pts[0, 1])
    side_a, side_b = occ.addLine(e, g), occ.addLine(g, pts[0, 2])
    tri_si = occ.addPlaneSurface([occ.addCurveLoop([port_si, wire_side, fan_edge, -arcs[0, 0], -axis])])
    tri_ox = occ.addPlaneSurface([occ.addCurveLoop([port_ox, side_a, side_b, -arcs[0, 1], -fan_edge, -wire_side])])
    occ.synchronize()
    return arcs, rays, blocks, tri_si, tri_ox, fan_edge


def set_sizes(c, h, cells, arcs, rays, blocks, tri_si, fan_edge):
    """Structured cells over the fan; around the wire, sizes from H_SI at the wire to H_CLAD."""
    import gmsh

    mesh, fields = gmsh.model.mesh, gmsh.model.mesh.field

    def set_numbers(field, **values):
        for key, value in values.items():
            fields.setNumber(field, key, value)

    r_end = c.radius(c.f_end, c.side_angle)
    n_phi = [max(2, int(np.ceil(np.radians(a) * r_end / H_ARC))) for a in (c.fan_angle, MARGIN_ANGLE)]
    for (i, j), tag in arcs.items():
        mesh.setTransfiniteCurve(tag, n_phi[j] + 1)
    for (i, j), tag in rays.items():
        mesh.setTransfiniteCurve(tag, cells[i] + 1)
    for tag in blocks:
        mesh.setTransfiniteSurface(tag)
        mesh.setRecombine(2, tag)

    box = fields.add("Box")
    set_numbers(box, VIn=H_SI, VOut=H_CLAD, XMin=-1.0, XMax=0.5 * W_WIRE + 0.3, YMin=-1.0, YMax=c.y_wire_end + 0.3,
                ZMin=Z_BOTTOM - 1.0, ZMax=Z_BOTTOM + 1.0, Thickness=1.0)
    taper = fields.add("MathEval")
    fields.setString(taper, "F", f"{h['h_taper']}")
    in_fan = fields.add("Restrict")
    fields.setNumber(in_fan, "InField", taper)
    fields.setNumbers(in_fan, "SurfacesList", [tri_si])
    edge = fields.add("Distance")
    fields.setNumbers(edge, "CurvesList", [fan_edge])
    fields.setNumber(edge, "Sampling", 200)
    beside = fields.add("Threshold")
    set_numbers(beside, InField=edge, SizeMin=h["h_taper"], SizeMax=H_CLAD, DistMin=0.0, DistMax=1.0)
    finest = fields.add("Min")
    fields.setNumbers(finest, "FieldsList", [box, in_fan, beside])
    fields.setAsBackgroundMesh(finest)
    gmsh.option.setNumber("Mesh.MeshSizeExtendFromBoundary", 1)
    gmsh.option.setNumber("Mesh.MeshSizeFromPoints", 0)
    gmsh.option.setNumber("Mesh.MeshSizeFromCurvature", 0)


def extrude_stack(faces, h):
    """Extrude the plan view @p faces through the layers, with fine layers at the silicon and at the
    power planes; the layer of each volume, and the faces of the power planes."""
    import gmsh

    hz, growth = h["h_z"], h["z_growth"]
    box_low, over_low = Z_DOWN_PLANE + H_BOX, Z_UP_PLANE - T_SI
    stack = [  # name, thickness, layers (the thickness is given: the layers sum to it only up to rounding)
        ("substrate", H_SUBSTRATE, uniform(H_SUBSTRATE, H_SUB)),
        ("box_low", box_low, graded(box_low, 1.5 * H_SUB, H_PLANE, hz, growth)),
        ("box", H_BOX - box_low, graded(H_BOX - box_low, H_PLANE, H_SI, hz, growth)),
        ("slab", T_SI - ETCH, uniform(T_SI - ETCH, H_SI)),
        ("etch", ETCH, uniform(ETCH, H_SI)),
        ("overclad_low", over_low, graded(over_low, H_SI, H_PLANE, hz, growth)),
        ("overclad", H_OVERCLAD - over_low, graded(H_OVERCLAD - over_low, H_PLANE, hz, hz, growth)),
        ("resin", H_RESIN, uniform(H_RESIN, hz)),
    ]
    layer_of, planes = {}, {}
    for name, thickness, layers in stack:
        heights = [sum(layers[: k + 1]) / thickness for k in range(len(layers))]
        heights[-1] = 1.0
        out = gmsh.model.occ.extrude(faces, 0, 0, thickness, numElements=[1] * len(layers), heights=heights,
                                     recombine=True)
        faces = [out[k - 1] for k, (dim, _) in enumerate(out) if dim == 3]
        layer_of.update({tag: name for dim, tag in out if dim == 3})
        if name in PLANES:
            planes[PLANES[name]] = [t for _, t in faces]
    gmsh.model.occ.synchronize()
    return layer_of, planes


def material_of(c, layer, x, y):
    """The material at (@p x, @p y) in @p layer."""
    if layer == "resin":
        return "Resin"
    if layer == "substrate" or (layer == "slab" and c.in_fan(x, y)) or (
            layer == "etch" and c.in_fan(x, y) and not c.in_groove(x, y)):
        return "Silicon"
    return "SiO2"


def physical_groups(c, layer_of, planes):
    """The volumes of each material, the port, the symmetry plane, the absorbing faces and the
    power planes, as physical groups."""
    import gmsh

    model, occ = gmsh.model, gmsh.model.occ

    # Materials, read in the middle of each block in (F, angle): the centre of mass of a long, thin,
    # curved block can lie outside it.
    volumes = {"Silicon": [], "SiO2": [], "Resin": []}
    for _, tag in model.getEntities(3):
        x, y, _ = occ.getCenterOfMass(3, tag)
        corners = [model.getValue(0, t, []) for _, t in model.getBoundary([(3, tag)], combined=False, recursive=True)]
        fs = [c.f_of(p[0], p[1]) for p in corners]
        if min(fs) >= c.f_start - 1e-6:
            phis = [np.degrees(np.arctan2(p[0], p[1] - L_WIRE)) for p in corners]
            x, y = c.point(0.5 * (min(fs) + max(fs)), 0.5 * (min(phis) + max(phis)))
        volumes[material_of(c, layer_of[tag], x, y)].append(tag)

    # Boundaries: the port (without the substrate, whose slab modes would be launched instead), the
    # symmetry plane and the absorbing faces.
    eps = 1e-6
    groups = {"InputPort": [], "Symmetry": [], "Top": [], "Bottom": [], "Sides": [], "End": []}
    for _, tag in model.getBoundary(model.getEntities(3), combined=True, oriented=False):
        xmin, ymin, zmin, xmax, ymax, zmax = model.getBoundingBox(2, tag)
        x, y, z = occ.getCenterOfMass(2, tag)
        if xmax - xmin < eps and abs(xmin) < eps:
            groups["Symmetry"].append(tag)
        elif ymax - ymin < eps and abs(ymin) < eps:
            groups["InputPort" if z > -H_BOX else "Sides"].append(tag)
        elif zmax - zmin < eps and abs(zmin - Z_TOP) < eps:
            groups["Top"].append(tag)
        elif zmax - zmin < eps and abs(zmin - Z_BOTTOM) < eps:
            groups["Bottom"].append(tag)
        elif c.f_of(x, y) > 0.5 * (c.f_si_end + c.f_end):
            groups["End"].append(tag)
        else:
            groups["Sides"].append(tag)

    for name, tags in volumes.items():
        model.addPhysicalGroup(3, tags, name=name)
    for name, tags in {**groups, **planes}.items():
        model.addPhysicalGroup(2, tags, name=name)


def build_mesh(c, resolution, path):
    """Mesh the coupler @p c at @p resolution (coarse or nominal) into the gmsh 2.2 file @p path."""
    import gmsh

    h = RESOLUTION[resolution]
    gmsh.initialize()
    gmsh.option.setNumber("General.Terminal", 0)

    levels, cells = radial_cells(c, h)
    arcs, rays, blocks, tri_si, tri_ox, fan_edge = plan_view(c, levels)
    set_sizes(c, h, cells, arcs, rays, blocks, tri_si, fan_edge)
    layer_of, planes = extrude_stack([(2, t) for t in blocks + [tri_si, tri_ox]], h)
    physical_groups(c, layer_of, planes)

    gmsh.model.mesh.generate(3)
    gmsh.option.setNumber("Mesh.MshFileVersion", 2.2)
    gmsh.write(path)
    gmsh.finalize()


def write(design, resolution, path):
    """Mesh the design (published, optimized or the path of a design JSON) at resolution into path.
    The mesh goes to a temporary file first, renamed at the end, so that other processes waiting for
    path never read it half-written."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    partial = os.path.join(os.path.dirname(os.path.abspath(path)), "partial_" + os.path.basename(path))
    build_mesh(Coupler(**load_design(design)), resolution, partial)
    os.replace(partial, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--design", default="published", help="published, optimized or a design JSON")
    ap.add_argument("--resolution", choices=sorted(RESOLUTION), default="nominal",
                    help="coarse (the optimization) or nominal (the reported results)")
    ap.add_argument("--out", required=True, help="the mesh file")
    args = ap.parse_args()
    write(args.design, args.resolution, args.out)


if __name__ == "__main__":
    main()
