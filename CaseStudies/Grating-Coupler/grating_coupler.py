"""Fan grating coupler for a multimode optical pin: one design in 3D.

    pymufem grating_coupler.py --design published --mesh results_published/mesh.msh --out results_published

"./case.sh run" meshes the design with mesh.py and runs this script.

The Time-Harmonic Maxwell model with second-order Nedelec elements, on the mesh of the design made
by mesh.py; the design (see mesh.py) places the beam plane over the fan. The TE0 mode of a silicon
wire is launched through a waveguide port into a fan whose shallow-etched grooves are confocal
ellipses around a focus in the wire, so that they radiate a beam focused in both directions,
12.7 deg off the normal, into the optical pin above the chip. The outer faces absorb; a symmetry
plane runs through the fan axis. The script writes to --out:

    metrics.json     the metrics below
    beam_plane.npz   the grid x, y, E_x (ex, complex) and S_z (sz) on the beam plane 1 um above the
                     silicon, and phase_sign, for the near and far fields
    Output.vtkhdf    the real and imaginary parts of the electric field (unless --no-field-export)

    up, down    power through planes 0.5 um above and below the silicon (fractions of the input)
    r           reflection back into the wire, |S11|^2
    angle_core  beam angle in the pin core [deg], from the far field of the beam plane
    spot_x/y    near-field D4 sigma diameters on the beam plane [um]
    acc_gi50    share of the upward beam inside the GI50 fibre's acceptance (NA 0.2 around the
                pin's 8 deg axis in its core)
    p_gi50      up * acc_gi50: the objective of the optimization

Units throughout: lengths in um, angles in deg, powers as fractions of the input. Requires mufem.
"""

import argparse
import json
import os
import shutil

import numpy as np

import mufem
from mufem import Bnd, Vol
from mufem.electromagnetics.timeharmonicmaxwell import (
    AbsorbingBoundaryCondition,
    PerfectElectricConductorCondition,
    SParametersReport,
    TimeHarmonicMaxwellGeneralMaterial,
    TimeHarmonicMaxwellModel,
    WaveguideInputPortCondition,
)

from mesh import L_WIRE, N_CORE, N_SI, N_SIO2, T_SI, WAVELENGTH, X_PORT, Coupler, load_design

UM = 1e-6  # [m]
SPEED_OF_LIGHT = 299792458.0  # [m/s]
Z_BEAM = T_SI + 1.0  # [um] the beam plane, in the SiO2 above the silicon
PIN_TILT, NA_GI50 = 8.0, 0.2  # [deg] pin axis in its core; GI50 fibre behind the pin


def power_up(plane):
    """The power through the horizontal @p plane, upwards [W]; the input is 1 W."""
    return mufem.SurfaceIntegralReport(name=plane, marker=plane @ Bnd, cff_name="Poynting Vector").evaluate().z


def probe_line(cff, x, z, y0, y1, n):
    """The field @p cff at @p n points along y from @p y0 to @p y1 at (@p x, @p z) [um]; None
    outside the mesh."""
    values = mufem.ProbeReport.Line(name=cff, cff_name=cff, start=(x * UM, y0 * UM, z * UM),
                                    end=(x * UM, y1 * UM, z * UM), number_points=n).evaluate_all()
    return [v for _, v in values]


def ex_line(x, z, y0, y1, n):
    """The complex E_x along a line as probe_line; zero outside the mesh."""
    re = probe_line("Electric Field-Real", x, z, y0, y1, n)
    im = probe_line("Electric Field-Imag", x, z, y0, y1, n)
    return np.array([0j if a is None or b is None else a.x + 1j * b.x for a, b in zip(re, im)])


def solve(c, mesh_path, out_of_core, field_path=None):
    """Solve the coupler @p c meshed in @p mesh_path, the solver's factors in @p out_of_core, the
    electric field exported to the folder @p field_path if given; return its metrics and the beam plane (on the
    main process), else None."""
    # The mesh is in um; one steady solve.
    sim = mufem.Simulation.New(name="Grating Coupler", mesh_path=mesh_path)
    sim.get_domain().get_mesh().scale(UM)
    sim.set_runner(mufem.SteadyRunner(total_iterations=1))

    model = TimeHarmonicMaxwellModel(frequency=SPEED_OF_LIGHT / (WAVELENGTH * UM), order=2)
    sim.get_model_manager().add_model(model)

    # The direct solver (MUMPS): block low-rank compression, the factors on disk.
    os.makedirs(out_of_core, exist_ok=True)
    direct = model.get_solver().get_linear_solver()
    direct.set_blr_tolerance(1e-6)
    direct.set_use_out_of_core(True)
    direct.set_out_of_core_directory(out_of_core)

    silicon = TimeHarmonicMaxwellGeneralMaterial.Constant(
        name="Silicon", marker="Silicon" @ Vol, relative_electric_permittivity=N_SI**2)
    sio2 = TimeHarmonicMaxwellGeneralMaterial.Constant(
        name="SiO2", marker="SiO2" @ Vol, relative_electric_permittivity=N_SIO2**2)
    resin = TimeHarmonicMaxwellGeneralMaterial.Constant(
        name="Resin", marker="Resin" @ Vol, relative_electric_permittivity=N_CORE**2)  # the pin's core
    model.add_materials([silicon, sio2, resin])

    # The TE0 mode of the wire enters through the port; the outer faces absorb. The mode is even in
    # x: E_y and E_z vanish on x = 0, an exact PEC wall.
    port = WaveguideInputPortCondition(name="InputPort", marker="InputPort" @ Bnd, mode_index=0)
    model.add_condition(port)
    for name in ("Top", "Bottom", "Sides", "End"):
        model.add_condition(AbsorbingBoundaryCondition(name=name, marker=name @ Bnd))
    model.add_condition(PerfectElectricConductorCondition(name="Symmetry", marker="Symmetry" @ Bnd))

    exporter = sim.get_field_exporter()
    exporter.set_active(field_path is not None)
    if field_path is not None:
        exporter.add_field_outputs(["Electric Field-Real", "Electric Field-Imag"])
        exporter.set_order(2)
        exporter.set_format(mufem.FieldFormat.VTKHDF)  # one file, Output.vtkhdf in the folder
        exporter.set_output_directory(field_path)
        exporter.set_events(events=[mufem.Event.RunCompletion])

    sim.run()

    result = dict(up=power_up("UpPlane"), down=-power_up("DownPlane"),
                  r=float(abs(SParametersReport("S11", port, 1).evaluate()[0, 0]) ** 2))

    # Beam plane, 1 um above the silicon, over the fan, clear of the absorbing faces: E_x and S_z on a
    # grid over the half x > 0, zero elsewhere.
    k = 2.0 * np.pi / WAVELENGTH  # [1/um]
    ys = np.arange(L_WIRE + c.r_first - 3.0, c.point(c.f_end - 0.3 * c.scale, 0.0)[1], 0.02)
    xs = np.arange(1e-3, c.point(c.f_end, c.side_angle)[0] - 0.2, 0.1)
    ex, sz = np.zeros((len(xs), len(ys)), dtype=complex), np.zeros((len(xs), len(ys)))
    tan_side, y_side0 = np.tan(np.radians(c.side_angle)), c.point(c.f_start, c.side_angle)[1]
    for i, x in enumerate(xs):
        inside = np.flatnonzero((ys - L_WIRE > x / tan_side + 0.1) & (c.f_of(x, ys) < c.f_end - 0.2 * c.scale)
                                & ((ys > y_side0 + 0.05) | (x < X_PORT - 0.05)))
        if len(inside) > 1:
            j0, j1 = inside[0], inside[-1]
            ex[i, j0:j1 + 1] = ex_line(x, Z_BEAM, ys[j0], ys[j1], j1 - j0 + 1)
            sz[i, j0:j1 + 1] = [0.0 if v is None else v.z
                                for v in probe_line("Poynting Vector", x, Z_BEAM, ys[j0], ys[j1], j1 - j0 + 1)]

    # Near field: D4 sigma diameters of the upward S_z (mirrored in x).
    up = np.clip(sz, 0.0, None)
    y_mean = (up.sum(axis=0) * ys).sum() / up.sum()
    result["spot_x"] = 4.0 * np.sqrt((up.sum(axis=1) * xs**2).sum() / up.sum())
    result["spot_y"] = 4.0 * np.sqrt((up.sum(axis=0) * (ys - y_mean) ** 2).sum() / up.sum())

    # The sign that turns the guided wave's phase into a forward wavenumber, independent of the
    # time convention: read in the plain fan ahead of the grating.
    phase = np.unwrap(np.angle(ex_line(1e-3, 0.5 * T_SI, L_WIRE + 2.0, L_WIRE + c.r_first - 1.0, 201)))
    sign = 1.0 if phase[-1] < phase[0] else -1.0

    # Far field: the peak direction along the axis, and the share of the power carried into the
    # pin core within the GI50 fibre's acceptance.
    weights = np.full(len(xs), 2.0 * (xs[1] - xs[0]))  # the half x > 0, mirrored (E_x even in x)
    u_along = np.sin(np.radians(np.arange(-30.0, 40.0, 0.01)))
    along = np.abs(np.exp(1j * sign * k * np.outer(u_along, ys)) @ (weights[:, None] * ex).sum(axis=0)) ** 2
    u_peak = u_along[np.argmax(along * (1.0 - u_along**2))]
    result["angle_core"] = np.degrees(np.arcsin(u_peak / N_CORE))
    _, _, power, accepted = far_field(xs, ys, ex, sign)
    result["acc_gi50"] = float(power[accepted].sum() / power.sum())
    result["p_gi50"] = result["up"] * result["acc_gi50"]
    beam = dict(x=xs, y=ys, ex=ex, sz=sz, phase_sign=sign)
    return (result, beam) if sim.get_machine().is_main_process() else None


def far_field(xs, ys, e, sign):
    """The power the beam plane's E_x (@p e on the grid @p xs, @p ys, x > 0) carries into the pin
    core per direction u = (u_x, u_y), the tangential wavenumber over k0, conserved through the
    planar layers: u_x >= 0 (E_x even in x), and the mask of the directions inside the GI50
    fibre's acceptance around the pin axis. @p sign turns the phase into a forward wavenumber."""
    k = 2.0 * np.pi / WAVELENGTH
    dx, dy = xs[1] - xs[0], ys[1] - ys[0]

    # The plane-wave spectrum: a Fourier transform along y, then a cosine transform along x (the
    # half x > 0 of an even field).
    u_x, u_y = np.arange(0.0, N_SIO2, 0.005), np.arange(-N_SIO2, N_SIO2, 0.005)
    along_y = e @ np.exp(1j * sign * k * np.outer(ys, u_y)) * dy
    spectrum = np.cos(k * np.outer(u_x, xs)) @ (2.0 * dx * along_y)
    ux, uy = np.meshgrid(u_x, u_y, indexing="ij")

    # The power per direction carried into the pin core, |A|^2 cos(theta), for the directions that
    # propagate in the SiO2.
    sin2_core = (ux**2 + uy**2) / N_CORE**2
    cos_core = np.sqrt(np.clip(1.0 - sin2_core, 0.0, None))
    power = np.where(sin2_core < (N_SIO2 / N_CORE) ** 2, np.abs(spectrum) ** 2 * cos_core, 0.0)

    # The fibre's acceptance: within asin(NA / n_core) of the pin axis, tilted by PIN_TILT along y.
    tilt = np.radians(PIN_TILT)
    cos_axis = uy / N_CORE * np.sin(tilt) + cos_core * np.cos(tilt)
    accepted = cos_axis >= np.cos(np.arcsin(NA_GI50 / N_CORE))
    return ux, uy, power, accepted


def run(design, mesh, out, field_export=True):
    """Solve the design (published, optimized or a design JSON) on its mesh and write the results to
    out (see the module's docstring)."""
    os.makedirs(out, exist_ok=True)
    out_of_core = os.path.join(os.path.dirname(os.path.abspath(mesh)), "ooc")
    try:
        solved = solve(Coupler(**load_design(design)), mesh, out_of_core,
                       out if field_export else None)
    finally:
        shutil.rmtree(out_of_core, ignore_errors=True)
    if solved is None:  # not the main process
        return

    result, beam = solved
    np.savez_compressed(os.path.join(out, "beam_plane.npz"), **beam)
    with open(os.path.join(out, "metrics.json"), "w") as f:
        json.dump(result, f, indent=2)

    print(f"P_GI50 {result['p_gi50']:.4f}: up {result['up']:.4f}, R {100 * result['r']:.2f}%, "
          f"beam {result['angle_core']:.2f} deg in the core, spot {result['spot_x']:.1f} x "
          f"{result['spot_y']:.1f} um; written to {out}", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--design", default="published", help="published, optimized or a design JSON (see mesh.py)")
    ap.add_argument("--mesh", required=True, help="the mesh of the design, from mesh.py")
    ap.add_argument("--out", required=True, help="the output folder")
    ap.add_argument("--no-field-export", action="store_true", help="skip the field export (optimization runs)")
    args = ap.parse_args()
    run(args.design, args.mesh, args.out, field_export=not args.no_field_export)


if __name__ == "__main__":
    main()
