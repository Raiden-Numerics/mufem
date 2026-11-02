"""
Converts the IEEJ portal data and the rfmkit 2D results of the D-model to the conventions of case.py.

    python3 prepare_references.py /path/to/rfmkit/validation/Fujita_2011_IEEJ_D_Model_IPM

Without the argument only the IEEJ Fig. 3.36 torque waveform is converted.

case.py uses the frame, winding and dq currents of the rfmkit D-model; its rotor angle is θ = ωt / p from the
drawing position. An rfmkit sweep over θ therefore maps to t = θ / (360° f / p) within one electrical period.
"""

import csv
import json
import math
import os
import sys

import numpy as np

FREQUENCY = 50.0
POLE_PAIRS = 2

PORTAL = "IEEJ Public Use Motors, D-model, http://www2.iee.or.jp/~drm/PublicUseMotors/actualMotors/PMSM/Dmodel/"
RFMKIT = "rfmkit 2D (portal DXF geometry, P2, 60 mm stack, JIS50A350, Br 1.25 T, mu_r 1.05)"


def read_rows(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.reader(f))


def fundamental(angle_deg, values):
    """Complex amplitude c of the first harmonic, values ≈ Re(c e^{-j angle})."""
    a = np.radians(angle_deg)
    return 2.0 * np.mean(np.asarray(values) * np.exp(1j * a))


def write(path, header, rows):
    with open(path, "w") as f:
        for line in header:
            f.write(f"# {line}\n")
        for row in rows:
            f.write(",".join(f"{v:.10g}" for v in row) + "\n")


def rfmkit_rows(path):
    """Convert an rfmkit sweep to rows (t, ωt, Ψ_U, Ψ_V, Ψ_W, T) of case.py, sorted in time over one electrical period."""
    rows = []
    for r in csv.DictReader(open(path)):
        wt = (POLE_PAIRS * float(r["theta_deg"])) % 360.0
        t = wt / (360.0 * FREQUENCY)
        rows.append(
            (
                t,
                wt,
                float(r["psi_U"]),
                float(r["psi_V"]),
                float(r["psi_W"]),
                float(r["torque"]),
            )
        )
    return sorted(rows)


def ieej_fig_3_36(here):
    """Torque waveform of IEEJ TR 1244, Fig. 3.36 (analyses No. 1/2, 3D FEA, rated load) on the time base of case.py.

    The figure has no rotor-angle reference: its 12th torque harmonic is put in phase with that of the rfmkit
    waveform (Reference_rfmkit_2D_Load.csv).
    """
    fig = np.loadtxt(
        os.path.join(here, "Torque_vs_Electrical_Angle.csv"), delimiter=",", comments="#"
    )
    rfmkit = np.loadtxt(
        os.path.join(here, "Reference_rfmkit_2D_Load.csv"), delimiter=",", comments="#"
    )

    grid = np.arange(0.0, 360.0, 0.5)

    def periodic(x, y):
        order = np.argsort(x % 360.0)
        xs = (x % 360.0)[order]
        return np.interp(grid, np.concatenate([xs - 360.0, xs, xs + 360.0]), np.tile(y[order], 3))

    c_fig = np.mean(periodic(fig[:, 0], fig[:, 1]) * np.exp(12j * np.radians(grid)))
    c_ref = np.mean(periodic(rfmkit[:, 1], rfmkit[:, 5]) * np.exp(12j * np.radians(grid)))
    shift = math.degrees(np.angle(c_ref / c_fig)) / 12.0

    wt = (fig[:, 0] + shift) % 360.0
    order = np.argsort(wt)
    print(f"Fig. 3.36 shifted by {shift:.2f} deg")
    write(
        os.path.join(here, "Reference_IEEJ_Fig3_36_Torque.csv"),
        [
            "IEEJ Technical Report 1244, Fig. 3.36: torque waveform of analyses No. 1/2 (lab A, 3D FEA),",
            f"3 Arms, beta = 25 deg, 1500 min^-1 (digitised, shifted by {shift:.2f} deg: 12th harmonic in phase with rfmkit)",
            "t [s], omega t [deg], T [N m]",
        ],
        [(wt[i] / (360.0 * FREQUENCY), wt[i], fig[i, 1]) for i in order],
    )


def main(rfmkit_dir):
    here = os.path.dirname(os.path.abspath(__file__))
    iron_loss = os.path.join(rfmkit_dir, "iron_loss")
    results = os.path.join(iron_loss, "results")
    theta0 = json.load(open(os.path.join(results, "theta0.json")))["theta0_deg"]
    print(f"rfmkit theta0 = {theta0:.4f} deg (case.py: 60 deg)")

    # Mean torque vs current phase at 3 Arms, 1500 min^-1.
    rows = [
        r
        for r in read_rows(os.path.join(iron_loss, "Dmodel_T-beta.csv"))[2:]
        if r and r[1].strip()
    ]
    write(
        os.path.join(here, "Reference_Torque_vs_Beta.csv"),
        [
            f"{PORTAL} Dmodel_T-beta.csv (3 Arms, 1500 min^-1)",
            "beta [deg], T measured [N m], T FEA 2D [N m]",
        ],
        [(float(r[0]), float(r[1]), float(r[2])) for r in rows],
    )

    # rfmkit, rated load (3 Arms, beta = 25 deg).
    load = rfmkit_rows(os.path.join(results, "load_fit_n180.csv"))
    write(
        os.path.join(here, "Reference_rfmkit_2D_Load.csv"),
        [
            f"{RFMKIT}, 3 Arms, beta = 25 deg, iron_loss/results/load_fit_n180.csv",
            "t [s], omega t [deg], Psi_U [Wb], Psi_V [Wb], Psi_W [Wb], T [N m]",
        ],
        load,
    )


if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1])
    ieej_fig_3_36(os.path.dirname(os.path.abspath(__file__)))
