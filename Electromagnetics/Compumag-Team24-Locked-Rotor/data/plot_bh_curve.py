"""Plot the B-H curve of tables/Table_1_BH_curve.csv and extend it to low fields.

Below the first measured point the curve is replaced by the modified Fröhlich formula fitted to
the first four points; the result is written to tables/Updated_BH_curve.csv. The original curve is
plotted into tables/Table_1_BH_curve.png, both curves into tables/Updated_BH_curve.png.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from scipy.optimize import curve_fit

tables = Path(__file__).resolve().parent / "tables"

bh = np.loadtxt(tables / "Table_1_BH_curve.csv", delimiter=",", comments="#")

plt.clf()
plt.plot(bh[:, 0], bh[:, 1], linewidth=2.5)
plt.xlim((0, 1e5))
plt.ylim((0.0, 2.2))
plt.yticks([0.0, 0.5, 1.0, 1.5, 2.0])
plt.xlabel("Magnetic Field Strength [A/m]")
plt.ylabel("Magnetic Flux Density [T]")
plt.savefig(tables / "Table_1_BH_curve.png", bbox_inches="tight")


def modified_frohlich_formula(h, a, b):
    mu0 = 4 * np.pi * 1e-7

    # Diez (2015), Eq. (1) with degree d = 1
    return h / (a + b * h) + mu0 * h


(a_fitted, b_fitted), _ = curve_fit(modified_frohlich_formula, bh[:4, 0], bh[:4, 1])
print(f"Fitted Fröhlich model: a={a_fitted}, b={b_fitted}")

# Scaling factor to ensure continuity at low H values
scaling = bh[1, 1] / modified_frohlich_formula(bh[1, 0], a_fitted, b_fitted)

h_low = np.linspace(0, bh[1, 0], 8)
lower_bh = np.column_stack((h_low, scaling * modified_frohlich_formula(h_low, a_fitted, b_fitted)))
bh_combined = np.concatenate((lower_bh[:-1, :], bh[1:, :]))

plt.clf()
plt.plot(bh[:, 0], bh[:, 1], "o-", label="Original BH curve", linewidth=2.5)
plt.plot(bh_combined[:, 0], bh_combined[:, 1], "s-", label="Updated BH curve", linewidth=2.5)
plt.xlabel("H [A/m]")
plt.ylabel("B [T]")
plt.legend().draw_frame(False)
plt.xlim((0, 1e4))
plt.ylim((0.0, 2.2))
plt.yticks([0.0, 0.5, 1.0, 1.5, 2.0])
plt.savefig(tables / "Updated_BH_curve.png", bbox_inches="tight")

np.savetxt(
    tables / "Updated_BH_curve.csv",
    bh_combined,
    delimiter=",",
    header="H (A/m), B (T)",
    comments="#",
)
