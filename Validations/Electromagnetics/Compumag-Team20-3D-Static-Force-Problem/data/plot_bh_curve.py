"""Plot the B-H curve of Table_1_BH_Curve.csv into bh_curve.png, with the low fields enlarged."""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

data_dir = Path(__file__).resolve().parent

data = np.loadtxt(data_dir / "Table_1_BH_Curve.csv", delimiter=",", skiprows=1)
B = data[:, 0]
H = data[:, 1]

fig, ax = plt.subplots()
ax.plot(H, B, "o-", linewidth=2.5, markersize=5.0)

ax.set_xlabel("Magnetic Field Strength [A/m]")
ax.set_ylabel("Magnetic Flux Density [T]")
ax.set_xlim((0, 20000))
ax.set_ylim((0, 2.0))
ax.set_yticks([0.0, 0.5, 1.0, 1.5, 2.0])

axins = ax.inset_axes([0.35, 0.13, 0.57, 0.6])
axins.set_xlim((0, 500))
axins.set_ylim((0, 1.0))
axins.set_xticks([0, 250, 500])
axins.set_yticks([0, 0.5, 1.0])
axins.plot(H, B, "o-", linewidth=2.5, markersize=5.0)
ax.indicate_inset_zoom(axins, edgecolor="black")

plt.savefig(data_dir / "bh_curve.png", bbox_inches="tight")
