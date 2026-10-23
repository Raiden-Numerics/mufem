"""Plot the B-H curve of bh_table.csv into bh_curve.png and, up to 1000 A/m, bh_curve_low.png."""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

data_dir = Path(__file__).resolve().parent

data = np.loadtxt(data_dir / "bh_table.csv", delimiter=",", skiprows=1)
B = data[:, 0]
H = data[:, 1]

plt.plot(H, B, marker="o")

plt.xlabel("Magnetic Field Strength H [A/m]")
plt.ylabel("Magnetic Flux Density B [T]")

plt.xlim((0, 10000))
plt.ylim((0, 2.0))
plt.yticks([0.0, 0.5, 1.0, 1.5, 2.0])
plt.savefig(data_dir / "bh_curve.png", bbox_inches="tight")

plt.xlim((0, 1000))
plt.savefig(data_dir / "bh_curve_low.png", bbox_inches="tight")
