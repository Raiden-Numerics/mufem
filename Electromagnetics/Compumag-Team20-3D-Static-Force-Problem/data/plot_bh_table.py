import matplotlib.pyplot as plt
import numpy as np

# flake8: noqa
data = np.loadtxt("Table_1_BH_Curve.csv", delimiter=",", skiprows=1)

H = data[:, 1]
B = data[:, 0]

# Plot the BH curve
fig, ax = plt.subplots()


ax.plot(H, B, "o-", linewidth=2.5, markersize=5.0)

ax.set_xlabel("Magnetic Field Strength $\\left[ \\frac{\\rm{A}}{\\rm{m}} \\right]$")
ax.set_ylabel("Magnetic Flux Density [T]")

ax.set_xlim((0, 20000))
ax.set_ylim((0, 2.0))

ax.set_yticks([0.0, 0.5, 1.0, 1.5, 2.0])

axins = ax.inset_axes([0.35, 0.13, 0.57, 0.6], xlim=(0, 1000), ylim=(0, 1.0))

axins.set_xlim((0, 500))
axins.set_ylim((0, 1.0))

axins.set_xticks([0, 250, 500])
axins.set_yticks([0, 0.5, 1.0])


axins.plot(H, B, "o-", linewidth=2.5, markersize=5.0)

ax.indicate_inset_zoom(axins, edgecolor="black")


plt.savefig("bh_curve.png", bbox_inches="tight")
