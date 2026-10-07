import matplotlib.pyplot as plt
import numpy as np

# Load the CSV data using numpy.loadtxt
data = np.loadtxt("bh_table.csv", delimiter=",", skiprows=1)

# Extract B and H columns
H = data[:, 1]  # Second column
B = data[:, 0]  # First column

# Plot the BH curve
plt.plot(H, B, marker="o")

plt.xlabel("Magnetic Field Strength H [A/m]")
plt.ylabel("Magnetic Flux Density B [T]")

plt.xlim((0, 10000))
plt.ylim((0, 2.0))

plt.yticks([0.0, 0.5, 1.0, 1.5, 2.0])

plt.savefig("bh_curve.png", bbox_inches="tight")

plt.xlim((0, 1000))

plt.savefig("bh_curve_low.png", bbox_inches="tight")
