import pylab
import numpy

# flake8: noqa

# Plot the bh curve
pylab.clf()

bh = pylab.loadtxt("Table_1_BH_curve.csv", delimiter=",", comments="#")

pylab.plot(bh[:, 0], bh[:, 1], linewidth=2.5)

pylab.xlim((0, 1e5))
pylab.ylim((0.0, 2.2))

pylab.yticks([0.0, 0.5, 1.0, 1.5, 2.0])

pylab.xlabel("Magnetic Field Strength [A/m]")
pylab.ylabel("Magnetic Flux Density [T]")

pylab.savefig("Table_1_BH_curve.png", bbox_inches="tight")


# Plot the coil current
pylab.clf()

coil_current = pylab.loadtxt("Table_3_Coil_Current.csv", delimiter=",", comments="#")


pylab.xlim((0, 0.15))
pylab.ylim((0.0, 8.0))

pylab.xticks([0.0, 0.05, 0.1, 0.15])
pylab.yticks([0.0, 2.0, 4.0, 6.0, 8.0])

pylab.xlabel("Time [s]")
pylab.ylabel("Coil Current [A]")

pylab.plot(coil_current[:, 0], coil_current[:, 1], linewidth=2.5)

pylab.savefig("Table_3_Coil_Current.png", bbox_inches="tight")


# Update the BH curve (we need to update the augment the BH curve with the modified Fröhlich model
# to ensure reasonable well behaved BH curve at low magnetic field strengths)

from scipy.optimize import curve_fit


def modified_frohlich_formula(h, a, b):
    mu0 = 4 * numpy.pi * 1e-7

    # Diez, 2015, Eq (11)
    return h / (a + b * h) + mu0 * h


# Fit Fröhlich formula to the data using the first 4 points
popt, pcov = curve_fit(modified_frohlich_formula, bh[:4, 0], bh[:4, 1])
a_fitted, b_fitted = popt

print(f"Fitted Fröhlich model: a={a_fitted}, b={b_fitted}")

# Scaling factor to ensure continuity at low H values
scaling = bh[1, 1] / modified_frohlich_formula(bh[1, 0], a_fitted, b_fitted)

# Generate lower BH curve using the fitted model
lower_bh = pylab.array(
    [
        (h, scaling * modified_frohlich_formula(h, a_fitted, b_fitted))
        for h in pylab.linspace(0, bh[1, 0], 8)
    ]
)


# Concatenate the lower BH curve with the original data
bh_combined = pylab.concatenate((lower_bh[:-1, :], bh[1:, :]))


pylab.clf()

pylab.plot(bh[:, 0], bh[:, 1], "o-", label="Original BH curve", linewidth=2.5)
pylab.plot(bh_combined[:, 0], bh_combined[:, 1], "s-", label="Updated BH curve", linewidth=2.5)
pylab.xlabel("H [A/m]")
pylab.ylabel("B [T]")

pylab.legend().draw_frame(False)


pylab.xlim((0, 1e4))
pylab.ylim((0.0, 2.2))

pylab.yticks([0.0, 0.5, 1.0, 1.5, 2.0])

pylab.savefig("Updated_BH_curve.png", bbox_inches="tight")

pylab.savetxt(
    "Updated_BH_curve.csv",
    numpy.column_stack((bh_combined[:, 0], bh_combined[:, 1])),
    delimiter=",",
    header="H (A/m), B (T)",
    comments="#",
)
