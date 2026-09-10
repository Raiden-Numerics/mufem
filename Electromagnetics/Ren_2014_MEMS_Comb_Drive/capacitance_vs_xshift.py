import matplotlib.pyplot as plt
import numpy as np

data = np.loadtxt("results/Capacitance.csv", delimiter=",")

xshifts = np.unique(data[:, 0])

N = len(xshifts)

x = np.zeros(N)
C = np.zeros(N)

for i, xshift in enumerate(xshifts):
    subdata = data[data[:, 0] == xshift]

    ncells = subdata[:, 1]
    capacitance = subdata[:, 2]

    x[i] = xshift * 1e-6
    C[i] = capacitance[-1]

a, b = np.polyfit(x, C, 1)
print(a, " ", b)

V = 1  # [V] applied voltage
dCdx = a  # [F/m] derivative of the capacitance
F = 1 / 2 * dCdx * V**2  # [N] comb drive force

print(f"Force F = {F} [N]")
print(f"Force F = {F/1e-9} [nN]")

plt.figure(constrained_layout=True)
plt.plot(x / 1e-6, C / 1e-15, "o", label="mufem")
plt.plot(x / 1e-6, (a * x + b) / 1e-15, "-", label="linear fit")
plt.legend(loc=0, frameon=False)
plt.xlabel("Shift [μm]")
plt.ylabel("Capacitance [fF]")
plt.savefig("results/Capacitance_Vs_Xshift.png")

plt.show()
