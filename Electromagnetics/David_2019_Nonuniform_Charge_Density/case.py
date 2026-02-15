import numpy as np
import math
import matplotlib.pyplot as plt

import mufem
import mufem.electromagnetics.electrostatics as estat

# Setup the simulation -----------------------------------------------------------------
sim = mufem.Simulation.New(
    name="Nonuniform Charge Density",
    mesh_path="geometry.msh",
)

runner = mufem.SteadyRunner(total_iterations=3)
sim.set_runner(runner)

# Setup the model and material ---------------------------------------------------------
domain_marker = "Domain" @ mufem.Vol

model = estat.ElectrostaticsModel(marker=domain_marker, order=2)
sim.get_model_manager().add_model(model)

material = estat.ElectrostaticMaterial(name="Air", marker=domain_marker)
model.add_material(material)

# Setup the conditions -----------------------------------------------------------------
Q = 1.0  # [C] charge
a = 0.5  # [m] radius of the charge distribution

charge_expr = f"""
    var r := sqrt(x()^2 + y()^2 + z()^2);
    var Q := {Q};
    var a := {a};

    Q / (4 * pi) * exp(-r^2 / (2 * a^2))
"""

charge_density_condition = estat.ChargeDensityCondition(
    name="Volume Charge", marker=domain_marker, charge_density=charge_expr
)

boundary_marker = "Domain::Boundary" @ mufem.Bnd
potential_condition = estat.ElectricPotentialCondition(
    name="Potential = 0V", marker=boundary_marker, electric_potential=0
)

model.add_conditions([charge_density_condition, potential_condition])

# Run the simulation -------------------------------------------------------------------
sim.run()


# Analyze the results ------------------------------------------------------------------
def theory(r):
    eps0 = 8.8541878188e-12  # [F/m] vacuum permittivity
    factor = Q / (4 * np.pi * eps0 * r**2)
    term1 = np.sqrt(np.pi / 2) * a**3 * math.erf(r / (np.sqrt(2) * a))
    term2 = a**2 * r * np.exp(-(r**2) / (2 * a**2))
    return factor * (term1 - term2)


R = 10.0  # [m] sphere radius
Nr = 500

r = np.linspace(-R + 0.01, R - 0.01, Nr)
E_mufem = np.zeros(Nr)
E_theory = np.zeros(Nr)

for i in range(Nr):
    report = mufem.ProbeReport.SinglePoint(
        name="Electric Field Report",
        cff_name="Electric Field",
        x=r[i],
        y=0,
        z=0,
    )
    E = report.evaluate()
    E_mufem[i] = E.x

    E_theory[i] = theory(r[i])

plt.figure(constrained_layout=True)
plt.plot(r, E_theory / 1e9, "k-", label="Theory")
plt.plot(r, E_mufem / 1e9, label="$\\mu$fem")
plt.legend(loc="best", frameon=False)
plt.xlabel("Distance $r$ [m]")
plt.ylabel("Electric field $E$ [GV/m]")
plt.savefig("results/Electric_Field.png")

# Export the electric field data to a VTK file:
vis = sim.get_field_exporter()
vis.add_field_output("Electric Field")
vis.save(order=2)
