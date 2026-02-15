import matplotlib.pyplot as plt
import numpy

from mufem import Bnd, Vol, Simulation, SteadyRunner
from mufem.electromagnetics.timeharmonicmaxwell import (
    PerfectElectricConductorCondition,
    SParametersReport,
    TimeHarmonicMaxwellGeneralMaterial,
    TimeHarmonicMaxwellModel,
    WaveguideInputPortCondition,
    WaveguideOutputPortCondition,
)

# **************************************************************************************
# Problem setup
# **************************************************************************************
sim = Simulation.New(
    name="Montejo-Garai_1995_Circular_Cavity_Filter",
    mesh_path="geometry.msh",
)

runner = SteadyRunner(total_iterations=0)

is_main_process = sim.get_machine().is_main_process()


# **************************************************************************************
# Model
# **************************************************************************************
model = TimeHarmonicMaxwellModel(
    marker="Domain" @ Vol,
    frequency=14.5e9,  # [Hz] radiation frequency
    order=2,  # finite element polynomial degree
)
sim.get_model_manager().add_model(model)


# **************************************************************************************
# Materials
# **************************************************************************************
material_air = TimeHarmonicMaxwellGeneralMaterial.Constant(
    name="Air",
    marker="Domain" @ Vol,
)
model.add_material(material_air)


# **************************************************************************************
# Boundary conditions
# **************************************************************************************
condition_pec = PerfectElectricConductorCondition(
    name="PEC",
    marker="Walls" @ Bnd,
)

condition_input_port = WaveguideInputPortCondition(
    name="Input",
    marker="InputPort" @ Bnd,
    mode_index=0,  # index of the mode that will be launched from the input port
)

condition_output_port = WaveguideOutputPortCondition(
    name="Output",
    marker="OutputPort" @ Bnd,
)

model.add_conditions([condition_pec, condition_input_port, condition_output_port])


# **************************************************************************************
# Reports
# **************************************************************************************
report_s_parameters = SParametersReport(
    name="S-parameters",
    condition=condition_output_port,
    nmodes=1,  # number of modes to be calculated for the report
)
sim.get_report_manager().add_report(report_s_parameters)


# **************************************************************************************
# Run the simulation
# **************************************************************************************
Nf = 251  # number of frequencies to scan
frequencies = numpy.linspace(10e9, 15e9, Nf)  # [Hz] frequencies to scan

frequencies_paraview = [12e9, 14e9]  # [Hz] frequencies at which to save the field

vis = sim.get_field_exporter()
vis.add_field_output("Electric Field-Real")

S21 = numpy.zeros(Nf, dtype=complex)

for i, frequency in enumerate(frequencies):
    if is_main_process:
        print(f"\nFrequency {i+1}/{Nf}: {frequency/1e9:.3f}GHz")

    model.set_frequency(frequency)
    runner.advance(1)

    if frequency in frequencies_paraview:
        vis.save(order=2)

    report_data = report_s_parameters.evaluate().to_numpy()
    S21[i] = report_data[0, 0]


# **************************************************************************************
# Plot the results
# **************************************************************************************
plt.clf()

# Reference data:
data = numpy.loadtxt("data/Montejo-Garai_1995.csv", delimiter=",")
f_GHz = data[:, 0]
S21_dB = data[:, 1]
plt.plot(f_GHz, S21_dB, "k^", label="Montejo-Garai 1995", markersize=10)

# Simulated data:
f_GHz = frequencies / 1e9
S21_abs2 = numpy.abs(S21) ** 2
S21_dB = 10 * numpy.log10(S21_abs2)
plt.plot(f_GHz, S21_dB, label="$\\mu$fem", color="red")

plt.legend(loc="best", frameon=False)
plt.xlabel("Frequency [GHz]")
plt.ylabel("|S21|$^2$ [dB]")
plt.savefig("results/S21_vs_frequency.png", bbox_inches="tight")
