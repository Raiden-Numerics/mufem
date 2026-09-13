# mufem: fast and accurate simulations

mufem is a [finite-element simulation code](https://raiden-numerics.github.io/mufem/) focused on
**electromagnetics**, **plasmas**, and **coupled multi-physics problems**, built for **industry-relevant**
engineering applications.

mufem is driven through a **Python interface**, making it ideal for exploratory work, **parametric studies**
and **design optimization**, and a natural fit for **agentic workflows**. mufem is
**free for both academic and commercial use**.

For questions or support, please [open an issue](https://github.com/Raiden-Numerics/mufem-release/issues/new/choose)
or contact us at [info@raiden-numerics.com](mailto:info@raiden-numerics.com).

This repository hosts a quick introduction to mufem together with a collection of validation and example
cases. For platform-specific setup see the
[Installation guide](https://raiden-numerics.github.io/mufem-doc/getting_started/installation.html), and for
tutorials and the full API reference see the
[mufem documentation](https://raiden-numerics.github.io/mufem-doc/index.html).

![Logo](.logo.png)

## Why mufem

* **Python-native**: build, run, and post-process simulations from a clean Python API; no custom input decks.
* **Multi-physics**: electromagnetics (low- and high-frequency), plasmas, thermal and structural, with coupling.
* **High-order & parallel**: built on [MFEM](https://mfem.org/) for high-order finite elements and MPI scalability.
* **Validated**: continuously tested against the TEAM and NAFEMS benchmark suites as well as published experimental, analytical, and reference numerical results (see below).
* **Automation-friendly**: a scriptable interface that fits parametric sweeps, optimization, and agentic workflows.
* **Free**: for both academic and commercial use.

## Quick example

Solve the electrostatic field inside a cube held at 1 V across two faces. The simulation reads a mesh
whose **tagged attributes** (a `Cube` volume and its `Anode`/`Cathode` boundary faces) are referenced by
markers (`"Cube" @ Vol`, `"Anode" @ Bnd`, ...):

```python
import mufem
import mufem.electromagnetics.electrostatics as estat
from mufem import Vol, Bnd

sim = mufem.Simulation.New(name="Charged Cube", mesh_path="cube.msh")
sim.set_runner(mufem.SteadyRunner(total_iterations=1))

# Electrostatics model on the tagged "Cube" volume
model = estat.ElectrostaticsModel(order=2)
sim.get_model_manager().add_model(model)
model.add_material(estat.ElectrostaticMaterial(name="Air", marker="Cube" @ Vol))

# Apply 1 V across the cube: anode at 1 V, cathode grounded
model.add_conditions([
    estat.ElectricPotentialCondition(name="Anode", marker="Anode" @ Bnd, electric_potential=1.0),
    estat.ElectricPotentialCondition(name="Cathode", marker="Cathode" @ Bnd, electric_potential=0.0),
])

# Report the stored electric energy
report = mufem.VolumeIntegralReport(name="Energy", cff_name="Electric Energy Density")
sim.get_report_manager().add_report(report)

sim.run()
print("Electric energy:", report.evaluate(), "J")

# Export the fields for visualization (ParaView / VTK)
vis = sim.get_field_exporter()
vis.add_field_output("Electric Potential")
vis.add_field_output("Electric Field")
vis.save()
```

See the [electrostatics cases](Electromagnetics/Ren_2014_MEMS_Comb_Drive/README.md) for full, runnable
examples, including mesh generation and comparison against reference results.

## Gallery

<table>
<tr>
<td width="40%"><a href="Electromagnetics/Compumag-Team24-Locked-Rotor/README.md"><img src="Electromagnetics/Compumag-Team24-Locked-Rotor/results/Result_Animation.gif" width="100%"></a></td>
<td width="60%">

**[Locked rotor (TEAM 24)](Electromagnetics/Compumag-Team24-Locked-Rotor/README.md)**

Study the transient rotor torque and coil currents of a rotating machine using the **Time-Domain Magnetic**
model coupled to an **Excitation Coil**.

</td>
</tr>
<tr>
<td width="40%"><a href="Electromagnetics/Stutzman_2012_Dipole_Antenna/README.md"><img src="Electromagnetics/Stutzman_2012_Dipole_Antenna/results/Scene_Radiation_Pattern.png" width="100%"></a></td>
<td width="60%">

**[Dipole antenna (Stutzman 2012)](Electromagnetics/Stutzman_2012_Dipole_Antenna/README.md)**

Compute the full-wave radiation pattern and far-field of a dipole antenna using the **Time-Harmonic Maxwell**
model.

</td>
</tr>
<tr>
<td width="40%"><a href="Electromagnetics/Compumag-Team1b-Felix-Cylinder/README.md"><img src="Electromagnetics/Compumag-Team1b-Felix-Cylinder/results/Scene_Electric_Current_Density.png" width="100%"></a></td>
<td width="60%">

**[Felix cylinder (TEAM 1b)](Electromagnetics/Compumag-Team1b-Felix-Cylinder/README.md)**

Resolve induced eddy-current density and ohmic losses in a conducting cylinder using the **Time-Domain
Magnetic** model.

</td>
</tr>
</table>

## Getting started

First create and activate a virtual environment:

```bash
python -m venv mufem-venv
source mufem-venv/bin/activate
```

Then install the latest release from PyPI:

```bash
pip install mufem
```

See the [Installation guide](https://raiden-numerics.github.io/mufem-doc/getting_started/installation.html)
for platform-specific instructions, and the [mufem documentation](https://raiden-numerics.github.io/mufem-doc/index.html)
for tutorials and API reference.

That is all you need to run the [validation cases](#validation-cases) below directly.

## Validation cases

This repository collects validation examples for mufem (tested against the pinned [version](VERSION)).
After following the [Installation guide](https://raiden-numerics.github.io/mufem-doc/getting_started/installation.html),
run a specific case with:

```bash
(mufem-venv) pymufem Electromagnetics/Compumag-Team1b-Felix-Cylinder/case.py
```

### Electromagnetics

mufem supports both low-frequency (magnetostatics, eddy currents, time-domain and time-harmonic magnetics)
and high-frequency (full-wave Maxwell) electromagnetics.

* [**TEAM (Testing Electromagnetic Analysis Methods) Benchmark Suite**](https://www.compumag.org/wp/team/) \
  Introduced in the late 1980s and continuously updated, the TEAM benchmarks focus primarily on low-frequency magnetic problems, providing a standard framework for evaluating numerical methods. Available cases:

  - [Compumag TEAM 1b: The Felix Cylinder](Electromagnetics/Compumag-Team1b-Felix-Cylinder/README.md)
  - [Compumag TEAM 7: Asymmetrical Conductor with a Hole](Electromagnetics/Compumag-Team7-Asymmetrical-Conductor-with-a-Hole/README.md)
  - [Compumag TEAM 13: 3-D Non-Linear Magnetostatic Model](Electromagnetics/Compumag-Team13-3-D-Non-Linear-Magnetostatic-Model/README.md)
  - [Compumag TEAM 20: 3D Static Force Problem](Electromagnetics/Compumag-Team20-3D-Static-Force-Problem/README.md)
  - [Compumag TEAM 24: Locked Rotor](Electromagnetics/Compumag-Team24-Locked-Rotor/README.md)
  - [Compumag TEAM 36: Induction Heating Device](Electromagnetics/Compumag-Team36-Induction-Heating-Device/README.md)

* **[Electrostatic](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/electrostatics/model.html)**
  - [Ren 2014: MEMS Comb Drive](Electromagnetics/Ren_2014_MEMS_Comb_Drive/README.md)
  - [David 2019: Nonuniform Charge Density](Electromagnetics/David_2019_Nonuniform_Charge_Density/README.md)

* **[Time-Domain Magnetic](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/time_domain_magnetic/model.html)**
  - [Lubin 2015: Axial-Flux Eddy Current Brake](Electromagnetics/Lubin_2015_Axial_Flux_Eddy_Current_Brake/README.md)
  - [Berger 2017: High-Temperature Superconductor Cube](Electromagnetics/Berger_2017_HTS_Cube/README.md)

* **[Time-Harmonic Magnetic](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/time_harmonic_magnetic/model.html)**
  - [Biro 1993: 3D Iron Core Current Driven Conductors](Electromagnetics/Biro_1993_3D_Iron_Core_Current_Driven_Conductors/README.md)

* **[Time-Harmonic Maxwell](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/time_harmonic_maxwell/model.html)**
  - [Montejo-Garai 1995: Circular Cavity Filter](Electromagnetics/Montejo-Garai_1995_Circular_Cavity_Filter/README.md)
  - [Stutzman 2012: Dipole Antenna](Electromagnetics/Stutzman_2012_Dipole_Antenna/README.md)

### Structural

* [**NAFEMS Benchmark Suite**](https://www.nafems.org/publications/resource_center/r0006/) \
  A long-standing set of reference problems from the NAFEMS simulation community
  covering structural, thermal, fluid, and multi-physics analyses.

  - [Cameron 1986: Heat Transfer With Convection](Thermal/Cameron_1986_Heat_Transfer_With_Convection/README.md)

* **Structural Mechanics**
  - [Slaughter 2002: Linear Cantilever Beam](Structural/Slaughter_2002_Linear_Cantilever_Beam/README.md)

* **Thermal**
  - [Goldak 1984: Welding Heat Source](Thermal/Goldak_1984_Welding_Heat_Source/README.md)
  - [Bruce 2012: Heat Transfer in Electronic Design](Thermal/Bruce_2012_Heat_Transfer_Electronic_Design/README.md)


## Continuous Integration

[![Examples · Linux x86-64 · Python 3.12](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem-examples/run_cases.yml?label=Examples%20%C2%B7%20Linux%20x86-64%20%C2%B7%20Python%203.12)](https://github.com/Raiden-Numerics/mufem-examples/actions/workflows/run_cases.yml)
[![Smoke · Linux x86-64 · Python 3.13](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem-examples/smoke_py313.yml?label=Smoke%20%C2%B7%20Linux%20x86-64%20%C2%B7%20Python%203.13)](https://github.com/Raiden-Numerics/mufem-examples/actions/workflows/smoke_py313.yml)
[![Smoke · Linux x86-64 · Python 3.14](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem-examples/smoke_py314.yml?label=Smoke%20%C2%B7%20Linux%20x86-64%20%C2%B7%20Python%203.14)](https://github.com/Raiden-Numerics/mufem-examples/actions/workflows/smoke_py314.yml)
[![Smoke · Windows x86-64 · Python 3.13](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem-examples/smoke_windows_py313.yml?label=Smoke%20%C2%B7%20Windows%20x86-64%20%C2%B7%20Python%203.13)](https://github.com/Raiden-Numerics/mufem-examples/actions/workflows/smoke_windows_py313.yml)

