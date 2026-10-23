# mufem: fast and accurate simulations

mufem (pronounced /ˈmjuːfɛm/) is an API-first finite-element simulation code for
**electromagnetics**, **photonics**, and **plasmas**, and their **coupled multi-physics problems**,
built for **industry-relevant** engineering applications.

mufem is driven through a **Python interface**, making it ideal for exploratory work, **parametric studies**
and **design optimization**, and a natural fit for **agentic workflows**. The mufem Community version is
**free for both academic and commercial use**.

For questions or support, please [open an issue](https://github.com/Raiden-Numerics/mufem/issues/new/choose)
or contact us at [info@raiden-numerics.com](mailto:info@raiden-numerics.com).

**Contents:** [Introduction](#introduction) · [Gallery](#gallery) · [Models](#models) ·
[Getting started](#getting-started) · [Validation cases](#validation-cases) ·
[Tested Platforms](#tested-platforms)

## Introduction

This repository hosts a quick introduction to mufem together with a collection of validation and example
cases. For platform-specific setup see the
[Installation guide](https://raiden-numerics.github.io/mufem-doc/getting_started/installation.html), and for
tutorials and the full API reference see the
[mufem documentation](https://raiden-numerics.github.io/mufem-doc/index.html).

![Marquee](https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/.marquee.png)

### Why mufem

<table>
<tr>
<td width="50%" valign="top"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/docs/assets/icons/python.svg" width="20" align="absmiddle"> <strong>Python-native</strong><br>build, run, and post-process simulations from a clean Python API; ideal for parametric sweeps, optimization, and agentic workflows.</td>
<td width="50%" valign="top"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/docs/assets/icons/account_tree.svg" width="20" align="absmiddle"> <strong>Multi-physics</strong><br>model electromagnetic, thermal, and structural phenomena and their interactions, all within a single framework.</td>
</tr>
<tr>
<td width="50%" valign="top"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/docs/assets/icons/code.svg" width="20" align="absmiddle"> <strong>Advanced discretization</strong><br>built on <a href="https://mfem.org/">MFEM</a> for high-order finite elements on curved, unstructured, non-conformal, and Cartesian meshes.</td>
<td width="50%" valign="top"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/docs/assets/icons/memory.svg" width="20" align="absmiddle"> <strong>GPU-accelerated</strong><br>parallel CPU and GPU solvers that scale efficiently from a single laptop to a large cluster.</td>
</tr>
<tr>
<td width="50%" valign="top"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/docs/assets/icons/fact_check.svg" width="20" align="absmiddle"> <strong>Validated</strong><br>continuously tested against established benchmark suites and published experimental, analytical, and reference results.</td>
<td width="50%" valign="top"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/docs/assets/icons/check_circle.svg" width="20" align="absmiddle"> <strong>Free</strong><br>the community version is free for academic and commercial use, with no license fees, covering most workflows on a single workstation. See <a href="https://mufem.raiden-numerics.com/#pricing">pricing</a> for paid tiers.</td>
</tr>
</table>

### Licensing

mufem is **free for academic and commercial use**. The Community version needs no license key, includes
most physics models, and uses all the cores of your workstation, so you can run real projects and client
work without paying anything.

When your models outgrow a single machine, a paid license lets mufem grow with them:

- **Bigger models, faster answers**: spread a simulation across a compute cluster or run it on GPUs, for much
  shorter run times, making large parametric studies practical.
- **Specialized physics models** for advanced applications that go beyond the Community version.
- **Direct support** from the developers by email, instead of community support via GitHub Issues.
- **Enterprise options**: multi-seat and on-premises licensing, integration and validation services.

See [mufem.raiden-numerics.com](https://mufem.raiden-numerics.com/#pricing) for plans and pricing.

### Quick example

Solve the electrostatic field inside a cube held at 1 V across two faces. The simulation reads a mesh
whose **tagged attributes** (a `Cube` volume and its `Anode`/`Cathode` boundary faces) are referenced by
markers (`"Cube" @ Vol`, `"Anode" @ Bnd`, ...):

```python
import mufem
import mufem.electromagnetics.electrostatics as estat
from mufem import Vol, Bnd

sim = mufem.Simulation.New(name="Charged Cube", mesh_path="cube.msh")
sim.set_runner(mufem.SteadyRunner(total_iterations=1))

# Electrostatics model, with air filling the tagged "Cube" volume
model = estat.ElectrostaticsModel(order=2)
sim.get_model_manager().add_model(model)
model.add_material(estat.ElectrostaticMaterial(name="Air", marker="Cube" @ Vol))

# Apply 1 V across the cube: anode at 1 V, cathode grounded
model.add_conditions(
    [
        estat.ElectricPotentialCondition(
            name="Anode", marker="Anode" @ Bnd, electric_potential=1.0
        ),
        estat.ElectricPotentialCondition(
            name="Cathode", marker="Cathode" @ Bnd, electric_potential=0.0
        ),
    ]
)

# Report the stored electric energy
report = mufem.VolumeIntegralReport(name="Energy", cff_name="Electric Energy Density")
sim.get_report_manager().add_report(report)

sim.run()
print("Electric energy:", report.evaluate(), "J")

# Export the fields for visualization (ParaView / VTK)
vis = sim.get_field_exporter()
vis.set_output_directory("ChargedCubeOutput")
vis.add_field_output("Electric Potential")
vis.add_field_output("Electric Field")
vis.save()
```

## Gallery

<table>
<tr>
<td width="40%"><a href="https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Electromagnetics/Compumag-Team24-Locked-Rotor/README.md"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/Validations/Electromagnetics/Compumag-Team24-Locked-Rotor/results/Animation_Electric_Current_Density.gif" width="100%"></a></td>
<td width="60%" valign="top">
<strong><a href="https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Electromagnetics/Compumag-Team24-Locked-Rotor/README.md">Locked rotor (TEAM 24)</a></strong><br>
Study the transient rotor torque and coil currents of a rotating machine using the <strong>Time-Domain Magnetic</strong>
model coupled to an <strong>Excitation Coil</strong>.
</td>
</tr>
<tr>
<td width="40%"><a href="https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Electromagnetics/Stutzman_2012_Dipole_Antenna/README.md"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/Validations/Electromagnetics/Stutzman_2012_Dipole_Antenna/results/Scene_Radiation_Pattern.png" width="100%"></a></td>
<td width="60%" valign="top">
<strong><a href="https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Electromagnetics/Stutzman_2012_Dipole_Antenna/README.md">Dipole antenna (Stutzman 2012)</a></strong><br>
Compute the full-wave radiation pattern and far-field of a dipole antenna using the <strong>Time-Harmonic Maxwell</strong>
model.
</td>
</tr>
<tr>
<td width="40%"><a href="https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Electromagnetics/Compumag-Team1b-Felix-Cylinder/README.md"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/Validations/Electromagnetics/Compumag-Team1b-Felix-Cylinder/results/Scene_Electric_Current_Density.png" width="100%"></a></td>
<td width="60%" valign="top">
<strong><a href="https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Electromagnetics/Compumag-Team1b-Felix-Cylinder/README.md">FELIX cylinder (TEAM 1b)</a></strong><br>
Resolve induced eddy-current density and ohmic losses in a conducting cylinder using the <strong>Time-Domain
Magnetic</strong> model.
</td>
</tr>
</table>

## Models

mufem provides finite-element models across several physics domains, composable for coupled multi-physics:

- **Electrostatics**: electric fields and potentials in dielectrics.
- **Magnetostatics**: static magnetic fields, including nonlinear materials.
- **Time-Domain Magnetic**: eddy currents and transient low-frequency magnetics.
- **Time-Harmonic Magnetic**: steady-state AC magnetics.
- **Full-wave Maxwell (time-harmonic)**: high-frequency electromagnetics and antennas.
- **Thermal**: steady and transient heat conduction.
- **Structural**: linear elasticity.

See the [documentation](https://raiden-numerics.github.io/mufem-doc/index.html) for the full model list and details.

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
for tutorials and API reference. For a complete, runnable case, including mesh generation and a
comparison with an analytical solution, see the
[electrostatics tutorial](https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Electromagnetics/David_2019_Nonuniform_Charge_Density/README.md).

## Validation cases

This repository collects validation cases for mufem, each comparing its results with published,
measured, or analytical reference values. See
[Validations.md](https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Validations.md)
for the list of cases and how to run them.

## Tested Platforms

[![tested version](https://img.shields.io/badge/dynamic/yaml?url=https%3A%2F%2Fraw.githubusercontent.com%2FRaiden-Numerics%2Fmufem%2Fmain%2FVERSION&query=%24&label=tested%20version)](https://pypi.org/project/mufem/)

|  | Python 3.12 | Python 3.13 | Python 3.14 | Python 3.15 |
|---|---|---|---|---|
| **Linux** x86-64 | [![validations](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/validations_linux_mpi.yml?branch=main&label=validations)](https://github.com/Raiden-Numerics/mufem/actions/workflows/validations_linux_mpi.yml) [![e2e](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/validations_linux_e2e.yml?branch=main&label=e2e)](https://github.com/Raiden-Numerics/mufem/actions/workflows/validations_linux_e2e.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_py313.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_py313.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_py314.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_py314.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_py315.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_py315.yml) |
| **Windows** x86-64 | [![validations](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/validations_windows_py312.yml?branch=main&label=validations)](https://github.com/Raiden-Numerics/mufem/actions/workflows/validations_windows_py312.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_windows_py313.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_windows_py313.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_windows_py314.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_windows_py314.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_windows_py315.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_windows_py315.yml) |
| **macOS** arm64 | [![validations](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/validations_macos_py312.yml?branch=main&label=validations)](https://github.com/Raiden-Numerics/mufem/actions/workflows/validations_macos_py312.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_macos_py313.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_macos_py313.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_macos_py314.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_macos_py314.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_macos_py315.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_macos_py315.yml) |
| **Linux distros**¹ | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_linux_distros.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_linux_distros.yml) |  |  |  |

- **validations**: all validation cases on Linux; the moderate tier on macOS and Windows (without the `long`, `eternal` and `mumps` cases).
- **smoke**: a single case (Team1b), confirming that the release installs and runs.
- **e2e**: weekly; all validation cases with every geometry, mesh and scene regenerated from scratch.

¹ Ubuntu 26.04, Debian 13, Fedora 43, AlmaLinux 10, openSUSE Tumbleweed and Arch Linux.
Linux requires glibc ≥ 2.39; Ubuntu 22.04, Debian 12, RHEL 8/9 and SLES 15 are not yet supported.
