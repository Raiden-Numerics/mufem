# mufem: fast and accurate simulations

mufem (pronounced /ˈmjuːfɛm/) is an API-first finite-element simulation code for
**electromagnetics**, **photonics**, and **plasmas**, and their **coupled multi-physics problems**,
built for **industry-relevant** engineering applications.

mufem is driven through a **Python interface**, making it ideal for exploratory work, **parametric studies**
and **design optimization**, and a natural fit for **agentic workflows**.

For questions or support, please [open an issue](https://github.com/Raiden-Numerics/mufem/issues/new/choose)
or contact us at [info@raiden-numerics.com](mailto:info@raiden-numerics.com).

**Contents:** [Introduction](#introduction) · [Case Studies](#case-studies) · [Models](#models) ·
[Getting Started](#getting-started) · [Validations](#validations) ·
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
<td width="50%" valign="top"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/docs/assets/icons/check_circle.svg" width="20" align="absmiddle"> <strong>Free</strong><br>mufem (Community) is free for academic and commercial use, with no license fees, covering most workflows on a single workstation. See <a href="https://mufem.raiden-numerics.com/#pricing">pricing</a> for paid tiers.</td>
</tr>
</table>

### Licensing

mufem (Community) is **free for academic and commercial use**. It needs no license key, includes
all physics models, and runs multithreaded, making good use of the cores of typical desktops and laptops,
so you can run real projects and client work without paying anything.

When your models outgrow a single machine, a paid license for mufem (Professional) lets mufem grow with them.
The Professional packages are `mufem-mpi`, `mufem-cuda` and `mufem-hip`:

- **Bigger models, faster answers**: distributed parallel computing that keeps scaling where threads level off, on a
  many-core workstation, across a compute cluster, or on GPUs. Run times keep dropping as you add cores,
  nodes or GPUs, which makes large models and parametric studies practical. See
  [benchmarks](https://github.com/Raiden-Numerics/mufem/blob/main/Benchmarks/README.md) for more
  details.
- **Direct support** from the developers by email, instead of community support via GitHub Issues.
- **Enterprise options**: multi-seat and on-premises licensing, integration and validation services.

See [mufem.raiden-numerics.com](https://mufem.raiden-numerics.com/#pricing) for plans and pricing.

### Quick Example

Solve the electrostatic field inside a cube held at 1 V across two faces. The simulation reads a mesh
whose **tagged attributes** (a `Cube` volume and its `Anode`/`Cathode` boundary faces) are referenced by
markers (`"Cube" @ Vol`, `"Anode" @ Bnd`, ...). The script and its mesh are in
[QuickExample](https://github.com/Raiden-Numerics/mufem/tree/main/QuickExample); run it there with
`python charged_cube.py`:

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
field_exporter = sim.get_field_exporter()
field_exporter.set_output_directory("ChargedCubeOutput")
field_exporter.add_field_output("Electric Potential")
field_exporter.add_field_output("Electric Field")
field_exporter.save()
```

It prints the energy of the uniform field between the plates, $`\varepsilon_0 V^2 d / 2 \approx 4.43 \times 10^{-13}`$ J
for the 10 cm cube.

## Case Studies

Case studies apply mufem to complete engineering problems, from the geometry to the design decision.

[Browse all case studies here](https://github.com/Raiden-Numerics/mufem/blob/main/CaseStudies/README.md).

<table>
<tr>
<td width="40%"><a href="https://github.com/Raiden-Numerics/mufem/blob/main/CaseStudies/PMSM-Motor/README.md"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/CaseStudies/PMSM-Motor/results/Case_Study_Thumbnail.png" width="100%"></a></td>
<td width="60%" valign="top">
<strong><a href="https://github.com/Raiden-Numerics/mufem/blob/main/CaseStudies/PMSM-Motor/README.md">Step skew in a hairpin IPM traction motor</a></strong><br>
Follow a skew design from 2D to full 3D on a 48-slot, 8-pole traction motor.
<ul>
<li>Cogging torque and load ripple of the skewed and unskewed machine</li>
<li>Comparison with the fast 2D multi-slice method</li>
<li>AC copper losses of the whole hairpin winding, end turns included</li>
<li>Full 3D model: turning rotor, sliding interface, non-linear iron, eddy currents</li>
</ul>
</td>
</tr>
</table>

## Models

<a href="https://raiden-numerics.github.io/mufem-doc/models/models.html"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/.mufem-models.svg" alt="mufem models" width="100%"></a>

See the [List of Models](https://raiden-numerics.github.io/mufem-doc/models/models.html) for all models and details.

## Getting Started

First create and activate a virtual environment:

```bash
python -m venv mufem-venv
source mufem-venv/bin/activate
```

Then install the latest release of mufem (Community) from PyPI:

```bash
pip install mufem
```

The mufem (Professional) packages come from the mufem package index; see
[Install mufem package](https://raiden-numerics.github.io/mufem-doc/getting_started/installation.html#install-mufem-package).

See the [Installation guide](https://raiden-numerics.github.io/mufem-doc/getting_started/installation.html)
for platform-specific instructions, and the [mufem documentation](https://raiden-numerics.github.io/mufem-doc/index.html)
for tutorials and API reference. For a complete, runnable case, including mesh generation and a
comparison with an analytical solution, see the
[electrostatics tutorial](https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Electromagnetics/David_2019_Nonuniform_Charge_Density/README.md).

## Validations

This repository collects validation cases for mufem, each comparing its results with published,
measured, or analytical reference values.

[Browse all validation cases here](https://github.com/Raiden-Numerics/mufem/blob/main/Validations/README.md).

<div align="center">
<a href="https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Electromagnetics/Compumag-Team24-Locked-Rotor/README.md"><img src="https://raw.githubusercontent.com/Raiden-Numerics/mufem/main/Validations/Electromagnetics/Compumag-Team24-Locked-Rotor/results/Animation_Electric_Current_Density.gif" width="80%"></a>
<br>
<sub>TEAM 24: eddy currents in a locked rotor after a voltage step (left), and the coil current and the
rotor torque over time compared with measurements (right).</sub>
</div>

## Tested Platforms

[![Tested Version](https://img.shields.io/badge/dynamic/yaml?url=https%3A%2F%2Fraw.githubusercontent.com%2FRaiden-Numerics%2Fmufem%2Fmain%2FVERSION&query=%24&label=tested%20version)](https://pypi.org/project/mufem/)

Automated tests install the released packages of the tested version on each platform and run the
validation cases of this repository with them. Each badge shows the result of the latest run.

### mufem (Community)

|  | Python 3.12 | Python 3.13 | Python 3.14 | Python 3.15 |
|---|---|---|---|---|
| **Linux** x86-64 | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_py312.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_py312.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_py313.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_py313.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_py314.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_py314.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_py315.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_py315.yml) |
| **Windows** x86-64 | [![validations](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/validations_windows_py312.yml?branch=main&label=validations)](https://github.com/Raiden-Numerics/mufem/actions/workflows/validations_windows_py312.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_windows_py313.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_windows_py313.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_windows_py314.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_windows_py314.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_windows_py315.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_windows_py315.yml) |
| **macOS** arm64 | [![validations](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/validations_macos_py312.yml?branch=main&label=validations)](https://github.com/Raiden-Numerics/mufem/actions/workflows/validations_macos_py312.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_macos_py313.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_macos_py313.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_macos_py314.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_macos_py314.yml) | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_macos_py315.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_macos_py315.yml) |
| **Linux distros**¹ | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_linux_distros.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_linux_distros.yml) |  |  |  |

- **validations**: the moderate tier on macOS and Windows (without the `long`, `eternal` and `mumps` cases).
- **smoke**: a single case (TEAM 1b), confirming that the release installs and runs.

¹ Ubuntu 26.04, Debian 13, Fedora 43, AlmaLinux 10, openSUSE Tumbleweed and Arch Linux.
Linux requires glibc ≥ 2.39; Ubuntu 22.04, Debian 12, RHEL 8/9 and SLES 15 are not yet supported.

### mufem (Professional)

| Package | Platform | Run | Status |
|---|---|---|---|
| `mufem-mpi` | Linux x86-64 | 15 MPI ranks | [![validations](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/validations_linux.yml?branch=main&label=validations)](https://github.com/Raiden-Numerics/mufem/actions/workflows/validations_linux.yml) [![e2e](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/validations_linux_e2e.yml?branch=main&label=e2e)](https://github.com/Raiden-Numerics/mufem/actions/workflows/validations_linux_e2e.yml) |
| `mufem-cuda` | Linux x86-64, NVIDIA GPU | 1 MPI rank | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_pro_cuda.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_pro_cuda.yml) |
| `mufem-hip` | Linux x86-64, AMD GPU | 1 MPI rank | [![smoke](https://img.shields.io/github/actions/workflow/status/Raiden-Numerics/mufem/smoke_pro_hip.yml?branch=main&label=smoke)](https://github.com/Raiden-Numerics/mufem/actions/workflows/smoke_pro_hip.yml) |

Each package is installed from the mufem package index on Python 3.12. `mufem-mpi` runs all validation cases
(**validations**), and weekly with every geometry, mesh and scene regenerated from scratch (**e2e**); the GPU
packages run a single case (TEAM 1b).
