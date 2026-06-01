# Compumag TEAM Problem 7: Asymmetrical Conductor with a Hole

## Introduction

Problem 7 of the Compumag TEAM benchmark suite [1] is a thick aluminium plate with an
off-centred rectangular hole, placed below an excitation coil driven by a sinusoidal
current. It is a classical 3-D eddy-current validation case, with measured data
published at $`50\,\mathrm{Hz}`$ and $`200\,\mathrm{Hz}`$ [2].

<div align="center">
<img src="./data/Geometry.png" alt="Geometry of the benchmark" width="600">
</div>
<div align="center">
<em>Figure 1: Geometry of the benchmark. A coil is placed above an aluminium plate with an off-centred hole.</em>
</div>


## Problem Description

The aluminium plate has an electrical conductivity of $`\sigma = 3.526 \times 10^7\,\mathrm{S/m}`$.
The stranded coil is driven by a sinusoidal current of $`2742\,\mathrm{AT}`$ at a frequency
of $`f = 50\,\mathrm{Hz}`$ (reference data for $`200\,\mathrm{Hz}`$ also exists).
The numerical results are compared with measurements of the magnetic flux density along two
lines above the plate, denoted A1-B1 and A2-B2, as reported by Fujiwara and Nakata [2].
A discrepancy in the absolute coil-current values reported in [2] has been cross-checked
against the NGSolve TEAM-7 reference [3].


## Setup

Since the problem is linear and the excitation is sinusoidal, the
[Time-Harmonic Magnetic Model](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/time_harmonic_magnetic/model.html)
can be used. The excitation is prescribed using the
[Excitation Coil Model](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/excitation_coil/model.html).

The setup script is provided in [case.py](case.py) and the corresponding mesh can be found in [geometry.mesh](geometry.mesh). The mesh contains three
[named attributes](https://mfem.org/mesh-format-v1.0/#mfem-mesh-v13): **Air**, **Coil**, and **Plate**.

### Model

To compensate for the relatively coarse mesh, a third-order spatial discretization is employed
in the time-harmonic magnetic model:

```python
magnetic_model = TimeHarmonicMagneticModel(
    Vol.Everywhere,
    frequency=50,
    order=3,
)
```

### Materials

Three
[materials](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/time_harmonic_magnetic/materials/general_material.html)
are defined: *air*, *copper*, and *aluminium*. Only aluminium is electrically conductive and
therefore supports eddy currents.

```python
air_material = TimeHarmonicMagneticGeneralMaterial(
    name="Air",
    marker="Air" @ Vol,
    has_eddy_currents=False,
)

copper_material = TimeHarmonicMagneticGeneralMaterial(
    name="Copper",
    marker="Coil" @ Vol,
    has_eddy_currents=False,
)

alu_material = TimeHarmonicMagneticGeneralMaterial(
    name="Alu",
    marker="Plate" @ Vol,
    magnetic_permeability=1.0,
    electric_conductivity=3.526e7,
    has_eddy_currents=True,
)
```


### Coil Excitation

The
[Excitation Coil Model](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/excitation_coil/model.html)
is added to the simulation. The coil is modeled as

- a [current excitation](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/excitation_coil/excitations/current.html) with $`I = 1\,\mathrm{A}`$,
- a [stranded coil type](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/excitation_coil/types/stranded_coil.html) with 2742 turns,
- a [closed coil topology](https://raiden-numerics.github.io/mufem-doc/models/electromagnetics/excitation_coil/topologies/closed_coil.html).


```python
coil_model = ExcitationCoilModel()
sim.get_model_manager().add_model(coil_model)

coil_topology = CoilTopologyClosed(
    x=0.2, y=0.01, z=0.07,
    dx=1.0, dy=0.0, dz=0.0,
)

coil_type = CoilTypeStranded(number_of_turns=2742)

coil_excitation = CoilExcitationCurrent.Harmonic(
    magnitude=1.0,
    phase=0.0,
)

coil = CoilSpecification(
    name="Coil",
    marker="Coil" @ Vol,
    topology=coil_topology,
    type=coil_type,
    excitation=coil_excitation,
)
```


## Results

After running the simulation with `pymufem`, the following results are obtained in the
`results` directory.

### Magnetic Flux Density

The computed magnetic flux density is compared with the reference data from [2]. The reference
provides real and imaginary components of the magnetic flux density, corresponding to
measurements at

- $`t = 0\,\mathrm{ms}`$ (phase $`\phi = 0^\circ`$),
- $`t = 5\,\mathrm{ms}`$ (phase $`\phi = 90^\circ`$).

| Magnetic Flux Density along A1-B1 | Magnetic Flux Density along A2-B2 |
|----------------------------------|----------------------------------|
| <img src="./results/Magnetic_Flux_Density-A1-B1.png" width="600"> | <img src="./results/Magnetic_Flux_Density-A2-B2.png" width="600"> |

A very good agreement is observed for both measurement lines.

Note that the solution is time-periodic with a period of $`T = 20\,\mathrm{ms}`$. The magnetic flux
density at an arbitrary time $`t`$ can be
reconstructed from the complex solution using

```math
\vec{B}(t) = \vec{B}_r \cos(\omega t) - \vec{B}_i \sin(\omega t),
```
where $`\omega = 2\pi f`$.


## Visualization

The periodic evolution of the magnetic flux density and the induced currents can be visualized
over one excitation cycle.

<div align="center">
<img src="./results/Team7_Animation.gif" alt="Magnetic flux density animation" width="1200">
</div>
<div align="center">
<em>Absolute value of the magnetic flux density over one period.</em>
</div>

The animation is generated using the script [`create_anim.sh`](create_anim.sh). A static
scene of the absolute magnetic flux density is rendered via [`create_scene.py`](create_scene.py).


## References

[1] Compumag, "Problem 7 - Asymmetrical Conductor with a Hole",
    https://www.compumag.org/wp/wp-content/uploads/2018/06/problem7.pdf

[2] K. Fujiwara and T. Nakata, "Results for benchmark problem 7 (asymmetrical conductor
    with a hole)," *COMPEL - The International Journal for Computation and Mathematics
    in Electrical and Electronic Engineering*, vol. 9, no. 3, pp. 137-154, 1990.

[3] NGSolve TEAM-7 reference,
    https://ngsolve.github.io/TEAM-problems/TEAM-7/team7.html
