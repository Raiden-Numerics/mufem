# Cameron 1986: Heat Transfer With Convection

## Introduction

This test case reproduces the NAFEMS benchmark T4 [1].
It considers steady-state heat transfer in a rectangular domain of uniform
thickness with mixed boundary conditions: prescribed temperature, adiabatic,
and convective.
The objective is to verify the temperature at a specified location.

<div align="center">
<img src="data/Geometry.png" alt="Geometry" width="45%">
<img src="results/Scene_Mesh.png" alt="Mesh" width="45%">
<br/>
<br/>
<em>Figure 1: The geometry of the computational domain with the boundary conditions and the evaluation point E (left), and the corresponding mesh (right).</em>
</div>
<br/>

## Setup

The computational domain is a rectangle of width 0.6 m and height 1 m with a thermal conductivity of
$`k = 52`$ W/(m K). The two-dimensional benchmark is modeled as a 10 mm thick plate whose front and back
faces are adiabatic.
The bottom edge is held at a prescribed temperature of $`100\,{}^{\circ}\mathrm{C}`$ (modeled by
[TemperatureCondition](https://raiden-numerics.github.io/mufem-doc/models/mechanical/solid_temperature/conditions/temperature.html)).
The left edge is adiabatic (modeled by
[AdiabaticBoundaryCondition](https://raiden-numerics.github.io/mufem-doc/models/mechanical/solid_temperature/conditions/adiabatic.html)).
The top and right edges are subject to convection to an ambient temperature of
$`0\,{}^{\circ}\mathrm{C}`$ with a surface heat transfer coefficient
$`h = 750`$ W/($`\text{m}^2`$ K) (modeled by
[ConvectionBoundaryCondition](https://raiden-numerics.github.io/mufem-doc/models/mechanical/solid_temperature/conditions/convection.html)).
No internal heat generation is present.

## Running

Run the case with `pymufem case.py`.

## Results

**Temperature**

The temperature is evaluated at point E of the benchmark, on the right edge, 0.2 m above the bottom
edge. mufem gives $`18.24\,{}^{\circ}\mathrm{C}`$ against the NAFEMS target of $`18.3\,{}^{\circ}\mathrm{C}`$, and the case checks
this value.

Figure 2 presents the temperature profile along the x-axis at a fixed
height of $`y = 0.5`$ m.

<div align="center">
<img src="results/Temperature.png" alt="Temperature profile" width="75%">
<br/>
<br/>
<em>Figure 2: Temperature along the x-axis at <i>y</i> = 0.5 m.</em>
</div>
<br/>

## Scenes

The temperature is exported to `VisualizationOutput/`; Figure 3 shows the temperature distribution over
the computational domain.

<div align="center">
<img src="results/Scene_Temperature.png" alt="Temperature scene" width="45%">
<br/>
<br/>
<em>Figure 3: Temperature distribution over the computational domain.</em>
</div>
<br/>

## References

[1] A. D. Cameron, J. A. Casey and G. B. Simpson (1986). *Benchmark Tests for Thermal Analysis (Summary)*. NAFEMS.
