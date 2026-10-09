# Cameron 1986: Heat Transfer With Convection

## Introduction

This test case reproduces the NAFEMS benchmark T4 [1].
It considers steady-state heat transfer in a rectangular domain of uniform
thickness with mixed boundary conditions: prescribed temperature, adiabatic,
and convective.
The objective is to verify the temperature at a specified location.

<div align="center">
<img src="data/Geometry.jpg" alt="Geometry" width="40%">
&nbsp;&nbsp;&nbsp;
<img src="data/Mesh.jpg" alt="Mesh" width="40%">
</div>
<div align="center">
<em>The geometry of the computational domain and the corresponding mesh.</em>
</div>
<br />

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

The figure below presents the temperature profile along the x-axis at a fixed
height of $`y = 0.5`$ m.

![Temperature](results/Temperature.png)

## Scenes

The temperature is exported to `VisualizationOutput/`; the figure below, rendered from it with
ParaView by [create_scene.py](create_scene.py) (run with `pvpython create_scene.py` after the case),
shows the temperature distribution over the computational domain.

![Temperature](results/Scene_Temperature.png)

## References

[1] A. D. Cameron, J. A. Casey and G. B. Simpson (1986). *Benchmark Tests for Thermal Analysis (Summary)*. NAFEMS.
