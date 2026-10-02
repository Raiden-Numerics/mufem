# Biro 1993: 3D Iron Core Current Driven Conductors

We are testing the current-driven solid coils following the example shown in [1], Section IV. We validate by comparing the
Ohmic heating within each individual conductor to the reference.


<div align="center">
<img src="./data/Geometry.png" alt="drawing" width="600">
</div>
<div align="center">
<em>The geometry of the setup: a core and 25 solid coils. Due to symmetry, only 1/8th of the geometry is modelled.</em>
</div>
<br /><br />

## Introduction

The core has a permeability of $`\mu_r=1000`$ (with no eddy currents), and the conductors have a
conductivity of $`\sigma=5.6 \times 10^7 \, \mathrm{S/m}`$. In each turn, a peak current of $`I=10 \, \mathrm{A}`$, phase
$`\phi=0^\circ`$, and frequency $`f = 5 \, \mathrm{kHz}`$ is imposed.

We compare the Ohmic heating generated inside each conductor with the values provided in [1] (Table I) for
3D with air gap.

Each copper conductor is set up as a solid coil (conductor) - thus eddy currents are resolved and we have
a strong skin effect.

## Setup

We use 2nd order accuracy to ensure smooth curves. Note that we impose the current inside the coil through a
**source** constraint.

## Results

* **Ohmic heating**

  The total Ohmic heating in each conductor is calculated and compared with the reference.

    | Coil | Reference | Obtained | Abs Error | Rel Error (%) |
    | ---- | --------- | -------- | --------- | ------------- |
    | 1    | 0.0618    | 0.06079  | 0.00101   | 1.63          |
    | 2    | 0.0557    | 0.05725  | 0.00155   | 2.78          |
    | 3    | 0.0501    | 0.05494  | 0.00484   | 9.66          |
    | 4    | 0.0481    | 0.05550  | 0.00740   | 15.38         |
    | 5    | 0.0521    | 0.06067  | 0.00857   | 16.45         |
    | 6    | 0.2880    | 0.26373  | 0.02427   | 8.43          |
    | 7    | 0.2331    | 0.21589  | 0.01721   | 7.38          |
    | 8    | 0.1726    | 0.16626  | 0.00634   | 3.67          |
    | 9    | 0.1255    | 0.12789  | 0.00239   | 1.90          |
    | 10   | 0.1021    | 0.10677  | 0.00467   | 4.57          |
    | 11   | 0.9296    | 0.87791  | 0.05169   | 5.56          |
    | 12   | 0.6964    | 0.64639  | 0.05001   | 7.18          |
    | 13   | 0.4556    | 0.42718  | 0.02842   | 6.24          |
    | 14   | 0.2802    | 0.27094  | 0.00926   | 3.30          |
    | 15   | 0.1854    | 0.17937  | 0.00603   | 3.25          |
    | 16   | 2.6304    | 2.79468  | 0.16428   | 6.25          |
    | 17   | 1.6056    | 1.51576  | 0.08984   | 5.60          |
    | 18   | 0.8140    | 0.74613  | 0.06787   | 8.34          |
    | 19   | 0.3918    | 0.36845  | 0.02335   | 5.96          |
    | 20   | 0.2046    | 0.19528  | 0.00932   | 4.56          |
    | 21   | 4.9960    | 7.27032  | 2.27432   | 45.52         |
    | 22   | 1.9424    | 1.83208  | 0.11032   | 5.68          |
    | 23   | 0.7424    | 0.65902  | 0.08338   | 11.23         |
    | 24   | 0.2920    | 0.27364  | 0.01836   | 6.29          |
    | 25   | 0.1166    | 0.12217  | 0.00557   | 4.78          |

    Most conductors deviate by around 10% or less (median 6%); conductor 21, next to the core, deviates by about 45%. However, the size of the gap is an uncertainty that needs to be quantified (does a smaller gap improve the results?).

## Scenes

* **Electric Current Density**


  | Electric Current Density ($`\phi=0`$) | Electric Current Density ($`\phi=90`$) |
  | ---- | ---- |
  | ![Re Electric Current Density](./results/Scene_Electric_Current_Density_Phase_Real.png) | ![Im Electric Current Density](./results/Scene_Electric_Current_Density_Phase_Imag.png) |


  Strong eddy currents are created at the surface of each conductor.

* **Magnetic Flux Density**

  | Magnetic Flux Density ($`\phi=0`$) | Magnetic Flux Density ($`\phi=90`$) |
  | ---- | ---- |
  | ![Re Magnetic Flux Density](./results/Scene_Magnetic_Flux_Density_Phase_Real.png) | ![Im Magnetic Flux Density](./results/Scene_Magnetic_Flux_Density_Phase_Imag.png) |


## Animation

![Animation Electric Current Density](./results/animation.gif)

## References

[1] O. Biro, K. Preis, W. Renhart, G. Vrisk and K.R. Richter, Computation of 3D current driven skin effect problems using a current vector potential, IEEE Transactions on Magnetics, 29, 2, pp. 1325-1328, (1993).
