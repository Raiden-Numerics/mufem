# Lubin 2015: Axial-Flux Eddy-Current Brake

A permanent-magnet rotor turning in front of a stationary copper disc. The eddy currents induced in the disc interact with the magnetic field and produce a torque that opposes the relative rotation (the slip). The case follows Lubin and Rezzoug [1] and is the standard validation scenario for axial-flux eddy-current couplers / brakes. Here, we compare against the analytical solution of [1] using a fully transient finite-element simulation performed with **mufem**.

<figure style="text-align: center;">
<img src="./data/Geometry.png" alt="drawing" width="600">
<figcaption style="width: 75%; margin: 0 auto; text-align: left;">
<em>Figure 1</em>: Eddy-current brake consisting of a conductive copper plate and a magnetic plate with permanent magnets.
</figcaption>
</figure>
<br /><br />

## Introduction

The *magnet plate* carries $`p`$ pole pairs (here $`p = 5`$) of axially magnetized permanent magnets (NdFeB, $`B_r = 1.25\,\mathrm{T}`$, pole-arc to pole-pitch ratio 0.9). The opposing *copper plate* ($`\sigma = 57\,\mathrm{MS/m}`$) is the conductor in which eddy currents are induced when relative rotation is imposed. The two plates are separated by an air gap, here $`c = 3\,\mathrm{mm}`$ (other values $`c = 5\,\mathrm{mm}`$ and $`c = 7\,\mathrm{mm}`$ are considered in [1]).

The dimensions are those of Table I of [1]: magnets from $`R_1 = 30`$ to $`R_2 = 60\,\mathrm{mm}`$ and $`10\,\mathrm{mm}`$ thick on a $`10\,\mathrm{mm}`$ back iron (here a disc up to $`R_2`$; the analytical models extend it to $`R_3`$), and the copper plate from $`R_0 = 15`$ to $`R_3 = 75\,\mathrm{mm}`$, $`5\,\mathrm{mm}`$ thick on an $`8\,\mathrm{mm}`$ back iron. The back-iron plates on both sides have $`\mu_r = 1000`$ (a linear approximation justified by the design intent of avoiding saturation) and no conductivity; in [2] a conductivity $`\sigma_b = 7\,\mathrm{MS/m}`$ is assigned to the copper-side back iron.

Reference [1] derives a closed-form 3-D analytical model for the braking torque and axial force as functions of the rotation rate, which is used here as the validation reference. Reference [2] improves the formula with curvature corrections for the eddy currents in the disc; reference [3] compares the eddy-current and synchronous coupler in transient startup.

## Setup

The rotational motion can be applied either to the copper plate or to the magnetic plate using the `RigidBodyMotionModel`. As in the test bench of [1], the copper side is held and the magnet side rotates:

```python
rbm_model = RigidBodyMotionModel(mesh_motion_strategy=MeshMotionPartialRemeshing("Air" @ Vol))

self.motion = RotatingMotion(
    name="Rotation",
    marker=["Back Iron::Magnet Side", *magnets] @ Vol,
    origin=[0.0, 0.0, 0.0],
    axis=[0.0, 0.0, -1.0],
    rotation_rate=0,
)
rbm_model.add_motion(self.motion)
sim.get_model_manager().add_model(rbm_model)
```

The braking torque is evaluated on the copper plate and its back iron with a Magnetic Torque Report.

A naive rigid transformation of the mesh nodes belonging to the magnet side would quickly lead to severe distortion of the surrounding air elements and eventually to invalid mesh cells (e.g. negative volumes). To avoid this, the motion handling must be specified explicitly.

Here, `MeshMotionPartialRemeshing` is used to remesh the surrounding air region at every time step, maintaining mesh quality while allowing large rotational displacements.

### Time-step sizing

Two competing time scales drive the time step.

* **Electrical (pole-passage) time scale**

```math
\frac{1}{T_e} = f_e = p \cdot \frac{n}{60} \quad,
```

where $`n`$ is the mechanical speed in rpm. We use $`N = 40`$–$`80`$ steps per electrical period: $`\Delta t_e = T_e / N`$. **Dominates at high slip speeds.**

* **Magnetic-diffusion time scale**

```math
\tau_d \sim \mu\, \sigma\, L^2 \quad,
```

with $`L`$ the copper plate thickness. The diffusion-resolved step is $`\Delta t_d = \tau_d / M`$ with $`M \approx 20`$. **Dominates at low slip speeds**, where $`T_e \to \infty`$.

For our setup ($`p = 5`$, $`d = 5\,\mathrm{mm}`$ copper), with $`N = 40`$ and $`M = 20`$:

| Slip Speed [rpm] | $`T_e`$ [ms] | $`\Delta t_e`$ [ms] | $`\tau_d`$ [ms] | $`\Delta t_d`$ [ms] |
| ---------------- | ------------ | ------------------- | --------------- | ------------------- |
|                0 |     $`\infty`$ |            $`\infty`$ |            1.79 |              0.0895 |
|              500 |         24.0 |               0.600 |            1.79 |              0.0895 |
|             1000 |         12.0 |               0.300 |            1.79 |              0.0895 |
|             2000 |          6.0 |               0.150 |            1.79 |              0.0895 |
|             3000 |          4.0 |               0.100 |            1.79 |              0.0895 |

We use $`\Delta t = 0.5\,\mathrm{ms}`$ throughout — slightly under-resolved at the highest rpm. The case simulates the slip speeds 500, 1000 and 2000 rpm; after each rotation-rate change, we advance for 20 time steps before evaluating the quasi-steady torque. First-order elements are used.

The geometry is built with netgen in the `build_geometry` method of [case.py](case.py) and meshed in `generate_mesh`; both run only when the mesh is regenerated with `pymufem case.py --rebuild-mesh`. The case itself is run with `pymufem case.py`.

## Results

### Torque vs Time

<figure style="text-align: center;">
<img src="./results/Torque_vs_Time.png" alt="drawing" width="600">
<figcaption style="width: 75%; margin: 0 auto; text-align: left;">
<em>Figure 2</em>: 
    Braking torque as a function of time. After each change in rotation rate, an initial transient occurs; the quasi-steady torque is obtained only after this transient has decayed.
</figcaption>
</figure>
<br /><br />

### Torque vs Slip Speed

Below is the braking torque vs the slip speed. 

<figure style="text-align: center;">
<img src="./results/Torque_vs_RPM.png" alt="drawing" width="600">
<figcaption style="width: 75%; margin: 0 auto; text-align: left;">
    <em>Figure 3.</em> Braking torque as a function of slip speed. The torque rises with increasing slip due to stronger induced eddy currents, reaches a maximum, and then decreases as skin-depth effects and magnetic shielding limit field penetration and reduce electromagnetic coupling.
</figcaption>
</figure>
<br /><br />

The reference is the analytical torque–slip characteristic of [1] for $`c = 3\,\mathrm{mm}`$ (Fig. 11 of [1], [Torque_Vs_Slip_speed.csv](data/Torque_Vs_Slip_speed.csv)), which agrees closely with the 3-D FEM results shown there:

| Slip speed [rpm] | Torque mufem [Nm] | Torque analytical [Nm] |
| ---------------- | ----------------- | ---------------------- |
| 500              | 24.7              | 22.9                   |
| 1000             | 27.4              | 27.8                   |
| 2000             | 21.4              | 22.8                   |

The case checks the torque at the three slip speeds against the reference; the short transients of 20 steps per speed stay within about 8 % of it.

The braking torque initially increases with slip speed because the induced electromotive force and the resulting eddy currents grow, strengthening the Lorentz force opposing the motion. As the slip speed increases further, the torque reaches a maximum and subsequently decreases. This reduction is caused by skin-depth effects and magnetic field shielding, which limit field penetration into the conductor and reduce the effective coupling between current and magnetic flux.

## Animation

An animation is shown below, created with [create_animation.py](create_animation.py) (requires an installation of the *focus-viewer*). To produce its input, set `output_for_animation = True` in [case.py](case.py) and run the case; it then exports the fields and writes a torque plot into `vis/` for every time step (30 steps per slip speed). Afterwards run `python create_animation.py` in the case directory.


<figure style="text-align: center;">
<img src="./results/Result_Animation.gif" alt="drawing">
<figcaption style="width: 75%; margin: 0 auto; text-align: left;">
    <em>Figure 4.</em> Time evolution of the axial-flux eddy current brake simulation. The rotating conductive plate induces eddy currents that interact with the magnetic field of the permanent magnets, producing a braking torque and axial force while transient electromagnetic diffusion and skin effects develop over time.
</figcaption>
</figure>

## Notes

- Second-order discretization (the case uses first order) gives a notably better match to [1, 2] at the cost of runtime.
- Dynamic time-stepping does not appear to help here.

## References

[1] Lubin, T. and Rezzoug, A., 2015. *3-D analytical model for axial-flux eddy-current couplings and brakes under steady-state conditions*. IEEE Transactions on Magnetics, 51(10), pp. 1–12.

[2] Lubin, T. and Rezzoug, A., 2017. *Improved 3-D analytical model for axial-flux eddy-current couplings with curvature effects*. IEEE Transactions on Magnetics, 53(9), pp. 1–9.

[3] Lubin, T., Fontchastagner, J., Mezani, S. and Rezzoug, A., 2016. *Comparison of transient performances for synchronous and eddy-current torque couplers*. In 2016 XXII International Conference on Electrical Machines (ICEM), pp. 695–701. IEEE.
