# Case Studies

This page lists the case studies of mufem. Each case study applies mufem to a complete engineering
problem, from the geometry to the design decision. Where possible, a case study first checks its
method against a reference, then uses it to answer the engineering question.

The [validation cases](../Validations/README.md) check single models against published, measured, or
analytical reference values. The case studies show how these models work together on an industrial
design task.

See [Running the case studies](#running-the-case-studies) for how to run them.

## Cases

<table>
<tr>
<td width="25%" height="130" align="center"><a href="PMSM-Motor/README.md"><img src="PMSM-Motor/results/Case_Study_Thumbnail.png" width="100%"></a></td>
<td width="75%" valign="top">
<strong><a href="PMSM-Motor/README.md">Step Skew in a Hairpin IPM Traction Motor</a></strong><br>
A 48-slot, 8-pole interior permanent-magnet traction motor with a hairpin winding and a 7-step V
skew of the rotor. The study finds how much the skew reduces the cogging torque and the load
ripple, and what it costs in mean torque. It compares the fast 2D multi-slice method with a full 3D
model of the machine: turning rotor, saturating iron, the connected hairpin winding with its end
turns, and eddy currents in all copper. The 3D model gives the AC copper loss of the whole winding,
end turns included.
</td>
</tr>
</table>

## Running the Case Studies

Each case study has its own script and its own run instructions in its README. Some case studies
need large meshes that are not part of the repository; the README of each case study lists them.

Install mufem as described in the [README](../README.md#getting-started), then run the script of the
case study from its folder. For example:

```bash
(mufem-venv) cd CaseStudies/PMSM-Motor
(mufem-venv) mpirun -np 8 python pmsm_motor.py --machine skewed --steps 30 --out results_skewed
```

Full 3D case studies need a parallel run. Refer to the README of each case study for the
recommended number of processes and the run time.

## Get in Touch

Would you like a case study on your own design? Contact us at
[info@raiden-numerics.com](mailto:info@raiden-numerics.com) or visit
[mufem.raiden-numerics.com](https://mufem.raiden-numerics.com).
