# Benchmarks

Solver time of mufem on reproducible cases on consumer hardware: one desktop computer, as used for
everyday engineering work. Each case compares the Community edition (OpenMP threads in one process)
with the Professional edition (MPI processes).

**Contents:** [Machine and Software](#machine-and-software) · [Strong Scaling](#strong-scaling)
([TEAM 1b](#team-1b) · [IEEJ Model D](#ieej-model-d)) · [Reproduce](#reproduce)

## Machine and Software

| | |
|---|---|
| CPU | AMD Ryzen 9 7950X3D (16 cores); the runs use up to 8 cores, no SMT |
| Memory | 64 GB |
| OS | Ubuntu 24.04, Python 3.12 |
| mufem | v0.8.37: `mufem` (Community, OpenMP) and `mufem-mpi` (Professional, MPI) |
| Measured | Solver time (time stepping). Start-up, mesh loading and field export are not included. |

Each run is a separate process on an idle machine.

## Strong Scaling

How the solver time of a fixed problem drops with the number of cores.

### TEAM 1b

[Compumag TEAM 1b](../Validations/Electromagnetics/Compumag-Team1b-Felix-Cylinder/README.md):
eddy currents in an aluminum cylinder. Time-domain magnetic model, order 1, 20 time steps,
44,498 tetrahedra (about 53,000 unknowns).

<div align="center">
<img src="./results/Team1b_Scaling.png" alt="TEAM 1b strong scaling: Community vs Professional" width="100%">
<br/>
<em>Figure 1: Solver time (left) and speedup over one core (right) of TEAM 1b.</em>
</div>
<br/>

Median solver time of three runs, in seconds (speedup over one core):

| Cores | Professional (MPI) | Community (OpenMP) |
|---|---|---|
| 1 | 16.12 | 16.61 |
| 2 | 10.06 (1.60x) | 10.11 (1.64x) |
| 4 | 5.65 (2.85x) | 6.65 (2.50x) |
| 8 | 3.30 (4.88x) | 4.47 (3.72x) |

- On one core, the editions are within 3%. With more cores, Professional scales further.
- The case is small, which limits the scaling of both editions. Larger problems scale further.
- The three runs of each point differ by less than 3%. Raw times:
  [results/Team1b_Scaling.csv](./results/Team1b_Scaling.csv).

### IEEJ Model D

[IEEJ Model D](../Validations/Electromagnetics/IEEJ_2012_IPM_Motor_Model_D/README.md): an interior
permanent magnet motor with saturating iron and a turning rotor. One electrical period at
1500 rpm in 120 time steps.

<div align="center">
<img src="./results/ModelD_Scaling.png" alt="IEEJ Model D solver time and speedup: Community vs Professional" width="100%">
<br/>
<em>Figure 2: Solver time (left) and speedup over one core (right) of IEEJ Model D.</em>
</div>
<br/>

Solver time of one run (speedup over one core):

| Cores | Professional (MPI) | Community (OpenMP) |
|---|---|---|
| 1 | 566.3 s | 565.4 s |
| 2 | 312.8 s (1.81x) | 334.5 s (1.69x) |
| 4 | 179.5 s (3.15x) | 211.0 s (2.68x) |
| 8 | 111.7 s (5.07x) | 147.4 s (3.84x) |

- On 8 cores, Professional needs 24% less solver time than Community. The parallel efficiency is
  63% (Professional) and 48% (Community), close to TEAM 1b.
- The rotor motion adds work to each time step that scales less well with the number of cores.
  Raw times: [results/ModelD_Scaling.csv](./results/ModelD_Scaling.csv).

## Reproduce

Install each edition in its own environment with casekit, then run the benchmarks and plot the
results. [scaling.py](./scaling.py) pins each run to the cores 0 to n-1 with `taskset` and starts it
as follows:

| Edition | Started as |
|---|---|
| Professional | `pymufem <n> driver.py --no-field-export` with `OMP_NUM_THREADS=1` |
| Community | `python driver.py --no-field-export` with `OMP_NUM_THREADS=<n> OMP_PROC_BIND=close OMP_PLACES=cores` |

```bash
python -m venv community && community/bin/pip install mufem && community/bin/pip install -e ./casekit
python -m venv professional && professional/bin/pip install mufem-mpi \
    --extra-index-url https://mufem.raiden-numerics.com/packages/ && professional/bin/pip install -e ./casekit

cd Benchmarks
export MUFEM_LICENSE_KEY=...    # for the Professional edition
python scaling.py --community ../community --professional ../professional
python scaling.py --case modeld --repeats 1 --community ../community --professional ../professional
python plot_scaling.py           # needs matplotlib
```
