# Running the validation cases

This page collects the details of running the validation cases; see the
[README](https://github.com/Raiden-Numerics/mufem/blob/main/README.md#validation-cases)
for the installation and a first run.

## run_cases.py

`run_cases.py` runs every `case.py` below a directory (default: the repository root):

```bash
(mufem-venv) python run_cases.py                       # all cases
(mufem-venv) python run_cases.py Thermal               # all thermal cases
(mufem-venv) python run_cases.py --exclude-tag long --exclude-tag eternal
```

| Option | Effect |
| ------ | ------ |
| `--exclude-tag TAG` | skips the cases with the tag; repeatable |
| `--launcher CMD` | command that runs each case (default `pymufem`; `python` for a serial run) |
| `--rebuild-mesh` | rebuilds the geometry and mesh of each case before running it |
| `--render-geometry` | also creates the geometry image of each case (`data/Geometry.png`, netgen viewer; needs a display, e.g. `xvfb-run`) |
| `--render-scenes` | also creates the scenes of each case (see [Scenes](#scenes)) |

## Scenes

Some cases render images and animations of their fields (the scenes) with
[PyVista](https://pyvista.org/) in `create_scenes()`. They need the optional dependencies and are
created only on request, after the run or from the output of a previous one:

```bash
(mufem-venv) pip install "./casekit[scenes]"
(mufem-venv) pymufem Electromagnetics/Compumag-Team24-Locked-Rotor/case.py --render-scenes
(mufem-venv) python Electromagnetics/Compumag-Team24-Locked-Rotor/case.py --render-scenes-only
```

The scenes render off screen and need no display; in a bare Linux container install the EGL
library first (`apt-get install libegl1` on Ubuntu).

## Tags

| Tag | Meaning |
| --- | ------- |
| `moderate`, `long`, `eternal` | run time of the case |
| `mumps` | needs the MUMPS direct solver |

## Meshes

Each case loads its committed mesh (`geometry.mesh`, or `geometry.msh` for the cases meshed with
gmsh). The geometry and mesh are built in the case itself, together with `geometry.step`, using
[netgen](https://ngsolve.org/) or [gmsh](https://gmsh.info/) (both installed with the shared
helpers), and can be regenerated with:

```bash
(mufem-venv) pymufem Thermal/Cameron_1986_Heat_Transfer_With_Convection/case.py --rebuild-mesh
```

The flag only rebuilds the mesh; run the case afterwards as usual (`run_cases.py --rebuild-mesh`
does both for every case). A mesh that is missing, such as those of
[Ren 2014](https://github.com/Raiden-Numerics/mufem/blob/main/Electromagnetics/Ren_2014_MEMS_Comb_Drive/README.md)
(`geometry_xshift=<shift>.msh`, one per comb shift, not committed), is built by `run_cases.py`
before it runs the case, and by a serial `python case.py`; an MPI run asks for `--rebuild-mesh`
first. The committed netgen meshes were generated with netgen-mesher 6.2.2608; other versions
produce slightly different meshes, but the results should still pass the case's checks.
