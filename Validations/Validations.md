# Running the validation cases

This page collects the details of running the validation cases; see the
[README](https://github.com/Raiden-Numerics/mufem/blob/main/README.md#validation-cases)
for the installation and a first run.

## run_cases.py

`run_cases.py` runs every `case.py` below a directory (default: the repository root):

```bash
(mufem-venv) python run_cases.py                       # all cases
(mufem-venv) python run_cases.py Validations/Thermal   # all thermal cases
(mufem-venv) python run_cases.py --exclude-tag long --exclude-tag eternal
```

| Option | Effect |
| ------ | ------ |
| `--exclude-tag TAG` | skips the cases with the tag; repeatable |
| `--launcher CMD` | command that runs each case (default `pymufem`; `python` for a serial run) |
| `--rebuild-mesh` | rebuilds the geometry and mesh of each case before running it |
| `--render-geometry` | also creates the geometry image of each case (see [Geometry images](#geometry-images)) |
| `--render-scenes` | also creates the scenes of each case (see [Scenes](#scenes)) |

## Images

### Geometry images

The geometry image of a case, `data/Geometry.png`, is taken from its `geometry.step` with the
[netgen](https://ngsolve.org/) viewer by `create_geometry_image()` (`--render-geometry`), in the
view of the scenes of the case. The viewer needs a display; on a machine without one, run it in a
virtual X server:

```bash
(mufem-venv) xvfb-run -a -s "-screen 0 2400x1600x24" python Validations/Structural/Slaughter_2002_Linear_Cantilever_Beam/case.py --render-geometry
```

`--rebuild-mesh --render-geometry` builds `geometry.step` first. The colors of the bodies come from
the STEP file: the cases built with netgen set them in `build_geometry()`, and those built with
gmsh, which writes no colors, add them with `color_step()` of `casekit/gmsh_meshing.py`.

### Scenes

The scenes and animations of a case, `results/Scene_*.png` and `results/Animation_*.gif`, are
rendered from the fields exported to `VisualizationOutput/` with [PyVista](https://pyvista.org/) by
`create_scenes()`. They need the optional dependencies and are created after the run
(`--render-scenes`), or from the output of a previous one (`--render-scenes-only`):

```bash
(mufem-venv) pip install "./casekit[scenes]"
(mufem-venv) pymufem Validations/Electromagnetics/Compumag-Team24-Locked-Rotor/case.py --render-scenes
(mufem-venv) python Validations/Electromagnetics/Compumag-Team24-Locked-Rotor/case.py --render-scenes-only
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
(mufem-venv) pymufem Validations/Thermal/Cameron_1986_Heat_Transfer_With_Convection/case.py --rebuild-mesh
```

The flag only rebuilds the mesh; run the case afterwards as usual (`run_cases.py --rebuild-mesh`
does both for every case). A mesh that is missing, such as those of
[Ren 2014](https://github.com/Raiden-Numerics/mufem/blob/main/Validations/Electromagnetics/Ren_2014_MEMS_Comb_Drive/README.md)
(`geometry_xshift=<shift>.msh`, one per comb shift, not committed), is built by `run_cases.py`
before it runs the case, and by a serial `python case.py`; an MPI run asks for `--rebuild-mesh`
first. The committed netgen meshes were generated with netgen-mesher 6.2.2608; other versions
produce slightly different meshes, but the results should still pass the case's checks.
