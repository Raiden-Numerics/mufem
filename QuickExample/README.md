# Quick Example: Charged Cube

The electrostatic field in a 10 cm cube of air with 1 V across it: the top face (anode) at 1 V, the bottom face
(cathode) grounded. The introduction video in the [main README](../README.md#getting-started) walks through it.

* `setup.py` builds the cube with gmsh, tags its volume and the two faces (`Cube`, `Anode`, `Cathode`), meshes it
  with six tetrahedra along each edge, and writes `cube.msh` (and `cube.step` for CAD tools).
* `case.py` solves the electrostatics model (order 2) on that mesh, prints the stored electric energy and exports the
  electric potential and field to `ChargedCubeOutput/`.

## Run it

```bash
python -m venv mufem-venv
source mufem-venv/bin/activate
pip install mufem gmsh pyvista
cd QuickExample
python setup.py   # geometry and mesh; add -nopopup to skip the gmsh GUI
python case.py    # prints the stored electric energy
```

`case.py` prints about 4.43e-13 J, the energy of the uniform field $`E = 10`$ V/m in the cube,
$`W = \tfrac12 \varepsilon_0 E^2 L^3 = 4.427 \times 10^{-13}`$ J.

Open the fields in `ChargedCubeOutput/` with ParaView or PyVista to view them. For the platform-specific
installation see the [Installation guide](https://raiden-numerics.github.io/mufem-doc/getting_started/installation.html).
