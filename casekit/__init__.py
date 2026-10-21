"""Shared helpers for the mufem validation cases.

`netgen_geometry`, `netgen_meshing` and `gmsh_meshing` are not re-exported: they need
netgen or gmsh, which only `build_geometry()` and `generate_mesh()` use.

Keep the imports of this module light: casekit.plots imports numpy and matplotlib only inside
its functions (see there), and casekit.pyvista_scene, which needs the optional PyVista, is not
re-exported.
"""

from casekit.plots import PlotStyle, xy_axes, xy_plot
from casekit.validation_case import ValidationCase, expect, run_case

__all__ = ["PlotStyle", "ValidationCase", "expect", "run_case", "xy_axes", "xy_plot"]
