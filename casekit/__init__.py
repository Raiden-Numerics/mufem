"""Shared helpers for the mufem validation cases.

`netgen_geometry`, `netgen_meshing` and `gmsh_meshing` are not re-exported: they need
netgen or gmsh, which only `build_geometry()` and `generate_mesh()` use.

Keep the imports of this module light: the scene scripts run under ParaView's pvpython, which
imports this package on the way to casekit.paraview_scene and casekit.images, but has neither
mufem nor the other packages of the cases (casekit.plots imports numpy and matplotlib only
inside its functions).
"""

from casekit.plots import PlotStyle, xy_plot
from casekit.validation_case import ValidationCase, expect, run_case

__all__ = ["PlotStyle", "ValidationCase", "expect", "run_case", "xy_plot"]
