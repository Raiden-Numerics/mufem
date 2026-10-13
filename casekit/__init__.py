"""Shared helpers for the mufem validation cases.

`netgen_geometry`, `netgen_meshing` and `gmsh_meshing` are not re-exported: they need
netgen or gmsh, which only `build_geometry()` and `generate_mesh()` use.
"""

from casekit.plots import PlotStyle, xy_plot
from casekit.validation_case import ValidationCase, expect, run_case

__all__ = ["PlotStyle", "ValidationCase", "expect", "run_case", "xy_plot"]
