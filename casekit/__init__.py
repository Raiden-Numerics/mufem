"""Shared helpers for the mufem validation cases.

`meshing` is not re-exported: it needs netgen, which only `generate_mesh()` uses.
"""

from casekit.plots import PlotStyle, xy_plot
from casekit.validation_case import ValidationCase, expect

__all__ = ["PlotStyle", "ValidationCase", "expect", "xy_plot"]
