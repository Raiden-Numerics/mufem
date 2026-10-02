"""Shared helpers for the mufem validation cases.

Import this package before mufem. With REBUILD_MESH=1 it loads netgen, which must
come first. Rebuilding a mesh needs a separately installed netgen
(`pip install netgen-mesher`): libmufem bundles a netgen of its own, but without the
Python bindings and OpenCascade support that `netgen.occ` provides. Both ship their
core library under the same name (libngcore.so), and whichever is loaded first is
used by both; netgen's Python modules fail with libmufem's copy.

Normal runs never load netgen, because
- CI does not install it;
- under pymufem it cannot load at all (LD_LIBRARY_PATH points to libmufem's copy);
- loaded first, it makes mufem run on netgen's core library instead of its own;
- an MPI-enabled netgen also clashes with mufem's MPI.

`meshing` is not re-exported: it needs netgen, which only `generate_mesh()` uses.
"""

import os
import sys

if os.environ.get("REBUILD_MESH") == "1":
    if "mufem" in sys.modules:
        raise ImportError("Import validation_tools before mufem to rebuild the mesh.")
    import netgen.occ  # noqa: F401

from validation_tools.plots import PlotStyle, xy_plot  # noqa: E402
from validation_tools.validation_case import ValidationCase, expect  # noqa: E402

__all__ = ["PlotStyle", "ValidationCase", "expect", "xy_plot"]
