"""Base class for mufem validation / example cases.

`ValidationCase.run()` fixes the workflow; a case implements the steps:

    [build_geometry -> generate_mesh]  only when the mesh is rebuilt
    set_up -> solve -> validate -> visualize

A case must implement `set_up()` and `validate()`. `solve()` defaults to running
the simulation, `visualize()` to doing nothing. `build_geometry()` and
`generate_mesh()` are only needed to regenerate the committed mesh, which is done
with `REBUILD_MESH=1 python case.py`. netgen must then be imported before mufem
(libmufem bundles its own netgen core libraries), so a case that meshes with netgen
starts with

    import os

    if os.environ.get("REBUILD_MESH") == "1":
        import netgen.occ  # noqa: F401  must precede mufem

Normal runs never load netgen: CI does not install it, and an MPI-enabled netgen
would clash with mufem's MPI. Rebuilding does not work under pymufem, which puts
libmufem's libraries first on LD_LIBRARY_PATH.

Because the metadata lives as class attributes, a runner can read the tags without
running the case. That is what lets CI select a subset (e.g. skip `long` cases, or
`mumps` cases on a build without a direct solver): workflows pass `--exclude-tag`.

Typical case file:

    from validation_tools import ValidationCase

    class Cameron1986(ValidationCase):
        name = "Cameron 1986: Heat Transfer With Convection"
        # one runtime tier (moderate/long/eternal) plus any capability the case
        # needs, e.g. {"long", "mumps"}. CI excludes tags it can't run.
        tags = {"moderate"}

        def build_geometry(self):
            from netgen.occ import Box
            ...

        def generate_mesh(self, geometry):
            from validation_tools.meshing import mesh_and_save
            mesh_and_save(geometry, basesize=0.02, path=self.mesh_path)

        def set_up(self):
            sim = mufem.Simulation.New(name=self.name, mesh_path=f"{self.mesh_path}")
            ...
            return sim

        def validate(self):
            T = self.probe_temperature()
            self.expect(T, 291.45, rel_tol=1e-3, label="probe temperature")

    if __name__ == "__main__":
        Cameron1986().run()
"""

from __future__ import annotations

import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Set

if TYPE_CHECKING:
    import mufem


class ValidationCase(ABC):
    # --- metadata (override per case; read by the runner without running) ----
    name: str = ""
    #: labels, e.g. {"long"} for a slow case or {"mumps"} for a direct-solver
    #: case. CI excludes tags it can't run via --exclude-tag.
    tags: Set[str] = set()

    #: the Simulation returned by `set_up()`; available to all later steps
    sim: "mufem.Simulation"

    # --- workflow -------------------------------------------------------------
    def run(self, rebuild_mesh: Optional[bool] = None) -> None:
        """Run the case; raises on a failed check, so the process exits non-zero.

        `rebuild_mesh` defaults to the REBUILD_MESH=1 environment variable.
        """
        if rebuild_mesh is None:
            rebuild_mesh = os.environ.get("REBUILD_MESH") == "1"

        self.results_path.mkdir(exist_ok=True)

        if rebuild_mesh:
            self.generate_mesh(self.build_geometry())

        self.sim = self.set_up()
        self.solve()
        self.validate()
        self.visualize()

    # --- steps ----------------------------------------------------------------
    def build_geometry(self) -> Any:
        """Create and return the geometry; also export geometry.step if useful."""
        raise NotImplementedError(f"{type(self).__name__} cannot rebuild its geometry")

    def generate_mesh(self, geometry: Any) -> None:
        """Mesh `geometry` and write it to `self.mesh_path`."""
        raise NotImplementedError(f"{type(self).__name__} cannot rebuild its mesh")

    @abstractmethod
    def set_up(self) -> "mufem.Simulation":
        """Construct and return the fully configured Simulation."""

    def solve(self) -> None:
        self.sim.run()

    @abstractmethod
    def validate(self) -> None:
        """Post-run correctness checks. Raise on failure. Runs on all ranks."""

    def visualize(self) -> None:
        """Plots / field exports. Optional.

        Runs on ALL ranks: probe/report evaluation and field export are
        collective MPI operations, so every rank must reach them together.
        Guard purely rank-local output (matplotlib file writes, prints) with
        `self.is_main()`.
        """

    # --- helpers --------------------------------------------------------------
    def is_main(self) -> bool:
        """True on the main MPI rank; use to guard non-collective output."""
        return self.sim.get_machine().is_main_process()

    @property
    def dir_path(self) -> Path:
        """Directory of the concrete case file (for meshes / reference data)."""
        module_file = sys.modules[type(self).__module__].__file__
        return Path(module_file).resolve().parent

    @property
    def mesh_path(self) -> Path:
        return self.dir_path / "geometry.mesh"

    @property
    def results_path(self) -> Path:
        """Output directory for plots / tables; created by `run()`."""
        return self.dir_path / "results"

    def expect(
        self,
        actual: float,
        expected: float,
        *,
        rel_tol: float = 1e-2,
        abs_tol: float = 0.0,
        label: str = "value",
    ) -> None:
        """Assert `actual` matches `expected` within tolerance."""
        tol = max(abs_tol, rel_tol * abs(expected))
        ok = abs(actual - expected) <= tol
        status = "OK" if ok else "FAIL"
        print(f"[check {status}] {label}: got {actual}, expected {expected} (tol {tol})")
        if not ok:
            raise AssertionError(f"{label}: {actual} != {expected} within tol {tol}")
