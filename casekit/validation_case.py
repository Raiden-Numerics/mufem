"""Base class for mufem validation / example cases.

A case implements the steps of two separate workflows:

    build_geometry_and_mesh():  build_geometry -> generate_mesh    (--rebuild-mesh)
    run():                      setup_case -> solve -> validate -> postprocess

A case must implement `setup_case()` and `validate()`. `solve()` defaults to running
the simulation, `postprocess()` to doing nothing. `build_geometry()` and
`generate_mesh()` are only needed to regenerate the committed mesh, which is done
on a single process with `pymufem 1 case.py --rebuild-mesh` (or
`python case.py --rebuild-mesh`) before the case is run with `pymufem case.py`;
netgen is imported inside those methods, so normal runs do not load it.

Because the metadata lives as class attributes, a runner can read the tags without
running the case. That is what lets CI select a subset (e.g. skip `long` cases, or
`mumps` cases on a build without a direct solver): workflows pass `--exclude-tag`.

Typical case file:

    from casekit import ValidationCase, expect, run_case

    import mufem

    class Cameron1986(ValidationCase):
        name = "Cameron 1986: Heat Transfer With Convection"
        # one runtime tier (moderate/long/eternal) plus any capability the case
        # needs, e.g. {"long", "mumps"}. CI excludes tags it can't run.
        tags = {"moderate"}

        def build_geometry(self):
            from netgen.occ import Box
            ...
            geometry.WriteStep(f"{self.step_path}")

        def generate_mesh(self):
            from casekit.netgen_meshing import mesh_and_save
            mesh_and_save(self.step_path, basesize=0.02, path=self.mesh_path)

        def setup_case(self):
            sim = mufem.Simulation.New(name=self.name, mesh_path=f"{self.mesh_path}")
            ...
            return sim

        def validate(self):
            T = self.probe_temperature()
            expect(T, 291.45, rel_tol=1e-3, label="probe temperature")

    if __name__ == "__main__":
        run_case(Cameron1986)
"""

from __future__ import annotations

import argparse
import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Set

if TYPE_CHECKING:
    import mufem


def expect(
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


class ValidationCase(ABC):
    # --- metadata (override per case; read by the runner without running) ----
    name: str = ""
    # labels, e.g. {"long"} for a slow case or {"mumps"} for a direct-solver
    # case. CI excludes tags it can't run via --exclude-tag.
    tags: Set[str] = set()

    # the Simulation returned by `setup_case()`; available to all later steps
    sim: Optional["mufem.Simulation"] = None

    # --- workflow -------------------------------------------------------------
    def run(self) -> None:
        """Run the case; raises on a failed check, so the process exits non-zero."""
        self.results_path.mkdir(exist_ok=True)

        self.sim = self.setup_case()
        self.solve()
        self.validate()
        self.postprocess()

    def build_geometry_and_mesh(self) -> None:
        """Rebuild the geometry and the mesh, on a single process."""
        # Meshing does not use MPI: under mpirun every process would build the same
        # geometry and mesh and write the same files at once (no is_main() before
        # setup_case()), which is slower and can corrupt them.
        if not self._is_single_process():
            raise RuntimeError(
                "Rebuild the mesh on a single process: pymufem 1 case.py --rebuild-mesh "
                "or python case.py --rebuild-mesh"
            )
        self.build_geometry()
        self.generate_mesh()

    # --- steps ----------------------------------------------------------------
    def build_geometry(self) -> None:
        """Create the geometry and write it to `self.step_path`.

        Optional: by default the committed geometry.step is meshed as is.
        """

    def generate_mesh(self) -> None:
        """Mesh `self.step_path` and write it to `self.mesh_path`."""
        raise NotImplementedError(f"{type(self).__name__} cannot rebuild its mesh")

    @abstractmethod
    def setup_case(self) -> "mufem.Simulation":
        """Construct and return the fully configured Simulation."""

    def solve(self) -> None:
        self.sim.run()

    @abstractmethod
    def validate(self) -> None:
        """Post-run correctness checks. Raise on failure. Runs on all ranks."""

    def postprocess(self) -> None:
        """Plots / field exports. Optional.

        Runs on ALL ranks: probe/report evaluation and field export are
        collective MPI operations, so every rank must reach them together.
        Guard purely rank-local output (matplotlib file writes, prints) with
        `self.is_main()`.
        """

    # --- helpers --------------------------------------------------------------
    @staticmethod
    def _is_single_process() -> bool:
        """True unless an MPI launcher started more than one process."""
        return all(
            int(os.environ.get(size_variable, "1")) <= 1
            for size_variable in ("OMPI_COMM_WORLD_SIZE", "PMI_SIZE")
        )

    def is_main(self) -> bool:
        """True on the main MPI rank; use to guard non-collective output."""
        if self.sim is None:
            raise RuntimeError(
                "is_main() needs the Simulation, which exists only after setup_case() "
                "has returned it; do not call is_main() before or inside setup_case()"
            )
        return self.sim.get_machine().is_main_process()

    @property
    def dir_path(self) -> Path:
        """Directory of the concrete case file (for meshes / reference data)."""
        module_file = sys.modules[type(self).__module__].__file__
        return Path(module_file).resolve().parent

    @property
    def step_path(self) -> Path:
        return self.dir_path / "geometry.step"

    @property
    def mesh_path(self) -> Path:
        return self.dir_path / "geometry.mesh"

    @property
    def results_path(self) -> Path:
        """Output directory for plots / tables; created by `run()`."""
        return self.dir_path / "results"


def run_case(case_class: type[ValidationCase]) -> None:
    """Command line entry point of a case: `pymufem case.py [--rebuild-mesh]`."""
    parser = argparse.ArgumentParser(
        description=case_class.name,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--rebuild-mesh",
        action="store_true",
        help="rebuild geometry and mesh instead of running the case (on a single process)",
    )
    args = parser.parse_args()

    case = case_class()
    if args.rebuild_mesh:
        case.build_geometry_and_mesh()
    else:
        case.run()
