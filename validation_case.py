"""Base class for mufem validation / example cases.

A case subclasses `ValidationCase`, sets its metadata attributes, and implements
`build()` (and optionally `validate()` / `visualize()`). Because the metadata
lives as class attributes, a runner can import a case and read its tags without
executing the solve — the solve only happens inside `run()`. That is what lets
CI select a subset (e.g. skip `long` cases, or `mumps` cases on a build without a
direct solver) before spending runner minutes: workflows pass `--exclude-tag`.

Typical case file:

    from validation_case import ValidationCase

    class Cameron1986(ValidationCase):
        name = "Cameron 1986: Heat Transfer With Convection"
        # one runtime tier (moderate/long/eternal) plus any capability the case
        # needs, e.g. {"long", "mumps"}. CI excludes tags it can't run.
        tags = {"moderate"}

        def build(self):
            sim = mufem.Simulation.New(...)
            ...
            return sim

        def validate(self, sim):
            T = self.probe_temperature(sim)
            self.expect(T, 291.45, rel_tol=1e-2, label="probe temperature")

    if __name__ == "__main__":
        Cameron1986().run()
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Set

if TYPE_CHECKING:
    import mufem


class ValidationCase:
    # --- metadata (override per case; read by the runner without solving) ---
    name: str = ""
    #: labels, e.g. {"long"} for a slow case or {"mumps"} for a direct-solver
    #: case. CI excludes tags it can't run via --exclude-tag.
    tags: Set[str] = set()

    # --- lifecycle (override build; validate/visualize are optional) --------
    def build(self) -> "mufem.Simulation":
        """Construct and return the fully configured Simulation."""
        raise NotImplementedError

    def validate(self, sim: "mufem.Simulation") -> None:
        """Post-run correctness checks. Raise on failure. Runs on all ranks."""

    def visualize(self, sim: "mufem.Simulation") -> None:
        """Plots / field exports. Optional.

        Runs on ALL ranks: probe/report evaluation and field export are
        collective MPI operations, so every rank must reach them together.
        Guard purely rank-local output (matplotlib file writes, prints) with
        `self.is_main(sim)`.
        """

    def run(self) -> None:
        sim = self.build()
        sim.run()
        self.validate(sim)
        self.visualize(sim)

    # --- helpers ------------------------------------------------------------
    @staticmethod
    def is_main(sim: "mufem.Simulation") -> bool:
        """True on the main MPI rank; use to guard non-collective output."""
        return sim.get_machine().is_main_process()

    @property
    def dir_path(self) -> Path:
        """Directory of the concrete case file (for meshes / reference data)."""
        module_file = sys.modules[type(self).__module__].__file__
        return Path(module_file).resolve().parent

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
            raise AssertionError(
                f"{label}: {actual} != {expected} within tol {tol}"
            )
