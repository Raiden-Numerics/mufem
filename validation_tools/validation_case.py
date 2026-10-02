"""Base class for mufem validation / example cases.

A case subclasses `ValidationCase`, sets its metadata attributes, and implements
`build()` (and optionally `validate()` / `visualize()`). Because the metadata
lives as class attributes, a runner can import a case and read its tags without
executing the solve — the solve only happens inside `run()`. That is what lets
CI select a subset (e.g. skip `long` cases, or `mumps` cases on a build without a
direct solver) before spending runner minutes: workflows pass `--exclude-tag`.

Typical case file:

    from validation_tools import ValidationCase

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
            self.expect(T, 291.45, rel_tol=1e-3, label="probe temperature")

            # regression check against baselines/Temperature.csv
            self.expect_baseline(sim, "Temperature", self.temperature_profile(sim))

    if __name__ == "__main__":
        Cameron1986().run()
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Sequence, Set

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
        self.results_path.mkdir(exist_ok=True)

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

    def expect_baseline(
        self,
        sim: "mufem.Simulation",
        name: str,
        rows: Iterable[Sequence[float]],
        *,
        rel_tol: float = 1e-3,
        abs_tol: float = 0.0,
        header: str = "",
    ) -> None:
        """Assert `rows` match the stored `baselines/<name>.csv` within tolerance.

        A baseline is a regression reference: a previously computed result of this
        case, not an analytical or published value. Run with UPDATE_BASELINES=1 to
        (re)write the file from `rows` instead of comparing; `header` is written as
        its comment line, e.g. "Position [m], Temperature [K]".
        """
        path = self.dir_path / "baselines" / f"{name}.csv"
        rows = [[float(v) for v in row] for row in rows]

        if os.environ.get("UPDATE_BASELINES") == "1":
            if self.is_main(sim):
                path.parent.mkdir(exist_ok=True)
                with open(path, "w") as file:
                    if header:
                        file.write(f"# {header}\n")
                    file.writelines(",".join(f"{v:.15e}" for v in row) + "\n" for row in rows)
                print(f"[baseline updated] {name}: {path}")
            return

        with open(path) as file:
            baseline = [
                [float(v) for v in line.split(",")]
                for line in file
                if line.strip() and not line.startswith("#")
            ]

        if [len(row) for row in rows] != [len(row) for row in baseline]:
            raise AssertionError(
                f"baseline {name}: shape mismatch, got {len(rows)} rows, "
                f"expected {len(baseline)} rows in {path}"
            )

        failures = []
        max_deviation = 0.0
        for i, (row, expected_row) in enumerate(zip(rows, baseline)):
            for j, (actual, expected) in enumerate(zip(row, expected_row)):
                tol = max(abs_tol, rel_tol * abs(expected))
                max_deviation = max(max_deviation, abs(actual - expected) / max(tol, 1e-300))
                if abs(actual - expected) > tol:
                    failures.append(f"  [{i}, {j}]: got {actual}, expected {expected} (tol {tol})")

        status = "FAIL" if failures else "OK"
        print(
            f"[check {status}] baseline {name}: {len(rows)} rows, "
            f"max deviation {max_deviation:.3g} x tol"
        )
        if failures:
            raise AssertionError(f"baseline {name} mismatch:\n" + "\n".join(failures))
