"""Base class for mufem validation / example cases.

A case implements the steps of two separate workflows:

    build_geometry_and_mesh():  build_geometry -> generate_mesh    (--rebuild-mesh)
                                [-> create_geometry_image, warns without a display]
    create_geometry_image():    from the committed geometry.step   (--render-geometry)
    run():                      setup_case -> solve -> validate -> postprocess
                                [-> create_scenes                  (--render-scenes)]
    create_scenes():            from the output of a run           (--render-scenes-only)

A case must implement `setup_case()` and `validate()`. `solve()` defaults to running
the simulation, `postprocess()`, `create_scenes()` and `create_geometry_image()` to doing
nothing. `build_geometry()` and `generate_mesh()` default to doing nothing; they regenerate
the mesh with `pymufem case.py --rebuild-mesh`, and a mesh that is not committed is built with
them before the first run (by run_cases.py, or by a serial `python case.py`). netgen is
imported inside those methods, so normal runs do not load it.

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
import warnings
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Set

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
    def run(self, render_scenes: bool = False) -> None:
        """Run the case, with `render_scenes` also its scenes; raises on a failed check, so the
        process exits non-zero."""
        self.results_path.mkdir(exist_ok=True)

        self.sim = self.setup_case()
        self.solve()
        self.validate()
        self.postprocess()
        if render_scenes and self.is_main():
            self.create_scenes()

    def build_geometry_and_mesh(self) -> None:
        """Rebuild the geometry and the mesh."""
        # Meshing does not use MPI: every process would build the same geometry and mesh
        # and write the same files at once, so the other processes just return.
        if not self._is_launcher_main_process():
            return
        self.build_geometry()
        self.generate_mesh()

    def try_create_geometry_image(self) -> None:
        """Create the geometry image after a rebuild of the mesh; without a display only warn,
        the mesh is usable without it."""
        import tkinter

        try:
            self.create_geometry_image()
        except tkinter.TclError as error:
            warnings.warn(f"{self.name}: geometry image not rendered ({error}); use xvfb-run")

    # --- steps ----------------------------------------------------------------
    def build_geometry(self) -> None:
        """Create the geometry and write it to `self.step_path`.

        Optional: by default the committed geometry.step is meshed as is.
        """

    def generate_mesh(self) -> None:
        """Mesh `self.step_path` and write it to `self.mesh_path`.

        Optional: by default the committed mesh is used as is.
        """

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

    def create_scenes(self) -> None:
        """Images and animations of the fields (casekit.pyvista_scene). Optional.

        Runs on the main process only and reads nothing but what a run left on disk (the fields
        exported to VisualizationOutput/ and `self.scene_data_path`), so that the scenes can be
        redrawn without solving again (`--render-scenes-only`); there is no Simulation then. Import
        PyVista inside: it is an optional dependency (`pip install ./casekit[scenes]`).
        """

    def create_geometry_image(self) -> None:
        """The image of `self.step_path` in data/, taken with the netgen viewer
        (casekit.netgen_image). Optional.

        Runs after `--rebuild-mesh` (only warning without a display) and alone with
        `--render-geometry`, not when a missing mesh is built before a run. It needs a display;
        headless: `xvfb-run -a -s "-screen 0 2400x1600x24" python case.py --render-geometry`.
        Import netgen inside, as in `build_geometry()`.
        """

    # --- helpers --------------------------------------------------------------
    def mesh_missing(self) -> bool:
        """True if a mesh of `self.mesh_paths` has not been built yet."""
        return any(not path.exists() for path in self.mesh_paths)

    @staticmethod
    def _launcher_size() -> int:
        """Number of processes started by the MPI launcher (1 without one)."""
        for key in ("OMPI_COMM_WORLD_SIZE", "PMIX_SIZE", "PMI_SIZE"):
            if (value := os.environ.get(key)) is not None:
                return int(value)
        return 1

    @staticmethod
    def _is_launcher_main_process() -> bool:
        """True on rank 0 or without an MPI launcher; read from the launcher's environment
        because no Simulation exists yet."""
        for key in ("OMPI_COMM_WORLD_RANK", "PMIX_RANK", "PMI_RANK"):
            if (value := os.environ.get(key)) is not None:
                return int(value) == 0
        return True

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
    def mesh_paths(self) -> List[Path]:
        """All meshes the case loads; override for a case with several."""
        return [self.mesh_path]

    @property
    def scene_data_path(self) -> Path:
        """Extra input of `create_scenes()` that the field export does not hold (e.g. monitor
        values), written with numpy.savez next to the exported fields by `postprocess()`; not
        shipped, so that the scenes can be redrawn after one run of the case."""
        path = self.dir_path / "VisualizationOutput" / "Scene_Data.npz"
        path.parent.mkdir(exist_ok=True)
        return path

    @property
    def results_path(self) -> Path:
        """Output directory for plots / tables; created by `run()`."""
        return self.dir_path / "results"


def run_case(case_class: type[ValidationCase]) -> None:
    """Command line entry point of a case: `pymufem case.py [--rebuild-mesh | --render-geometry |
    --render-scenes | --render-scenes-only]`."""
    parser = argparse.ArgumentParser(
        description=case_class.name,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--rebuild-mesh",
        action="store_true",
        help="rebuild geometry and mesh instead of running the case",
    )
    parser.add_argument(
        "--render-geometry",
        action="store_true",
        help="only create the geometry image, from the committed geometry.step",
    )
    scenes = parser.add_mutually_exclusive_group()
    scenes.add_argument(
        "--render-scenes",
        action="store_true",
        help="also create the scenes after running the case",
    )
    scenes.add_argument(
        "--render-scenes-only",
        action="store_true",
        help="only create the scenes, from the output of a previous run",
    )
    args = parser.parse_args()

    case = case_class()
    if args.rebuild_mesh:
        case.build_geometry_and_mesh()
        if case._is_launcher_main_process():
            case.try_create_geometry_image()
        return
    if args.render_geometry:
        if case._is_launcher_main_process():
            case.create_geometry_image()
        return
    if args.render_scenes_only:
        if case._is_launcher_main_process():
            case.create_scenes()
        return

    if case.mesh_missing():
        # Without a Simulation there is no MPI barrier, so the other processes could not
        # wait for the main one to build the mesh: build it only in a serial run.
        if case._launcher_size() > 1:
            sys.exit(
                f"{case_class.name}: the mesh is missing; build it first with "
                "`pymufem case.py --rebuild-mesh`"
            )
        case.build_geometry_and_mesh()
    case.run(render_scenes=args.render_scenes)
