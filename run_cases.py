import argparse
import importlib.util
import inspect
import os
import subprocess
import sys
import time

from typing import List, Optional, Set, Tuple

from casekit import ValidationCase


def load_app_class(case_path: str) -> Optional[type]:
    """Import a case module and return its ValidationCase subclass (metadata only).

    Importing runs the module's top-level code but NOT the solve — that lives in
    ValidationCase.run(), guarded by `if __name__ == "__main__"`. So this is cheap and
    lets us read tags before deciding whether to run the case.
    Returns None for legacy cases that don't define a ValidationCase subclass yet.

    sys.argv is isolated during the import so a case that parses arguments at
    module level sees only its own name (not the runner's flags), and we catch
    BaseException so a strict argparse SystemExit can't abort the whole run.
    """
    spec = importlib.util.spec_from_file_location("_mufem_case", case_path)
    module = importlib.util.module_from_spec(spec)
    # Registered so that ValidationCase.dir_path finds the file of the case.
    sys.modules[spec.name] = module
    saved_argv = sys.argv
    sys.argv = [case_path]
    try:
        spec.loader.exec_module(module)
    except BaseException as e:
        print(f"  (could not import {case_path} for metadata: {e!r})")
        return None
    finally:
        sys.argv = saved_argv

    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, ValidationCase) and obj is not ValidationCase:
            return obj
    return None


def run_cases(
    base_directory: str,
    launcher: str,
    exclude_tags: Set[str],
    rebuild_mesh: bool = False,
    render_geometry: bool = False,
    render_scenes: bool = False,
) -> None:

    failed_cases: List[str] = []
    timings: List[Tuple[str, float, str]] = []  # (case_path, seconds, status)

    for root, _, files in os.walk(top=base_directory):
        if "case.py" not in files:
            continue

        case_path = os.path.join(root, "case.py")

        # Importing a case runs only its module top level, which is side-effect-free for
        # class-based cases; it gives the tags and whether the mesh still has to be built.
        app = load_app_class(case_path)
        if exclude_tags:
            if app is None:
                # Metadata unavailable (its imports don't resolve in this environment).
                # When filtering we run only cases we can positively clear, so skip
                # rather than risk running an excluded one.
                print(f"Skipping (no readable metadata): {case_path}")
                continue
            skip = set(app.tags) & exclude_tags
            if skip:
                print(f"Skipping (tag {sorted(skip)}): {case_path}")
                continue
        build_mesh = rebuild_mesh or (app is not None and app().mesh_missing())

        print(f"Running case: {case_path}")
        original_dir = os.getcwd()
        start = time.monotonic()
        status = "OK"
        try:
            os.chdir(path=root)
            geometry_args = " --render-geometry" if render_geometry else ""
            if build_mesh:
                geometry_args = " --rebuild-mesh" + geometry_args
            if geometry_args:
                subprocess.run(
                    args=f"{launcher} case.py{geometry_args}", shell=True, check=True, text=True
                )
            # The fields that only the scenes need are exported with --export-scenes.
            scene_args = " --export-scenes" if render_scenes else ""
            subprocess.run(
                args=f"{launcher} case.py{scene_args}", shell=True, check=True, text=True
            )
            if render_scenes:
                # Serially after the run: the scenes read the complete export, and VTK stays
                # out of the MPI processes.
                subprocess.run(
                    args=[sys.executable, "case.py", "--render-scenes-only"], check=True, text=True
                )
            print(f"Success: {case_path}")
        except subprocess.CalledProcessError as e:
            print(f"Error running {case_path}: {e}")
            failed_cases.append(case_path)
            status = "FAIL"
        finally:
            os.chdir(path=original_dir)
            timings.append((case_path, time.monotonic() - start, status))

    # Timing summary (slowest first) — use it to pick the mac smoke subset.
    print("\n=== Case timings (slowest first) ===")
    for case_path, seconds, status in sorted(timings, key=lambda t: t[1], reverse=True):
        print(f"  {seconds:8.1f}s  [{status:4}]  {case_path}")
    total = sum(seconds for _, seconds, _ in timings)
    print(f"  {'-' * 40}")
    print(f"  {total:8.1f}s  total over {len(timings)} case(s)")

    if failed_cases:
        print("\nThe following cases failed:")
        for case in failed_cases:
            print(case)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run mufem example / validation cases")
    parser.add_argument(
        "base_directory", nargs="?", default=".", help="directory to walk for case.py"
    )
    parser.add_argument(
        "--launcher",
        default="pymufem",
        help="launch command per case (default: pymufem; use 'python' for serial)",
    )
    parser.add_argument(
        "--exclude-tag",
        action="append",
        default=[],
        metavar="TAG",
        help="skip cases carrying this tag (repeatable), e.g. --exclude-tag long",
    )
    parser.add_argument(
        "--rebuild-mesh",
        action="store_true",
        help="rebuild each case's geometry and mesh (serially) before running it",
    )
    parser.add_argument(
        "--render-geometry",
        action="store_true",
        help="also create each case's geometry image (needs a display, e.g. xvfb-run)",
    )
    parser.add_argument(
        "--render-scenes",
        action="store_true",
        help="also create each case's scenes (needs casekit[scenes])",
    )
    args = parser.parse_args()

    print(f"Running cases in directory: {args.base_directory}")
    run_cases(
        base_directory=args.base_directory,
        launcher=args.launcher,
        exclude_tags=set(args.exclude_tag),
        rebuild_mesh=args.rebuild_mesh,
        render_geometry=args.render_geometry,
        render_scenes=args.render_scenes,
    )
