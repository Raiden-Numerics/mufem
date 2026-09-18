import argparse
import importlib.util
import inspect
import os
import subprocess
import sys
import time

from typing import List, Optional, Set, Tuple

from mufem_test import MufemTest


def load_app_class(case_path: str) -> Optional[type]:
    """Import a case module and return its MufemTest subclass (metadata only).

    Importing runs the module's top-level code but NOT the solve — that lives in
    MufemTest.run(), guarded by `if __name__ == "__main__"`. So this is cheap and
    lets us read tags/requires before deciding whether to run the case.
    Returns None for legacy cases that don't define a MufemTest subclass yet.

    sys.argv is isolated during the import so a case that parses arguments at
    module level sees only its own name (not the runner's flags), and we catch
    BaseException so a strict argparse SystemExit can't abort the whole run.
    """
    spec = importlib.util.spec_from_file_location("_mufem_case", case_path)
    module = importlib.util.module_from_spec(spec)
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
        if issubclass(obj, MufemTest) and obj is not MufemTest:
            return obj
    return None


def run_cases(
    base_directory: str,
    launcher: str,
    exclude_tags: Set[str],
    available: Set[str],
) -> None:

    failed_cases: List[str] = []
    timings: List[Tuple[str, float, str]] = []  # (case_path, seconds, status)

    for root, _, files in os.walk(top=base_directory):
        if "case.py" not in files:
            continue

        case_path = os.path.join(root, "case.py")

        # Only import a case to read its metadata when filtering is actually
        # requested. Importing runs the module's top level; for migrated
        # (class-based) cases that is side-effect-free, but a legacy script
        # would solve at import — so filtering presumes migrated cases.
        filtering = bool(exclude_tags) or bool(available)
        if filtering:
            app = load_app_class(case_path)
            if app is None:
                # Metadata unavailable (legacy case, or its imports don't resolve
                # in this environment). When filtering we run only cases we can
                # positively clear, so skip rather than risk running an excluded one.
                print(f"Skipping (no readable metadata): {case_path}")
                continue
            skip = set(app.tags) & exclude_tags
            missing = set(app.requires) - available
            if skip:
                print(f"Skipping (tag {sorted(skip)}): {case_path}")
                continue
            if missing:
                print(f"Skipping (requires {sorted(missing)}): {case_path}")
                continue

        print(f"Running case: {case_path}")
        original_dir = os.getcwd()
        start = time.monotonic()
        status = "OK"
        try:
            os.chdir(path=root)
            subprocess.run(args=f"{launcher} case.py", shell=True, check=True, text=True)
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
    parser.add_argument("base_directory", nargs="?", default=".", help="directory to walk for case.py")
    parser.add_argument("--launcher", default="pymufem", help="launch command per case (default: pymufem; use 'python' for serial)")
    parser.add_argument("--exclude-tag", action="append", default=[], metavar="TAG", help="skip cases carrying this tag (repeatable), e.g. --exclude-tag long")
    parser.add_argument("--have", action="append", default=[], metavar="FEATURE", help="engine feature available in this build (repeatable); cases requiring an absent feature are skipped, e.g. --have mumps")
    args = parser.parse_args()

    print(f"Running cases in directory: {args.base_directory}")
    run_cases(
        base_directory=args.base_directory,
        launcher=args.launcher,
        exclude_tags=set(args.exclude_tag),
        available=set(args.have),
    )
