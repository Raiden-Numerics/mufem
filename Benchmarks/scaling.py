"""Strong scaling of mufem Community (OpenMP) and Professional (MPI).

Runs a validation case (TEAM 1b or IEEJ Model D) on 1, 2, 4 and 8 cores
with each edition and writes the solver times to results/<case>_Scaling.csv;
plot_scaling.py draws them.

    python scaling.py --community /path/to/community-venv --professional /path/to/professional-venv
    python scaling.py --case modeld --repeats 1 --community ... --professional ...

Each environment holds one mufem build (`pip install mufem` or `pip install mufem-mpi`)
and casekit (`pip install -e ./casekit`). The Professional build reads its license from
MUFEM_LICENSE_KEY. The runs are pinned to the cores 0..n-1 (Linux, taskset).
"""

import argparse
import csv
import json
import os
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
VALIDATIONS = HERE.parent / "Validations" / "Electromagnetics"
CASE_FILES = ("case.py", "geometry.mesh", "geometry.step", "data")

# name -> (case directory, core counts, results file)
CASES = {
    "team1b": (VALIDATIONS / "Compumag-Team1b-Felix-Cylinder", (1, 2, 4, 8), "Team1b_Scaling.csv"),
    "modeld": (VALIDATIONS / "IEEJ_2012_IPM_Motor_Model_D", (1, 2, 4, 8), "ModelD_Scaling.csv"),
}

# Times ValidationCase.solve (the time stepping) on the main process; the import, the
# mesh loading and the post-processing are left out.
DRIVER = """\
import json
import os
import runpy
import time

from casekit import validation_case

_solve = validation_case.ValidationCase.solve


def _timed_solve(self):
    start = time.perf_counter()
    _solve(self)
    if self.is_main():
        with open(os.environ["MUFEM_BENCH_OUT"], "w") as file:
            json.dump({"solve": time.perf_counter() - start}, file)


validation_case.ValidationCase.solve = _timed_solve
runpy.run_path("case.py", run_name="__main__")
"""

# name -> (build, extra environment).
CONFIGURATIONS = {
    "Professional (MPI)": ("professional", {"OMP_NUM_THREADS": "1"}),
    "Community (OpenMP)": ("community", {}),
}


def command(build: str, venv: Path, cores: int) -> list[str]:
    pin = ["taskset", "-c", f"0-{cores - 1}"]
    if build == "professional":
        return pin + [str(venv / "bin" / "pymufem"), str(cores), "driver.py", "--no-field-export"]
    return pin + [str(venv / "bin" / "python"), "driver.py", "--no-field-export"]


def environment(build: str, extra: dict[str, str], cores: int, out: Path) -> dict[str, str]:
    env = dict(os.environ, MUFEM_BENCH_OUT=str(out), **extra)
    if build == "community":
        env.update(OMP_NUM_THREADS=str(cores), OMP_PROC_BIND="close", OMP_PLACES="cores")
    return env


def run(
    build: str, venv: Path, extra: dict[str, str], cores: int, work: Path
) -> tuple[float, float]:
    out = work / "time.json"
    out.unlink(missing_ok=True)
    start = time.perf_counter()
    subprocess.run(
        command(build, venv, cores),
        cwd=work,
        env=environment(build, extra, cores, out),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wall = time.perf_counter() - start
    return json.loads(out.read_text())["solve"], wall


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--community", type=Path, required=True, help="environment with mufem")
    parser.add_argument(
        "--professional", type=Path, required=True, help="environment with mufem-mpi"
    )
    parser.add_argument("--case", choices=CASES, default="team1b")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, help="default: results/<case>_Scaling.csv")
    args = parser.parse_args()
    case_dir, cores_list, results_file = CASES[args.case]
    output = args.output or HERE / "results" / results_file
    venvs = {"community": args.community.resolve(), "professional": args.professional.resolve()}

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for name in CASE_FILES:
            source = case_dir / name
            (shutil.copytree if source.is_dir() else shutil.copy)(source, work / name)
        (work / "driver.py").write_text(DRIVER)

        rows = []
        # Interleaved, so that a drift of the machine spreads over all configurations.
        for repeat in range(1, args.repeats + 1):
            for cores in cores_list:
                for name, (build, extra) in CONFIGURATIONS.items():
                    solve, wall = run(build, venvs[build], extra, cores, work)
                    rows.append(
                        {
                            "configuration": name,
                            "cores": cores,
                            "repeat": repeat,
                            "solve_s": solve,
                            "wall_s": wall,
                        }
                    )
                    print(
                        f"{name:20s} {cores} cores, repeat {repeat}: "
                        f"solve {solve:6.2f} s, wall {wall:6.2f} s"
                    )

    output.parent.mkdir(exist_ok=True)
    with output.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print("\nMedian solve time [s]")
    for name in CONFIGURATIONS:
        medians = [
            statistics.median(
                r["solve_s"] for r in rows if r["configuration"] == name and r["cores"] == c
            )
            for c in cores_list
        ]
        print(f"  {name:20s} " + "  ".join(f"{m:6.2f}" for m in medians))


if __name__ == "__main__":
    main()
