"""Optimization of the fan grating coupler: Ax/BoTorch proposes designs, mesh.py and
grating_coupler.py mesh and solve them.

    python optimize.py --trials 60          (or ./case.sh optimize --trials 60)

Starts from the published coupler (trial 0) and searches the variables below within the fabrication
rules (grooves and teeth >= 70 nm) for the most upward power inside the GI50 fiber's acceptance
(p_gi50), subject to the constraints below. The fan's footprint is fixed (by default the published
one's): the fan may be wider and shorter or narrower and longer, but not larger (Coupler.at_area).
Each trial writes its design to trials/trial_NNN.json in --out, meshes it on the coarse mesh with
mesh.py and solves it with grating_coupler.py, each in a subprocess; the trial's metrics.json and
log stay in trials/trial_NNN/. The run stops after --trials, or, after at least STOP_MIN_TRIALS,
once the best feasible p_gi50 has gained no more than STOP_GAIN over STOP_WINDOW trials. Each trial
is appended to Trials.jsonl (the Ax parameters, the design, its metrics and its time) and the Ax
state saved to Ax_State.json in --out; rerunning resumes. data/Optimization_Trials.jsonl is the
Trials.jsonl of the case study's run. Requires ax-platform 0.4.3, besides mufem and gmsh.
"""

import argparse
import json
import os
import subprocess
import sys
import time

from ax.modelbridge.generation_strategy import GenerationStep, GenerationStrategy
from ax.modelbridge.registry import Models
from ax.service.ax_client import AxClient, ObjectiveProperties

from mesh import DESIGN_KEYS, Coupler, load_design

HERE = os.path.dirname(os.path.abspath(__file__))

PARAMETERS = [
    dict(
        name="groove", type="range", bounds=[0.15, 0.85], value_type="float"
    ),  # >= 70 nm grooves and teeth
    dict(
        name="fan_angle", type="range", bounds=[10.0, 25.0], value_type="float"
    ),  # [deg] half angle; mesh limit 25
    dict(
        name="taper", type="range", bounds=[0.35, 0.8], value_type="float"
    ),  # radius share before the grating
    dict(name="ramp_grooves", type="range", bounds=[0, 12], value_type="int"),  # soft start
    dict(
        name="ramp_start", type="range", bounds=[0.0, 1.0], value_type="float"
    ),  # first groove: 70 nm .. full
    dict(
        name="pitch_offset", type="range", bounds=[-0.005, 0.005], value_type="float"
    ),  # [um] on the slab model
]
OBJECTIVE = "p_gi50"
PUBLISHED = Coupler(**load_design("published"))
# The constraints as (lower, upper) limits: the reflection into the wire <= -20 dB, the beam within
# 0.5 deg of the pin's axis in its core, the near field [um] inside the pin's 35 um core.
LIMITS = {
    "r": (None, 0.01),
    "angle_core": (7.5, 8.5),
    "spot_x": (None, 20.0),
    "spot_y": (None, 20.0),
}
# Fixed noise: the coarse mesh's scatter from remeshing, so the model does not fit it.
SEM = {OBJECTIVE: 0.005, "r": 0.0005, "angle_core": 0.05, "spot_x": 0.1, "spot_y": 0.1}
N_SOBOL, SEED = 12, 11
STOP_MIN_TRIALS, STOP_WINDOW, STOP_GAIN = 30, 10, 0.005  # STOP_MIN_TRIALS > STOP_WINDOW
TIMEOUT = 3 * 3600  # [s] per trial


def constraints():
    """LIMITS as Ax outcome constraints."""
    out = []
    for name, (low, high) in LIMITS.items():
        if low is not None:
            out.append(f"{name} >= {low}")
        if high is not None:
            out.append(f"{name} <= {high}")
    return out


def feasible(result):
    """True if the solved @p result is within LIMITS."""
    if result is None:
        return False
    return all(
        (low is None or result[name] >= low) and (high is None or result[name] <= high)
        for name, (low, high) in LIMITS.items()
    )


def design(params, area):
    """The design of the Ax parameters @p params at the footprint @p area."""
    c = Coupler.at_area(area, **params)
    return {k: getattr(c, k) for k in DESIGN_KEYS}


def all_cpus():
    """In the solver's subprocess: allow all CPUs. PyTorch, which Ax loads, may pin the optimizer's
    process to a few cores (with OMP_PROC_BIND set), and its subprocesses would inherit that."""
    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, range(os.cpu_count()))


def evaluate(trial_design, stem):
    """Mesh and solve @p trial_design, with its files at @p stem (.json, /): its metrics, or None
    on failure."""
    with open(stem + ".json", "w") as f:
        json.dump(trial_design, f, indent=2)
    os.makedirs(stem, exist_ok=True)
    mesh = os.path.join(stem, "mesh.msh")
    steps = [
        [
            os.path.join(HERE, "mesh.py"),
            "--design",
            stem + ".json",
            "--resolution",
            "coarse",
            "--out",
            mesh,
        ],
        [
            os.path.join(HERE, "grating_coupler.py"),
            "--design",
            stem + ".json",
            "--mesh",
            mesh,
            "--out",
            stem,
            "--no-field-export",
        ],
    ]
    with open(os.path.join(stem, "log.txt"), "w") as out:
        try:
            for step in steps:
                subprocess.run(
                    [sys.executable] + step,
                    stdout=out,
                    stderr=subprocess.STDOUT,
                    timeout=TIMEOUT,
                    check=True,
                    preexec_fn=all_cpus,
                )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass  # no metrics: a failure
    if os.path.exists(mesh):
        os.remove(mesh)  # 0.1-0.3 GB per trial
    metrics = os.path.join(stem, "metrics.json")
    if not os.path.exists(metrics):
        return None
    with open(metrics) as f:
        result = json.load(f)
    return dict(result, footprint=Coupler(**trial_design).footprint)


def record(client, index, result):
    if result is None:
        client.log_trial_failure(trial_index=index)
    else:
        client.complete_trial(trial_index=index, raw_data={k: (result[k], SEM[k]) for k in SEM})


def running_best(trials_path):
    """The best feasible objective after each trial."""
    best, out = 0.0, []
    with open(trials_path) as f:
        for line in f:
            row = json.loads(line)
            if feasible(row["result"]):
                best = max(best, row["result"][OBJECTIVE])
            out.append(best)
    return out


def converged(trials_path):
    """True if, after at least STOP_MIN_TRIALS, the best feasible objective has gained no more than
    STOP_GAIN over the last STOP_WINDOW trials."""
    if not os.path.exists(trials_path):
        return False
    best = running_best(trials_path)
    if len(best) < STOP_MIN_TRIALS or best[-1] - best[-1 - STOP_WINDOW] > STOP_GAIN:
        return False
    print(
        f"[stop] best feasible {best[-1]:.4f}: no gain above {STOP_GAIN} in {STOP_WINDOW} trials",
        flush=True,
    )
    return True


def new_client():
    """An Ax client with the experiment: quasi-random (Sobol) trials first, then the Bayesian
    model."""
    strategy = GenerationStrategy(
        steps=[
            GenerationStep(model=Models.SOBOL, num_trials=N_SOBOL, model_kwargs={"seed": SEED}),
            GenerationStep(model=Models.BOTORCH_MODULAR, num_trials=-1),
        ]
    )
    client = AxClient(generation_strategy=strategy, random_seed=SEED)
    client.create_experiment(
        name="grating_coupler",
        parameters=PARAMETERS,
        objectives={OBJECTIVE: ObjectiveProperties(minimize=False)},
        outcome_constraints=constraints(),
    )
    return client


def published_params():
    """The Ax parameters of the published coupler."""
    return dict(
        groove=PUBLISHED.groove,
        fan_angle=PUBLISHED.fan_angle,
        taper=PUBLISHED.r_first / PUBLISHED.radius(PUBLISHED.f_si_end, 0.0),
        ramp_grooves=PUBLISHED.ramp_grooves,
        ramp_start=PUBLISHED.ramp_start,
        pitch_offset=PUBLISHED.pitch_offset,
    )


def summary(result):
    """One line on a trial's @p result."""
    if result is None:
        return "failed"
    return (
        f"p_gi50 {result[OBJECTIVE]:.4f}, r {result['r']:.4f}, "
        f"angle {result['angle_core']:.2f} deg, "
        f"spot {result['spot_x']:.1f} x {result['spot_y']:.1f} um, "
        + ("feasible" if feasible(result) else "infeasible")
    )


def run(trials, area, out):
    """Optimize at the footprint area [um^2] (None: the published one's) for at most trials
    designs, the files in out."""
    area = PUBLISHED.footprint if area is None else area
    os.makedirs(os.path.join(out, "trials"), exist_ok=True)
    trials_path, state_path = os.path.join(out, "Trials.jsonl"), os.path.join(out, "Ax_State.json")

    # Resume a saved run, or start a new one.
    client = (
        AxClient.load_from_json_file(state_path) if os.path.exists(state_path) else new_client()
    )

    while len(client.experiment.trials) < trials and not converged(trials_path):
        # The next design: the published coupler first, then the optimizer's proposals.
        if not client.experiment.trials:
            params, index = client.attach_trial(parameters=published_params())
        else:
            params, index = client.get_next_trial()

        # Mesh and solve it.
        t0 = time.time()
        trial_design = design(params, area)
        result = evaluate(trial_design, os.path.join(out, "trials", f"trial_{index:03d}"))

        # Report the result to Ax, append it to the trial log and save the Ax state for resuming.
        record(client, index, result)
        with open(trials_path, "a") as f:
            f.write(
                json.dumps(
                    dict(
                        trial=index,
                        params=params,
                        design=trial_design,
                        result=result,
                        time_s=round(time.time() - t0, 1),
                    )
                )
                + "\n"
            )
        client.save_to_json_file(state_path)
        print(f"[trial {index}] {summary(result)}, {time.time() - t0:.0f} s", flush=True)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--trials", type=int, default=60, help="the most designs to solve")
    ap.add_argument(
        "--area", type=float, help="the fan's footprint [um^2] (default: the published one's)"
    )
    ap.add_argument(
        "--out", default=os.path.join(HERE, "results_optimization"), help="the output folder"
    )
    args = ap.parse_args()
    run(args.trials, args.area, args.out)


if __name__ == "__main__":
    main()
