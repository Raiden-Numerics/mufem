"""Plot results/Team1b_Scaling.csv (written by scaling.py) to results/Team1b_Scaling.png."""

import csv
import statistics
from pathlib import Path

import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"

# Categorical slots 1-3; marker shapes as a second cue besides color.
STYLE = {
    "Professional": {"color": "#2a78d6", "marker": "o"},
    "Community": {"color": "#eb6834", "marker": "s"},
    "Community, KMP_BLOCKTIME=1": {"color": "#1baf7a", "marker": "^"},
}
LABEL = {
    "Professional": "Professional (MPI)",
    "Community": "Community (OpenMP, wheel default)",
    "Community, KMP_BLOCKTIME=1": "Community (OpenMP, KMP_BLOCKTIME=1)",
}
SURFACE = "#fcfcfb"
INK = "#1f1f1e"
MUTED = "#6b6a63"
GRID = "#e4e3de"


def medians(path: Path) -> dict[str, dict[int, float]]:
    times: dict[str, dict[int, list[float]]] = {}
    with path.open() as file:
        for row in csv.DictReader(file):
            times.setdefault(row["configuration"], {}).setdefault(int(row["cores"]), []).append(
                float(row["solve_s"])
            )
    return {
        name: {cores: statistics.median(values) for cores, values in sorted(by_cores.items())}
        for name, by_cores in times.items()
    }


def style_axes(ax, ylabel: str) -> None:
    ax.set_facecolor(SURFACE)
    ax.set_xscale("log", base=2)
    ax.set_xticks([1, 2, 4, 8], ["1", "2", "4", "8"])
    ax.minorticks_off()
    ax.set_xlabel("Cores", color=INK)
    ax.set_ylabel(ylabel, color=INK)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelcolor=INK)


def main() -> None:
    data = medians(RESULTS / "Team1b_Scaling.csv")
    cores = sorted(next(iter(data.values())))

    plt.rcParams.update({"font.size": 11})
    fig, (ax_time, ax_speedup) = plt.subplots(1, 2, figsize=(11, 4.6), facecolor=SURFACE)

    for name, times in data.items():
        style = STYLE[name]
        x = list(times)
        t = list(times.values())
        common = {
            "color": style["color"],
            "marker": style["marker"],
            "linewidth": 2,
            "markersize": 8,
        }
        common["markeredgecolor"] = SURFACE
        ax_time.plot(x, t, label=LABEL[name], **common)
        ax_speedup.plot(x, [t[0] / v for v in t], **common)
        # Direct label: the time on the largest core count.
        ax_time.annotate(
            f"{t[-1]:.1f} s",
            (x[-1], t[-1]),
            xytext=(8, 0),
            textcoords="offset points",
            va="center",
            color=INK,
            fontsize=10,
        )

    ax_speedup.plot(cores, cores, color=MUTED, linestyle="--", linewidth=1.2, zorder=0)
    ax_speedup.annotate(
        "ideal",
        (cores[-1], cores[-1]),
        xytext=(6, 0),
        textcoords="offset points",
        va="center",
        color=MUTED,
        fontsize=10,
    )

    style_axes(ax_time, "Solver time [s]")
    ax_time.set_yscale("log")
    ax_time.minorticks_off()
    ticks = [
        t
        for t in (2, 3, 4, 6, 8, 12, 16, 24, 32)
        if t <= 1.1 * max(max(v.values()) for v in data.values())
    ]
    ax_time.set_yticks(ticks, [str(t) for t in ticks])
    ax_time.set_xlim(0.85, 11)
    ax_time.set_title("Solver time (lower is better)", color=INK, loc="left", fontsize=12)

    style_axes(ax_speedup, "Speedup over 1 core")
    ax_speedup.set_yscale("log", base=2)
    ax_speedup.set_yticks([1, 2, 4, 8], ["1", "2", "4", "8"])
    ax_speedup.set_xlim(0.85, 11)
    ax_speedup.set_title("Speedup (higher is better)", color=INK, loc="left", fontsize=12)

    fig.legend(
        loc="upper center", ncol=3, frameon=False, labelcolor=INK, bbox_to_anchor=(0.5, 1.0)
    )
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    fig.savefig(RESULTS / "Team1b_Scaling.png", dpi=150, facecolor=SURFACE)


if __name__ == "__main__":
    main()
