"""Shared plotting helpers for validation cases.

A lean release-repo analogue of mufem-dev's Testing/plots.py (without the
baseline/TestContext machinery): a case builds a list of curves — its computed
result plus one or more references — and calls `xy_plot(...)` to render a
consistent computed-vs-reference comparison.

    from plots import Curve, reference_curve, xy_plot

    xy_plot(
        [
            reference_curve(f"{dir_path}/data/Reference.csv", fmt="o", color="k"),
            Curve(xy_values, fmt="o-", color="r"),
        ],
        xlabel="x [m]", ylabel="B [T]",
        path=f"{dir_path}/results/B.png",
    )

Note: `fmt` is the marker/line style only — do NOT embed a color in it (matplotlib
rejects a color in both `fmt` and the `color` kwarg); pass the color via `color`.
"""

from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Sequence, Tuple

import numpy

MUFEM_LABEL = r"$\mu$fem"


@dataclass
class Curve:
    """A 2D curve to plot. `style` carries extra matplotlib kwargs (e.g.
    markerfacecolor). `fmt` must not embed a color — use `color`."""

    values: Iterable[Tuple[float, float]]
    label: str = MUFEM_LABEL
    fmt: str = ".-"
    color: str = "r"
    xscale: float = 1.0
    yscale: float = 1.0
    linewidth: float = 2.0
    markersize: float = 6.5
    style: Dict = field(default_factory=dict)

    def plot(self) -> None:
        import matplotlib.pyplot as plt

        xs = [self.xscale * x for x, _ in self.values]
        ys = [self.yscale * y for _, y in self.values]
        plt.plot(
            xs,
            ys,
            self.fmt,
            color=self.color,
            label=self.label,
            linewidth=self.linewidth,
            markersize=self.markersize,
            **self.style,
        )


def reference_curve(
    path: str,
    *,
    x_column: int = 0,
    y_column: int = 1,
    label: str = "Reference",
    fmt: str = "-",
    color: str = "k",
    xscale: float = 1.0,
    yscale: float = 1.0,
    linewidth: float = 3.0,
    **style: object,
) -> Curve:
    """A reference `Curve` loaded from a CSV (delimiter ',', '#' comments)."""
    data = numpy.loadtxt(path, delimiter=",", comments="#")
    values = list(zip(data[:, x_column], data[:, y_column]))
    return Curve(
        values,
        label=label,
        fmt=fmt,
        color=color,
        xscale=xscale,
        yscale=yscale,
        linewidth=linewidth,
        style=dict(style),
    )


def xy_plot(
    curves: Sequence[Curve],
    *,
    xlabel: str,
    ylabel: str,
    path: str,
    xlim: Optional[Tuple[float, float]] = None,
    ylim: Optional[Tuple[float, float]] = None,
    xticks: Optional[Sequence[float]] = None,
    yticks: Optional[Sequence[float]] = None,
    title: Optional[str] = None,
) -> None:
    """Render `curves` to `path` with a consistent style (best-loc legend, no frame)."""
    import matplotlib.pyplot as plt

    plt.clf()
    for curve in curves:
        curve.plot()

    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    if title:
        plt.title(title)
    if xlim:
        plt.xlim(*xlim)
    if ylim:
        plt.ylim(*ylim)
    if xticks is not None:
        plt.xticks(xticks)
    if yticks is not None:
        plt.yticks(yticks)

    plt.legend(loc="best", frameon=False)
    plt.savefig(path, bbox_inches="tight", metadata={"Software": None})
    plt.close()
