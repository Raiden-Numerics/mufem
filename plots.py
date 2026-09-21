"""Shared plotting helper for validation cases.

A lean release-repo analogue of mufem-dev's Testing/plots.py (without the
baseline/TestContext machinery). The common case — one computed curve versus one
CSV reference — is a single call:

    from plots import xy_plot

    xy_plot(
        center_piece_force_list,
        reference_file=f"{dir_path}/data/ReferenceForce.csv",
        xlabel="Coil Current [A]",
        ylabel="Pole Force [N]",
        path=f"{dir_path}/results/Force_vs_Current.png",
    )

For extra series, pass `additional_curves=[Curve(...), ...]`.

Note: `fmt` is the marker/line style only — do NOT embed a color in it (matplotlib
rejects a color in both `fmt` and the `color` kwarg); pass the color via `color`.
"""

from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Sequence, Tuple

import numpy

MUFEM_LABEL = r"$\mu$fem"


@dataclass
class Curve:
    """An extra 2D series for `xy_plot(additional_curves=...)`. `style` carries
    extra matplotlib kwargs (e.g. markerfacecolor); `fmt` must not embed a color."""

    values: Iterable[Tuple[float, float]]
    label: str = ""
    fmt: str = "-"
    color: str = "C0"
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


def xy_plot(
    xy_values: Iterable[Tuple[float, float]],
    *,
    xlabel: str,
    ylabel: str,
    path: str,
    # computed-curve styling
    label: str = MUFEM_LABEL,
    fmt: str = "o-",
    color: str = "r",
    xscale: float = 1.0,
    yscale: float = 1.0,
    linewidth: float = 2.0,
    markersize: float = 6.5,
    style: Optional[Dict] = None,
    # reference curve loaded from a CSV (delimiter ',', '#' comments)
    reference_file: Optional[str] = None,
    reference_x_column: int = 0,
    reference_y_column: int = 1,
    reference_label: str = "Reference",
    reference_fmt: str = "-",
    reference_color: str = "k",
    reference_xscale: float = 1.0,
    reference_yscale: float = 1.0,
    # axes
    xlim: Optional[Tuple[float, float]] = None,
    ylim: Optional[Tuple[float, float]] = None,
    xticks: Optional[Sequence[float]] = None,
    yticks: Optional[Sequence[float]] = None,
    title: Optional[str] = None,
    additional_curves: Optional[Sequence[Curve]] = None,
) -> None:
    """Plot `xy_values` (and an optional `reference_file`) to `path`, with a
    consistent style (best-loc legend, no frame)."""
    import matplotlib.pyplot as plt

    plt.clf()

    if reference_file is not None:
        data = numpy.loadtxt(reference_file, delimiter=",", comments="#")
        plt.plot(
            reference_xscale * data[:, reference_x_column],
            reference_yscale * data[:, reference_y_column],
            reference_fmt,
            color=reference_color,
            label=reference_label,
            linewidth=3.0,
            markersize=6.5,
        )

    for curve in additional_curves or []:
        curve.plot()

    plt.plot(
        [xscale * x for x, _ in xy_values],
        [yscale * y for _, y in xy_values],
        fmt,
        color=color,
        label=label,
        linewidth=linewidth,
        markersize=markersize,
        **(style or {}),
    )

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
