"""Shared plotting helper for validation cases.

A lean release-repo analogue of mufem-dev's Testing/plots.py (without the
baseline/TestContext machinery). The common case — one computed curve versus one
CSV reference — is a single call:

    from plots import xy_plot, PlotStyle

    xy_plot(
        values=center_piece_force_list,
        reference_file=f"{dir_path}/data/ReferenceForce.csv",
        xlabel="Coil Current [A]",
        ylabel="Pole Force [N]",
        path=f"{dir_path}/results/Force_vs_Current.png",
    )

Colors are fixed for consistency across cases: the computed curve is always
`$\\mu$fem` red, the reference always black. Line/marker rendering is chosen with
the `PlotStyle` enum (LINE, POINTS, LINE_POINTS). All arguments are keyword-only.
"""

from enum import Enum
from typing import Iterable, Optional, Sequence, Tuple

import numpy

MUFEM_LABEL = r"$\mu$fem"

#: fixed colors so all cases render identically
MUFEM_COLOR = "r"
REFERENCE_COLOR = "k"

_MARKERSIZE = 6.5


class PlotStyle(Enum):
    """How a curve is drawn: a line, discrete points, or both."""

    LINE = "-"
    POINTS = "o"
    LINE_AND_POINTS = "o-"


def _draw(values, style: PlotStyle, color, label, linewidth):
    import matplotlib.pyplot as plt

    plt.plot(
        [x for x, _ in values],
        [y for _, y in values],
        style.value,
        color=color,
        label=label,
        linewidth=linewidth,
        markersize=_MARKERSIZE,
    )


def xy_plot(
    *,
    values: Iterable[Tuple[float, float]],
    xlabel: str,
    ylabel: str,
    path: str,
    # computed curve (always MUFEM_COLOR)
    style: PlotStyle = PlotStyle.LINE_AND_POINTS,
    label: str = MUFEM_LABEL,
    xscale: float = 1.0,
    yscale: float = 1.0,
    # reference curve loaded from a CSV (delimiter ',', '#' comments; always black)
    reference_file: Optional[str] = None,
    reference_style: PlotStyle = PlotStyle.LINE,
    reference_x_column: int = 0,
    reference_y_column: int = 1,
    reference_label: str = "Reference",
    reference_xscale: float = 1.0,
    reference_yscale: float = 1.0,
    # axes
    xlim: Optional[Tuple[float, float]] = None,
    ylim: Optional[Tuple[float, float]] = None,
    xticks: Optional[Sequence[float]] = None,
    yticks: Optional[Sequence[float]] = None,
    title: Optional[str] = None,
) -> None:
    """Plot `values` (and an optional `reference_file`) to `path`, with a
    consistent style (best-loc legend, no frame)."""
    import matplotlib.pyplot as plt

    plt.clf()

    if reference_file is not None:
        data = numpy.loadtxt(reference_file, delimiter=",", comments="#")
        ref = list(
            zip(
                reference_xscale * data[:, reference_x_column],
                reference_yscale * data[:, reference_y_column],
            )
        )
        _draw(ref, reference_style, REFERENCE_COLOR, reference_label, linewidth=3.0)

    scaled = [(xscale * x, yscale * y) for x, y in values]
    _draw(scaled, style, MUFEM_COLOR, label, linewidth=2.0)

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
