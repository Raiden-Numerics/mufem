"""Shared plotting helper for validation cases.

A lean release-repo analogue of mufem-dev's Testing/plots.py (without the
baseline/TestContext machinery). The common case — one computed curve versus one
CSV reference — is a single call:

    from plots import xy_plot, PlotStyle

    xy_plot(
        center_piece_force_list,
        reference_file=f"{dir_path}/data/ReferenceForce.csv",
        xlabel="Coil Current [A]",
        ylabel="Pole Force [N]",
        path=f"{dir_path}/results/Force_vs_Current.png",
    )

Colors are fixed for consistency across cases: the computed curve is always
`$\\mu$fem` red, the reference always black. Line/marker rendering is chosen with
the `PlotStyle` enum (LINE, POINTS, LINE_POINTS). For extra series, pass
`additional_curves=[Curve(...), ...]`.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, Optional, Sequence, Tuple

import numpy

MUFEM_LABEL = r"$\mu$fem"

#: fixed colors so all cases render identically
MUFEM_COLOR = "r"
REFERENCE_COLOR = "k"

_LINEWIDTH = 2.0
_MARKERSIZE = 6.5


class PlotStyle(Enum):
    """How a curve is drawn: a line, discrete points, or both."""

    LINE = "-"
    POINTS = "o"
    LINE_POINTS = "o-"


def _draw(values, style: PlotStyle, color, label, *, linewidth=_LINEWIDTH, extra=None):
    import matplotlib.pyplot as plt

    plt.plot(
        [x for x, _ in values],
        [y for _, y in values],
        style.value,
        color=color,
        label=label,
        linewidth=linewidth,
        markersize=_MARKERSIZE,
        **(extra or {}),
    )


@dataclass
class Curve:
    """An extra 2D series for `xy_plot(additional_curves=...)`. Unlike the main
    computed/reference curves it takes an explicit `color` (extra series are
    case-specific). `style_kwargs` carries extra matplotlib kwargs."""

    values: Iterable[Tuple[float, float]]
    label: str = ""
    style: PlotStyle = PlotStyle.LINE
    color: str = "C0"
    xscale: float = 1.0
    yscale: float = 1.0
    style_kwargs: Dict = field(default_factory=dict)

    def plot(self) -> None:
        scaled = [(self.xscale * x, self.yscale * y) for x, y in self.values]
        _draw(scaled, self.style, self.color, self.label, extra=self.style_kwargs)


def xy_plot(
    xy_values: Iterable[Tuple[float, float]],
    *,
    xlabel: str,
    ylabel: str,
    path: str,
    # computed curve (always MUFEM_COLOR)
    style: PlotStyle = PlotStyle.LINE_POINTS,
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
    additional_curves: Optional[Sequence[Curve]] = None,
) -> None:
    """Plot `xy_values` (and an optional `reference_file`) to `path`, with a
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

    for curve in additional_curves or []:
        curve.plot()

    scaled = [(xscale * x, yscale * y) for x, y in xy_values]
    _draw(scaled, style, MUFEM_COLOR, label)

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
