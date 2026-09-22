"""Shared plotting helper for validation cases.

A lean release-repo analogue of mufem-dev's Testing/plots.py (without the
baseline/TestContext machinery). The common case — one computed curve versus one
CSV reference — is a single call:

    from plots import xy_plot, PlotStyle

    xy_plot(
        values=center_piece_force_list,
        reference_file=f"{dir_path}/data/ReferenceForce.csv",
        reference_label="Takahashi & Nakata (1994)",
        xlabel="Coil Current [A]",
        ylabel="Pole Force [N]",
        path=f"{dir_path}/results/Force_vs_Current.png",
    )

Styling is fixed for consistency across cases: the reference (black) is drawn
first as a thicker line/points underneath, then the mufem curve (red) on top as a
line with square markers. Line/marker rendering is chosen with the `PlotStyle` enum
(LINE, POINTS, LINE_AND_POINTS). All arguments are keyword-only.
"""

from enum import Enum
from typing import Iterable, Optional, Sequence, Tuple

import numpy

MUFEM_LABEL = "mufem"

#: fixed colors / markers so all cases render identically
MUFEM_COLOR = "r"
MUFEM_MARKER = "s"  # square
REFERENCE_COLOR = "k"
REFERENCE_MARKER = "o"  # circle

_MARKERSIZE = 5.0
_REFERENCE_MARKERSIZE = 8.0
_LINEWIDTH = 3.0
_REFERENCE_LINEWIDTH = 5.0  # 25% thicker than the computed line

#: 16:10 figure at 1600x1000 px (8x5 inches * 200 dpi)
_FIGSIZE = (8.0, 5.0)
_DPI = 200

#: font sizes (kept larger than the matplotlib defaults for readability)
_LABEL_FONTSIZE = 15
_TICK_FONTSIZE = 13
_LEGEND_FONTSIZE = 15


class PlotStyle(Enum):
    """How a curve is drawn: a line, discrete points, or both."""

    LINE = "line"
    POINTS = "points"
    LINE_AND_POINTS = "line_and_points"

    @property
    def has_line(self) -> bool:
        return self in (PlotStyle.LINE, PlotStyle.LINE_AND_POINTS)

    @property
    def has_markers(self) -> bool:
        return self in (PlotStyle.POINTS, PlotStyle.LINE_AND_POINTS)


def _draw(values, style, color, label, marker, *, linewidth, markersize):
    import matplotlib.pyplot as plt

    plt.plot(
        [x for x, _ in values],
        [y for _, y in values],
        color=color,
        label=label,
        linestyle="-" if style.has_line else "None",
        marker=marker if style.has_markers else "None",
        linewidth=linewidth,
        markersize=markersize,
    )


def xy_plot(
    *,
    values: Iterable[Tuple[float, float]],
    xlabel: str,
    ylabel: str,
    path: str,
    # computed curve (always mufem red, line + square markers)
    style: PlotStyle = PlotStyle.LINE_AND_POINTS,
    label: str = MUFEM_LABEL,
    xscale: float = 1.0,
    yscale: float = 1.0,
    # reference curve, from a CSV (delimiter ',', '#' comments) or inline
    # (x, y) values; always black. Give at most one of the two.
    reference_file: Optional[str] = None,
    reference_values: Optional[Iterable[Tuple[float, float]]] = None,
    reference_style: PlotStyle = PlotStyle.POINTS,
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

    fig = plt.figure(figsize=_FIGSIZE, layout="constrained")

    # reference first, drawn as a thicker line/marker underneath ...
    ref = None
    if reference_file is not None:
        data = numpy.loadtxt(reference_file, delimiter=",", comments="#")
        ref = list(
            zip(
                reference_xscale * data[:, reference_x_column],
                reference_yscale * data[:, reference_y_column],
            )
        )
    elif reference_values is not None:
        ref = [(reference_xscale * x, reference_yscale * y) for x, y in reference_values]
    if ref is not None:
        _draw(
            ref,
            reference_style,
            REFERENCE_COLOR,
            reference_label,
            REFERENCE_MARKER,
            linewidth=_REFERENCE_LINEWIDTH,
            markersize=_REFERENCE_MARKERSIZE,
        )

    # ... then the computed mufem curve on top (red line + square markers).
    scaled = [(xscale * x, yscale * y) for x, y in values]
    _draw(
        scaled,
        style,
        MUFEM_COLOR,
        label,
        MUFEM_MARKER,
        linewidth=_LINEWIDTH,
        markersize=_MARKERSIZE,
    )

    plt.xlabel(xlabel, fontsize=_LABEL_FONTSIZE)
    plt.ylabel(ylabel, fontsize=_LABEL_FONTSIZE)
    if title:
        plt.title(title, fontsize=_LABEL_FONTSIZE)
    if xlim:
        plt.xlim(*xlim)
    if ylim:
        plt.ylim(*ylim)
    if xticks is not None:
        plt.xticks(xticks)
    if yticks is not None:
        plt.yticks(yticks)
    plt.tick_params(labelsize=_TICK_FONTSIZE)

    plt.legend(loc="best", frameon=False, fontsize=_LEGEND_FONTSIZE)
    fig.savefig(path, dpi=_DPI, metadata={"Software": None})
    plt.close(fig)
