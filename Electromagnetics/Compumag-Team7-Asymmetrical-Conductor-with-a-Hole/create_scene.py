"""Render results/Team7_Animation.gif from the output of case.py.

Run with `pvpython create_scene.py` after the case (requires `ffmpeg`). The frames show the eddy
current density J(t) = J_r cos(wt) - J_i sin(wt) at 50 Hz over one period, next to the coil
current and B_z along A1-B1 at the same time.
"""

import math
import sys
from pathlib import Path

case_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(case_dir.parents[1]))

import matplotlib  # noqa: E402

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import paraview.simple as pvs  # noqa: E402

from casekit.paraview_scene import (  # noqa: E402
    color_by,
    combine_images,
    new_view,
    phase_field,
    read_output,
    save,
    set_camera,
    show,
    write_gif,
)

frequency = 50.0
frames_per_period = 40
vis = case_dir / "vis"

# B_z along A1-B1 [mT]: x, Re and -Im of the solution (case.py), and x, wt = 0 and 90 deg of the
# measurement [G], so that B_z(t) = Re cos(wt) + Im sin(wt) for both.
computed = np.loadtxt(case_dir / "results" / "Bz_A1-B1_mufem.csv", delimiter=",")
measured = np.loadtxt(case_dir / "data" / "Bz_A1-B1.csv", delimiter=",")


def plot_coil_current(phase, path):
    """Coil current cos(wt) over the period, with the current time marked."""
    period_ms = 1e3 / frequency
    t = np.linspace(0.0, period_ms, 200)
    plt.figure()
    plt.plot(t, np.cos(2 * np.pi * t / period_ms), "-", color="#444444", linewidth=3.5)
    plt.plot(
        period_ms * phase / (2 * np.pi),
        np.cos(phase),
        "o",
        markersize=8.0,
        color="r",
        label="Applied Current",
    )
    plt.xlabel("Cycle Time [ms]")
    plt.ylabel("Coil Current [A]")
    plt.xlim((0, period_ms))
    plt.xticks([0, 5, 10, 15, 20])
    plt.yticks([-1, -0.5, 0.0, 0.5, 1.0])
    plt.legend(loc="best").draw_frame(False)
    plt.savefig(path, bbox_inches="tight")
    plt.close()


def plot_flux_density(phase, path):
    """B_z along A1-B1 at the phase, computed and measured."""
    plt.figure()
    plt.plot(
        measured[:, 1],
        0.1 * (measured[:, 2] * np.cos(phase) + measured[:, 3] * np.sin(phase)),
        "ko-",
        markersize=6.0,
        linewidth=2.0,
        label="Fujiwara (1990)",
    )
    plt.plot(
        computed[:, 0],
        computed[:, 1] * np.cos(phase) + computed[:, 2] * np.sin(phase),
        color="r",
        linewidth=3.0,
        label="$\\mu$fem",
    )
    plt.xlim((0, 288))
    plt.ylim((-9, 9))
    plt.xticks([0, 72, 144, 216, 288])
    plt.xlabel("Position [mm]")
    plt.ylabel("Magnetic Flux Density along A1-B1 [mT]")
    plt.legend(loc="best").draw_frame(False)
    plt.savefig(path, bbox_inches="tight")
    plt.close()


view = new_view((1600, 1200))
data = read_output(case_dir)
conductors = pvs.ExtractBlock(Input=data, Selectors=["/Root/Coil", "/Root/Plate"])
show(conductors, view, color=(0.9, 0.9, 0.9))

# The view of data/Geometry.png.
position = (-0.3697352196806951, 0.3392467327757224, 0.22955715848836572)
focal_point = (-0.3041336634862759, 0.31113183987720244, 0.20412014606490986)
direction = [p - f for p, f in zip(position, focal_point)]
set_camera(
    view,
    direction,
    (0, 0, 1),
    focal_point,
    parallel_scale=0.18,
)

frames = []
for i in range(frames_per_period):
    phase = 2.0 * math.pi * i / frames_per_period
    current = phase_field(conductors, "Electric Current Density", math.degrees(phase))
    glyph = pvs.Glyph(Input=current, GlyphType="Arrow")
    glyph.OrientationArray = ["POINTS", "Electric Current Density"]
    glyph.ScaleArray = ["POINTS", "Electric Current Density"]
    glyph.ScaleFactor = 2e-8
    glyph.GlyphMode = "All Points"
    glyph.GlyphType.ShaftRadius = 0.07
    glyph.GlyphType.ShaftResolution = 16
    glyph.GlyphType.TipRadius = 0.12
    glyph.GlyphType.TipLength = 0.15
    glyph.GlyphType.TipResolution = 16

    display = show(glyph, view)
    color_by(
        display,
        view,
        "Electric Current Density",
        "Electric Current Density [A/m²]",
        [0.0, 1.0e6, 2.0e6],
        "%.0e",
        position=(0.35, 0.1),
        length=0.3,
        thickness=40,
        title_size=32,
        label_size=28,
        component="Magnitude",
    )
    scene = vis / f"Scene_Electric_Current_Density_{i:03d}.png"
    save(view, scene, crop=False)
    display.SetScalarBarVisibility(view, False)
    for proxy in (glyph, current):
        pvs.Delete(proxy)

    plot_coil_current(phase, vis / f"Coil_Current_{i:03d}.png")
    plot_flux_density(phase, vis / f"Magnetic_Flux_Density_{i:03d}.png")
    frames.append(vis / f"Scene_{i:03d}.png")
    combine_images(
        scene,
        [vis / f"Coil_Current_{i:03d}.png", vis / f"Magnetic_Flux_Density_{i:03d}.png"],
        frames[-1],
    )

write_gif(frames, case_dir / "results" / "Team7_Animation.gif", width=1200)
