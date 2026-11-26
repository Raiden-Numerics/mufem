"""The figures of the README, from the runs of the case and the optimization data.

    xvfb-run -a python figures.py                          # all figures (or ./case.sh figures)
    xvfb-run -a python figures.py near_field far_field     # some of them

Reads results_published/ and results_optimized/, written by "./case.sh run --design published"
(and the same for the optimized design), and data/; writes the images of the device to data/ and
those of the results to results/. Needs mufem, matplotlib and PyVista.
"""

import argparse
import functools
import json
import os
import shutil

import matplotlib

matplotlib.use("Agg")
import matplotlib.patches  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import meshio  # noqa: E402
import numpy as np  # noqa: E402
import pyvista as pv  # noqa: E402
from PIL import Image  # noqa: E402
from vtkmodules.vtkFiltersParallel import vtkMergeBlocks  # noqa: E402
from vtkmodules.vtkIOHDF import vtkHDFReader  # noqa: E402

from grating_coupler import NA_GI50, PIN_TILT, far_field  # noqa: E402
from mesh import ETCH, L_WIRE, N_CORE, T_SI, W_WIRE, Coupler, load_design  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DATA, RESULTS = os.path.join(HERE, "data"), os.path.join(HERE, "results")
DESIGNS = ("published", "optimized")
COLOR = {"published": "tab:blue", "optimized": "tab:red"}
LABEL = {"published": "Published", "optimized": "Optimized"}
DPI = 150
PAD = 10  # [px] kept around the cropped 3D views
N_SOBOL = 12  # the quasi-random trials at the start of the optimization (optimize.py)
MAGNITUDE_MAP, WAVE_MAP = "cividis", "coolwarm"
MATERIALS = {"Silicon": "#b8b4ac", "SiO2": "#cfe8f7", "Resin": "#fdf1d8"}
MATERIAL_LABEL = {"Silicon": "Si", "SiO2": "SiO$_2$", "Resin": "Resin"}
LABEL_BOX = dict(facecolor="white", edgecolor="none", pad=1.5)  # behind the labels in the plots


def run_dir(design):
    return os.path.join(HERE, f"results_{design}")


def metrics(design):
    with open(os.path.join(run_dir(design), "metrics.json")) as f:
        return json.load(f)


def beam(design):
    return np.load(os.path.join(run_dir(design), "beam_plane.npz"))


def coupler(design):
    return Coupler(**load_design(design))


def trials():
    with open(os.path.join(DATA, "Optimization_Trials.jsonl")) as f:
        return [json.loads(line) for line in f]


def feasible(result):
    """True if the solved result meets the constraints of the optimization (LIMITS in optimize.py)."""
    return (result is not None and result["r"] <= 0.01 and 7.5 <= result["angle_core"] <= 8.5
            and result["spot_x"] <= 20.0 and result["spot_y"] <= 20.0)


def save(fig, folder, name):
    fig.savefig(os.path.join(folder, name), dpi=DPI, bbox_inches="tight", pad_inches=0.1, metadata={"Software": None})
    plt.close(fig)


def mirror(a, sign=1.0):
    """The array a, given over x > 0 (its first axis), extended to x < 0, times sign there."""
    return np.concatenate([sign * a[::-1], a])


def create_scene(window_size):
    """An off-screen PyVista plotter: parallel projection, no scalar bar."""
    theme = pv.themes.DocumentTheme()
    theme.anti_aliasing = "msaa"
    theme.lighting_params.ambient = 0.3
    theme.lighting_params.diffuse = 0.8
    theme.camera.parallel_projection = True
    theme.show_scalar_bar = False
    return pv.Plotter(theme=theme, off_screen=True, window_size=window_size)


def crop(images):
    """The images cropped alike to the non-white part of the first, with PAD pixels around it."""
    rows, cols = np.nonzero((images[0] < 250).any(axis=2))
    return [image[rows.min() - PAD:rows.max() + PAD, cols.min() - PAD:cols.max() + PAD] for image in images]


def save_gif(frames, path, fps):
    """An animated GIF of the screenshots with one palette for all of them; white stays
    white, and pixels that do not change between frames keep their colour, so that the dithering
    does not shimmer."""
    palette = Image.fromarray(np.vstack(frames)).quantize(method=Image.Quantize.MAXCOVERAGE)
    indices = [np.array(Image.fromarray(frame).quantize(palette=palette)) for frame in frames]
    colors = np.frombuffer(palette.palette.tobytes(), np.uint8).reshape(-1, 3)
    white = np.flatnonzero((colors == 255).all(axis=1))
    if len(white):
        for frame, index in zip(frames, indices):
            index[(frame == 255).all(axis=2)] = white[0]
    for i in range(1, len(frames)):
        still = (frames[i] == frames[i - 1]).all(axis=2)
        indices[i][still] = indices[i - 1][still]
    images = [Image.fromarray(index, "P") for index in indices]
    for image in images:
        image.putpalette(palette.getpalette())
    images[0].save(path, save_all=True, append_images=images[1:], duration=round(1000 / fps), loop=0)


# ---- the device --------------------------------------------------------------------------------

def plan_outline(ax, c, color, alpha=1.0):
    """The fan of the coupler c in plan view, both halves: its edges, its grooves and the wire."""
    phis = np.linspace(-c.fan_angle, c.fan_angle, 121)

    def arc(f):
        r = np.array([c.radius(f, abs(p)) for p in phis])
        return r * np.sin(np.radians(phis)), L_WIRE + r * np.cos(np.radians(phis))

    for f0, f1 in c.grooves:
        (x0, y0), (x1, y1) = arc(f0), arc(f1)
        ax.fill(np.concatenate([x0, x1[::-1]]), np.concatenate([y0, y1[::-1]]), color=color, alpha=alpha, lw=0)
    x_end, y_end = arc(c.f_si_end)
    for side in (-1, 1):
        ax.plot([side * 0.5 * W_WIRE, side * 0.5 * W_WIRE, side * x_end[-1]], [0.0, c.y_wire_end, y_end[-1]],
                color="k", lw=1.0)
    ax.plot(x_end, y_end, color="k", lw=1.0)


def figure_principle():
    """Schematic: the side view of the grating and its layers, and the plan view of the fan."""
    c = coupler("published")
    fig, (side, plan) = plt.subplots(1, 2, figsize=(12.4, 5.2), width_ratios=(1.57, 1.0), layout="constrained")

    # Side view, not to scale: substrate, BOX, silicon with grooves, cladding, resin.
    layers = [(-1.2, -0.7, "#a19d94", "silicon substrate"), (-0.7, 0.0, "#dceefa", "SiO$_2$ buried oxide, 2 µm"),
              (0.0, 0.25, "#a19d94", "silicon, 200 nm"), (0.25, 1.0, "#dceefa", "SiO$_2$ over-cladding, 2 µm"),
              (1.0, 1.9, "#fdf1d8", "resin (optical pin)")]
    for z0, z1, color, text in layers:
        side.fill_between([-4.0, 11.8], z0, z1, color=color, lw=0)
        side.text(-3.8, 0.5 * (z0 + z1), text, va="center", fontsize=10)
    for i in range(12):
        side.fill_between([3.0 + 0.6 * i, 3.3 + 0.6 * i], 0.15, 0.25, color="#dceefa", lw=0)
    side.annotate("grooves, 70 nm deep", (3.15, 0.2), (3.15, 0.86), ha="center", va="bottom", fontsize=10,
                  arrowprops=dict(arrowstyle="-", color="k", lw=0.8, shrinkA=1, shrinkB=0))
    arrow = dict(arrowstyle="-|>", lw=2.5, mutation_scale=18)
    side.annotate("", (2.6, 0.125), (0.2, 0.125), arrowprops=dict(arrow, color="tab:red"))
    side.text(1.4, 0.33, "guided TE0 mode", ha="center", fontsize=10, color="tab:red")
    for y in (5.0, 7.0, 9.0):
        side.annotate("", (y + 0.25, 1.75), (y, 0.3), arrowprops=dict(arrow, color="tab:red"))
        side.annotate("", (y + 0.08, -0.6), (y, -0.05), arrowprops=dict(arrow, color="tab:blue", lw=1.5))
    side.text(9.6, 1.45, "up: 8° to the\nnormal in the\nresin", fontsize=10, color="tab:red")
    side.text(9.6, -0.42, "down: lost in\nthe substrate", fontsize=10, color="tab:blue")
    side.set_xlim(-4.0, 11.8)
    side.set_ylim(-1.2, 1.9)
    side.set_title("Side view (not to scale)")
    side.axis("off")

    # Plan view of the published fan, to scale, with rays from the focus.
    plan_outline(plan, c, "tab:blue")
    for phi in np.linspace(-c.fan_angle, c.fan_angle, 5):
        r = c.radius(c.f_si_end, abs(phi))
        plan.plot([0.0, r * np.sin(np.radians(phi))], [L_WIRE, L_WIRE + r * np.cos(np.radians(phi))],
                  color="0.6", lw=0.8, ls="--")
    plan.plot(0.0, L_WIRE, "k.", ms=8)
    plan.text(-0.6, L_WIRE, "focus", fontsize=10, ha="right", va="center")
    # The first line's baseline at the wire's end: "baseline" aligns the last line, one line height (1.2 em) lower.
    plan.annotate("feed wire\n350 nm wide", (0.6, 0.0), xytext=(0.0, -12.0), textcoords="offset points", fontsize=10,
                  ha="left", va="baseline")
    plan.set_ylim(bottom=-2.0)  # room for the wire label
    plan.set_aspect("equal")
    plan.set_xlabel("x [µm]")
    plan.set_ylabel("y [µm]")
    plan.set_title("Plan view: confocal grooves")
    save(fig, DATA, "Principle.png")


def figure_constraints():
    """Sketch of the optimization: the constraints on the beam in side view, and in plan view the
    fixed footprint with the variables of the fan."""
    c = coupler("published")
    fig, (side, plan) = plt.subplots(1, 2, figsize=(11.35, 5.0), width_ratios=(1.35, 1.0), layout="constrained")

    # Side view, not to scale: the beam's angle window and spot, the reflection, the 70 nm rule.
    layers = [(-0.7, 0.0, "#dceefa"), (0.0, 0.25, "#a19d94"), (0.25, 1.0, "#dceefa"), (1.0, 2.9, "#fdf1d8")]
    for z0, z1, color in layers:
        side.fill_between([-4.0, 11.8], z0, z1, color=color, lw=0)
    for i in range(12):
        side.fill_between([3.0 + 0.6 * i, 3.3 + 0.6 * i], 0.15, 0.25, color="#dceefa", lw=0)
    side.annotate("grooves and teeth ≥ 70 nm", (3.15, 0.2), (3.15, 0.86), ha="center", va="bottom", fontsize=10,
                  arrowprops=dict(arrowstyle="-", color="k", lw=0.8, shrinkA=1, shrinkB=0))
    arrow = dict(arrowstyle="-|>", lw=2.5, mutation_scale=18)
    side.annotate("", (2.6, 0.17), (0.2, 0.17), arrowprops=dict(arrow, color="tab:red"))
    side.annotate("", (0.2, 0.06), (2.6, 0.06), arrowprops=dict(arrow, color="tab:blue", lw=1.5))
    side.text(1.4, -0.08, "reflection into the wire ≤ 1 % (−20 dB)", fontsize=10, color="tab:blue", ha="center", va="top")

    # The beam from the grating: a band as wide as the spot along its axis, the angle drawn larger to be seen.
    x0, z0, dz = 6.3, 0.3, 2.2
    stretch = 2.9  # the panel's vertical exaggeration: a drawn angle a needs dx = tan(a) * dz * stretch
    half_core = 2.7
    half_spot = half_core * 20.0 / 35.0  # the 20 um spot in the 35 um core

    def axis(z):  # the beam axis, which the pin follows
        return x0 + np.tan(np.radians(15.0)) * (z - z0) * stretch

    z_top = z0 + dz
    side.plot([x0, x0], [z0, z_top], color="0.5", lw=0.8, ls="--")
    side.fill([x0 - half_spot, x0 + half_spot, axis(z_top) + half_spot, axis(z_top) - half_spot], [z0, z0, z_top, z_top],
              color="tab:red", alpha=0.15, lw=0)
    side.annotate("", (axis(z_top), z_top), (x0, z0), arrowprops=dict(arrow, color="tab:red"))
    side.text(axis(z_top), z_top + 0.1, "beam angle in the resin\n8° ± 0.5°", fontsize=10, color="tab:red",
              ha="center", va="bottom")

    # The pin's core around the beam, and the spot at its bottom.

    for side_sign in (-1, 1):
        side.plot([axis(1.0) + side_sign * half_core, axis(2.9) + side_sign * half_core], [1.0, 2.9], color="0.4",
                  lw=1.0)
    side.annotate("", (axis(1.12) + half_core, 1.12), (axis(1.12) - half_core, 1.12),
                  arrowprops=dict(arrowstyle="<->", color="0.4", lw=0.8))
    side.text(axis(1.12) - half_core - 0.2, 1.12, "pin core, Ø35 µm", fontsize=10, color="0.3", ha="right",
              va="center")
    xs = axis(1.45)
    side.annotate("", (xs + half_spot, 1.45), (xs - half_spot, 1.45),
                  arrowprops=dict(arrowstyle="<->", color="tab:red", lw=1.2))
    side.text(axis(1.45) - half_core - 0.35, 1.45, "spot (D4σ) ≤ 20 µm", fontsize=10, color="tab:red", ha="right",
              va="center")
    side.set_xlim(-1.8, 11.8)
    side.set_ylim(-0.25, 2.9)
    side.set_title("Side view: the constraints (not to scale)")
    side.axis("off")

    # Plan view: fans of the published footprint, the published one with its grooves.
    plan_outline(plan, c, "tab:blue", alpha=0.3)
    for angle, taper in ((11.0, 0.55), (24.0, 0.55)):
        other = Coupler.at_area(c.footprint, c.groove, angle, taper, 0, 1.0, 0.0)
        phis = np.linspace(-other.fan_angle, other.fan_angle, 121)
        r = np.array([other.radius(other.f_si_end, abs(p)) for p in phis])
        x, y = r * np.sin(np.radians(phis)), L_WIRE + r * np.cos(np.radians(phis))
        plan.plot(np.concatenate([[0.0], x, [0.0]]), np.concatenate([[L_WIRE], y, [L_WIRE]]), color="0.5",
                  lw=1.0, ls="--")
    plan.text(0.0, 33.0, f"footprint fixed: {c.footprint:.0f} µm²", ha="center", fontsize=10)
    arc = np.radians(np.linspace(0.0, c.fan_angle, 30))
    plan.plot(9.0 * np.sin(arc), L_WIRE + 9.0 * np.cos(arc), color="k", lw=0.8)
    plan.plot([0.0, 0.0], [L_WIRE, L_WIRE + 12.0], color="0.5", lw=0.8, ls=":")
    middle = 0.5 * np.radians(c.fan_angle)  # the middle of the arc
    plan.annotate("half angle\n10–25°", (9.0 * np.sin(middle), L_WIRE + 9.0 * np.cos(middle)), (12.5, 5.0),
                  fontsize=10, ha="right", va="top", arrowprops=dict(arrowstyle="-", color="k", lw=0.6, relpos=(0.5, 1.0)))
    f0, f1 = c.grooves[0]
    y_first = L_WIRE + c.radius(0.5 * (f0 + f1), 0.0)  # the middle of the first groove, on the axis
    plan.annotate("grating starts\nat 0.35–0.8 of\nthe radius", (0.0, y_first), (-12.5, 5.0), fontsize=10, va="top",
                  arrowprops=dict(arrowstyle="-", color="k", lw=0.6, relpos=(0.5, 1.0)))  # from the label's top centre
    plan.set_xlim(-14.0, 14.0)
    plan.set_ylim(-2.0, 35.0)
    plan.set_aspect("equal")
    plan.set_xlabel("x [µm]")
    plan.set_ylabel("y [µm]")
    plan.set_title("Plan view: fans of the same area")
    save(fig, DATA, "Constraints.png")


def read_mesh(design):
    """The mesh of a run (the half model) as a PyVista grid with its material name per cell."""
    m = meshio.read(os.path.join(run_dir(design), "mesh.msh"))
    names = {tag: name for name, (tag, dim) in m.field_data.items() if dim == 3}
    grid = pv.from_meshio(m)
    grid = grid.extract_cells(np.isin(grid.cell_data["gmsh:physical"], list(names)))
    grid.cell_data["material"] = np.array([names[t] for t in grid.cell_data["gmsh:physical"]])
    return grid


def material_legend(ax, names, corner):
    """Colour boxes of the materials names, their lower right corner at corner (axes fraction)."""
    handles = [matplotlib.patches.Patch(facecolor=MATERIALS[n], edgecolor="0.4", label=MATERIAL_LABEL[n]) for n in names]
    ax.legend(handles=handles, loc="lower right", bbox_to_anchor=corner, ncol=len(handles), borderaxespad=0.0,
              borderpad=0.0, frameon=False, fontsize=11)


def device_scene():
    """A scene with the camera and lights of the 3D views of the device: a key light from behind the fan
    darkens the groove walls that face the camera; a weaker fill from the camera."""
    scene = create_scene((1400, 1000))
    scene.remove_all_lights()
    scene.add_light(pv.Light(position=(0.4, 1.0, 0.8), focal_point=(0.0, 0.0, 0.0), intensity=1.0))
    scene.add_light(pv.Light(position=(0.55, -1.0, 0.8), focal_point=(0.0, 0.0, 0.0), intensity=0.5))
    return scene


def save_device(scene, names, name):
    """The screenshot of the device scene, cropped, with the legend of the materials names."""
    scene.view_vector((0.55, -1.0, 0.8), viewup=(0, 0, 1))
    scene.camera.zoom(1.25)
    image = crop([scene.screenshot()])[0]
    scene.close()
    fig, ax = plt.subplots(figsize=(image.shape[1] / DPI, image.shape[0] / DPI), layout="constrained")
    ax.imshow(image)
    ax.axis("off")
    material_legend(ax, names, (1.0 - PAD / image.shape[1], PAD / image.shape[0]))
    save(fig, DATA, name)


def figure_geometry():
    """The published coupler in 3D: the silicon of the wire and the fan on the buried oxide and the
    substrate; the claddings above are left out."""
    grid = read_mesh("published")
    centers = grid.cell_centers().points
    material = grid.cell_data["material"]
    # The silicon of the device and the substrate, and the buried oxide between them.
    shown = (material == "Silicon") | ((material == "SiO2") & (centers[:, 2] < 0.0))
    scene = device_scene()
    for name in ("Silicon", "SiO2"):
        part = grid.extract_cells(shown & (material == name)).extract_surface(algorithm=None)
        for half in (part, part.reflect((1, 0, 0), point=(0, 0, 0))):
            scene.add_mesh(half, color=MATERIALS[name])
    save_device(scene, ("Silicon", "SiO2"), "Geometry.png")
    shutil.copyfile(os.path.join(DATA, "Geometry.png"), os.path.join(RESULTS, "Case_Study_Thumbnail.png"))


MESH_WIDTH, ZOOM_WIDTH = 13.0, 6.0  # [in] in the ratio of their widths in the README (62.4 % : 28.8 %)
MESH_TITLE = 0.4  # [in] the strip of the titles, the same in both columns


def mesh_image(faces, view, size, line_width, focus=None, zoom=None, marker=None):
    """A screenshot of the mesh faces seen along view ("yz" or "xy") and the corners of the area it
    shows: fitted to the faces, or zoomed on focus; marker, the area of a close-up, as a red outline."""
    scene = create_scene(size)
    for material, color in MATERIALS.items():
        part = faces.extract_cells(faces.cell_data["material"] == material)
        if part.n_cells:
            scene.add_mesh(part, color=color, show_edges=True, edge_color="black", line_width=line_width)
    if view == "yz":
        scene.view_yz()
    else:
        scene.view_xy()
        scene.camera.up = (-1.0, 0.0, 0.0)  # the fan to the right
    if zoom is None:  # fit: the window has the faces' aspect ratio
        b = faces.bounds
        scene.set_focus(faces.center)
        scene.camera.parallel_scale = 0.5 * ((b.z_max - b.z_min) if view == "yz" else (b.x_max - b.x_min))
    else:
        scene.set_focus(focus)
        scene.camera.zoom(zoom)
    if marker is not None:
        scene.add_mesh(pv.lines_from_points(marker + marker[:1]), color="red", line_width=4)

    # The visible area, between the faces and the camera: x is vertical in the top view.
    fx, fy, fz = scene.camera.focal_point
    half_h = scene.camera.parallel_scale
    half_w = half_h * size[0] / size[1]
    if view == "yz":
        x = 0.05 * np.sign(scene.camera.position[0] - fx)
        area = [(x, fy + sy * half_w, fz + sz * half_h) for sy, sz in ((-1, -1), (1, -1), (1, 1), (-1, 1))]
    else:
        area = [(fx + sx * half_h, fy + sy * half_w, T_SI + 0.05) for sx, sy in ((-1, -1), (-1, 1), (1, 1), (1, -1))]

    image = scene.screenshot()
    scene.close()
    return image, area


def save_titled(image, title, width, name):
    """The image, width inches wide, under its title in a strip of MESH_TITLE inches, so that two
    images shown side by side in the README in the ratio of their widths have titles of one size."""
    h = width * image.shape[0] / image.shape[1]
    fig = plt.figure(figsize=(width, h + MESH_TITLE))
    ax = fig.add_axes((0.0, 0.0, 1.0, h / (h + MESH_TITLE)))
    ax.imshow(image)
    ax.axis("off")
    fig.text(0.5, 1.0 - 0.5 * MESH_TITLE / (h + MESH_TITLE), title, ha="center", va="center", fontsize=14)
    fig.savefig(os.path.join(DATA, name), dpi=200, metadata={"Software": None})
    plt.close(fig)


def figure_mesh():
    """The model of the published coupler: the half model in 3D, mirrored so that its face on the
    symmetry plane faces the camera; the mesh on the symmetry plane and on top of the grooves, overall
    and at the start of the grating."""
    grid = read_mesh("published")
    surface = grid.extract_surface(algorithm=None)
    c = coupler("published")
    y_start = L_WIRE + c.r_first  # the first groove

    scene = device_scene()
    mirrored = surface.reflect((1, 0, 0), point=(0, 0, 0))
    for name, color in MATERIALS.items():
        scene.add_mesh(mirrored.extract_cells(mirrored.cell_data["material"] == name), color=color)
    save_device(scene, tuple(MATERIALS), "Mesh_stack.png")

    symmetry = surface.extract_cells(np.abs(surface.cell_centers().points[:, 0]) < 1e-6)
    z = grid.cell_centers().points[:, 2]
    layer = grid.extract_cells((z > T_SI - ETCH) & (z < T_SI)).extract_surface(algorithm=None)
    top = layer.extract_cells(np.isclose(layer.cell_centers().points[:, 2], T_SI))

    # The overall views fit their faces; the close-ups are as high as them in the README.
    b = top.bounds
    plan = (b.x_max - b.x_min) / (b.y_max - b.y_min)
    b = symmetry.bounds
    side = (b.z_max - b.z_min) / (b.y_max - b.y_min)
    ratio = MESH_WIDTH / ZOOM_WIDTH

    zoom, area = mesh_image(top, "xy", (1400, round(1400 * ratio * plan)), 1.2, (1.6, y_start + 0.8, T_SI), 9.0)
    save_titled(zoom, "Top view: start of the grating", ZOOM_WIDTH, "Mesh_top_zoom.png")
    overall, _ = mesh_image(top, "xy", (2000, round(2000 * plan)), 0.5, marker=area)
    save_titled(overall, "Top view: the top of the grooves", MESH_WIDTH, "Mesh_top.png")

    zoom, area = mesh_image(symmetry, "yz", (1400, round(1400 * ratio * side)), 1.2, (0.0, y_start + 0.4, 0.1), 16.0)
    save_titled(zoom, "Side view: start of the grating", ZOOM_WIDTH, "Mesh_side_zoom.png")
    overall, _ = mesh_image(symmetry, "yz", (2000, round(2000 * side)), 0.4, marker=area)
    save_titled(overall, "Side view: the symmetry plane", MESH_WIDTH, "Mesh_side.png")


# ---- the fields ----------------------------------------------------------------------------------

def read_fields(design):
    """The exported electric field of a run, all bodies and partitions in one grid, in um."""
    reader = vtkHDFReader()
    reader.SetFileName(os.path.join(run_dir(design), "Output.vtkhdf"))
    merge = vtkMergeBlocks()
    merge.SetMergePoints(False)  # the field is discontinuous between the cells
    merge.SetInputConnection(reader.GetOutputPort())
    merge.Update()
    fields = pv.wrap(merge.GetOutput())
    fields.points *= 1e6
    return fields


def complex_ex(mesh):
    return mesh["Electric Field-Real"][:, 0] + 1j * mesh["Electric Field-Imag"][:, 0]


@functools.cache
def field_limit():
    """The colour range of E_x [V/m], for both designs: the E_x the published coupler radiates above
    the grating, on the symmetry plane; the guided wave, much stronger, saturates."""
    sym = read_fields("published").slice(normal="x", origin=(1e-3, 0, 0))
    above = sym.points[:, 2] > T_SI + 0.5
    return float(np.percentile(np.abs(complex_ex(sym)[above]), 99.5))


ANIMATION_SCALE = 11.6  # [um] half the height of the animations' view: the published model's fit, for both designs


def figure_animation(design):
    """E_x(t) = Re(E_x e^{j phase}) over one period on the surface of the half model, seen as in the
    3D views of the device: the symmetry plane towards the camera, the beam leaving through the top."""
    surface = read_fields(design).extract_surface(algorithm=None).reflect((1, 0, 0), point=(0, 0, 0))
    ex = complex_ex(surface)
    limit = field_limit()
    scene = create_scene((1400, 1200))
    surface["E_x"] = ex.real
    scene.add_mesh(surface, scalars="E_x", cmap=WAVE_MAP, clim=(-limit, limit), name="field")
    scene.view_vector((0.55, -1.0, 0.8), viewup=(0, 0, 1))
    scene.camera.parallel_scale = ANIMATION_SCALE

    frames = []
    for phase in np.arange(0.0, 360.0, 20.0):
        surface["E_x"] = (ex * np.exp(1j * np.radians(phase))).real
        scene.render()
        frames.append(scene.screenshot())
    scene.close()
    frames = crop(frames)
    bar = colorbar_image(frames[0].shape[1])
    frames = [np.vstack([frame, bar]) for frame in frames]
    save_gif(frames, os.path.join(RESULTS, f"Animation_Electric_Field_{LABEL[design]}.gif"), fps=12)


def colorbar_image(width):
    """The colour bar of the animations as an RGB image width pixels wide, to go under their frames."""
    limit = field_limit() / 1e6
    fig = plt.figure(figsize=(width / DPI, 1.0), dpi=DPI)
    ax = fig.add_axes((0.08, 0.62, 0.84, 0.25))
    bar = fig.colorbar(matplotlib.cm.ScalarMappable(matplotlib.colors.Normalize(-limit, limit), WAVE_MAP), cax=ax,
                       orientation="horizontal")
    bar.set_label("Electric field $E_x$ [MV/m]", fontsize=11)
    bar.ax.tick_params(labelsize=10)
    fig.canvas.draw()
    image = np.asarray(fig.canvas.buffer_rgba())[:, :, :3].copy()
    plt.close(fig)
    return image


def chosen_trial(rows):
    """The trial of the optimized design, equal up to rounding (its pitch was converted)."""
    optimized = load_design("optimized")
    for row in rows:
        if row["design"] and all(abs(row["design"][k] - v) < 1e-9 for k, v in optimized.items()):
            return row


def figure_trial_history():
    rows = trials()
    fig, ax = plt.subplots(figsize=(9.0, 5.0), layout="constrained")
    ok = [(row["trial"], row["result"]["p_gi50"]) for row in rows if feasible(row["result"])]
    bad = [(row["trial"], row["result"]["p_gi50"]) for row in rows if row["result"] and not feasible(row["result"])]
    ax.plot(*zip(*bad), "o", mfc="none", mec="0.5", label="infeasible (mostly R > 1%)")
    ax.plot(*zip(*ok), "o", color="tab:red", label="feasible")
    published = rows[0]["result"]["p_gi50"]
    ax.axhline(published, color="tab:blue", ls="--", lw=1.2, label="published coupler")
    ax.axvline(N_SOBOL + 0.5, color="0.4", ls=":", lw=1.0)
    ax.text(0.5 * (N_SOBOL + 0.5), 0.365, "Sobol: spread over the space", ha="center", color="0.3", bbox=LABEL_BOX)
    ax.text(18.5, 0.365, "Bayesian (BoTorch)", ha="center", color="0.3", bbox=LABEL_BOX)
    chosen = chosen_trial(rows)
    ax.annotate(f"trial {chosen['trial']}, chosen", (chosen["trial"], chosen["result"]["p_gi50"]),
                (chosen["trial"] - 6, 0.505), arrowprops=dict(arrowstyle="->", color="k"), bbox=LABEL_BOX)
    # The best on the coarse mesh reflects 1.04% on the nominal mesh (see the README).
    best = max((row for row in rows if feasible(row["result"])), key=lambda row: row["result"]["p_gi50"])
    ax.annotate(f"trial {best['trial']}: R 1.04% on the nominal mesh, rejected",
                (best["trial"], best["result"]["p_gi50"]), (best["trial"] - 20, 0.552),
                arrowprops=dict(arrowstyle="->", color="k"), bbox=LABEL_BOX)
    ax.set_xlabel("Trial")
    ax.set_ylabel("Power into the GI50 fibre, $P_{GI50}$")
    ax.set_ylim(0.36, 0.56)
    ax.set_title("Optimization at the published footprint, coarse mesh")
    ax.grid(alpha=0.3)
    ax.legend(loc="lower right", fontsize=9)
    save(fig, RESULTS, "Trial_History.png")


def figure_fan_outlines():
    fig, axes = plt.subplots(1, 2, figsize=(10.0, 6.0), sharey=True, layout="constrained")
    for ax, design in zip(axes, DESIGNS):
        c = coupler(design)
        plan_outline(ax, c, COLOR[design])
        ax.set_title(f"{LABEL[design]}: half angle {c.fan_angle:.1f}°, {c.ramp_grooves + c.n_periods} grooves,\n"
                     f"groove {c.groove:.2f} of the {1e3 * c.pitch:.1f} nm pitch, footprint {c.footprint:.0f} µm²",
                     fontsize=11)
        ax.set_aspect("equal")
        ax.set_xlim(-8.5, 8.5)
        ax.set_xlabel("x [µm]")
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("y [µm]")
    save(fig, RESULTS, "Fan_Outlines.png")


# ---- near and far field ------------------------------------------------------------------------

def relative_map(ax, h, v, values):
    """values (0 to 1) over the grid h, v as a colour map."""
    return ax.pcolormesh(h, v, values, cmap=MAGNITUDE_MAP, vmin=0.0, vmax=1.0, shading="auto", rasterized=True)


def figure_near_field():
    data = {d: beam(d) for d in DESIGNS}
    high = max(float((np.abs(b["ex"]) ** 2).max()) for b in data.values())
    fig, axes = plt.subplots(1, 2, figsize=(11.0, 4.6), sharex=True, sharey=True, layout="constrained")
    for ax, design in zip(axes, DESIGNS):
        b, m = data[design], metrics(design)
        intensity = np.abs(b["ex"]) ** 2 / high
        image = relative_map(ax, b["y"], mirror(b["x"], -1.0), mirror(intensity))
        ax.set_title(f"{LABEL[design]}: spot {m['spot_x']:.1f} × {m['spot_y']:.1f} µm (D4σ)", fontsize=11)
        ax.set_facecolor(matplotlib.colormaps[MAGNITUDE_MAP](0.0))  # no field outside the beam plane
        ax.set_xlim(6.0, 27.0)
        ax.set_ylim(-8.0, 8.0)
        ax.set_aspect("equal")
        ax.set_xlabel("y, along the fan [µm]")
    axes[0].set_ylabel("x, across [µm]")
    fig.colorbar(image, ax=axes, label="$|E_x|^2$, relative", shrink=0.8)
    save(fig, RESULTS, "Near_Field.png")


def acceptance_cone():
    """The edge of the GI50 fibre's acceptance (NA 0.2 around the pin's 8 deg axis in its core) as
    (angle along, angle across) [deg]."""
    tilt, half = np.radians(PIN_TILT), np.arcsin(NA_GI50 / N_CORE)
    psi = np.linspace(0.0, 2.0 * np.pi, 361)
    axis = np.array([0.0, np.sin(tilt), np.cos(tilt)])  # the pin axis, and two directions across it
    across_x, across_y = np.array([1.0, 0, 0]), np.array([0.0, np.cos(tilt), -np.sin(tilt)])
    around = np.outer(across_x, np.cos(psi)) + np.outer(across_y, np.sin(psi))
    edge = np.cos(half) * axis[:, None] + np.sin(half) * around
    return np.degrees(np.arcsin(edge[1])), np.degrees(np.arcsin(edge[0]))


def figure_far_field():
    fig, axes = plt.subplots(1, 2, figsize=(11.0, 5.0), sharey=True, layout="constrained")
    spectra = {}
    for design in DESIGNS:
        b = beam(design)
        spectra[design] = far_field(b["x"], b["y"], b["ex"], float(b["phase_sign"]))
    high = max(float(s[2].max()) for s in spectra.values())
    for ax, design in zip(axes, DESIGNS):
        ux, uy, power, accepted = spectra[design]
        theta_x, theta_y = np.degrees(np.arcsin(ux / N_CORE)), np.degrees(np.arcsin(uy / N_CORE))
        image = relative_map(ax, mirror(theta_y), mirror(theta_x, -1.0), mirror(power) / high)
        ax.plot(*acceptance_cone(), color="w", lw=1.5, ls="--")
        m = metrics(design)
        ax.set_title(f"{LABEL[design]}: {100 * m['acc_gi50']:.1f}% inside the fibre's acceptance", fontsize=11)
        ax.set_xlim(-12.0, 28.0)
        ax.set_ylim(-20.0, 20.0)
        ax.set_aspect("equal")
        ax.set_xlabel("Angle in the resin, along the fan [deg]")
    axes[0].set_ylabel("Angle across [deg]")
    fig.colorbar(image, ax=axes, label="Power per direction, relative", shrink=0.8)
    save(fig, RESULTS, "Far_Field.png")


FIGURES = {
    "principle": figure_principle,
    "geometry": figure_geometry,
    "constraints": figure_constraints,
    "mesh": figure_mesh,
    "animation_published": lambda: figure_animation("published"),
    "animation_optimized": lambda: figure_animation("optimized"),
    "trial_history": figure_trial_history,
    "fan_outlines": figure_fan_outlines,
    "near_field": figure_near_field,
    "far_field": figure_far_field,
}


def run(names):
    """Draw the figures names (empty: all of FIGURES)."""
    unknown = set(names) - set(FIGURES)
    if unknown:
        raise SystemExit(f"unknown figures {sorted(unknown)}; known: {', '.join(FIGURES)}")
    os.makedirs(DATA, exist_ok=True)
    os.makedirs(RESULTS, exist_ok=True)
    for name in names or FIGURES:
        print(f"[figure] {name}", flush=True)
        FIGURES[name]()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("figures", nargs="*", help=f"the figures to draw (default: all of {', '.join(FIGURES)})")
    args = ap.parse_args()
    run(args.figures)


if __name__ == "__main__":
    main()
