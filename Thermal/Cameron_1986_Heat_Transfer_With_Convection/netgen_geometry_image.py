"""Render data/Geometry.png from geometry.step with the netgen viewer.

The plate is seen from the front (onto the x-y plane), as the scene of create_scene.py, with
the boundary conditions of the benchmark and the evaluation point E. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python netgen_geometry_image.py
"""

from pathlib import Path

from netgen.occ import OCCGeometry

from casekit.netgen_image import Labels, pad, snapshot, trim

case_dir = Path(__file__).resolve().parent

solids = OCCGeometry(f"{case_dir}/geometry.step").shape.solids
image = snapshot(solids, direction=(0, 0, 1), up=(0, 1, 0), zoom=0, size=(1200, 1600))

# The plate, 0.6 m x 1.0 m, with room around it for the boundary conditions.
plate = trim(image, border=0)
scale = plate.height / 1.0  # [px/m]
left, top, right, bottom = 250, 110, 360, 110
image = pad(plate, left, top, right, bottom)

labels = Labels(image, font_size=32)
x0, x1 = left, left + plate.width
y0, y1 = top, top + plate.height
xm, ym = (x0 + x1) / 2, (y0 + y1) / 2
labels.text((xm, y1 + 55), "T = 100 °C")
labels.text((x0 - 25, ym), "Adiabatic", "rm")
labels.text((xm, y0 - 55), "Convection")
labels.text((x1 + 25, ym - 25), "Convection", "lm")
labels.text((x1 + 25, ym + 25), "h = 750 W/(m² K)", "lm")
labels.text((x1 + 25, ym + 75), "T∞ = 0 °C", "lm")

# Point E on the right edge, 0.2 m above the bottom edge.
e = (x1, y1 - 0.2 * scale)
labels.dot(e)
labels.text((e[0] + 25, e[1]), "E", "lm")

image.save(case_dir / "data" / "Geometry.png")
