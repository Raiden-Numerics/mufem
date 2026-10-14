"""Render data/Geometry.png from geometry.step with the netgen viewer.

The plate is seen from the front (onto the x-y plane), as the scene of create_scene.py, with
the boundary conditions of the benchmark. Needs a display; headless:

    xvfb-run -a -s "-screen 0 2400x1600x24" python netgen_geometry_image.py
"""

import os

import matplotlib
import netgen
import netgen.gui
from netgen.occ import Glue, OCCGeometry
from PIL import Image, ImageDraw, ImageFont, ImageOps

script_dir = os.path.dirname(os.path.abspath(__file__))
width, height = 1200, 1600

shape = OCCGeometry(f"{script_dir}/geometry.step").shape
OCCGeometry(Glue(shape.solids)).Draw()

tk = netgen.gui.win.tk
tk.eval(f"wm geometry . {width}x{height}")
netgen.Redraw(blocking=True)

image = Image.fromarray(netgen.gui.Snapshot(width, height)).convert("RGB")

# Trim the white margins: the image is then the plate, 0.6 m x 1.0 m.
plate = image.crop(ImageOps.invert(image).getbbox())
scale = plate.height / 1.0  # [px/m]

# Room around the plate for the boundary conditions.
left, top, right, bottom = 250, 110, 360, 110
image = Image.new("RGB", (plate.width + left + right, plate.height + top + bottom), "white")
image.paste(plate, (left, top))
draw = ImageDraw.Draw(image)
font = ImageFont.truetype(f"{matplotlib.get_data_path()}/fonts/ttf/DejaVuSans-Bold.ttf", 32)

x0, x1 = left, left + plate.width
y0, y1 = top, top + plate.height
draw.text(((x0 + x1) / 2, y1 + 55), "T = 100 °C", font=font, fill="black", anchor="mm")
draw.text((x0 - 25, (y0 + y1) / 2), "Adiabatic", font=font, fill="black", anchor="rm")
draw.text(((x0 + x1) / 2, y0 - 55), "Convection", font=font, fill="black", anchor="mm")
draw.text((x1 + 25, (y0 + y1) / 2 - 25), "Convection", font=font, fill="black", anchor="lm")
draw.text((x1 + 25, (y0 + y1) / 2 + 25), "h = 750 W/(m² K)", font=font, fill="black", anchor="lm")
draw.text((x1 + 25, (y0 + y1) / 2 + 75), "T∞ = 0 °C", font=font, fill="black", anchor="lm")

# Point E on the right edge, 0.2 m above the bottom edge.
e = (x1, y1 - 0.2 * scale)
draw.ellipse([e[0] - 12, e[1] - 12, e[0] + 12, e[1] + 12], fill="black")
draw.text((e[0] + 25, e[1]), "E", font=font, fill="black", anchor="lm")

image.save(f"{script_dir}/data/Geometry.png")
