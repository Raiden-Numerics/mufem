"""Colors of the bodies of the cases, shared by the geometry (casekit.netgen_geometry,
casekit.gmsh_meshing.color_step) and its image."""

from typing import Optional, Tuple

Color = Tuple[float, ...]


def hex_to_float(hex: str, transparency: Optional[float] = None) -> Color:
    """RGB color from "rrggbb"; with `transparency` in [0, 1] an RGBA color."""
    rgb = tuple(int(hex[i : i + 2], 16) / 255.0 for i in (0, 2, 4))

    if transparency is None:
        return rgb

    if not 0.0 <= transparency <= 1.0:
        raise ValueError("Transparency must be between 0.0 and 1.0")

    return rgb + (1.0 - transparency,)


color_air = hex_to_float("a6e7ff", transparency=0.6)
color_aluminum = hex_to_float("848789")
color_blue = hex_to_float("00a2e8")
color_copper = hex_to_float("B87333")
color_green = hex_to_float("00af7f")
color_hts = hex_to_float("4c9173")
color_iron = hex_to_float("a19d94")
color_red = hex_to_float("ed1c24")
color_steel = hex_to_float("71797E")
