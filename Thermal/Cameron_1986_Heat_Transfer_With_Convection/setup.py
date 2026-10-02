from netgen.occ import Box, Glue, X, Y

from validation_tools.meshing import mesh_and_save, name_body, nice_green


def create_geometry():

    plate_body = Box((0, 0, 0), (0.6, 1.0, 0.01))

    name_body(plate_body, "Plate", color=nice_green)

    plate_body.faces.Min(X).name = "Plate::Insulated"
    plate_body.faces.Max(X).name = "Plate::AmbientTemperature"

    plate_body.faces.Min(Y).name = "Plate::FixedTemperature"
    plate_body.faces.Max(Y).name = "Plate::AmbientTemperature"

    geometry = Glue([plate_body])

    geometry.WriteStep("geometry.step")

    return geometry


if __name__ == "__main__":
    geometry = create_geometry()

    mesh_and_save(geometry, basesize=0.02)
