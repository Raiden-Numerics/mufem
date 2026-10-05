from casekit import ValidationCase, expect

import mufem
from mufem import Bnd, Vol
from mufem.electromagnetics.coil import (
    CoilExcitationCurrent,
    CoilSpecification,
    CoilTopologyOpen,
    CoilTypeSolid,
    ExcitationCoilModel,
)
from mufem.electromagnetics.timeharmonicmagnetic import (
    TangentialMagneticFluxBoundaryCondition,
    TimeHarmonicMagneticGeneralMaterial,
    TimeHarmonicMagneticModel,
)


class Biro1993IronCore(ValidationCase):
    name = "Biro 1993: 3D Iron Core Current Driven Conductors"
    tags = {"eternal"}

    # 5 x 5 conductors
    number_of_coils = 25

    def build_geometry(self):
        from netgen.occ import Box, Cylinder, Glue, X, Y, Z

        from casekit.geometry_helpers import hollow_cylinder
        from casekit.meshing import color_air, color_copper, color_iron, name_body

        # Core -------------------------------------------------------------------------
        box_1 = Box((0, 0, 0.000), (0.025, 0.01, 0.018))
        box_2 = Box((0, 0, 0.0), (0.012, 0.01, 0.001))

        core_hole = hollow_cylinder(r_inner=0.0118, r_outer=0.019, axis=Z, height=0.012)

        core = box_1 - box_2 - core_hole
        name_body(core, "Core", color=color_iron, individual_names=False)

        core.faces.Min(Y).name = "Core::Front"
        core.faces.Min(X).name = "Core::Back"
        core.faces.Min(Z).name = "Core::Symmetry"

        octant = Box((0, 0, 0), (0.05, 0.05, 0.05))

        # Air --------------------------------------------------------------------------
        air = Cylinder((0.0, 0.0, 0.0), Z, r=0.04, h=0.035) * octant
        name_body(air, "Air", color=color_air, individual_names=False)
        air.faces.name = "Air::TangentialFlux"
        air.faces.Min(Z).name = "Air::Symmetry"

        air = air - core

        # Coils: 5 x 5 conductors of 1 mm x 2 mm with a 0.1 mm gap ---------------------
        coils = []

        for i in range(self.number_of_coils):
            gap = 0.0001

            row = i % 5
            col = 4 - i // 5

            r_inner = 0.012 + row * 0.001 + gap
            r_outer = r_inner + 0.001 - gap

            height = 0.002 - gap
            offset_y = col * 0.002 + gap

            coil = hollow_cylinder(
                r_inner=r_inner, r_outer=r_outer, axis=Z, height=height, offset=offset_y
            )

            coil = coil * octant
            name_body(coil, f"Coil {i + 1}", color=color_copper, individual_names=False)

            coil.faces.Min(Y).name = f"Coil {i + 1}::Front"
            coil.faces.Min(X).name = f"Coil {i + 1}::Back"

            coil.maxh = 0.00035

            coils.append(coil)

        geometry = Glue([core, *coils, air])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=0.05, path=self.mesh_path, second_order=True)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        runner = mufem.SteadyRunner(total_iterations=1)
        sim.set_runner(runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeHarmonicMagneticModel(frequency=5000, order=2)
        sim.get_model_manager().add_model(magnetic_model)

        magnetic_solver = magnetic_model.get_solver()
        magnetic_solver.set_verbose(True)
        magnetic_solver.set_iteration_number(150)

        # Materials --------------------------------------------------------------------
        air_material = TimeHarmonicMagneticGeneralMaterial(
            "Air", "Air" @ Vol, has_eddy_currents=False
        )

        core_material = TimeHarmonicMagneticGeneralMaterial(
            "Iron",
            Vol("Core.*"),
            magnetic_permeability=1000.0,
            has_eddy_currents=False,
        )

        copper_material = TimeHarmonicMagneticGeneralMaterial(
            "Copper",
            Vol("Coil.*"),
            electric_conductivity=5.6e7,
            has_eddy_currents=True,
        )

        magnetic_model.add_materials([air_material, core_material, copper_material])

        # Boundary conditions ----------------------------------------------------------
        tangential_magnetic_flux_bc = TangentialMagneticFluxBoundaryCondition(
            "Tangential Flux",
            Bnd(".*Front") + Bnd(".*Back") + "Air::TangentialFlux" @ Bnd,
        )

        magnetic_model.add_condition(tangential_magnetic_flux_bc)

        # Coils ------------------------------------------------------------------------
        coil_model = ExcitationCoilModel()
        sim.get_model_manager().add_model(coil_model)

        for n in range(self.number_of_coils):
            coil_topology = CoilTopologyOpen(
                f"Coil {n + 1}::Back" @ Bnd, f"Coil {n + 1}::Front" @ Bnd
            )
            coil_type = CoilTypeSolid()
            coil_type.drive_method = CoilTypeSolid.DriveMethod.Source

            coil_excitation = CoilExcitationCurrent(current=(10, 0.0))

            coil = CoilSpecification(
                f"Coil {n + 1}",
                Vol(f"Coil {n + 1}"),
                coil_topology,
                coil_type,
                coil_excitation,
            )
            coil_model.add_coil_specification(coil)

        return sim

    def validate(self):
        # Ohmic loss per conductor; the model covers a quarter of the device.
        ohmic_losses = []
        for n in range(self.number_of_coils):
            report = mufem.VolumeIntegralReport(
                "Ohmic Heating", f"Coil {n + 1}" @ Vol, "Ohmic Heating"
            )
            ohmic_losses.append(4.0 * report.evaluate())

        if self.is_main():
            for n, loss in enumerate(ohmic_losses):
                print(f"Coil {n + 1}: Ohmic Heating = {loss:.5f} W")

        # Conductor 21 sits next to the core and carries the largest loss.
        expect(ohmic_losses[20], 7.2703, rel_tol=5e-2, label="ohmic loss coil 21 [W]")
        expect(sum(ohmic_losses), 19.349, rel_tol=5e-2, label="total ohmic loss [W]")

    def postprocess(self):
        # ParaView export (collective) ------------------------------------------------
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Magnetic Flux Density-Real")
        vis.add_field_output("Magnetic Flux Density-Imag")
        vis.add_field_output("Electric Current Density-Real")
        vis.add_field_output("Electric Current Density-Imag")
        vis.save(order=2)


if __name__ == "__main__":
    Biro1993IronCore().run()
