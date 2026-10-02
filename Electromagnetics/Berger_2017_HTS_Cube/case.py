from validation_tools import PlotStyle, ValidationCase, expect, xy_plot

import math

import mufem
from mufem import Bnd, Vol
from mufem.electromagnetics.module.superconductor import SuperconductorMagneticMaterial
from mufem.electromagnetics.timedomainmagnetic import (
    LineSearchStrategy,
    TangentialMagneticFieldBoundaryCondition,
    TangentialMagneticFluxBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)

FREQUENCY = 50.0  # [Hz]
PERIOD = 1.0 / FREQUENCY


class Berger2017HtsCube(ValidationCase):
    name = "Berger (2017): High-Temperature Superconductor Cube"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import Box, Glue, Sphere, X, Y, Z

        from validation_tools.meshing import color_air, color_hts, name_body

        length_cube = 0.01
        # The 100 mm air radius matches the paper's air box and keeps the dipole
        # perturbation at the outer boundary negligible.
        radius_air = 0.1

        # 1/8 of the cube (positive octant). The field is along Y: X = 0 and Z = 0 are
        # B-tangential symmetry planes, Y = 0 is the B-normal plane.
        cube = Box((0, 0, 0), (length_cube / 2, length_cube / 2, length_cube / 2))
        name_body(cube, "Cube", color=color_hts)

        cube.faces.Min(X).name = "Cube::TangentialFlux::X"
        cube.faces.Min(Z).name = "Cube::TangentialFlux::Z"
        cube.faces.Min(Y).name = "Cube::NormalField"
        cube.faces.Max(X).name = "Cube::AirInterface::X"
        cube.faces.Max(Y).name = "Cube::AirInterface::Y"
        cube.faces.Max(Z).name = "Cube::AirInterface::Z"
        cube.maxh = 0.0005

        # 1/8 of the air ball with the cube cut out.
        air_box = Box((0, 0, 0), (radius_air, radius_air, radius_air))
        air_sphere = Sphere((0, 0, 0), radius_air)
        air = (air_sphere * air_box) - cube
        name_body(air, "Air", color=color_air)

        air.faces.Min(X).name = "Air::TangentialFlux::X"
        air.faces.Min(Z).name = "Air::TangentialFlux::Z"
        air.faces.Min(Y).name = "Air::NormalField"
        air.faces[0].name = "Air::Outer"  # spherical surface where the field is applied

        geometry = Glue([cube, air])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from validation_tools.meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=5.0e-2, path=self.mesh_path)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        runner = mufem.UnsteadyRunner(
            total_time=PERIOD,
            time_step_size=PERIOD / 50.0,
            total_inner_iterations=10,
        )
        sim.set_runner(runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeDomainMagneticModel(order=1, magnetostatic_initialization=False)
        sim.get_model_manager().add_model(magnetic_model)

        # Line search stabilises Newton's iteration on the n=25 power-law nonlinearity.
        line_search = magnetic_model.get_solver().get_line_search()
        line_search.set_active(True)
        line_search.set_strategy(LineSearchStrategy.ThreePointQuadratic)
        line_search.set_iteration_window(min_iter=0, max_iter=100000000)
        line_search.set_residual_skip_threshold(1.0e-10)
        line_search.set_max_alpha(1.0)

        # Materials --------------------------------------------------------------------
        air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

        # n=25, Jc=2.5e6 A/m^2, Ec=1e-4 V/m are characteristic of commercial Bi-2223
        # (1G HTS tape) at 77 K self-field, matching Berger 2017 §II.B.
        hts_material = SuperconductorMagneticMaterial(
            name="Bi-2223",
            marker="Cube" @ Vol,
            Ec=1.0e-4,
            Jc=2.5e6,
            n=25,
        )

        magnetic_model.add_materials([air_material, hts_material])

        # Boundary conditions ----------------------------------------------------------
        # Applied field: B_a(t) = B_max sin(2 pi f t) along y.
        # B_max = 20 mT > B_p = mu0 * Jc * d / 2 ~ 15.7 mT places the case in the
        # full-penetration regime.
        b_max = 20.0e-3
        h_max = b_max / (4.0e-7 * math.pi)

        cff_applied_field = mufem.CffExpressionVector(
            f"[0, {h_max}*sin(2*pi*{FREQUENCY}*{{Time}}), 0]"
        )

        applied_field_bc = TangentialMagneticFieldBoundaryCondition(
            name="Applied Field",
            marker="Air::Outer" @ Bnd,
            tangential_magnetic_field=cff_applied_field,
        )

        # 1/8-symmetry: x=0 and z=0 are B-tangential planes (Tangential-A=0).
        symmetry_bc = TangentialMagneticFluxBoundaryCondition(
            name="Symmetry Plane",
            marker=[
                "Cube::TangentialFlux::X",
                "Cube::TangentialFlux::Z",
                "Air::TangentialFlux::X",
                "Air::TangentialFlux::Z",
            ]
            @ Bnd,
        )

        magnetic_model.add_conditions([applied_field_bc, symmetry_bc])

        # Reports ----------------------------------------------------------------------
        ohmic_heating_report = mufem.VolumeIntegralReport(
            name="Ohmic Heating", marker="Cube" @ Vol, cff_name="Ohmic Heating"
        )
        sim.get_report_manager().add_report(ohmic_heating_report)

        self.ohmic_heating_monitor = mufem.ReportMonitor(
            name="Ohmic Heating Monitor", report_name="Ohmic Heating"
        )
        sim.get_monitor_manager().add_monitor(self.ohmic_heating_monitor)

        return sim

    def validate(self):
        # Peak AC loss over the period; the octant model integrates 1/8 of the cube.
        peak_loss = 8.0 * max(loss for _, loss in self.ohmic_heating_monitor.get_values())
        expect(peak_loss, 0.02983, rel_tol=1e-2, label="peak AC loss [W]")

    def postprocess(self):
        if self.is_main():
            xy_plot(
                values=self.ohmic_heating_monitor.get_values(),
                xscale=1.0e3,  # s -> ms
                yscale=8.0e3,  # octant W -> full-cube mW (x8, x1e3)
                style=PlotStyle.LINE_AND_POINTS,
                reference_file=f"{self.dir_path}/data/AC_Losses_B20mT.csv",
                reference_style=PlotStyle.POINTS,
                reference_label="Berger et al. (2017)",
                xlabel="Time [ms]",
                ylabel="Ohmic Heating [mW]",
                xlim=(0.0, 1.0e3 * PERIOD),
                ylim=(0.0, None),
                path=f"{self.results_path / 'Ohmic_Heating.png'}",
            )

        # ParaView export (collective) ------------------------------------------------
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Magnetic Flux Density")
        vis.add_field_output("Electric Current Density")
        vis.save()


if __name__ == "__main__":
    Berger2017HtsCube().run()
