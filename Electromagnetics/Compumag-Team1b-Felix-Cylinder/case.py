from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot

import mufem
from mufem import Bnd, Vol
from mufem.electromagnetics.timedomainmagnetic import (
    TangentialMagneticFieldBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)


class Team1bFelixCylinder(ValidationCase):
    name = "Compumag Team1b: Felix Cylinder"
    tags = {"moderate"}

    def build_geometry(self):
        from netgen.occ import Box, Cylinder, Glue, Pnt, Z, gp_Ax2

        from casekit.netgen_geometry import color_air, color_copper, name_body

        cylinder_length = 0.20
        cylinder_inner_radius = 0.05715
        cylinder_outer_radius = 0.06985

        air_box_half_length = cylinder_length

        # Cylinder ---------------------------------------------------------------------
        axis_z = gp_Ax2((0, 0, -cylinder_length / 2), Z)

        cylinder_outer = Cylinder(axis_z, cylinder_outer_radius, cylinder_length)
        cylinder_inner = Cylinder(axis_z, cylinder_inner_radius, cylinder_length)

        cylinder_body = cylinder_outer - cylinder_inner

        name_body(cylinder_body, "Cylinder", color=color_copper)

        # Air --------------------------------------------------------------------------
        air_pnt0 = Pnt(-air_box_half_length, -air_box_half_length, -air_box_half_length)
        air_pnt1 = Pnt(air_box_half_length, air_box_half_length, air_box_half_length)

        air_body = Box(air_pnt0, air_pnt1)
        name_body(air_body, "Air", color=color_air, individual_names=False)

        air_body = air_body - cylinder_body

        air_body.faces.maxh = 0.05
        cylinder_body.faces.maxh = 0.008

        geometry = Glue([cylinder_body, air_body])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=5.0e-2, path=self.mesh_path)

    def setup_case(self):
        sim = mufem.Simulation.New(
            name=self.name,
            mesh_path=f"{self.mesh_path}",
        )

        runner = mufem.UnsteadyRunner(
            total_time=0.02, time_step_size=0.001, total_inner_iterations=3
        )
        sim.set_runner(runner)

        # Model ------------------------------------------------------------------------
        magnetic_model = TimeDomainMagneticModel(order=1, magnetostatic_initialization=True)
        sim.get_model_manager().add_model(magnetic_model)

        # Materials --------------------------------------------------------------------
        air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

        aluminum_material = TimeDomainMagneticGeneralMaterial(
            name="Al", marker="Cylinder" @ Vol, electric_conductivity=25380710.659898475
        )
        magnetic_model.add_materials([air_material, aluminum_material])

        # Boundary conditions ----------------------------------------------------------
        cff_magnetic_field = mufem.CffExpressionVector(
            "[0, 79577.488101574*exp(-{Time}/0.0069), 0]"
        )

        tangential_magnetic_field_bc = TangentialMagneticFieldBoundaryCondition(
            name="ExternalField",
            marker="Air::Boundary" @ Bnd,
            tangential_magnetic_field=cff_magnetic_field,
        )
        magnetic_model.add_condition(tangential_magnetic_field_bc)

        # Reports ----------------------------------------------------------------------
        self.ohmic_heating_report = mufem.VolumeIntegralReport(
            name="Ohmic Heating", marker="Cylinder" @ Vol, cff_name="Ohmic Heating"
        )
        sim.get_report_manager().add_report(self.ohmic_heating_report)

        self.ohmic_heating_monitor = mufem.ReportMonitor(
            name="Ohmic Heating Monitor", report_name="Ohmic Heating"
        )
        sim.get_monitor_manager().add_monitor(self.ohmic_heating_monitor)

        return sim

    def validate(self):
        # Ohmic heating loss at the final time t = 0.02 s.
        expect(
            self.ohmic_heating_report.evaluate(),
            132.5,
            rel_tol=1e-2,
            label="ohmic heating loss at t = 0.02 s [W]",
        )

    def postprocess(self):
        if self.is_main():
            xy_plot(
                values=self.ohmic_heating_monitor.get_values(),
                style=PlotStyle.LINE_AND_POINTS,
                reference_file=f"{self.dir_path}/data/PowerLoss.csv",
                reference_style=PlotStyle.POINTS,
                reference_label="Davey (1988)",
                xlabel="Time [s]",
                ylabel="Ohmic Heating Loss [W]",
                xlim=(0.0, 0.02),
                xticks=[0, 0.01, 0.02],
                ylim=(0.0, 600.0),
                path=f"{self.results_path / 'OhmicHeating.png'}",
            )

        # ParaView export (collective) ------------------------------------------------
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Magnetic Flux Density")
        vis.add_field_output("Electric Current Density")
        vis.save()


if __name__ == "__main__":
    run_case(Team1bFelixCylinder)
