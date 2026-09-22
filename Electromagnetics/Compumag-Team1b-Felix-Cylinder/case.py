import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2])
)  # repo root: validation_case
import mufem

from mufem import Bnd, Vol
from plots import xy_plot, PlotStyle
from mufem.electromagnetics.timedomainmagnetic import (
    TangentialMagneticFieldBoundaryCondition,
    TimeDomainMagneticGeneralMaterial,
    TimeDomainMagneticModel,
)

from pathlib import Path

dir_path = Path(__file__).resolve().parent


from validation_case import ValidationCase


class Team1bFelixCylinder(ValidationCase):
    tags = {"moderate"}

    def run(self):
        sim = mufem.Simulation.New(
            name="Compumag Team1b: Felix Cylinder",
            mesh_path=f"{dir_path}/geometry.mesh",
        )

        # Setup Problem
        mufem.UnsteadyRunner(
            total_time=0.02, time_step_size=0.001, total_inner_iterations=3
        )

        magnetic_model = TimeDomainMagneticModel(
            order=1, magnetostatic_initialization=True
        )
        sim.get_model_manager().add_model(magnetic_model)

        # Setup Materials
        air_material = TimeDomainMagneticGeneralMaterial(name="Air", marker="Air" @ Vol)

        copper_material = TimeDomainMagneticGeneralMaterial(
            name="Al", marker="Cylinder" @ Vol, electric_conductivity=25380710.659898475
        )
        magnetic_model.add_materials([air_material, copper_material])

        # Setup Boundary Conditions
        cff_magnetic_field = mufem.CffExpressionVector(
            "[0, 79577.488101574*exp(-{Time}/0.0069), 0]"
        )

        tangential_magnetic_field_bc = TangentialMagneticFieldBoundaryCondition(
            name="ExternalField",
            marker="Air::Boundary" @ Bnd,
            tangential_magnetic_field=cff_magnetic_field,
        )
        magnetic_model.add_condition(tangential_magnetic_field_bc)

        # Setup Reports
        ohmic_heating_report = mufem.VolumeIntegralReport(
            name="Ohmic Heating", marker="Cylinder" @ Vol, cff_name="Ohmic Heating"
        )
        sim.get_report_manager().add_report(ohmic_heating_report)

        ohmic_heating_monitor = mufem.ReportMonitor(
            name="Ohmic Heating Monitor", report_name="Ohmic Heating"
        )
        sim.get_monitor_manager().add_monitor(ohmic_heating_monitor)

        sim.run()

        vis = sim.get_field_exporter()
        vis.add_field_output("Magnetic Flux Density")
        vis.add_field_output("Electric Current Density")
        vis.save()

        # Plot the losses

        xy_plot(
            values=ohmic_heating_monitor.get_values(),
            style=PlotStyle.LINE_AND_POINTS,
            reference_file=f"{dir_path}/data/PowerLoss.csv",
            reference_style=PlotStyle.POINTS,
            reference_label="Davey (1988)",
            xlabel="Time [s]",
            ylabel="Ohmic Heating Loss [W]",
            xlim=(0.0, 0.02),
            xticks=[0, 0.01, 0.02],
            ylim=(0.0, 600.0),
            path=f"{dir_path}/results/OhmicHeating.png",
        )


if __name__ == "__main__":
    Team1bFelixCylinder().run()
