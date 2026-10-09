from casekit import PlotStyle, ValidationCase, expect, run_case, xy_plot


import numpy

import mufem
import mufem.methods as method
from mufem.electromagnetics.coil import (
    CoilExcitationCurrent,
    CoilSpecification,
    CoilTopologyOpen,
    CoilTypeStranded,
    ExcitationCoilModel,
)
from mufem.electromagnetics.timeharmonicmagnetic import (
    MagneticPermeabilityMethodTemperatureTableSusceptibility,
    RelaxationType as MagneticRelaxationType,
    TangentialMagneticFluxBoundaryCondition,
    TimeHarmonicMagneticGeneralMaterial,
    TimeHarmonicMagneticModel,
)
from mufem.thermal import (
    ConvectionBoundaryCondition,
    RadiationBoundaryCondition,
    RelaxationType as ThermalRelaxationType,
    SolidTemperatureMaterial,
    SolidTemperatureModel,
)


class Team36InductionHeating(ValidationCase):
    name = "Compumag TEAM 36: Induction Heating Device"
    tags = {"long"}

    def build_geometry(self):
        from netgen.occ import Cylinder, Glue, Vec, X, Y, Z

        from casekit.netgen_geometry import (
            color_air,
            color_copper,
            color_iron,
            name_body,
            polygon_face,
            revolve_rotate_cut,
            triangle_sector,
        )

        billet_axial_length = 1.0
        billet_external_radius = 0.03
        coil_internal_radius = 0.048
        coil_axial_length = 0.04
        coil_radial_width = 0.02
        copper_thickness = 0.003

        # 30-degree sector of the axisymmetric device, bounded by symmetry planes.
        cut = triangle_sector(1.0, 30, 1.0)

        # Billet: a rectangular cross-section revolved into the sector -------------------
        billet_face = polygon_face(
            [
                (0, 0, 0),
                (billet_external_radius, 0, 0),
                (billet_external_radius, billet_axial_length / 2, 0),
                (0, billet_axial_length / 2, 0),
            ]
        )
        billet = revolve_rotate_cut(billet_face, cut)
        # The billet surface, where the eddy currents and heating concentrate, dominates
        # the mesh size.
        billet.faces.maxh = 2.0e-3

        name_body(billet, "Billet", color=color_iron)
        billet.faces.Min(Z).name = "Billet::1::Symmetry::TangentialFlux"
        billet.faces.Max(Z).name = "Billet::2::Symmetry::TangentialFlux"
        billet.faces.Max(X).name = "Billet::2::LatteralSurface"
        billet.faces.Min(Y).name = "Billet::3::Symmetry::Bottom::NormalFlux"
        billet.faces.Max(Y).name = "Billet::EndSurface"

        # Inductor: a hollow copper turn (outer minus inner), replicated axially ----------
        half_offset = 0.2 / 19.0 / 2.0  # 19 gaps share 1 m - 20 x 4 cm = 0.2 m
        r0, r1 = coil_internal_radius, coil_internal_radius + coil_radial_width
        y0, y1 = half_offset, half_offset + coil_axial_length
        t = copper_thickness

        coil_outer = revolve_rotate_cut(
            polygon_face([(r0, y0, 0), (r1, y0, 0), (r1, y1, 0), (r0, y1, 0)]),
            cut,
        )
        coil_inner = revolve_rotate_cut(
            polygon_face(
                [
                    (r0 + t, y0 + t, 0),
                    (r1 - t, y0 + t, 0),
                    (r1 - t, y1 - t, 0),
                    (r0 + t, y1 - t, 0),
                ]
            ),
            cut,
        )
        coil = (coil_outer - coil_inner) * cut

        coils = []
        for n in range(10):
            turn = coil.Move(Vec(0, n * (coil_axial_length + 2 * half_offset), 0))
            name_body(turn, f"Coil::{n}", color=color_copper)
            turn.faces.Max(Z).name = f"Coil::{n}::In"
            turn.faces.Min(Z).name = f"Coil::{n}::Out"
            coils.append(turn)

        # Air: the surrounding sector; it overlaps the billet and coils, which Glue
        # resolves ------------------------------------------------------------------------
        air = Cylinder((0, 0, 0), Y, r=0.25, h=0.65) * cut
        name_body(air, "Air", color=color_air)
        air.faces.Max(Z).name = "Air::1::Symmetry::TangentialFlux"
        air.faces.Min(Z).name = "Air::2::Symmetry::TangentialFlux"
        air.faces.Min(Y).name = "Air::3::Symmetry::NormalFlux"
        air.faces.Max(Y).name = "Air::4::Symmetry::TangentialFlux"
        air.faces.Max(X).name = "Air::5::Symmetry::TangentialFlux"

        geometry = Glue([billet, *coils, air])

        geometry.WriteStep(f"{self.step_path}")

    def generate_mesh(self):
        from casekit.netgen_meshing import mesh_and_save

        mesh_and_save(self.step_path, basesize=0.015, path=self.mesh_path)

    def setup_case(self):
        sim = mufem.Simulation.New(name=self.name)

        # De-refinement (used by the adaptive strategy) requires a nonconforming mesh.
        nonconforming_options = mufem.NonConformingOption(
            is_nonconforming=True, simplicies_nonconforming=True
        )
        sim.get_domain().load_mesh(f"{self.mesh_path}", nonconforming=nonconforming_options)

        billet_marker = "Billet" @ mufem.Vol
        air_marker = "Air" @ mufem.Vol

        self.runner = mufem.UnsteadyRunner(
            total_time=100.0,
            time_step_size=5.0,
            total_inner_iterations=8,
        )
        sim.set_runner(self.runner)

        # Time-harmonic magnetic model -------------------------------------------------
        magnetic_model = TimeHarmonicMagneticModel(frequency=2000.0, order=1)
        sim.get_model_manager().add_model(magnetic_model)

        magnetic_solver = magnetic_model.get_solver()
        magnetic_solver.set_under_relaxation_factor(0.7)
        magnetic_solver.set_relaxation_type(MagneticRelaxationType.Aitken)
        magnetic_solver.set_verbose(False)

        air_material = TimeHarmonicMagneticGeneralMaterial("Air", air_marker)

        copper_material = TimeHarmonicMagneticGeneralMaterial(
            "Copper",
            mufem.Vol("Coil::.*"),
            electric_conductivity=5.998e7,
            has_eddy_currents=True,
        )

        # Temperature-dependent steel properties.
        rho_T = self.load_csv("Steel_ElectricResistivity.csv")
        h_b = self.load_csv("Steel_BHCurve.csv")
        xi_T = self.load_csv("Steel_MagneticSusceptibility.csv")

        permeability_method = MagneticPermeabilityMethodTemperatureTableSusceptibility(
            h_b[:, 0], h_b[:, 1], xi_T[:, 0] + 273.15, xi_T[:, 1]
        )

        billet_material = TimeHarmonicMagneticGeneralMaterial(
            "Billet",
            billet_marker,
            permeability_method,
            electric_conductivity=method.TemperatureTable(rho_T[:, 0] + 273.15, 1.0 / rho_T[:, 1]),
            has_eddy_currents=True,
        )

        magnetic_model.add_materials([air_material, copper_material, billet_material])

        # Tangential-flux (symmetry) boundaries, plus every coil terminal face.
        magnetic_model.add_condition(
            TangentialMagneticFluxBoundaryCondition(
                "TangentialFlux",
                mufem.Bnd([".*::TangentialFlux", "Coil::.*::In", "Coil::.*::Out"]),
            )
        )

        # Excitation coils -------------------------------------------------------------
        coil_model = ExcitationCoilModel()
        sim.get_model_manager().add_model(coil_model)

        for n in range(10):
            coil = CoilSpecification(
                "Coil",
                f"Coil::{n}" @ mufem.Vol,
                CoilTopologyOpen(f"Coil::{n}::In" @ mufem.Bnd, f"Coil::{n}::Out" @ mufem.Bnd),
                CoilTypeStranded(1),
                CoilExcitationCurrent(current=3500.0 * numpy.sqrt(2)),  # peak of 3500 A RMS
            )
            coil_model.add_coil_specification(coil)

        # Thermal model ----------------------------------------------------------------
        thermal_model = SolidTemperatureModel(billet_marker, 1)
        sim.get_model_manager().add_model(thermal_model)
        thermal_model.get_initial_condition().set_constant(25.0 + 273.15)

        lambda_T = self.load_csv("Steel_ThermalConductivity.csv")
        cp_T = self.load_csv("Steel_SpecificHeatCapacity.csv")

        thermal_billet_material = SolidTemperatureMaterial(
            name="Billet",
            marker=billet_marker,
            thermal_conductivity=method.TemperatureTable(lambda_T[:, 0] + 273.15, lambda_T[:, 1]),
            specific_heat_capacity=method.TemperatureTable(cp_T[:, 0] + 273.15, cp_T[:, 1]),
            density=7800,
        )
        thermal_model.add_materials([thermal_billet_material])

        # Lateral surface: convection + radiation at 70 °C ambient.
        lateral_surface_marker = "Billet::2::LatteralSurface" @ mufem.Bnd
        thermal_model.add_conditions(
            [
                ConvectionBoundaryCondition(
                    "Lateral Surface Convection", lateral_surface_marker, 7.0, 273.0 + 70.0
                ),
                RadiationBoundaryCondition(
                    "Lateral Surface Radiation", lateral_surface_marker, 0.8, 273.0 + 70.0
                ),
            ]
        )

        # End surface: convection + radiation at 25 °C ambient.
        end_surface_marker = "Billet::EndSurface" @ mufem.Bnd
        thermal_model.add_conditions(
            [
                ConvectionBoundaryCondition(
                    "End Surface Convection", end_surface_marker, 7.0, 273.0 + 25.0
                ),
                RadiationBoundaryCondition(
                    "End Surface Radiation", end_surface_marker, 0.8, 273.0 + 25.0
                ),
            ]
        )

        thermal_solver = thermal_model.get_solver()
        thermal_solver.set_under_relaxation_factor(0.7)
        thermal_solver.set_relaxation_type(ThermalRelaxationType.Aitken)

        # Reports and monitors ---------------------------------------------------------
        ohmic_heating_report = mufem.VolumeIntegralReport(
            name="OhmicHeatingReport", marker=billet_marker, cff_name="Ohmic Heating"
        )
        sim.get_report_manager().add_report(ohmic_heating_report)
        self.ohmic_heating_monitor = mufem.ReportMonitor(
            "Ohmic Heating Monitor", "OhmicHeatingReport"
        )
        sim.get_monitor_manager().add_monitor(self.ohmic_heating_monitor)

        eps = 1.0e-6
        self.temperature_monitors = {}
        for name, point in [("Center", (eps, eps, 0.0)), ("Surface", (0.03 - eps, eps, 0.0))]:
            probe = mufem.ProbeReport.SinglePoint(
                name=name, cff_name="Temperature", x=point[0], y=point[1], z=point[2]
            )
            sim.get_report_manager().add_report(probe)
            self.temperature_monitors[name] = mufem.ReportMonitor(name, name)
            sim.get_monitor_manager().add_monitor(self.temperature_monitors[name])

        self.refinement_model = mufem.RefinementModel()
        sim.get_model_manager().add_model(self.refinement_model)

        return sim

    def solve(self):
        vis = self.sim.get_field_exporter()
        vis.add_field_output("Temperature")
        vis.add_field_output("Magnetic Flux Density-Real")
        vis.add_field_output("Magnetic Flux Density-Imag")
        vis.add_field_output("Ohmic Heating")

        self.sim.initialize()
        vis.save()

        # dt = 5 s, T_end = 100 s -> 20 steps. Refine once at t = 45 s (step 9).
        for _ in range(9):
            self.runner.advance(1)
            vis.save()

        self.refinement_model.refine_mesh()
        vis.save()

        for _ in range(11):
            self.runner.advance(1)
            vis.save()

    def validate(self):
        # Temperatures at t = 100 s; Di Barba et al. (2018), Fig. 8a, interpolated.
        # mufem stays about 2% below the reference curves here.
        temperature = {
            name: monitor.get_values()[-1][1] - 273.15
            for name, monitor in self.temperature_monitors.items()
        }
        expect(temperature["Center"], 811.5, rel_tol=0.15, label="center temperature [°C]")
        expect(temperature["Surface"], 899.2, rel_tol=0.15, label="surface temperature [°C]")

    def postprocess(self):
        if not self.is_main():
            return

        # Ohmic heating of the full device: two halves of twelve 30-degree sectors.
        symmetry_factor = 2 * (360.0 / 30.0)

        ohmic = self.ohmic_heating_monitor.get_values()
        ref_t, ref_p = self.load_csv("Fig6a_Ohmic_Heating_Power.csv").T

        xy_plot(
            values=[(t, p * symmetry_factor * 1e-3) for t, p in ohmic],
            style=PlotStyle.LINE_AND_POINTS,
            reference_values=list(zip(ref_t, ref_p * 1e-3)),
            reference_style=PlotStyle.POINTS,
            reference_label="Di Barba et al. (2017)",
            xlabel="Time t [s]",
            ylabel="Ohmic Heating [kW]",
            xlim=(0, 80),
            path=f"{self.results_path / 'Ohmic_Heating.png'}",
        )

        # Temperature evolution at the center and the surface.
        for name, reference_file in [
            ("Center", "Fig8a_Temperature_vs_Time_0cm.csv"),
            ("Surface", "Fig8a_Temperature_vs_Time_3cm.csv"),
        ]:
            values = self.temperature_monitors[name].get_values()
            ref_t, ref_T = self.load_csv(reference_file).T

            xy_plot(
                values=[(t, T - 273.15) for t, T in values],
                style=PlotStyle.LINE_AND_POINTS,
                reference_values=list(zip(ref_t, ref_T)),
                reference_style=PlotStyle.POINTS,
                reference_label="Di Barba et al. (2018)",
                xlabel="Time [s]",
                ylabel="Temperature [°C]",
                xlim=(0, 100),
                path=f"{self.results_path / f'Temperature_{name}.png'}",
            )

    def load_csv(self, file_name):
        return numpy.loadtxt(self.dir_path / "data" / file_name, delimiter=",", comments="#")


if __name__ == "__main__":
    run_case(Team36InductionHeating)
