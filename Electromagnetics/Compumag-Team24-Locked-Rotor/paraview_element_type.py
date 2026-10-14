"""Render results/Scene_ElementType.png: prism (6) and tetrahedral (4) elements.

Run the case with `output_for_animation = True` first (it exports the element type), then:

    pvbatch paraview_element_type.py
"""

import os

import paraview.simple as pvs

script_dir = os.path.dirname(os.path.abspath(__file__))

view = pvs.CreateView("RenderView")
pvs._DisableFirstRenderCameraReset()
view.ViewSize = [1989, 1471]
view.OrientationAxesVisibility = 0
view.UseColorPaletteForBackground = 0
view.Background = [1.0, 1.0, 1.0]

data = pvs.OpenDataFile(f"{script_dir}/VisualizationOutput/Output_0.vtpc")
blocks = pvs.ExtractBlock(
    Input=data, Selectors=["/Root/Stator", "/Root/Rotor", "/Root/LowerCoil", "/Root/UpperCoil"]
)

# The camera looks from +z at the symmetry plane z = 0, where the prism layers show as quads.
display = pvs.Show(blocks, view, "UnstructuredGridRepresentation")
display.Representation = "Surface With Edges"
display.EdgeColor = [0.0, 0.0, 0.0]
pvs.ColorBy(display, ("POINTS", "Element Type"))

ctf = pvs.GetColorTransferFunction("ElementType")
ctf.ApplyPreset("Cool to Warm", True)
ctf.RescaleTransferFunction(4.0, 6.0)

display.SetScalarBarVisibility(view, True)
scalar_bar = pvs.GetScalarBar(ctf, view)
scalar_bar.Title = "Element Type"
scalar_bar.ComponentTitle = ""
scalar_bar.TitleColor = [0.0, 0.0, 0.0]
scalar_bar.LabelColor = [0.0, 0.0, 0.0]
scalar_bar.TitleFontSize = 30
scalar_bar.LabelFontSize = 28
scalar_bar.WindowLocation = "Any Location"
scalar_bar.Position = [0.86, 0.04]
scalar_bar.ScalarBarLength = 0.35
scalar_bar.RangeLabelFormat = "%-#6.1e"

view.CameraPosition = [-0.012, 0.06, 0.16]
view.CameraFocalPoint = [0.0, 0.045, -0.006]
view.CameraViewUp = [0.0, 1.0, 0.0]
view.CameraViewAngle = 30.0

pvs.Render(view)
pvs.SaveScreenshot(
    f"{script_dir}/results/Scene_ElementType.png", view, ImageResolution=[1989, 1471]
)
