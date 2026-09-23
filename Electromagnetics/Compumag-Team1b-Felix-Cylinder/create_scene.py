import paraview.simple as pvs
import os

renderView1 = pvs.CreateView("RenderView")


renderView1.Set(
    ViewSize=[1600, 1300],
    CameraPosition=[-0.331145, 0.126167, -0.215592],
    CameraFocalPoint=[0.00336064, -0.0151335, 0.00804053],
    CameraViewUp=[0.222756, 0.939455, 0.260393],
    CameraViewAngle=30.0,
    EyeAngle=2.0,
    CameraFocalDisk=1.0,
    CameraFocalDistance=0.0,
)


pvs._DisableFirstRenderCameraReset()

script_dir = os.path.dirname(os.path.abspath(__file__))


outputvtpcseries = pvs.XMLPartitionedDatasetCollectionReader(
    registrationName="Output.vtpc.series",
    FileName=[f"{script_dir}/VisualizationOutput/Output.vtpc.series"],
)

glyph1 = pvs.Glyph(registrationName="Current Density", Input=outputvtpcseries, GlyphType="Arrow")

glyph1.Set(
    OrientationArray=["POINTS", "Electric Current Density"],
    ScaleArray=["POINTS", "Electric Current Density"],
    ScaleFactor=1e-08,
    GlyphMode="All Points",
)


# show data from outputvtpcseries
outputvtpcseriesDisplay = pvs.Show(outputvtpcseries, renderView1, "UnstructuredGridRepresentation")

# trace defaults for the display properties.
outputvtpcseriesDisplay.Set(
    Representation="Surface",
    AmbientColor=[0.6901960968971252, 0.6901960968971252, 0.6901960968971252],
    ColorArrayName=["POINTS", ""],
    DiffuseColor=[0.6901960968971252, 0.6901960968971252, 0.6901960968971252],
    ComputePointNormals=1,
    Assembly="Hierarchy",
    BlockSelectors=["/Root/Cylinder"],
)

# show data from glyph1
glyph1Display = pvs.Show(glyph1, renderView1, "GeometryRepresentation")

ctf = pvs.GetColorTransferFunction("ElectricCurrentDensity")
ctf.ApplyPreset("Cool to Warm")
ctf.RescaleTransferFunction(0, 3.0e6)

scalar_bar = pvs.GetScalarBar(ctf)
scalar_bar.Orientation = "Horizontal"
scalar_bar.WindowLocation = "Any Location"

scalar_bar.Title = "Electric Current Density [J/m²]"
scalar_bar.ComponentTitle = ""
scalar_bar.UseCustomLabels = True
scalar_bar.CustomLabels = [0, 1.0e6, 2.0e6, 3.0e6]
scalar_bar.TitleFontSize = 32
scalar_bar.LabelFontSize = 28
scalar_bar.TitleBold = 1
scalar_bar.LabelBold = 1
scalar_bar.TitleColor = [0, 0, 0]
scalar_bar.LabelColor = [0, 0, 0]
scalar_bar.Position = [0.58, 0.1]
scalar_bar.ScalarBarLength = 0.3
scalar_bar.ScalarBarThickness = 40


glyph1Display.Set(
    Representation="Surface",
    ColorArrayName=["POINTS", "Electric Current Density"],
    LookupTable=ctf,
    Assembly="Hierarchy",
)

glyph1Display.SetScalarBarVisibility(renderView1, True)


pvs.Render()
pvs.SaveScreenshot(
    f"{script_dir}/results/Scene_Electric_Current_Density.png",
    OverrideColorPalette="WhiteBackground",
)
