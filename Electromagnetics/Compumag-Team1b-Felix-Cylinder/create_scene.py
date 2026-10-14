import os

import paraview.simple as pvs
from PIL import Image, ImageOps

renderView1 = pvs.CreateView("RenderView")


renderView1.Set(
    ViewSize=[1600, 1300],
    OrientationAxesVisibility=0,
    # The horizontal view along (-1, 0, 1) with y up, as the geometry image data/Geometry.png.
    CameraPosition=[-0.3324, 0.0, 0.3324],
    CameraFocalPoint=[0.0, 0.0, 0.0],
    CameraViewUp=[0.0, 1.0, 0.0],
    CameraViewAngle=30.0,
    CameraParallelProjection=1,
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

scalar_bar.Title = "Electric Current Density [A/m²]"
scalar_bar.ComponentTitle = ""
scalar_bar.UseCustomLabels = True
scalar_bar.CustomLabels = [0, 1.0e6, 2.0e6, 3.0e6]
scalar_bar.AddRangeLabels = 0
scalar_bar.AutomaticLabelFormat = 0
scalar_bar.LabelFormat = "%.0e"
scalar_bar.TitleFontSize = 32
scalar_bar.LabelFontSize = 28
scalar_bar.TitleBold = 1
scalar_bar.LabelBold = 1
scalar_bar.TitleColor = [0, 0, 0]
scalar_bar.LabelColor = [0, 0, 0]
scalar_bar.Position = [0.35, 0.05]
scalar_bar.ScalarBarLength = 0.3
scalar_bar.ScalarBarThickness = 40


glyph1Display.Set(
    Representation="Surface",
    ColorArrayName=["POINTS", "Electric Current Density"],
    LookupTable=ctf,
    Assembly="Hierarchy",
)

glyph1Display.SetScalarBarVisibility(renderView1, True)


# Fit the cylinder (radius 0.07 m, length 0.2 m) with room for the color bar below it.
renderView1.CameraFocalPoint = [0.0, -0.016, 0.0]
renderView1.CameraPosition = [-0.3324, -0.016, 0.3324]
renderView1.CameraParallelScale = 0.12

pvs.Render()
path = f"{script_dir}/results/Scene_Electric_Current_Density.png"
pvs.SaveScreenshot(path, OverrideColorPalette="WhiteBackground")

# Trim the white margins, keeping a small border.
image = Image.open(path).convert("RGB")
left, top, right, bottom = ImageOps.invert(image).getbbox()
box = (
    max(left - 20, 0),
    max(top - 20, 0),
    min(right + 20, image.width),
    min(bottom + 20, image.height),
)
image.crop(box).save(path)
