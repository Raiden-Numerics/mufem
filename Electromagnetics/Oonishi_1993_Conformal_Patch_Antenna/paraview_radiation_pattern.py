import sys

import numpy as np
import paraview.simple as pvs
from vtkmodules.vtkCommonCore import vtkPoints, vtkDoubleArray
from vtkmodules.vtkCommonDataModel import vtkPolyData, vtkCellArray, vtkQuad

# Variant written by case.py: r=20mm (default), r=30mm or planar.
variant = sys.argv[1] if len(sys.argv) > 1 else "r=20mm"

# **************************************************************************************
# Load data
# **************************************************************************************
data = np.load(f"results/Far_Field_3D_{variant}.npz")

thetas = data["thetas"]
phis = data["phis"]
radiation_pattern = data["radiation_pattern"]

Nth = len(thetas)
Nph = len(phis)


# **************************************************************************************
# Build spherical surface PolyData from (thetas, phis, radiation_pattern)
# **************************************************************************************
field_name = "Radiation Pattern"

poly = vtkPolyData()

points = vtkPoints()
field_array = vtkDoubleArray()
field_array.SetName(field_name)
field_array.SetNumberOfComponents(1)
field_array.SetNumberOfTuples(Nth * Nph)

idx = 0
for j, theta in enumerate(thetas):
    for i, phi in enumerate(phis):
        r = float(radiation_pattern[j, i])

        x = r * np.sin(theta) * np.cos(phi)
        y = r * np.sin(theta) * np.sin(phi)
        z = r * np.cos(theta)

        points.InsertNextPoint(float(x), float(y), float(z))
        field_array.SetValue(idx, r)
        idx += 1

poly.SetPoints(points)
poly.GetPointData().AddArray(field_array)
poly.GetPointData().SetScalars(field_array)

cells = vtkCellArray()
for j in range(Nth - 1):
    for i in range(Nph - 1):
        p0 = j * Nph + i
        p1 = p0 + 1
        p2 = p0 + 1 + Nph
        p3 = p0 + Nph

        quad = vtkQuad()
        quad.GetPointIds().SetId(0, p0)
        quad.GetPointIds().SetId(1, p1)
        quad.GetPointIds().SetId(2, p2)
        quad.GetPointIds().SetId(3, p3)
        cells.InsertNextCell(quad)

poly.SetPolys(cells)


# **************************************************************************************
# Push PolyData into ParaView and style it
# **************************************************************************************
src = pvs.TrivialProducer()
src.GetClientSideObject().SetOutput(poly)


# View settings ------------------------------------------------------------------------
view = pvs.GetRenderView()

view.UseColorPaletteForBackground = 0
view.BackgroundColorMode = "Single Color"
view.Background = (1.0, 1.0, 1.0)
view.ViewSize = (1000, 1000)
view.OrientationAxesVisibility = 1
view.OrientationAxesLabelColor = (0.0, 0.0, 0.0)


# Display settings ---------------------------------------------------------------------
display = pvs.Show(src, view)

display.Representation = "Surface With Edges"
display.EdgeColor = (0.1, 0.1, 0.1)

# brighter shading:
display.Specular = 0.5
display.SpecularPower = 20.0
display.Ambient = 0.3
display.Diffuse = 0.7


# Scalar bar settings ------------------------------------------------------------------
pvs.ColorBy(display, ("POINTS", field_name))

ctf = pvs.GetColorTransferFunction(field_name)
ctf.ApplyPreset("Turbo")

scalar_bar = pvs.GetScalarBar(ctf)

scalar_bar.Title = f"{field_name} [-]"
scalar_bar.ComponentTitle = ""

scalar_bar.Orientation = "Horizontal"
scalar_bar.WindowLocation = "Lower Center"
scalar_bar.TitleColor = (0, 0, 0)
scalar_bar.LabelColor = (0, 0, 0)
scalar_bar.TitleFontSize = 32
scalar_bar.LabelFontSize = 28
scalar_bar.ScalarBarThickness = 32
scalar_bar.RangeLabelFormat = "%.2f"
scalar_bar.LabelFormat = "%.2f"

scalar_bar.LookupTable.RescaleTransferFunction(0.0, 1.0)
scalar_bar.LookupTable.NumberOfTableValues = 256
scalar_bar.LookupTable.Discretize = 1


# Camera settings ----------------------------------------------------------------------
# From the (+x, +y, +z) octant, so the bend toward +y is seen side-on; the focal point
# sits below the pattern's center to leave the lower strip to the scalar bar.
pvs.Render()

view.CameraViewUp = (0, 0, 1)
view.CameraPosition = (2.2, 2.2, 1.78)
view.CameraFocalPoint = (0.0, 0.0, 0.3)
view.CameraParallelProjection = 1
view.CameraParallelScale = 0.7


# Save screenshot ----------------------------------------------------------------------
pvs.SaveScreenshot(f"results/Scene_Radiation_Pattern_{variant}.png")


pvs.Interact()
