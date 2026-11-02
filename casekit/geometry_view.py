"""Geometry images of the cases, rendered from the STEP file with the OpenCascade viewer.

The geometry is drawn in the colors (and transparency) stored in the STEP. The view is given like
a camera, by the direction toward the viewer and the up direction, so that a geometry image can
share the view of the scenes of the case; the orthographic camera and the image size are fitted
to the projected geometry, so the image needs no cropping.

Needs an X display; headless, run the calling script with `xvfb-run -a`.
"""

from pathlib import Path
from typing import List, Sequence, Tuple

import numpy as np
from OCP.AIS import AIS_DisplayMode, AIS_InteractiveContext
from OCP.Aspect import Aspect_DisplayConnection
from OCP.BRep import BRep_Tool
from OCP.BRepMesh import BRepMesh_IncrementalMesh
from OCP.collections import Sequence_TDF_Label
from OCP.gp import gp_Dir, gp_Pnt
from OCP.Graphic3d import Graphic3d_BufferType, Graphic3d_Camera, Graphic3d_TypeOfShadingModel
from OCP.Image import Image_AlienPixMap, Image_Format
from OCP.OpenGl import OpenGl_GraphicDriver
from OCP.Quantity import Quantity_Color, Quantity_NOC_BLACK, Quantity_NOC_WHITE
from OCP.STEPCAFControl import STEPCAFControl_Reader
from OCP.TCollection import TCollection_AsciiString, TCollection_ExtendedString
from OCP.TDF import TDF_Label
from OCP.TDocStd import TDocStd_Document
from OCP.TopAbs import TopAbs_FACE
from OCP.TopExp import TopExp_Explorer
from OCP.TopLoc import TopLoc_Location
from OCP.TopoDS import TopoDS, TopoDS_Shape
from OCP.V3d import V3d_Viewer
from OCP.XCAFDoc import XCAFDoc_DocumentTool
from OCP.XCAFPrs import XCAFPrs_AISObject
from OCP.Xw import Xw_Window


def _read_step(step_path: Path) -> Tuple[TDocStd_Document, List[TDF_Label]]:
    """The document of `step_path` and its free shapes as labels, with names, colors and
    transparency."""
    doc = TDocStd_Document(TCollection_ExtendedString("XmlXCAF"))
    reader = STEPCAFControl_Reader()
    reader.SetColorMode(True)
    reader.SetNameMode(True)
    if reader.ReadFile(str(step_path)) != 1:  # IFSelect_RetDone
        raise RuntimeError(f"cannot read {step_path}")
    reader.Transfer(doc)
    labels = Sequence_TDF_Label()
    XCAFDoc_DocumentTool.ShapeTool_s(doc.Main()).GetFreeShapes(labels)
    return doc, [labels.Value(i) for i in range(1, labels.Length() + 1)]


def _vertices(shape: TopoDS_Shape, deflection: float = 1e-3) -> np.ndarray:
    """The vertices of the triangulation of `shape` (meshed with `deflection`)."""
    BRepMesh_IncrementalMesh(shape, deflection)
    points = []
    explorer = TopExp_Explorer(shape, TopAbs_FACE)
    while explorer.More():
        location = TopLoc_Location()
        triangulation = BRep_Tool.Triangulation_s(TopoDS.Face(explorer.Current()), location)
        if triangulation is not None:
            trsf = location.Transformation()
            for i in range(1, triangulation.NbNodes() + 1):
                p = triangulation.Node(i).Transformed(trsf)
                points.append((p.X(), p.Y(), p.Z()))
        explorer.Next()
    return np.array(points).reshape(-1, 3)


def _view_axes(
    direction: Sequence[float], up: Sequence[float]
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Unit vectors toward the viewer, screen right and screen up."""
    toward = np.asarray(direction, float)
    toward /= np.linalg.norm(toward)
    right = np.cross(up, toward)
    right /= np.linalg.norm(right)
    return toward, right, np.cross(toward, right)


def save_geometry_image(
    step_path: Path,
    image_path: Path,
    *,
    direction: Sequence[float],
    up: Sequence[float],
    height: int = 1200,
    margin: float = 0.03,
) -> None:
    """Render `step_path` seen from `direction` with `up` up and save it as PNG to `image_path`,
    `height` pixels high, with a `margin` (fraction of the extent) around the geometry."""
    doc, labels = _read_step(step_path)
    shape_tool = XCAFDoc_DocumentTool.ShapeTool_s(doc.Main())

    # Frame on the projected vertices: window aspect and orthographic scale fit the content.
    toward, right, screen_up = _view_axes(direction, up)
    points = np.vstack([_vertices(shape_tool.GetShape_s(label)) for label in labels])
    x, y = points @ right, points @ screen_up
    w, h = np.ptp(x) * (1 + 2 * margin), np.ptp(y) * (1 + 2 * margin)
    center = right * (x.max() + x.min()) / 2 + screen_up * (y.max() + y.min()) / 2
    center += toward * (points @ toward).mean()
    size = (round(height * w / h), height)

    display = Aspect_DisplayConnection()
    viewer = V3d_Viewer(OpenGl_GraphicDriver(display, False))
    viewer.SetDefaultLights()
    viewer.SetLightOn()
    viewer.SetDefaultShadingModel(Graphic3d_TypeOfShadingModel.Graphic3d_TypeOfShadingModel_Phong)
    context = AIS_InteractiveContext(viewer)
    context.SetDisplayMode(AIS_DisplayMode.AIS_Shaded.value, False)
    context.DefaultDrawer().SetFaceBoundaryDraw(True)
    context.DefaultDrawer().FaceBoundaryAspect().SetColor(Quantity_Color(Quantity_NOC_BLACK))

    view = viewer.CreateView()
    view.SetBackgroundColor(Quantity_Color(Quantity_NOC_WHITE))
    window = Xw_Window(display, "geometry", 0, 0, *size)
    window.SetVirtual(True)
    view.SetWindow(window)

    for label in labels:
        context.Display(XCAFPrs_AISObject(label), False)

    camera = view.Camera()
    camera.SetProjectionType(Graphic3d_Camera.Projection_e.Projection_Orthographic)
    camera.SetCenter(gp_Pnt(*center))
    camera.SetEye(gp_Pnt(*(center + toward * 10 * h)))
    camera.SetUp(gp_Dir(*screen_up))
    camera.SetScale(min(w, h))  # OCC applies the scale to the shorter side
    view.ZFitAll()
    view.Redraw()

    image = Image_AlienPixMap()
    image.InitZero(Image_Format.Image_Format_RGB, *size)
    view.ToPixMap(image, *size, Graphic3d_BufferType.Graphic3d_BT_RGB)
    if not image.Save(TCollection_AsciiString(str(image_path))):
        raise RuntimeError(f"cannot write {image_path}")
