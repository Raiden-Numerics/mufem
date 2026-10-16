"""PyVista support for the scene scripts (create_scene.py) of the cases.

Importing this module teaches `pv.read` the `.vtpc` files of the field export and provides the
common `theme` of the scenes; the scripts are otherwise plain PyVista:

    bodies = pv.read(output_files(case_dir)[0])
    plotter = pv.Plotter(theme=theme, off_screen=True)
    plotter.add_mesh(bodies, scalars="Temperature", clim=(300, 400))
    save(plotter, path)
"""

import json
from pathlib import Path
from typing import List, Sequence

import numpy as np
import pyvista as pv
from PIL import Image
from vtkmodules.vtkCommonDataModel import vtkCompositeDataSet
from vtkmodules.vtkIOXML import vtkXMLPartitionedDataSetCollectionReader

from casekit.images import save_gif as save_images_gif
from casekit.images import trim


@pv.register_reader(".vtpc")
def read_vtpc(path, **_) -> pv.MultiBlock:
    """One block per body, named as in case.py. The partitions of a body (one per MPI rank)
    are combined without merging their points, so that fields that are discontinuous between
    the cells stay so."""
    reader = vtkXMLPartitionedDataSetCollectionReader()
    reader.SetFileName(str(path))
    reader.Update()
    collection = reader.GetOutput()
    bodies = pv.MultiBlock()
    for i in range(collection.GetNumberOfPartitionedDataSets()):
        name = collection.GetMetaData(i).Get(vtkCompositeDataSet.NAME())
        partitions = pv.MultiBlock(
            [collection.GetPartition(i, j) for j in range(collection.GetNumberOfPartitions(i))]
        )
        bodies[name] = partitions.combine(merge_points=False)
    return bodies


def output_files(case_dir: Path) -> List[Path]:
    """The files of VisualizationOutput/Output.vtpc.series that case.py exports, in time order."""
    output_dir = Path(case_dir) / "VisualizationOutput"
    series = json.loads((output_dir / "Output.vtpc.series").read_text())
    return [output_dir / entry["name"] for entry in series["files"]]


def save(plotter: pv.Plotter, path: Path):
    """Screenshot of `plotter` without its white margins."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    trim(Image.fromarray(plotter.screenshot())).save(path)


def save_gif(frames: Sequence[np.ndarray], path: Path, fps: int = 8):
    """Animated GIF of the screenshots `frames`."""
    save_images_gif([Image.fromarray(frame) for frame in frames], path, fps)


theme = pv.themes.DocumentTheme()
theme.window_size = [1600, 1200]
theme.anti_aliasing = "ssaa"
theme.cmap = "coolwarm"
theme.edge_color = "black"
theme.line_width = 2
theme.lighting_params.ambient = 0.3
theme.lighting_params.diffuse = 0.8
theme.camera.parallel_projection = True
theme.font.title_size = 28
theme.font.label_size = 24
theme.colorbar_orientation = "vertical"
theme.colorbar_vertical.position_x = 0.8
theme.colorbar_vertical.position_y = 0.3
