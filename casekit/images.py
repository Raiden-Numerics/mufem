"""Image helpers shared by the scene scripts (create_scene.py, run with pvpython) and the
geometry image scripts (create_geometry_image.py): cropping, padding, composing and GIFs.

Only Pillow and ffmpeg are needed, so both interpreters can import this module.
"""

import shutil
import subprocess
from pathlib import Path
from typing import Optional, Sequence, Tuple

from PIL import Image, ImageChops


def content_box(*images: Image.Image) -> Tuple[int, int, int, int]:
    """Smallest box containing everything that is not white in all `images`."""
    boxes = []
    for image in images:
        box = ImageChops.difference(image, Image.new("RGB", image.size, "white")).getbbox()
        if box is None:
            raise ValueError("the image is blank: nothing was rendered")
        boxes.append(box)
    return (
        min(b[0] for b in boxes),
        min(b[1] for b in boxes),
        max(b[2] for b in boxes),
        max(b[3] for b in boxes),
    )


def trim(
    image: Image.Image, border: int = 20, box: Optional[Tuple[int, int, int, int]] = None
) -> Image.Image:
    """Crop the white margins (or to `box`), keeping `border` pixels."""
    left, top, right, bottom = box or content_box(image)
    return image.crop(
        (
            max(left - border, 0),
            max(top - border, 0),
            min(right + border, image.width),
            min(bottom + border, image.height),
        )
    )


def pad(image: Image.Image, left=0, top=0, right=0, bottom=0) -> Image.Image:
    """Add white margins, e.g. room for labels."""
    out = Image.new("RGB", (image.width + left + right, image.height + top + bottom), "white")
    out.paste(image, (left, top))
    return out


def place(
    path: Path,
    canvas: Tuple[int, int],
    left: int,
    width: int,
    top: Optional[int] = None,
    height: Optional[int] = None,
):
    """Crop the image at `path` to its content and place it, scaled, on a white canvas.

    The content is scaled to `width` x `height` (`height` keeps the aspect ratio when omitted)
    and put at `left`, `top` (vertically centered when omitted). Used to show a mesh at the
    scale of the geometry image beside it.
    """
    image = trim(Image.open(path).convert("RGB"), border=0)
    height = height or round(width * image.height / image.width)
    top = (canvas[1] - height) // 2 if top is None else top
    out = Image.new("RGB", canvas, "white")
    out.paste(image.resize((width, height), Image.LANCZOS), (left, top))
    out.save(path)


def combine_images(main: Path, sides: Sequence[Path], path: Path):
    """Put the images `sides` stacked on the right of `main`, each scaled to fit its height."""
    large = Image.open(main).convert("RGB")
    height = large.height // len(sides)
    smalls = []
    for side in sides:
        small = Image.open(side).convert("RGB")
        smalls.append(small.resize((round(small.width * height / small.height), height)))

    out = Image.new("RGB", (large.width + max(s.width for s in smalls), large.height), "white")
    out.paste(large, (0, 0))
    for i, small in enumerate(smalls):
        out.paste(small, (large.width, i * height + (large.height - len(sides) * height) // 2))
    out.save(path)


def write_gif(frames: Sequence[Path], path: Path, fps: int = 8, width: int = 800):
    """Encode the image files `frames` into an animated GIF of the given width."""
    if shutil.which("ffmpeg") is None:
        raise RuntimeError("write_gif needs ffmpeg on the PATH")

    work = Path(frames[0]).parent / "gif"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    for i, frame in enumerate(frames):
        shutil.copyfile(frame, work / f"{i:04d}.png")

    scale = f"scale={width}:-1:flags=lanczos"
    subprocess.run(
        ["ffmpeg", "-y", "-i", f"{work}/%04d.png", "-vf", f"{scale},palettegen",
         f"{work}/palette.png"],
        check=True,
        capture_output=True,
    )  # fmt: skip
    subprocess.run(
        ["ffmpeg", "-y", "-framerate", str(fps), "-i", f"{work}/%04d.png", "-i",
         f"{work}/palette.png", "-lavfi", f"{scale},paletteuse=dither=none", str(path)],
        check=True,
        capture_output=True,
    )  # fmt: skip
    shutil.rmtree(work)
