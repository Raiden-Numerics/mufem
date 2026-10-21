"""Image helpers of the geometry image scripts (create_geometry_image.py): cropping and padding."""

from typing import Optional, Tuple

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
