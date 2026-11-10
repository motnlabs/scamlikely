"""Perceptual avatar hashing (dHash, 16x16 = 256 bits).

The only non-stdlib dependency in ``core`` is Pillow, and only for this
module.  A dHash compares each pixel with its right-hand neighbour, so it is
stable across resizing and re-encoding: the same art served at 512px and at
760px hashes to distance 0.  Threshold: <= 8 of 256 bits is "same art".
"""
from __future__ import annotations

import io
from pathlib import Path

try:
    from PIL import Image
except Exception:  # pragma: no cover - only hit without Pillow installed
    Image = None

DHASH_SIZE = 16
DHASH_BITS = DHASH_SIZE * DHASH_SIZE
MATCH_DISTANCE = 8

_HEX_WIDTH = DHASH_BITS // 4


def _require_pillow() -> None:
    if Image is None:
        raise RuntimeError(
            "avatar hashing needs Pillow: python -m pip install pillow"
        )


def _open(source):
    _require_pillow()
    if isinstance(source, Image.Image):
        return source
    if isinstance(source, (bytes, bytearray, memoryview)):
        return Image.open(io.BytesIO(bytes(source)))
    if hasattr(source, "read"):
        return Image.open(source)
    return Image.open(Path(source))


def _flatten(image):
    if image.mode in ("RGBA", "LA") or (
        image.mode == "P" and "transparency" in image.info
    ):
        image = image.convert("RGBA")
        background = Image.new("RGBA", image.size, (255, 255, 255, 255))
        image = Image.alpha_composite(background, image)
    return image.convert("L")


def dhash(source, *, size: int = DHASH_SIZE) -> int:
    """256-bit difference hash of an image path, bytes, file or PIL image."""
    image = _open(source)
    owned = image is not source
    try:
        gray = _flatten(image).resize(
            (size + 1, size), Image.Resampling.LANCZOS
        )
        pixels = gray.tobytes()
    finally:
        if owned:
            image.close()

    bits = 0
    stride = size + 1
    for row in range(size):
        offset = row * stride
        for column in range(size):
            left = pixels[offset + column]
            right = pixels[offset + column + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return bits


def dhash_bytes(data: bytes, *, size: int = DHASH_SIZE) -> int:
    return dhash(data, size=size)


def dhash_file(path: str | Path, *, size: int = DHASH_SIZE) -> int:
    return dhash(path, size=size)


def distance(a: int, b: int) -> int:
    """Hamming distance between two dHashes (0..256)."""
    return (int(a) ^ int(b)).bit_count()


def is_same_art(a: int, b: int, *, threshold: int = MATCH_DISTANCE) -> bool:
    return distance(a, b) <= threshold


def to_hex(value: int) -> str:
    return format(int(value), f"0{_HEX_WIDTH}x")


def from_hex(value: str) -> int | None:
    if not value:
        return None
    try:
        return int(value, 16)
    except (TypeError, ValueError):
        return None
