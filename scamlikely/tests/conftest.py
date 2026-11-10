import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scamlikely.core.avatar import dhash  # noqa: E402

REAL_GUILD = 539258061081018378
VICTIM_ID = 321025125698895874
SUSPECT_ID = 689579838108991511


def _art(size: int, phase: float = 0.0):
    import math

    from PIL import Image

    image = Image.new("RGB", (size, size))
    span = max(1, size - 1)
    pixels = []
    for y in range(size):
        v = y / span
        for x in range(size):
            u = x / span
            pixels.append(
                (
                    int(128 + 80 * math.sin(6.28318 * (1.5 * u + 0.3) + phase)),
                    int(128 + 70 * math.cos(6.28318 * (1.1 * v - 0.2) + phase)),
                    int(128 + 60 * math.sin(6.28318 * (0.9 * u + 1.3 * v) + phase)),
                )
            )
    image.putdata(pixels)
    return image


def _encode(image, fmt: str, **kwargs) -> bytes:
    import io

    buffer = io.BytesIO()
    image.save(buffer, fmt, **kwargs)
    return buffer.getvalue()


@pytest.fixture(scope="session")
def same_art_images():
    from PIL import Image

    art_512 = _encode(_art(512, 0.5), "PNG")
    art_760 = _encode(
        _art(512, 0.5).resize((760, 760), Image.Resampling.LANCZOS),
        "JPEG",
        quality=85,
    )
    return art_512, art_760


@pytest.fixture(scope="session")
def same_art_dhash(same_art_images):
    return dhash(same_art_images[0]), dhash(same_art_images[1])


@pytest.fixture(scope="session")
def different_art_dhash(same_art_images):
    return dhash(same_art_images[0]), dhash(_encode(_art(512, 2.1), "PNG"))
