from pathlib import Path

import pytest

from scamlikely.core.avatar import (
    DHASH_BITS,
    MATCH_DISTANCE,
    dhash,
    dhash_bytes,
    dhash_file,
    distance,
    from_hex,
    is_same_art,
    to_hex,
)


def test_dhash_is_256_bits(same_art_dhash):
    value = same_art_dhash[0]
    assert 0 <= value < (1 << DHASH_BITS)


def test_same_art_different_bytes_is_zero(same_art_images, same_art_dhash):
    art_512, art_760 = same_art_images
    assert art_512 != art_760
    assert distance(*same_art_dhash) == 0
    assert is_same_art(*same_art_dhash)


def test_different_art_is_far(different_art_dhash):
    assert distance(*different_art_dhash) > MATCH_DISTANCE
    assert not is_same_art(*different_art_dhash)


def test_hash_is_symmetric(same_art_dhash):
    first, second = same_art_dhash
    assert distance(first, second) == distance(second, first)


def test_file_bytes_and_image_inputs_agree(same_art_images, tmp_path):
    art_512, _ = same_art_images
    path = Path(tmp_path) / "avatar.png"
    path.write_bytes(art_512)
    from_bytes = dhash_bytes(art_512)
    from_file = dhash_file(path)
    assert from_bytes == from_file
    assert dhash(path) == from_bytes


def test_hex_round_trip(same_art_dhash):
    value = same_art_dhash[0]
    text = to_hex(value)
    assert len(text) == 64
    assert from_hex(text) == value
    assert from_hex("") is None
    assert from_hex("not-hex") is None


def test_threshold_boundary(same_art_dhash):
    value = same_art_dhash[0]
    assert is_same_art(value, value ^ 0b1111)
    assert not is_same_art(value, value ^ 0xFFFF)


def test_hamming_distance_matches_bit_count():
    assert distance(0b1010, 0b0011) == 2
    assert distance(0, (1 << DHASH_BITS) - 1) == DHASH_BITS


def test_pillow_missing_is_an_explicit_error(monkeypatch):
    import scamlikely.core.avatar as avatar

    monkeypatch.setattr(avatar, "Image", None)
    with pytest.raises(RuntimeError, match="Pillow"):
        avatar.dhash(b"not-an-image")
