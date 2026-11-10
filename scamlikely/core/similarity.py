"""String similarity: Damerau-Levenshtein plus handle-aware rules."""
from __future__ import annotations

from dataclasses import dataclass

from .normalize import (
    PAD_SUFFIXES,
    normalize,
    normalize_handle,
    strip_padding,
    variants,
)

SHORT_HANDLE_LEN = 6
SHORT_THRESHOLD = 1
LONG_THRESHOLD = 2

_CONTAINMENT_MARKERS = set(PAD_SUFFIXES) | {"4", "u", "au", "ur"}


def damerau_levenshtein(a: str, b: str, *, max_distance: int | None = None) -> int:
    """Optimal-string-alignment distance (includes adjacent transpositions).

    ``max_distance`` is an early-exit bound: when the true distance exceeds it,
    the function returns ``max_distance + 1`` instead of computing the rest.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if max_distance is not None and abs(len(a) - len(b)) > max_distance:
        return max_distance + 1

    previous_previous: list[int] | None = None
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        row_min = current[0]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            value = min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + cost,
            )
            if (
                previous_previous is not None
                and i > 1
                and j > 1
                and ca == b[j - 2]
                and a[i - 2] == cb
            ):
                value = min(value, previous_previous[j - 2] + 1)
            current.append(value)
            row_min = min(row_min, value)
        if max_distance is not None and row_min > max_distance:
            return max_distance + 1
        previous_previous, previous = previous, current
    return previous[-1]


def threshold_for(a: str, b: str, *, short_len: int = SHORT_HANDLE_LEN) -> int:
    """Length-aware edit budget: 1 for short names, 2 for longer ones."""
    return SHORT_THRESHOLD if min(len(a), len(b)) <= short_len else LONG_THRESHOLD


def _variant_pairs(a: str, b: str) -> list[tuple[str, str]]:
    return [(x, y) for x in variants(a) for y in variants(b)]


def best_name_distance(a: str, b: str) -> int | None:
    """Minimum edit distance across the ``1``->l / ``1``->i readings."""
    pairs = _variant_pairs(a, b)
    if not pairs:
        return None
    return min(damerau_levenshtein(x, y) for x, y in pairs)


def names_equal(a: str, b: str) -> bool:
    """True when both names share a canonical reading."""
    return bool(set(variants(a)) & set(variants(b)))


@dataclass(frozen=True)
class HandleMatch:
    matched: bool
    distance: int | None
    method: str
    left: str
    right: str

    def describe(self) -> str:
        if not self.matched:
            return "no handle match"
        if self.method == "exact":
            return f"username {self.left!r} is identical to {self.right!r}"
        if self.method == "containment":
            return (
                f"username {self.left!r} contains {self.right!r} plus padding "
                f"({self.distance} extra char(s))"
            )
        if self.method == "suffix-stripped":
            return (
                f"username {self.left!r} is {self.distance} edit(s) from "
                f"{self.right!r} once padding suffixes are removed"
            )
        return (
            f"username {self.left!r} is {self.distance} edit(s) from "
            f"{self.right!r}"
        )


def _best_variant_distance(a: str, b: str) -> int:
    pairs = _variant_pairs(a, b)
    if not pairs:
        return max(len(a), len(b))
    return min(damerau_levenshtein(x, y) for x, y in pairs)


def compare_handles(
    a: str,
    b: str,
    *,
    short_len: int = SHORT_HANDLE_LEN,
    short_threshold: int = SHORT_THRESHOLD,
    long_threshold: int = LONG_THRESHOLD,
) -> HandleMatch:
    """Compare two usernames/handles.

    Four passes, strongest first:

    1. ``exact`` - equality after normalisation (leet and digraph folding).
    2. ``suffix-stripped`` - the ``4u`` / ``4you`` / ``official`` family:
       padding suffixes are removed from the raw handle before folding, then
       the stems are compared.  This runs before the plain edit pass because
       folding ``4you`` into ``au`` would otherwise inflate the distance.
    3. ``edit-distance`` - Damerau-Levenshtein within a length-aware budget.
    4. ``containment`` - if one stem is a prefix of the other and the
       remainder is numeric or a padding marker, it still counts.
    """
    if not a or not b:
        return HandleMatch(False, None, "none", a or "", b or "")

    full = _best_variant_distance(a, b)
    if full == 0:
        return HandleMatch(True, 0, "exact", a, b)

    stem_a = normalize_handle(a)
    stem_b = normalize_handle(b)
    stripped = (
        strip_padding(a) != a.lower().strip("._- ")
        or strip_padding(b) != b.lower().strip("._- ")
    )
    if stripped and stem_a and stem_b:
        stem = _best_variant_distance(stem_a, stem_b)
        if stem == 0:
            return HandleMatch(True, 0, "suffix-stripped", a, b)
        stem_limit = (
            short_threshold
            if min(len(stem_a), len(stem_b)) <= short_len
            else long_threshold
        )
        if stem <= stem_limit:
            return HandleMatch(True, stem, "suffix-stripped", a, b)

    limit = (
        short_threshold
        if min(len(normalize(a)), len(normalize(b))) <= short_len
        else long_threshold
    )
    if full <= limit:
        return HandleMatch(True, full, "edit-distance", a, b)

    if not stem_a or not stem_b:
        return HandleMatch(False, None, "none", a, b)

    if stem_a.startswith(stem_b) or stem_b.startswith(stem_a):
        longer, shorter = (stem_a, stem_b) if len(stem_a) >= len(stem_b) else (stem_b, stem_a)
        remainder = longer[len(shorter):]
        if remainder and (remainder.isdigit() or remainder in _CONTAINMENT_MARKERS):
            return HandleMatch(True, len(remainder), "containment", a, b)

    return HandleMatch(False, None, "none", a, b)
