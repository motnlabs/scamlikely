"""Handle / display-name normalisation.

The pipeline is deliberately fixed and boring so every step is testable:

1. NFKD-decompose, drop combining marks, lowercase.
2. Collapse the digraphs ``your`` -> ``ur``, ``you`` -> ``u`` and
   ``for`` -> ``4``.  These only fire on a standalone token (not inside a
   longer word: ``young`` must not become ``ung``, ``before`` must not become
   ``beae``).
3. Fold leet substitutions: 0->o, 1->l (or i, see ``variants``), 3->e,
   4->a, 5->s, 7->t, $->s, @->a, !->i, |->l.
4. Drop everything that is not ``[a-z0-9]``.
5. Collapse repeated padding: any run of 3+ identical characters becomes one,
   and a leading/trailing run of 2+ is trimmed for strings of 6+ characters
   (``tjaycodess`` -> ``tjaycodes``, but ``boss`` is left alone).

Consequence of step 2 followed by step 3: the literal suffix ``4you`` becomes
``au`` in a *display name*.  Handle comparison therefore calls
:func:`strip_padding` first, which removes ``4you`` / ``4u`` / ``official`` /
``real`` / ... before any folding, so ``tjaycode4you`` compares as
``tjaycode`` rather than as ``tjaycodeau``.
"""
from __future__ import annotations

import re
import unicodedata

LEET = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "$": "s",
    "@": "a",
    "!": "i",
    "|": "l",
    "+": "t",
}

LEET_ALTERNATE_ONE = {"1": "i"}

_DIGRAPHS = (
    (re.compile(r"(?<![a-z])your(?![a-z])"), "ur"),
    (re.compile(r"(?<![a-z])you(?![a-z])"), "u"),
    (re.compile(r"(?<![a-z])for(?![a-z])"), "4"),
)

PAD_SUFFIXES = (
    "official",
    "genuine",
    "backup",
    "actual",
    "real",
    "4you",
    "foryou",
    "foru",
    "4u",
    "you",
    "for",
    "tv",
    "hq",
    "xo",
    "yt",
    "alt",
)

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_RUN = re.compile(r"(.)\1{2,}")
_EDGE_RUN = re.compile(r"^(.)\1+|(.)\2+$")


def _strip_accents(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def _fold(text: str, one: str) -> str:
    table = dict(LEET)
    if one == "i":
        table.update(LEET_ALTERNATE_ONE)
    return text.translate(str.maketrans(table))


def _collapse_padding(text: str) -> str:
    text = _RUN.sub(r"\1", text)
    if len(text) >= 6:
        text = _EDGE_RUN.sub(lambda m: (m.group(1) or m.group(2)), text)
    return text


def strip_padding(value: str) -> str:
    """Remove lookalike padding tokens from a raw handle.

    Only suffixes are removed, and only when at least four characters remain
    (so ``the``, ``alt`` and friends cannot eat a real short handle).  The
    remainder is lowercased and trimmed of separators but not folded.
    """
    text = (value or "").lower().strip()
    text = text.strip("._- ")
    changed = True
    while changed:
        changed = False
        for token in PAD_SUFFIXES:
            if text.endswith(token) and len(text) - len(token) >= 4:
                text = text[: -len(token)].rstrip("._- ")
                changed = True
    return text


def normalize(value: str, *, one: str = "l") -> str:
    """Canonical form of a display name or handle.

    ``one`` selects how the digit ``1`` is folded: ``l`` (default, matching
    most leet spellings) or ``i``.  :func:`variants` returns both so
    comparisons do not have to guess.
    """
    if not value:
        return ""
    text = _strip_accents(str(value)).lower()
    for pattern, replacement in _DIGRAPHS:
        text = pattern.sub(replacement, text)
    text = _fold(text, one)
    text = _NON_ALNUM.sub("", text)
    return _collapse_padding(text)


def normalize_handle(value: str, *, one: str = "l") -> str:
    """Normalise a handle after stripping lookalike padding suffixes."""
    return normalize(strip_padding(value), one=one)


def variants(value: str) -> tuple[str, ...]:
    """Both canonical readings of a name (``1`` -> ``l`` and ``1`` -> ``i``)."""
    forms = (normalize(value, one="l"), normalize(value, one="i"))
    return tuple(dict.fromkeys(form for form in forms if form))
