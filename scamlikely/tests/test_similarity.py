from scamlikely.core.normalize import normalize
from scamlikely.core.similarity import (
    best_name_distance,
    compare_handles,
    damerau_levenshtein,
    names_equal,
    threshold_for,
)


def test_damerau_levenshtein_basics():
    assert damerau_levenshtein("", "") == 0
    assert damerau_levenshtein("abc", "") == 3
    assert damerau_levenshtein("kitten", "sitting") == 3
    assert damerau_levenshtein("tjaycodes", "tjaycodes") == 0


def test_damerau_transposition_is_one_edit():
    assert damerau_levenshtein("ab", "ba") == 1
    assert damerau_levenshtein("tjayocdes", "tjaycodes") == 1


def test_early_exit_bound():
    assert damerau_levenshtein("abcdef", "uvwxyz", max_distance=2) == 3


def test_length_aware_threshold():
    assert threshold_for("ace", "aeg") == 1
    assert threshold_for("tjaycodes", "tjaycodes") == 2
    assert compare_handles("ace", "acf").matched
    assert not compare_handles("ace", "aeg").matched
    assert compare_handles("tjaycidez", "tjaycodes").matched


def test_exact_handle_folds_leet():
    match = compare_handles("TJayC0des", "tjaycodes")
    assert match.matched
    assert match.distance == 0
    assert match.method == "exact"


def test_suffix_rule_real_pair():
    match = compare_handles("tjaycode4you", "tjaycodes")
    assert match.matched
    assert match.distance == 1
    assert match.method == "suffix-stripped"
    assert "1 edit" in match.describe()


def test_official_suffix():
    match = compare_handles("tjaycodesofficial", "tjaycodes")
    assert match.matched
    assert match.method == "suffix-stripped"


def test_containment_with_marker_remainder():
    match = compare_handles("aceau", "ace")
    assert match.matched
    assert match.method == "containment"


def test_unrelated_handles_do_not_match():
    assert not compare_handles("tjaycodes", "johndoe").matched
    assert not compare_handles("", "tjaycodes").matched
    assert not compare_handles("tjaycodes", "").matched


def test_name_helpers():
    assert names_equal("TJayCodes", "tjaycodes")
    assert names_equal("el1te", "elite")
    assert not names_equal("tjaycodes", "tjaycodez")
    assert best_name_distance("tjaycodes", "tjaycodez") == 1
    assert best_name_distance("", "") is None
    assert normalize("T Jay Oludemi") == "tjayoludemi"
