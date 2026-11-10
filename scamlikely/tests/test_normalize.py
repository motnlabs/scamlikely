from scamlikely.core.normalize import (
    normalize,
    normalize_handle,
    strip_padding,
    variants,
)


def test_lowercase_and_separators():
    assert normalize("TJayCodes") == "tjaycodes"
    assert normalize("t-jay_codes") == "tjaycodes"
    assert normalize("t.jay codes?") == "tjaycodes"
    assert normalize("  T JAY  ") == "tjay"


def test_accents_are_stripped():
    assert normalize("Olúdemi") == "oludemi"
    assert normalize("José") == "jose"


def test_leet_folding():
    assert normalize("tj4yc0d3s") == "tjaycodes"
    assert normalize("$t4y") == "stay"
    assert normalize("@lex") == "alex"
    assert normalize("7jay") == "tjay"


def test_one_has_two_readings():
    assert normalize("el1te") == "ellte"
    assert normalize("el1te", one="i") == "elite"
    assert variants("el1te") == ("ellte", "elite")


def test_you_digraph():
    assert normalize("4you") == "au"
    assert normalize("you") == "u"
    assert normalize_handle("tjaycode4you") == "tjaycode"
    assert normalize_handle("tjaycode4u") == "tjaycode"


def test_digraph_does_not_eat_real_words():
    assert normalize("youngdev") == "youngdev"
    assert normalize("before") == "before"
    assert normalize("yourself") == "yourself"


def test_repeated_padding_collapses():
    assert normalize("tjaycodesss") == "tjaycodes"
    assert normalize("tjaycodes__") == "tjaycodes"
    assert normalize("xxxtjaycodesxxx") == "xtjaycodesx"
    assert normalize("boss") == "boss"


def test_strip_padding_tokens():
    assert strip_padding("tjaycode4you") == "tjaycode"
    assert strip_padding("tjaycodesofficial") == "tjaycodes"
    assert strip_padding("tjaycodes_YT") == "tjaycodes"
    assert strip_padding("tjaycodesthq") == "tjaycodest"


def test_strip_padding_never_eats_a_short_handle():
    assert strip_padding("official") == "official"
    assert strip_padding("the") == "the"
    assert strip_padding("kagu") == "kagu"


def test_empty_input():
    assert normalize("") == ""
    assert normalize_handle("") == ""
    assert strip_padding("") == ""
    assert variants("") == ()
