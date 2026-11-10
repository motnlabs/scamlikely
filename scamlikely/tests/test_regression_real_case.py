"""Regression fixtures for the 2026-11-10 impersonation case.

Suspect 689579838108991511 spent a month warming up (2020 account, Nitro,
boost streak, three lookalike OAuth connections), then displayed
``tjaycodes`` with username ``tjaycode4you`` and a re-encoded copy of the
victim's avatar, posted as the victim, and left before being banned.

Measured facts encoded here:

* the two handles differ by a single character once ``4you`` is stripped;
* the avatar dHash distance is 0/256 even though one image is 512px and the
  other 760px with different bytes.
"""
from pathlib import Path

from scamlikely.core.avatar import distance
from scamlikely.core.models import MemberSnapshot, ProtectedIdentity
from scamlikely.core.registry import evaluate_member
from scamlikely.core.similarity import compare_handles

from .conftest import REAL_GUILD, SUSPECT_ID, VICTIM_ID

VICTIM_DISPLAY = "tjaycodes"
VICTIM_USERNAME = "tjaycodes4you"
SUSPECT_USERNAME = "tjaycode4you"
SUSPECT_DISPLAY = "tjaycodes"


def _registry(victim_dhash):
    return [
        ProtectedIdentity(
            guild_id=REAL_GUILD,
            user_id=VICTIM_ID,
            display_name=VICTIM_DISPLAY,
            username=VICTIM_USERNAME,
            avatar_dhash=victim_dhash,
            notes="victim of the 2026-11-10 impersonation",
        )
    ]


def test_handles_differ_by_one_character(same_art_dhash):
    match = compare_handles(SUSPECT_USERNAME, VICTIM_USERNAME)
    assert match.matched
    assert match.distance == 1
    assert match.method == "suffix-stripped"


def test_avatar_same_art_across_512_and_760(same_art_dhash):
    victim_dhash, suspect_dhash = same_art_dhash
    assert distance(victim_dhash, suspect_dhash) == 0


def test_real_case_is_high_severity(same_art_dhash):
    victim_dhash, suspect_dhash = same_art_dhash
    subject = MemberSnapshot(
        guild_id=REAL_GUILD,
        user_id=SUSPECT_ID,
        display_name=SUSPECT_DISPLAY,
        username=SUSPECT_USERNAME,
        avatar_dhash=suspect_dhash,
    )
    findings = evaluate_member(subject, _registry(victim_dhash))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "high"
    assert finding.protected_user_id == VICTIM_ID
    assert finding.avatar_distance == 0
    assert set(finding.signals) == {
        "display_name_exact",
        "username_match",
        "avatar_match",
    }
    assert "0/256" in finding.evidence
    assert "2020-03-17" in finding.evidence
    assert str(VICTIM_ID) in finding.evidence


def test_negative_control_similar_display_name(same_art_dhash, different_art_dhash):
    victim_dhash, _ = same_art_dhash
    _, other_dhash = different_art_dhash
    legitimate = MemberSnapshot(
        guild_id=REAL_GUILD,
        user_id=777777777777777777,
        display_name="tjaycodez",
        username="johndev",
        avatar_dhash=other_dhash,
    )
    findings = evaluate_member(legitimate, _registry(victim_dhash))
    assert findings
    assert findings[0].severity == "low"
    assert findings[0].signals == ("display_name_near",)


def test_negative_control_shared_common_name(same_art_dhash, different_art_dhash):
    victim_dhash, _ = same_art_dhash
    _, other_dhash = different_art_dhash
    staff_elsewhere = MemberSnapshot(
        guild_id=REAL_GUILD,
        user_id=252914006090711041,
        display_name="tjaycodes",
        username="unrelated_staff",
        avatar_dhash=other_dhash,
    )
    findings = evaluate_member(staff_elsewhere, _registry(victim_dhash))
    assert findings
    assert all(item.severity != "high" for item in findings)


def test_core_does_not_import_discord():
    core = Path(__file__).resolve().parents[1] / "core"
    for path in core.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "import discord" not in text
        assert "from discord" not in text
