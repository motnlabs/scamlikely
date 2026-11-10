from datetime import datetime, timezone

from scamlikely.core.models import MemberSnapshot, ProtectedIdentity, SEVERITY_RANK
from scamlikely.core.registry import evaluate_member, max_severity

GUILD = 111111111111111111
OTHER_GUILD = 222222222222222222
PROTECTED_ID = 333333333333333333
SUBJECT_ID = 444444444444444444
OLD = datetime(2026, 11, 10, tzinfo=timezone.utc)
OLD_ACCOUNT = 321025125698895874
SUSPECT_ID = 689579838108991511
YOUNG_ACCOUNT = 1561891700736000000

PROTECTED = ProtectedIdentity(
    guild_id=GUILD,
    user_id=PROTECTED_ID,
    display_name="tjaycodes",
    username="tjaycodes",
    avatar_dhash=0b1010,
    notes="owner",
)


def snapshot(**overrides):
    values = dict(
        guild_id=GUILD,
        user_id=SUBJECT_ID,
        display_name="someone",
        username="somebody",
        avatar_dhash=None,
    )
    values.update(overrides)
    return MemberSnapshot(**values)


def test_self_is_excluded():
    subject = snapshot(user_id=PROTECTED_ID, display_name="tjaycodes", username="tjaycodes", avatar_dhash=0b1010)
    assert evaluate_member(subject, [PROTECTED], now=OLD) == []


def test_guild_mismatch_is_ignored():
    subject = snapshot(guild_id=OTHER_GUILD, display_name="tjaycodes", username="tjaycodes", avatar_dhash=0b1010)
    assert evaluate_member(subject, [PROTECTED], now=OLD) == []


def test_bots_are_ignored():
    subject = snapshot(bot=True, display_name="tjaycodes", username="tjaycodes", avatar_dhash=0b1010)
    assert evaluate_member(subject, [PROTECTED], now=OLD) == []


def test_allowlist_covers_subject_and_protected():
    subject = snapshot(display_name="tjaycodes", username="tjaycodes", avatar_dhash=0b1010)
    assert evaluate_member(subject, [PROTECTED], now=OLD, allowlist=[SUBJECT_ID]) == []
    assert evaluate_member(subject, [PROTECTED], now=OLD, allowlist=[PROTECTED_ID]) == []


def test_display_name_alone_is_low_not_high():
    subject = snapshot(user_id=OLD_ACCOUNT, display_name="tjaycodes", username="unrelated_dev")
    findings = evaluate_member(subject, [PROTECTED], now=OLD)
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].signals == ("display_name_exact",)


def test_display_name_plus_username_is_high():
    subject = snapshot(user_id=OLD_ACCOUNT, display_name="tjaycodes", username="tjaycode4you")
    findings = evaluate_member(subject, [PROTECTED], now=OLD)
    assert findings[0].severity == "high"
    assert "display_name_exact" in findings[0].signals
    assert "username_match" in findings[0].signals


def test_username_alone_is_medium():
    subject = snapshot(user_id=OLD_ACCOUNT, display_name="totally different", username="tjaycode4you")
    findings = evaluate_member(subject, [PROTECTED], now=OLD)
    assert findings[0].severity == "medium"
    assert findings[0].signals == ("username_match",)


def test_username_plus_avatar_is_high_without_display_match():
    subject = snapshot(user_id=OLD_ACCOUNT, display_name="different", username="tjaycode4you", avatar_dhash=0b1011)
    findings = evaluate_member(subject, [PROTECTED], now=OLD)
    assert findings[0].severity == "high"
    assert findings[0].avatar_distance == 1


def test_avatar_alone_is_low():
    subject = snapshot(user_id=OLD_ACCOUNT, display_name="different", username="someoneelse", avatar_dhash=0b1011)
    findings = evaluate_member(subject, [PROTECTED], now=OLD)
    assert findings[0].severity == "low"
    assert findings[0].signals == ("avatar_match",)


def test_young_account_alone_does_not_fire():
    subject = snapshot(user_id=YOUNG_ACCOUNT, display_name="brand new", username="freshuser")
    assert evaluate_member(subject, [PROTECTED], now=OLD) == []


def test_young_account_corroborates_display_match():
    subject = snapshot(user_id=YOUNG_ACCOUNT, display_name="tjaycodes", username="freshuser")
    findings = evaluate_member(subject, [PROTECTED], now=OLD, young_days=30)
    assert findings[0].severity == "high"
    assert "young_account" in findings[0].signals


def test_similar_display_name_is_low():
    subject = snapshot(user_id=OLD_ACCOUNT, display_name="tjaycodez", username="johndev", avatar_dhash=0xFFFF)
    findings = evaluate_member(subject, [PROTECTED], now=OLD)
    assert findings[0].severity == "low"
    assert findings[0].signals == ("display_name_near",)
    assert "1 edit(s)" in findings[0].evidence


def test_short_names_do_not_match():
    subject = snapshot(user_id=OLD_ACCOUNT, display_name="TJ", username="nobody")
    assert evaluate_member(subject, [ProtectedIdentity(GUILD, PROTECTED_ID, "TJ", "tj")], now=OLD) == []


def test_two_staff_sharing_a_name_never_reach_high():
    protected = ProtectedIdentity(GUILD, PROTECTED_ID, "Alex", "alex")
    subject = snapshot(user_id=OLD_ACCOUNT, display_name="Alex", username="alex_dev")
    findings = evaluate_member(subject, [protected], now=OLD)
    assert findings
    assert all(item.severity != "high" for item in findings)


def test_evidence_is_human_readable():
    subject = snapshot(user_id=SUSPECT_ID, display_name="tjaycodes", username="tjaycode4you", avatar_dhash=0b1011)
    finding = evaluate_member(subject, [PROTECTED], now=OLD)[0]
    assert "identical" in finding.evidence
    assert "1 edit(s)" in finding.evidence
    assert "distance 1/256" in finding.evidence
    assert str(PROTECTED_ID) in finding.evidence
    assert "2020-03-17" in finding.evidence


def test_multiple_protected_identities_are_reported():
    second = ProtectedIdentity(GUILD, 999999999999999999, "othername", "otheruser")
    subject = snapshot(user_id=OLD_ACCOUNT, display_name="tjaycodes", username="tjaycode4you")
    findings = evaluate_member(subject, [second, PROTECTED], now=OLD)
    assert len(findings) == 1
    assert findings[0].protected_user_id == PROTECTED_ID


def test_max_severity():
    subject = snapshot(user_id=OLD_ACCOUNT, display_name="tjaycodes", username="tjaycode4you", avatar_dhash=0b1011)
    findings = evaluate_member(subject, [PROTECTED], now=OLD)
    assert max_severity(findings) == "high"
    assert max_severity([]) is None
    assert SEVERITY_RANK["high"] > SEVERITY_RANK["medium"] > SEVERITY_RANK["low"]
