import pytest

discord = pytest.importorskip("discord")

from scamlikely.bot import (  # noqa: E402
    AlertView,
    Config,
    ImpersonationBot,
    Storage,
    build_embed,
    load_config,
)
from scamlikely.core import Finding, MemberSnapshot, ProtectedIdentity, evaluate_member  # noqa: E402

GUILD = 539258061081018378
VICTIM = 321025125698895874
SUSPECT = 689579838108991511


class FakeMember:
    mention = f"<@{SUSPECT}>"
    display_avatar = None


def make_finding(severity: str, subject: int = SUSPECT, protected: int = VICTIM) -> Finding:
    identity = ProtectedIdentity(GUILD, protected, "tjaycodes", "tjaycodes", 0b1010)
    snapshot = MemberSnapshot(GUILD, subject, "tjaycodes", "tjaycode4you", 0b1011)
    findings = evaluate_member(snapshot, [identity])
    chosen = [item for item in findings if item.severity == severity]
    if chosen:
        return chosen[0]
    return Finding(
        severity=severity,
        subject_user_id=subject,
        protected_user_id=protected,
        protected_label="tjaycodes",
        signals=("display_name_exact",),
        evidence="synthetic",
        avatar_distance=1,
        display_name="tjaycodes",
        username="tjaycode4you",
        account_age_days=2430.0,
    )


@pytest.fixture
def config(tmp_path):
    return Config(
        token="test-token",
        alert_channel_id=None,
        db_path=tmp_path / "bot.db",
        avatar_distance_max=8,
        young_account_days=30,
        dedupe_hours=24,
        scan_pause=0.0,
        scan_max_alerts=5,
        scan_all_avatars=False,
        log_level="INFO",
    )


@pytest.fixture
def bot(config):
    instance = ImpersonationBot(config)
    instance.storage.init_schema()
    yield instance
    instance.storage.close()


def test_protected_roundtrip(bot):
    identity = ProtectedIdentity(GUILD, VICTIM, "tjaycodes", "tjaycodes", 0b1010, "owner")
    bot.storage.upsert_protected(identity, added_by=1)
    listed = bot.storage.list_protected(GUILD)
    assert len(listed) == 1
    assert listed[0].user_id == VICTIM
    assert listed[0].avatar_dhash == 0b1010
    assert listed[0].notes == "owner"
    bot.storage.upsert_protected(
        ProtectedIdentity(GUILD, VICTIM, "new name", "tjaycodes", None, ""), added_by=2
    )
    updated = bot.storage.get_protected(GUILD, VICTIM)
    assert updated.display_name == "new name"
    assert updated.avatar_dhash is None
    assert bot.storage.remove_protected(GUILD, VICTIM)
    assert bot.storage.list_protected(GUILD) == []


def test_name_history_dedupes_identical_sightings(bot):
    bot.storage.record_sighting(GUILD, SUSPECT, "tjaycodes", "tjaycode4you", 0b1011)
    bot.storage.record_sighting(GUILD, SUSPECT, "tjaycodes", "tjaycode4you", 0b1011)
    assert len(bot.storage.name_history(SUSPECT)) == 1
    bot.storage.record_sighting(GUILD, SUSPECT, "tjaycodes", "tjaycode4you", 0b1100)
    assert len(bot.storage.name_history(SUSPECT)) == 2


def test_avatar_cache(bot):
    bot.storage.cache_avatar(SUSPECT, "abc", 0b1011)
    assert bot.storage.cached_avatar(SUSPECT, "abc") == 0b1011
    assert bot.storage.cached_avatar(SUSPECT, "def") is None


def test_alert_lifecycle(bot):
    finding = make_finding("high")
    alert_id = bot.storage.record_alert(GUILD, finding, "member join")
    row = bot.storage.last_alert(GUILD, SUSPECT, VICTIM)
    assert row["id"] == alert_id
    assert row["severity"] == "high"
    assert row["decision"] is None
    assert bot.storage.pending_alerts() == []
    bot.storage.attach_alert_message(alert_id, GUILD, 111, 222)
    assert [item["id"] for item in bot.storage.pending_alerts()] == [alert_id]
    bot.storage.set_decision(alert_id, "ignore", 42)
    assert bot.storage.pending_alerts() == []
    updated = bot.storage.get_alert(alert_id)
    assert updated["decision"] == "ignore"
    assert updated["decided_by"] == 42


def test_should_alert_dedupes_and_escalates(bot):
    medium = make_finding("medium")
    high = make_finding("high")
    assert bot.should_alert(GUILD, medium)
    bot.storage.record_alert(GUILD, medium, "test")
    assert not bot.should_alert(GUILD, medium)
    assert bot.should_alert(GUILD, high)


def test_ignore_is_persistent_until_severity_rises(bot):
    medium = make_finding("medium")
    alert_id = bot.storage.record_alert(GUILD, medium, "test")
    bot.storage.set_decision(alert_id, "ignore", 42)
    assert not bot.should_alert(GUILD, medium)
    assert bot.should_alert(GUILD, make_finding("high"))


def test_forget_user_purges_everything(bot):
    bot.storage.upsert_protected(ProtectedIdentity(GUILD, SUSPECT, "x", "y"), added_by=1)
    bot.storage.record_sighting(GUILD, SUSPECT, "x", "y", 0b1)
    bot.storage.cache_avatar(SUSPECT, "key", 0b1)
    bot.storage.record_alert(GUILD, make_finding("high"), "test")
    counts = bot.storage.forget_user(GUILD, SUSPECT)
    assert counts["protected"] == 1
    assert counts["name_history"] == 1
    assert counts["avatar_cache"] >= 1
    assert counts["alerts"] == 1
    assert bot.storage.list_protected(GUILD) == []
    assert bot.storage.name_history(SUSPECT) == []


def test_build_embed_contains_the_required_fields():
    finding = make_finding("high")
    embed = build_embed(FakeMember(), finding, "member join")
    names = [field.name for field in embed.fields]
    assert names == [
        "Display name",
        "Username",
        "User ID",
        "Account age",
        "Avatar distance",
        "Matched protected",
        "Signals",
        "Evidence",
        "Trigger",
    ]
    values = {field.name: field.value for field in embed.fields}
    assert values["User ID"] == f"`{SUSPECT}`"
    assert values["Avatar distance"] == "1/256"
    assert values["Username"] == "`tjaycode4you`"
    assert "no action has been taken automatically" in embed.description.lower()
    assert "human decision" in embed.footer.text.lower()


def test_alert_view_is_post_only_without_ban_permission(bot):
    # Default: the bot was invited without Ban Members, so it must not offer an
    # action it cannot perform.
    view = AlertView(bot, 7, GUILD, SUSPECT)
    assert [child.custom_id for child in view.children] == ["imp:ignore:7"]
    view.disable_all()
    assert all(child.disabled for child in view.children)


def test_alert_view_offers_ban_when_permitted(bot, monkeypatch):
    from types import SimpleNamespace

    fake_guild = SimpleNamespace(me=SimpleNamespace(
        guild_permissions=SimpleNamespace(ban_members=True)))
    monkeypatch.setattr(bot, "get_guild", lambda gid: fake_guild)
    view = AlertView(bot, 7, GUILD, SUSPECT)
    assert [child.custom_id for child in view.children] == ["imp:ban:7", "imp:ignore:7"]
    view.disable_all()
    assert all(child.disabled for child in view.children)


def test_load_config_requires_a_token(monkeypatch):
    monkeypatch.delenv("DISCORD_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        load_config()


def test_load_config_reads_env(monkeypatch, tmp_path):
    monkeypatch.setenv("DISCORD_TOKEN", "abc")
    monkeypatch.setenv("BOT_DB_PATH", str(tmp_path / "x.db"))
    monkeypatch.setenv("YOUNG_ACCOUNT_DAYS", "7")
    monkeypatch.setenv("ALERT_DEDUPE_HOURS", "12")
    monkeypatch.setenv("SCAN_MAX_ALERTS", "3")
    config = load_config()
    assert config.token == "abc"
    assert config.db_path == tmp_path / "x.db"
    assert config.young_account_days == 7
    assert config.dedupe_hours == 12
    assert config.scan_max_alerts == 3
