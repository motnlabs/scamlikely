"""Discord layer for the sdev.up impersonation watch.

The detection rules live in :mod:`scamlikely.core` and are unit-tested without a
gateway.  This module only moves bytes: guild events, SQLite, embeds and the
human Ban / Ignore decision.

Run from the repository root::

    python -m scamlikely.bot

Required environment: ``DISCORD_TOKEN``.  Everything else has a default; see
``bot/.env.example``.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import discord
from discord import app_commands

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scamlikely.core import (  # noqa: E402
    SEVERITY_RANK,
    Finding,
    MemberSnapshot,
    ProtectedIdentity,
    account_age_days,
    created_at,
    dhash_bytes,
    evaluate_member,
    from_hex,
    to_hex,
)

LOG = logging.getLogger("sdev.bot")

BOT_DIR = Path(__file__).resolve().parent
SEVERITY_COLOURS = {
    "high": 0xE74C3C,
    "medium": 0xE67E22,
    "low": 0x95A5A6,
}
AVATAR_SIZE = 256


@dataclass(frozen=True)
class Config:
    token: str
    alert_channel_id: Optional[int]
    db_path: Path
    avatar_distance_max: int
    young_account_days: int
    dedupe_hours: int
    scan_pause: float
    scan_max_alerts: int
    scan_all_avatars: bool
    log_level: str


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def _int_env(name: str, default: int) -> int:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        LOG.warning("ignoring non-integer %s=%r", name, value)
        return default


def _float_env(name: str, default: float) -> float:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        return float(value)
    except ValueError:
        LOG.warning("ignoring non-numeric %s=%r", name, value)
        return default


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def load_config() -> Config:
    token = os.environ.get("DISCORD_TOKEN", "").strip()
    if not token:
        raise SystemExit(
            "DISCORD_TOKEN is not set. Copy bot/.env.example to bot/.env and fill it in, "
            "or export the variable."
        )
    raw_db = os.environ.get("BOT_DB_PATH", "").strip()
    db_path = Path(raw_db) if raw_db else BOT_DIR / "data" / "sdev-bot.db"
    return Config(
        token=token,
        alert_channel_id=_int_env("ALERT_CHANNEL_ID", 0) or None,
        db_path=db_path,
        avatar_distance_max=_int_env("AVATAR_DISTANCE_MAX", 8),
        young_account_days=_int_env("YOUNG_ACCOUNT_DAYS", 30),
        dedupe_hours=_int_env("ALERT_DEDUPE_HOURS", 24),
        scan_pause=_float_env("SCAN_PAUSE_SECONDS", 1.0),
        scan_max_alerts=_int_env("SCAN_MAX_ALERTS", 25),
        scan_all_avatars=_bool_env("SCAN_ALL_AVATARS", False),
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    )


def _utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _iso(moment: datetime | None = None) -> str:
    return (moment or _utc_now()).isoformat(timespec="seconds")


class Storage:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS guild_config (
                    guild_id INTEGER PRIMARY KEY,
                    alert_channel_id INTEGER
                );
                CREATE TABLE IF NOT EXISTS protected (
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    username TEXT NOT NULL DEFAULT '',
                    avatar_dhash TEXT,
                    notes TEXT NOT NULL DEFAULT '',
                    added_by INTEGER,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (guild_id, user_id)
                );
                CREATE TABLE IF NOT EXISTS name_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    username TEXT NOT NULL DEFAULT '',
                    avatar_dhash TEXT,
                    seen_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS name_history_user
                    ON name_history (user_id, seen_at DESC);
                CREATE TABLE IF NOT EXISTS avatar_cache (
                    user_id INTEGER NOT NULL,
                    avatar_key TEXT NOT NULL,
                    avatar_dhash TEXT NOT NULL,
                    seen_at TEXT NOT NULL,
                    PRIMARY KEY (user_id, avatar_key)
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER NOT NULL,
                    channel_id INTEGER,
                    message_id INTEGER,
                    subject_user_id INTEGER NOT NULL,
                    protected_user_id INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    trigger TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    decision TEXT,
                    decided_by INTEGER,
                    decided_at TEXT
                );
                CREATE INDEX IF NOT EXISTS alerts_pair
                    ON alerts (guild_id, subject_user_id, protected_user_id, id DESC);
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def set_alert_channel(self, guild_id: int, channel_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO guild_config (guild_id, alert_channel_id) VALUES (?, ?) "
                "ON CONFLICT(guild_id) DO UPDATE SET alert_channel_id=excluded.alert_channel_id",
                (int(guild_id), int(channel_id)),
            )

    def get_alert_channel(self, guild_id: int) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT alert_channel_id FROM guild_config WHERE guild_id=?",
                (int(guild_id),),
            ).fetchone()
        return int(row["alert_channel_id"]) if row and row["alert_channel_id"] else None

    def upsert_protected(self, identity: ProtectedIdentity, added_by: int | None = None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO protected
                    (guild_id, user_id, display_name, username, avatar_dhash, notes, added_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(guild_id, user_id) DO UPDATE SET
                    display_name=excluded.display_name,
                    username=excluded.username,
                    avatar_dhash=excluded.avatar_dhash,
                    notes=excluded.notes,
                    added_by=excluded.added_by
                """,
                (
                    int(identity.guild_id),
                    int(identity.user_id),
                    identity.display_name,
                    identity.username,
                    to_hex(identity.avatar_dhash) if identity.avatar_dhash is not None else None,
                    identity.notes,
                    int(added_by) if added_by else None,
                    _iso(),
                ),
            )

    def list_protected(self, guild_id: int) -> list[ProtectedIdentity]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM protected WHERE guild_id=? ORDER BY created_at",
                (int(guild_id),),
            ).fetchall()
        return [
            ProtectedIdentity(
                guild_id=int(row["guild_id"]),
                user_id=int(row["user_id"]),
                display_name=row["display_name"] or "",
                username=row["username"] or "",
                avatar_dhash=from_hex(row["avatar_dhash"]),
                notes=row["notes"] or "",
            )
            for row in rows
        ]

    def get_protected(self, guild_id: int, user_id: int) -> ProtectedIdentity | None:
        return next(
            (item for item in self.list_protected(guild_id) if item.user_id == int(user_id)),
            None,
        )

    def remove_protected(self, guild_id: int, user_id: int) -> bool:
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "DELETE FROM protected WHERE guild_id=? AND user_id=?",
                (int(guild_id), int(user_id)),
            )
        return cursor.rowcount > 0

    def record_sighting(
        self,
        guild_id: int,
        user_id: int,
        display_name: str,
        username: str,
        avatar_dhash: int | None,
    ) -> None:
        value = to_hex(avatar_dhash) if avatar_dhash is not None else None
        with self._lock, self._conn:
            last = self._conn.execute(
                "SELECT display_name, username, avatar_dhash FROM name_history "
                "WHERE user_id=? AND guild_id=? ORDER BY id DESC LIMIT 1",
                (int(user_id), int(guild_id)),
            ).fetchone()
            if (
                last
                and last["display_name"] == display_name
                and last["username"] == username
                and last["avatar_dhash"] == value
            ):
                return
            self._conn.execute(
                "INSERT INTO name_history "
                "(guild_id, user_id, display_name, username, avatar_dhash, seen_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (int(guild_id), int(user_id), display_name, username, value, _iso()),
            )

    def name_history(self, user_id: int, guild_id: int | None = None, limit: int = 10) -> list[sqlite3.Row]:
        with self._lock:
            if guild_id is None:
                return self._conn.execute(
                    "SELECT * FROM name_history WHERE user_id=? ORDER BY id DESC LIMIT ?",
                    (int(user_id), int(limit)),
                ).fetchall()
            return self._conn.execute(
                "SELECT * FROM name_history WHERE user_id=? AND guild_id=? ORDER BY id DESC LIMIT ?",
                (int(user_id), int(guild_id), int(limit)),
            ).fetchall()

    def cache_avatar(self, user_id: int, avatar_key: str, avatar_dhash: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO avatar_cache (user_id, avatar_key, avatar_dhash, seen_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(user_id, avatar_key) DO UPDATE SET "
                "avatar_dhash=excluded.avatar_dhash, seen_at=excluded.seen_at",
                (int(user_id), avatar_key, to_hex(avatar_dhash), _iso()),
            )

    def cached_avatar(self, user_id: int, avatar_key: str) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT avatar_dhash FROM avatar_cache WHERE user_id=? AND avatar_key=?",
                (int(user_id), avatar_key),
            ).fetchone()
        return from_hex(row["avatar_dhash"]) if row else None

    def record_alert(self, guild_id: int, finding: Finding, trigger: str) -> int:
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO alerts "
                "(guild_id, subject_user_id, protected_user_id, severity, evidence, trigger, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    int(guild_id),
                    int(finding.subject_user_id),
                    int(finding.protected_user_id),
                    finding.severity,
                    finding.evidence,
                    trigger,
                    _iso(),
                ),
            )
        return int(cursor.lastrowid)

    def attach_alert_message(self, alert_id: int, guild_id: int, channel_id: int, message_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE alerts SET guild_id=?, channel_id=?, message_id=? WHERE id=?",
                (int(guild_id), int(channel_id), int(message_id), int(alert_id)),
            )

    def delete_alert(self, alert_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM alerts WHERE id=?", (int(alert_id),))

    def last_alert(self, guild_id: int, subject_user_id: int, protected_user_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alerts WHERE guild_id=? AND subject_user_id=? "
                "AND protected_user_id=? ORDER BY id DESC LIMIT 1",
                (int(guild_id), int(subject_user_id), int(protected_user_id)),
            ).fetchone()

    def get_alert(self, alert_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alerts WHERE id=?", (int(alert_id),)
            ).fetchone()

    def set_decision(self, alert_id: int, decision: str, actor_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE alerts SET decision=?, decided_by=?, decided_at=? WHERE id=?",
                (decision, int(actor_id), _iso(), int(alert_id)),
            )

    def pending_alerts(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alerts WHERE decision IS NULL AND message_id IS NOT NULL"
            ).fetchall()

    def forget_user(self, guild_id: int, user_id: int) -> dict[str, int]:
        counts: dict[str, int] = {}
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "DELETE FROM protected WHERE guild_id=? AND user_id=?",
                (int(guild_id), int(user_id)),
            )
            counts["protected"] = cursor.rowcount
            cursor = self._conn.execute(
                "DELETE FROM name_history WHERE guild_id=? AND user_id=?",
                (int(guild_id), int(user_id)),
            )
            counts["name_history"] = cursor.rowcount
            cursor = self._conn.execute(
                "DELETE FROM avatar_cache WHERE user_id=?", (int(user_id),)
            )
            counts["avatar_cache"] = cursor.rowcount
            cursor = self._conn.execute(
                "DELETE FROM alerts WHERE guild_id=? AND (subject_user_id=? OR protected_user_id=?)",
                (int(guild_id), int(user_id), int(user_id)),
            )
            counts["alerts"] = cursor.rowcount
        return counts


def build_embed(member: discord.Member, finding: Finding, trigger: str) -> discord.Embed:
    created = created_at(finding.subject_user_id)
    embed = discord.Embed(
        title=f"Impersonation {finding.severity.upper()}",
        colour=SEVERITY_COLOURS.get(finding.severity, 0x95A5A6),
        description=(
            f"{member.mention} may be impersonating a protected identity. "
            "No action has been taken automatically."
        ),
        timestamp=_utc_now(),
    )
    embed.add_field(name="Display name", value=f"`{finding.display_name}`", inline=True)
    embed.add_field(name="Username", value=f"`{finding.username}`", inline=True)
    embed.add_field(name="User ID", value=f"`{finding.subject_user_id}`", inline=True)
    embed.add_field(
        name="Account age",
        value=f"{created.date().isoformat()} ({finding.account_age_days:.0f} days)",
        inline=True,
    )
    distance = (
        f"{finding.avatar_distance}/256" if finding.avatar_distance is not None else "n/a"
    )
    embed.add_field(name="Avatar distance", value=distance, inline=True)
    embed.add_field(
        name="Matched protected",
        value=f"{finding.protected_label} (`{finding.protected_user_id}`)",
        inline=True,
    )
    embed.add_field(name="Signals", value=finding.signal_string(), inline=False)
    embed.add_field(name="Evidence", value=finding.evidence[:1024], inline=False)
    embed.add_field(name="Trigger", value=trigger, inline=True)
    embed.set_footer(text="Ban is a human decision. Ignore silences this pair unless severity rises.")
    if member.display_avatar:
        embed.set_thumbnail(url=member.display_avatar.url)
    return embed


class AlertView(discord.ui.View):
    def __init__(self, bot: "ImpersonationBot", alert_id: int, guild_id: int, subject_id: int):
        super().__init__(timeout=None)
        self.bot = bot
        self.alert_id = alert_id
        self.guild_id = guild_id
        self.subject_id = subject_id
        ban = discord.ui.Button(
            style=discord.ButtonStyle.danger,
            label="Ban",
            custom_id=f"imp:ban:{alert_id}",
        )
        ignore = discord.ui.Button(
            style=discord.ButtonStyle.secondary,
            label="Ignore",
            custom_id=f"imp:ignore:{alert_id}",
        )
        ban.callback = self.on_ban
        ignore.callback = self.on_ignore
        # The bot only needs Ban Members if it is meant to act. A server that
        # grants post-only permissions gets a usable alert instead of a button
        # that always fails.
        guild = bot.get_guild(guild_id)
        can_ban = bool(guild and guild.me and guild.me.guild_permissions.ban_members)
        if can_ban:
            self.add_item(ban)
        self.add_item(ignore)

    def disable_all(self) -> None:
        for child in self.children:
            child.disabled = True

    async def _authorised(self, interaction: discord.Interaction) -> bool:
        permissions = interaction.user.guild_permissions
        if permissions.ban_members or permissions.manage_guild:
            return True
        await interaction.response.send_message(
            "You need Ban Members or Manage Server to use this.", ephemeral=True
        )
        return False

    async def on_ban(self, interaction: discord.Interaction) -> None:
        if not await self._authorised(interaction):
            return
        guild = self.bot.get_guild(self.guild_id)
        if guild is None:
            await interaction.response.send_message(
                "I am no longer in that guild.", ephemeral=True
            )
            return
        reason = f"sdev.up impersonation alert #{self.alert_id} (human-confirmed by {interaction.user})"
        try:
            await guild.ban(
                discord.Object(id=self.subject_id),
                reason=reason[:512],
            )
        except discord.Forbidden:
            await interaction.response.send_message(
                "I don't have permission to ban that user.", ephemeral=True
            )
            return
        except discord.HTTPException as error:
            await interaction.response.send_message(
                f"Ban failed: {error}", ephemeral=True
            )
            return
        self.bot.storage.set_decision(self.alert_id, "ban", interaction.user.id)
        self.disable_all()
        embed = interaction.message.embeds[0] if interaction.message.embeds else discord.Embed()
        embed.colour = 0x2ECC71
        embed.set_footer(text=f"Banned by {interaction.user} (alert #{self.alert_id}).")
        await interaction.response.edit_message(embed=embed, view=self)

    async def on_ignore(self, interaction: discord.Interaction) -> None:
        if not await self._authorised(interaction):
            return
        self.bot.storage.set_decision(self.alert_id, "ignore", interaction.user.id)
        self.disable_all()
        embed = interaction.message.embeds[0] if interaction.message.embeds else discord.Embed()
        embed.colour = 0x7F8C8D
        embed.set_footer(
            text=f"Ignored by {interaction.user} (alert #{self.alert_id}); this pair will stay quiet."
        )
        await interaction.response.edit_message(embed=embed, view=self)


class ImpersonationBot(discord.Client):
    def __init__(self, config: Config):
        intents = discord.Intents.default()
        intents.guilds = True
        intents.members = True
        super().__init__(intents=intents)
        self.config = config
        self.storage = Storage(config.db_path)
        self.tree = app_commands.CommandTree(self)
        self._register_commands()

    async def setup_hook(self) -> None:
        self.storage.init_schema()
        for row in self.storage.pending_alerts():
            view = AlertView(self, int(row["id"]), int(row["guild_id"]), int(row["subject_user_id"]))
            self.add_view(view, message_id=int(row["message_id"]))
        await self.tree.sync()
        LOG.info("setup complete: %d guild(s), slash commands synced", len(self.guilds))

    async def on_ready(self) -> None:
        LOG.info("logged in as %s (%s)", self.user, getattr(self.user, "id", "?"))
        for guild in self.guilds:
            LOG.info(
                "guild %s (%s), protected=%d",
                guild.name,
                guild.id,
                len(self.storage.list_protected(guild.id)),
            )

    async def avatar_hash(self, user: discord.abc.User) -> int | None:
        asset = getattr(user, "display_avatar", None) or getattr(user, "avatar", None)
        if asset is None or getattr(asset, "key", None) is None:
            return None
        is_default = getattr(asset, "is_default", None)
        if callable(is_default) and is_default():
            return None
        key = asset.key
        cached = self.storage.cached_avatar(user.id, key)
        if cached is not None:
            return cached
        try:
            data = await asset.replace(size=AVATAR_SIZE, format="png").read()
        except discord.HTTPException as error:
            LOG.warning("avatar download failed for %s: %s", user.id, error)
            return None
        try:
            value = await asyncio.to_thread(dhash_bytes, data)
        except OSError as error:
            LOG.warning("avatar decode failed for %s: %s", user.id, error)
            return None
        self.storage.cache_avatar(user.id, key, value)
        return value

    async def snapshot(self, member: discord.Member) -> MemberSnapshot:
        value = await self.avatar_hash(member)
        return MemberSnapshot(
            guild_id=member.guild.id,
            user_id=member.id,
            display_name=member.display_name,
            username=member.name,
            avatar_dhash=value,
            bot=member.bot,
        )

    def evaluate(self, snapshot: MemberSnapshot, identities: list[ProtectedIdentity]) -> list[Finding]:
        return evaluate_member(
            snapshot,
            identities,
            avatar_threshold=self.config.avatar_distance_max,
            young_days=self.config.young_account_days,
        )

    def should_alert(self, guild_id: int, finding: Finding) -> bool:
        last = self.storage.last_alert(guild_id, finding.subject_user_id, finding.protected_user_id)
        if last is None:
            return True
        if last["decision"] == "ban":
            return False
        last_rank = SEVERITY_RANK.get(last["severity"], 0)
        if last["decision"] == "ignore" and finding.rank <= last_rank:
            return False
        if last["decision"] is None:
            created = datetime.fromisoformat(last["created_at"])
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            fresh = created >= _utc_now() - timedelta(hours=self.config.dedupe_hours)
            if fresh and finding.rank <= last_rank:
                return False
        return True

    def alert_channel(self, guild: discord.Guild) -> discord.abc.Messageable | None:
        channel_id = self.storage.get_alert_channel(guild.id) or self.config.alert_channel_id
        if channel_id:
            channel = guild.get_channel(int(channel_id))
            if channel is not None:
                return channel
        return guild.system_channel

    async def post_alert(self, member: discord.Member, finding: Finding, trigger: str) -> bool:
        channel = self.alert_channel(member.guild)
        if channel is None:
            LOG.warning("no alert channel for guild %s; alert dropped", member.guild.id)
            return False
        alert_id = self.storage.record_alert(member.guild.id, finding, trigger)
        view = AlertView(self, alert_id, member.guild.id, member.id)
        try:
            message = await channel.send(embed=build_embed(member, finding, trigger), view=view)
        except discord.Forbidden:
            LOG.warning("cannot post in %s:%s", member.guild.id, getattr(channel, "id", "?"))
            self.storage.delete_alert(alert_id)
            return False
        except discord.HTTPException as error:
            LOG.warning("alert send failed: %s", error)
            self.storage.delete_alert(alert_id)
            return False
        self.storage.attach_alert_message(alert_id, member.guild.id, channel.id, message.id)
        LOG.info(
            "alert #%s guild=%s subject=%s protected=%s severity=%s",
            alert_id,
            member.guild.id,
            member.id,
            finding.protected_user_id,
            finding.severity,
        )
        return True

    async def handle_member(self, member: discord.Member, trigger: str) -> None:
        if member.bot or member.guild is None:
            return
        snapshot = await self.snapshot(member)
        self.storage.record_sighting(
            member.guild.id,
            member.id,
            snapshot.display_name,
            snapshot.username,
            snapshot.avatar_dhash,
        )
        identities = self.storage.list_protected(member.guild.id)
        if not identities:
            return
        for finding in self.evaluate(snapshot, identities):
            if self.should_alert(member.guild.id, finding):
                await self.post_alert(member, finding, trigger)

    async def on_member_join(self, member: discord.Member) -> None:
        await self.handle_member(member, "member join")

    async def on_member_update(self, before: discord.Member, after: discord.Member) -> None:
        before_avatar = before.guild_avatar.key if before.guild_avatar else None
        after_avatar = after.guild_avatar.key if after.guild_avatar else None
        if (
            before.display_name == after.display_name
            and before.name == after.name
            and before_avatar == after_avatar
        ):
            return
        await self.handle_member(after, "member profile update")

    async def on_user_update(self, before: discord.User, after: discord.User) -> None:
        for guild in self.guilds:
            member = guild.get_member(after.id)
            if member is not None:
                await self.handle_member(member, "username/avatar update")

    def _register_commands(self) -> None:
        @self.tree.command(name="protect", description="Protect an identity in this server.")
        @app_commands.describe(user="User to protect (id or member)", notes="Why this identity is protected")
        @app_commands.default_permissions(manage_guild=True)
        @app_commands.guild_only()
        async def protect(interaction: discord.Interaction, user: discord.User, notes: str = "") -> None:
            await self.cmd_protect(interaction, user, notes)

        @self.tree.command(name="protect-list", description="List protected identities in this server.")
        @app_commands.default_permissions(manage_guild=True)
        @app_commands.guild_only()
        async def protect_list(interaction: discord.Interaction) -> None:
            await self.cmd_protect_list(interaction)

        @self.tree.command(name="unprotect", description="Remove a protected identity.")
        @app_commands.describe(user="User to unprotect")
        @app_commands.default_permissions(manage_guild=True)
        @app_commands.guild_only()
        async def unprotect(interaction: discord.Interaction, user: discord.User) -> None:
            await self.cmd_unprotect(interaction, user)

        @self.tree.command(name="scan", description="Sweep current members against the registry.")
        @app_commands.default_permissions(manage_guild=True)
        @app_commands.guild_only()
        async def scan(interaction: discord.Interaction) -> None:
            await self.cmd_scan(interaction)

        @self.tree.command(name="forget", description="Delete stored data for a user (privacy).")
        @app_commands.describe(user="User whose stored data should be deleted")
        @app_commands.default_permissions(manage_guild=True)
        @app_commands.guild_only()
        async def forget(interaction: discord.Interaction, user: discord.User) -> None:
            await self.cmd_forget(interaction, user)

        @self.tree.command(name="alert-channel", description="Set the channel impersonation alerts go to.")
        @app_commands.describe(channel="Text channel for alerts")
        @app_commands.default_permissions(manage_guild=True)
        @app_commands.guild_only()
        async def alert_channel(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
            self.storage.set_alert_channel(interaction.guild_id, channel.id)
            await interaction.response.send_message(
                f"Alerts will go to {channel.mention}.", ephemeral=True
            )

    async def cmd_protect(self, interaction: discord.Interaction, user: discord.User, notes: str) -> None:
        guild = interaction.guild
        member = guild.get_member(user.id) if guild else None
        display_name = member.display_name if member else (user.global_name or user.name)
        avatar_dhash = await self.avatar_hash(member or user)
        identity = ProtectedIdentity(
            guild_id=guild.id,
            user_id=user.id,
            display_name=display_name,
            username=user.name,
            avatar_dhash=avatar_dhash,
            notes=notes,
        )
        self.storage.upsert_protected(identity, added_by=interaction.user.id)
        self.storage.record_sighting(guild.id, user.id, display_name, user.name, avatar_dhash)
        embed = discord.Embed(
            title="Identity protected",
            colour=0x2ECC71,
            description=f"{user.mention} (`{user.id}`) is now protected in this server.",
        )
        embed.add_field(name="Display name", value=f"`{display_name}`", inline=True)
        embed.add_field(name="Username", value=f"`{user.name}`", inline=True)
        embed.add_field(
            name="Avatar hash",
            value=to_hex(avatar_dhash) if avatar_dhash is not None else "not available",
            inline=False,
        )
        if notes:
            embed.add_field(name="Notes", value=notes[:1024], inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    async def cmd_protect_list(self, interaction: discord.Interaction) -> None:
        identities = self.storage.list_protected(interaction.guild_id)
        if not identities:
            await interaction.response.send_message(
                "No protected identities yet. Use /protect with a user id.", ephemeral=True
            )
            return
        embed = discord.Embed(
            title=f"Protected identities ({len(identities)})",
            colour=0x3498DB,
        )
        for identity in identities[:25]:
            embed.add_field(
                name=f"{identity.label} (`{identity.user_id}`)",
                value=(
                    f"username `{identity.username}`"
                    + (f"\n{identity.notes}" if identity.notes else "")
                ),
                inline=False,
            )
        if len(identities) > 25:
            embed.set_footer(text=f"showing 25 of {len(identities)}")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    async def cmd_unprotect(self, interaction: discord.Interaction, user: discord.User) -> None:
        removed = self.storage.remove_protected(interaction.guild_id, user.id)
        text = (
            f"Removed protection for `{user.id}`."
            if removed
            else f"`{user.id}` was not protected in this server."
        )
        await interaction.response.send_message(text, ephemeral=True)

    async def cmd_scan(self, interaction: discord.Interaction) -> None:
        guild = interaction.guild
        await interaction.response.defer(ephemeral=True, thinking=True)
        identities = self.storage.list_protected(guild.id)
        if not identities:
            await interaction.followup.send(
                "No protected identities yet. Add one with /protect first.", ephemeral=True
            )
            return

        # Two phases, because a 20k-member guild must not mean 20k avatar
        # downloads. Phase 1 reads names only (cheap string work) and queues
        # anyone who trips a name rule; phase 2 hashes just those avatars.
        # An avatar-only clone (same art, unrelated name) is only caught when
        # SCAN_ALL_AVATARS is on - one expensive pass, then cached per avatar key.
        scanned = 0
        queued: list[discord.Member] = []

        try:
            async for member in guild.fetch_members(limit=None):
                scanned += 1
                if not member.bot:
                    self.storage.record_sighting(
                        guild.id, member.id, member.display_name, member.name, None
                    )
                    snapshot = MemberSnapshot(
                        guild_id=guild.id,
                        user_id=member.id,
                        display_name=member.display_name,
                        username=member.name,
                        avatar_dhash=None,
                    )
                    if self.config.scan_all_avatars or self.evaluate(snapshot, identities):
                        queued.append(member)
                if scanned % 2000 == 0:
                    await asyncio.sleep(self.config.scan_pause)
        except discord.DiscordException as error:
            LOG.warning("scan aborted: %s", error)
            await interaction.followup.send(
                f"Scan aborted after {scanned} members: {error}", ephemeral=True
            )
            return

        alerted = 0
        suppressed = 0
        semaphore = asyncio.Semaphore(8)

        async def check(member: discord.Member) -> None:
            nonlocal alerted, suppressed
            async with semaphore:
                snapshot = await self.snapshot(member)
            self.storage.record_sighting(
                guild.id, member.id, snapshot.display_name, snapshot.username,
                snapshot.avatar_dhash,
            )
            for finding in self.evaluate(snapshot, identities):
                if not self.should_alert(guild.id, finding):
                    suppressed += 1
                    continue
                if alerted >= self.config.scan_max_alerts:
                    suppressed += 1
                    continue
                if await self.post_alert(member, finding, "manual /scan"):
                    alerted += 1

        await asyncio.gather(*(check(m) for m in queued))
        await interaction.followup.send(
            f"Scanned {scanned} members against {len(identities)} protected identities: "
            f"{len(queued)} name candidate(s) checked with avatars, "
            f"{alerted} alert(s) posted, {suppressed} suppressed (dedupe/limit).",
            ephemeral=True,
        )

    async def cmd_forget(self, interaction: discord.Interaction, user: discord.User) -> None:
        counts = self.storage.forget_user(interaction.guild_id, user.id)
        summary = ", ".join(f"{name}={count}" for name, count in counts.items())
        await interaction.response.send_message(
            f"Deleted stored data for `{user.id}` in this server ({summary}).",
            ephemeral=True,
        )


def main() -> None:
    load_dotenv(BOT_DIR / ".env")
    config = load_config()
    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    bot = ImpersonationBot(config)
    try:
        bot.run(config.token, log_handler=None)
    finally:
        bot.storage.close()


if __name__ == "__main__":
    main()
