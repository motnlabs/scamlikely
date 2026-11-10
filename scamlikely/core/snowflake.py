"""Discord account creation time from a snowflake id.

``timestamp_ms = (id >> 22) + 1420070400000`` (Discord epoch 2015-01-01Z).
No API call, no network, no token.
"""
from __future__ import annotations

from datetime import datetime, timezone

DISCORD_EPOCH_MS = 1420070400000


def created_at_ms(user_id: int) -> int:
    return (int(user_id) >> 22) + DISCORD_EPOCH_MS


def created_at(user_id: int) -> datetime:
    return datetime.fromtimestamp(created_at_ms(user_id) / 1000, tz=timezone.utc)


def account_age_days(user_id: int, *, now: datetime | None = None) -> float:
    """Age in days at ``now`` (UTC; defaults to the current time)."""
    moment = now or datetime.now(tz=timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    delta = moment - created_at(user_id)
    return delta.total_seconds() / 86400.0


def age_string(user_id: int, *, now: datetime | None = None) -> str:
    created = created_at(user_id)
    days = account_age_days(user_id, now=now)
    return f"{created.date().isoformat()} ({days:.0f} days old)"
