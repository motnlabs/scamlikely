from datetime import datetime, timezone

import pytest

from scamlikely.core.snowflake import (
    DISCORD_EPOCH_MS,
    account_age_days,
    age_string,
    created_at,
    created_at_ms,
)

SUSPECT = 689579838108991511
VICTIM = 321025125698895874


def test_snowflake_formula():
    assert created_at_ms(0) == DISCORD_EPOCH_MS
    assert created_at_ms(SUSPECT) == (SUSPECT >> 22) + 1420070400000


def test_known_account_creation_dates():
    assert created_at(SUSPECT).date().isoformat() == "2020-03-17"
    assert created_at(VICTIM).date().isoformat() == "2017-06-04"
    assert created_at(SUSPECT).tzinfo == timezone.utc


def test_account_age_days_at_fixed_now():
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    assert account_age_days(SUSPECT, now=now) == pytest.approx(2428.12, abs=0.02)


def test_naive_now_is_treated_as_utc():
    aware = datetime(2026, 11, 10, tzinfo=timezone.utc)
    naive = datetime(2026, 11, 10)
    assert account_age_days(SUSPECT, now=naive) == account_age_days(SUSPECT, now=aware)


def test_age_string():
    text = age_string(SUSPECT, now=datetime(2026, 11, 10, tzinfo=timezone.utc))
    assert text.startswith("2020-03-17")
    assert "days old" in text
