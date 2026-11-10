"""The detector: compare one member against a guild's protected identities.

Severity is the whole point of this module, so the contract is explicit:

* ``high`` requires corroboration - an identical display name **and** at least
  one of (username near-match / avatar match / young account), or a username
  near-match **and** an avatar match.  Two moderators from different servers
  who happen to share a display name therefore never reach ``high``.
* ``medium`` is a distinctive single signal (a near-miss username).
* ``low`` is a weak single signal (an uncorroborated identical or similar
  display name, a matching avatar with no name match).

The protected user themself, bots and ids on the allowlist are never reported.
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterable, Sequence

from .avatar import MATCH_DISTANCE, distance as hamming
from .models import (
    SEVERITY_RANK,
    Finding,
    MemberSnapshot,
    ProtectedIdentity,
)
from .normalize import normalize
from .similarity import (
    best_name_distance,
    compare_handles,
    names_equal,
    threshold_for,
)
from .snowflake import account_age_days, created_at

MIN_DISPLAY_LEN = 3
MIN_NEAR_DISPLAY_LEN = 4
DEFAULT_YOUNG_DAYS = 30


def _shortest_normalized(*values: str) -> int:
    lengths = [len(normalize(value)) for value in values if value]
    return min(lengths) if lengths else 0


def _display_state(
    snapshot: MemberSnapshot, identity: ProtectedIdentity
) -> tuple[bool, int | None]:
    if not snapshot.display_name or not identity.display_name:
        return False, None
    if names_equal(snapshot.display_name, identity.display_name):
        if _shortest_normalized(snapshot.display_name, identity.display_name) >= MIN_DISPLAY_LEN:
            return True, None
        return False, None
    if _shortest_normalized(snapshot.display_name, identity.display_name) < MIN_NEAR_DISPLAY_LEN:
        return False, None
    edit_distance = best_name_distance(snapshot.display_name, identity.display_name)
    if edit_distance is None:
        return False, None
    left = normalize(snapshot.display_name)
    right = normalize(identity.display_name)
    if 0 < edit_distance <= threshold_for(left, right):
        return False, edit_distance
    return False, None


def _severity(
    *,
    display_exact: bool,
    display_near: int | None,
    username_matched: bool,
    avatar_match: bool,
    young: bool,
) -> str | None:
    if display_exact and (username_matched or avatar_match or young):
        return "high"
    if username_matched and avatar_match:
        return "high"
    if username_matched:
        return "medium"
    if display_exact or display_near is not None or avatar_match:
        return "low"
    return None


def _evidence(
    *,
    snapshot: MemberSnapshot,
    identity: ProtectedIdentity,
    display_exact: bool,
    display_near: int | None,
    handle,
    avatar_distance: int | None,
    avatar_match: bool,
    young: bool,
    age_days: float,
) -> str:
    parts: list[str] = []
    if display_exact:
        parts.append(
            f"display name {snapshot.display_name!r} is identical to protected "
            f"{identity.display_name!r} ({identity.user_id})"
        )
    elif display_near is not None:
        parts.append(
            f"display name {snapshot.display_name!r} is {display_near} edit(s) "
            f"from protected {identity.display_name!r} ({identity.user_id})"
        )
    if handle.matched:
        parts.append(f"{handle.describe()} (protected is {identity.username!r})")
    if avatar_distance is not None:
        label = "same art" if avatar_match else "different art"
        parts.append(f"avatar dHash distance {avatar_distance}/256 ({label})")
    created = created_at(snapshot.user_id)
    age_label = f"account created {created.date().isoformat()} ({age_days:.0f} days old)"
    if young:
        age_label += ", young account"
    parts.append(age_label)
    return "; ".join(parts)


def evaluate_member(
    snapshot: MemberSnapshot,
    identities: Iterable[ProtectedIdentity],
    *,
    now: datetime | None = None,
    avatar_threshold: int = MATCH_DISTANCE,
    young_days: int = DEFAULT_YOUNG_DAYS,
    allowlist: Sequence[int] = (),
) -> list[Finding]:
    """Return one :class:`Finding` per protected identity that was matched."""
    if snapshot.bot:
        return []

    allowed = {int(value) for value in allowlist}
    if int(snapshot.user_id) in allowed:
        return []

    age_days = account_age_days(snapshot.user_id, now=now)
    young = age_days < young_days
    findings: list[Finding] = []

    for identity in identities:
        if int(identity.guild_id) != int(snapshot.guild_id):
            continue
        if int(identity.user_id) == int(snapshot.user_id):
            continue
        if int(identity.user_id) in allowed:
            continue

        display_exact, display_near = _display_state(snapshot, identity)
        handle = compare_handles(snapshot.username, identity.username)

        avatar_distance: int | None = None
        avatar_match = False
        if snapshot.avatar_dhash is not None and identity.avatar_dhash is not None:
            avatar_distance = hamming(snapshot.avatar_dhash, identity.avatar_dhash)
            avatar_match = avatar_distance <= avatar_threshold

        severity = _severity(
            display_exact=display_exact,
            display_near=display_near,
            username_matched=handle.matched,
            avatar_match=avatar_match,
            young=young,
        )
        if severity is None:
            continue

        signals: list[str] = []
        if display_exact:
            signals.append("display_name_exact")
        if display_near is not None:
            signals.append("display_name_near")
        if handle.matched:
            signals.append("username_match")
        if avatar_match:
            signals.append("avatar_match")
        if young:
            signals.append("young_account")

        findings.append(
            Finding(
                severity=severity,
                subject_user_id=int(snapshot.user_id),
                protected_user_id=int(identity.user_id),
                protected_label=identity.label,
                signals=tuple(signals),
                evidence=_evidence(
                    snapshot=snapshot,
                    identity=identity,
                    display_exact=display_exact,
                    display_near=display_near,
                    handle=handle,
                    avatar_distance=avatar_distance,
                    avatar_match=avatar_match,
                    young=young,
                    age_days=age_days,
                ),
                avatar_distance=avatar_distance,
                display_name=snapshot.display_name,
                username=snapshot.username,
                account_age_days=age_days,
            )
        )

    findings.sort(key=lambda item: (-SEVERITY_RANK[item.severity], item.protected_user_id))
    return findings


def max_severity(findings: Sequence[Finding]) -> str | None:
    if not findings:
        return None
    return max(findings, key=lambda item: item.rank).severity
