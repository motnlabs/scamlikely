"""Plain dataclasses shared by the detector and the Discord layer."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class ProtectedIdentity:
    guild_id: int
    user_id: int
    display_name: str = ""
    username: str = ""
    avatar_dhash: Optional[int] = None
    notes: str = ""

    @property
    def label(self) -> str:
        return self.display_name or self.username or str(self.user_id)


@dataclass(frozen=True)
class MemberSnapshot:
    guild_id: int
    user_id: int
    display_name: str = ""
    username: str = ""
    avatar_dhash: Optional[int] = None
    bot: bool = False


@dataclass(frozen=True)
class Finding:
    severity: str
    subject_user_id: int
    protected_user_id: int
    protected_label: str
    signals: Tuple[str, ...]
    evidence: str
    avatar_distance: Optional[int]
    display_name: str
    username: str
    account_age_days: float

    @property
    def dedupe_key(self) -> tuple[int, int]:
        return (self.subject_user_id, self.protected_user_id)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def signal_string(self) -> str:
        return ", ".join(self.signals)
