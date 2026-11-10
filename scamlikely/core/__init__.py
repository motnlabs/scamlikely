"""Pure-Python detection core.

Nothing in this package imports discord.py: every rule is unit-testable
against fixtures, with no gateway connection.
"""

from .avatar import (
    DHASH_BITS,
    MATCH_DISTANCE,
    dhash,
    dhash_bytes,
    dhash_file,
    distance,
    from_hex,
    to_hex,
)
from .models import Finding, MemberSnapshot, ProtectedIdentity, SEVERITY_RANK
from .normalize import normalize, normalize_handle, strip_padding, variants
from .registry import evaluate_member, max_severity
from .similarity import HandleMatch, compare_handles, damerau_levenshtein
from .snowflake import DISCORD_EPOCH_MS, account_age_days, created_at, created_at_ms

__all__ = [
    "DHASH_BITS",
    "MATCH_DISTANCE",
    "DISCORD_EPOCH_MS",
    "Finding",
    "HandleMatch",
    "MemberSnapshot",
    "ProtectedIdentity",
    "SEVERITY_RANK",
    "account_age_days",
    "compare_handles",
    "created_at",
    "created_at_ms",
    "damerau_levenshtein",
    "dhash",
    "dhash_bytes",
    "dhash_file",
    "distance",
    "from_hex",
    "to_hex",
    "evaluate_member",
    "max_severity",
    "normalize",
    "normalize_handle",
    "strip_padding",
    "variants",
]
