"""TokenCredential — the frozen token *output* of the OAuth2 acquisition seam.

A typed view of the token-store record (keys access_token / token_expires_at /
refresh_token). NOT a persisted credential schema — live token state is ops-managed
(Phase 2 evicted TOKEN_EXPIRES_AT from the schema). token_type is synthesized Bearer
(the record carries no token_type; these flows are Bearer-only).
"""
from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class TokenCredential:
    access_token: str
    token_type: str = "Bearer"
    expires_at: int | None = None
    refresh_token: str | None = None

    @classmethod
    def from_record(cls, record: dict) -> "TokenCredential":
        return cls(
            access_token=record["access_token"],
            expires_at=record.get("token_expires_at"),
            refresh_token=record.get("refresh_token"),
        )
