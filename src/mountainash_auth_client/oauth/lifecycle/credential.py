"""TokenCredential — the frozen token *output* of the OAuth2 acquisition seam.

A typed view of the token-store record (keys access_token / token_expires_at /
refresh_token). NOT a persisted credential schema — live token state is ops-managed
(Phase 2 evicted TOKEN_EXPIRES_AT from the schema). token_type is synthesized Bearer
(the record carries no token_type; these flows are Bearer-only).
"""
from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from mountainash_auth_client.oauth.records import read_oauth2_record

if TYPE_CHECKING:
    from mountainash_settings.secrets import SecretRecord


@dataclasses.dataclass(frozen=True)
class TokenCredential:
    access_token: str
    token_type: str = "Bearer"
    expires_at: int | None = None
    refresh_token: str | None = None

    @classmethod
    def from_record(cls, record: SecretRecord) -> "TokenCredential":
        tokens = read_oauth2_record(record)
        return cls(
            access_token=tokens["access_token"],
            expires_at=tokens.get("token_expires_at"),
            refresh_token=tokens.get("refresh_token"),
        )
