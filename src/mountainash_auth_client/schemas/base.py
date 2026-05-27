"""Base class for discriminated-union auth specs.

Each AuthSpec subclass declares a ``kind: Literal["..."]`` field that pydantic
uses as the discriminator. The base class does NOT declare ``kind`` — if it
did, every subclass would trip ``reportIncompatibleVariableOverride``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

__all__ = ["AuthSpec"]


class AuthSpec(BaseModel):
    """Base for typed auth modes used as a pydantic discriminated union."""

    model_config = ConfigDict(extra="forbid", frozen=True)
