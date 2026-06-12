"""AWS IAM authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["IAMAuthProfile", "IAM_SPEC"]

IAM_SPEC = ProfileSpec(
    name="iam",
    provider_type="iam",
    parameters=[
        # ROLE_ARN is config consumed by the storage profile's assume-role
        # shape, not a boto3.client() kwarg — kept as a field, never emitted.
        ParameterSpec(name="ROLE_ARN", type=str | None, tier="core", default=None),
        ParameterSpec(name="ACCESS_KEY_ID", type=str | None, tier="core",
                      driver_key={TargetFamily.BOTO: "aws_access_key_id"}, default=None),
        ParameterSpec(name="SECRET_ACCESS_KEY", type=str | None, tier="core",
                      driver_key={TargetFamily.BOTO: "aws_secret_access_key"}, default=None, secret=True),
        ParameterSpec(name="SESSION_TOKEN", type=str | None, tier="advanced",
                      driver_key={TargetFamily.BOTO: "aws_session_token"}, default=None, secret=True),
        ParameterSpec(name="PROFILE_NAME", type=str | None, tier="advanced", default=None),
    ],
)


@register
class IAMAuthProfile(Profile):
    __spec__ = IAM_SPEC
