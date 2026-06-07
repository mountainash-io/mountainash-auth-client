"""AWS IAM authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["IAMAuth", "IAM_SPEC"]

IAM_SPEC = ProfileSpec(
    name="iam",
    provider_type="iam",
    parameters=[
        ParameterSpec(name="ROLE_ARN", type=str | None, tier="core", driver_key="iam_role_arn", default=None),
        ParameterSpec(name="ACCESS_KEY_ID", type=str | None, tier="core", driver_key="aws_access_key_id", default=None),
        ParameterSpec(name="SECRET_ACCESS_KEY", type=str | None, tier="core", driver_key="aws_secret_access_key", default=None, secret=True),
        ParameterSpec(name="SESSION_TOKEN", type=str | None, tier="advanced", driver_key="aws_session_token", default=None, secret=True),
        ParameterSpec(name="PROFILE_NAME", type=str | None, tier="advanced", default=None),
    ],
)


@register
class IAMAuth(Profile):
    __spec__ = IAM_SPEC
