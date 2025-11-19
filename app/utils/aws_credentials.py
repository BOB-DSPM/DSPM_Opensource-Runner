# ===============================
# file: app/utils/aws_credentials.py
# ===============================
from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Any, Dict, Optional, Tuple


class IAMCredentialError(RuntimeError):
    """Raised when IAM role based credentials cannot be prepared."""


def _extract_region(payload: Dict[str, Any]) -> Optional[str]:
    """Pick an AWS region from payload or environment."""
    region_like_keys = (
        "iam_region",
        "region",
        "aws_region",
        "aws_default_region",
    )
    for key in region_like_keys:
        value = payload.get(key)
        if value:
            return str(value)
    for env_key in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        value = os.environ.get(env_key)
        if value:
            return value
    return None


def _clamp_duration(value: Any, default: int = 3600) -> int:
    """Clamp the STS session duration to AWS allowed range."""
    min_sec = 900
    max_sec = 43200
    try:
        sec = int(str(value))
    except (TypeError, ValueError):
        sec = default
    return max(min_sec, min(max_sec, sec))


def prepare_aws_execution_env(
    payload: Dict[str, Any]
) -> Tuple[Dict[str, str], Optional[Dict[str, Any]]]:
    """
    Build environment variables for child processes so that they rely on IAM
    roles instead of static credentials. When iam_role_arn is omitted the
    helper still injects AWS_REGION defaults if present.
    """
    env: Dict[str, str] = {}
    region = _extract_region(payload)
    if region:
        env["AWS_REGION"] = region
        env["AWS_DEFAULT_REGION"] = region

    iam_role_arn = str(payload.get("iam_role_arn") or "").strip()
    if not iam_role_arn:
        return env, None

    session_name = str(
        payload.get("iam_session_name") or f"sage-oss-{uuid.uuid4().hex[:8]}"
    )
    external_id = payload.get("iam_external_id")
    duration = _clamp_duration(payload.get("iam_session_duration"))

    try:
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    except Exception as exc:  # pragma: no cover - import failure path
        raise IAMCredentialError(
            "boto3 is required to assume IAM roles. Ensure requirements are installed."
        ) from exc

    client_kwargs: Dict[str, Any] = {}
    if region:
        client_kwargs["region_name"] = region

    try:
        sts = boto3.client("sts", **client_kwargs)
        assume_args: Dict[str, Any] = {
            "RoleArn": iam_role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": duration,
        }
        if external_id:
            assume_args["ExternalId"] = str(external_id)
        resp = sts.assume_role(**assume_args)
    except (BotoCoreError, ClientError) as exc:
        raise IAMCredentialError(f"Failed to assume IAM role: {exc}") from exc

    creds = resp.get("Credentials") or {}
    access_key = creds.get("AccessKeyId")
    secret_key = creds.get("SecretAccessKey")
    token = creds.get("SessionToken")
    if not (access_key and secret_key and token):
        raise IAMCredentialError(
            "STS assume_role response did not include full credentials."
        )

    env["AWS_ACCESS_KEY_ID"] = access_key
    env["AWS_SECRET_ACCESS_KEY"] = secret_key
    env["AWS_SESSION_TOKEN"] = token

    expires = creds.get("Expiration")
    if isinstance(expires, datetime):
        expires_at = expires.isoformat()
    else:
        expires_at = str(expires) if expires else None

    metadata = {
        "role_arn": iam_role_arn,
        "session_name": session_name,
        "expires_at": expires_at,
        "source": "assume-role",
    }
    return env, metadata
