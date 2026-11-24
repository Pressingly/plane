# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from dataclasses import dataclass

_TOKEN_USERNAME_CLAIMS = {"id": "cognito:username", "access": "username"}


@dataclass(frozen=True)
class AssertedIdentity:
    """What the proxy headers claim: the email Plane would log in as and every mPass id they name."""

    email: str
    mpass_ids: tuple[str, ...]


def token_mpass_id(claims: dict) -> str:
    """The mPass id a verified token names: ``cognito:username`` on id tokens, ``username`` on access tokens."""
    value = claims.get(_TOKEN_USERNAME_CLAIMS.get(claims.get("token_use"), ""))
    return value.strip() if isinstance(value, str) else ""


def token_email(claims: dict) -> str:
    """The token's email when it is an address; Cognito's ``cognito:default_val`` placeholder counts as none."""
    value = claims.get("email")
    if not isinstance(value, str) or "@" not in value:
        return ""
    return value.strip().lower()


def synthetic_email(mpass_id: str, synthetic_domain: str) -> str:
    return f"{mpass_id}@{synthetic_domain}".lower()


def _is_synthetic(email: str, synthetic_domain: str) -> bool:
    return email.rpartition("@")[2] == synthetic_domain.lower()


def binding_rejection(claims: dict, asserted: AssertedIdentity, synthetic_domain: str) -> str | None:
    """Why the asserted identity is not the one the verified token names, or None when it is.

    Every mPass id the headers name must be the token's. The email must match the token's
    email when the token carries one (id tokens), and a synthetic address must be the
    token's own ``<mpass id>@<synthetic domain>`` whatever the token kind.
    """
    expected_mpass_id = token_mpass_id(claims)
    if not expected_mpass_id:
        return "token_without_username"
    if not asserted.mpass_ids:
        return "missing_username"
    if any(mpass_id != expected_mpass_id for mpass_id in asserted.mpass_ids):
        return "username_mismatch"
    bound_email = token_email(claims)
    if bound_email and asserted.email != bound_email:
        return "email_mismatch"
    if _is_synthetic(asserted.email, synthetic_domain) and asserted.email != synthetic_email(
        expected_mpass_id, synthetic_domain
    ):
        return "synthetic_email_mismatch"
    return None
