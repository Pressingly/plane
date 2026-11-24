# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.
"""
Tests for FOSS-836: a header login is accepted only when the proxy-asserted
identity is the one the verified X-Auth-Request-Access-Token names.

Run (from apps/api/):
    pytest plane/authentication/tests/test_proxy_auth_binding.py -v
"""

import logging
from unittest.mock import patch

import pytest

from plane.authentication.middleware.identity_binding import (
    AssertedIdentity,
    binding_rejection,
    token_email,
    token_mpass_id,
)
from plane.authentication.tests.test_proxy_auth_trust import (  # noqa: F401
    PATCH_LOGOUT,
    PATCH_USER_LOGIN,
    _mpass_settings,
    access_token_claims,
    id_token_claims,
    make_middleware,
    make_request,
    sign,
)
from plane.db.models import User

SYNTHETIC_DOMAIN = "askii.ai"
MPASS_ID = "mpass-1"
REAL_EMAIL = "owner@example.com"
SYNTHETIC_EMAIL = f"{MPASS_ID}@{SYNTHETIC_DOMAIN}"
VICTIM_EMAIL = "victim@example.com"
VICTIM_MPASS_ID = "mpass-victim"


@pytest.fixture(autouse=True)
def _synthetic_domain(settings):
    settings.DEFAULT_EMAIL_DOMAIN = SYNTHETIC_DOMAIN


def headers(email, token, user=None, preferred=None):
    meta = {"HTTP_X_AUTH_REQUEST_EMAIL": email, "HTTP_X_AUTH_REQUEST_ACCESS_TOKEN": token}
    if user is not None:
        meta["HTTP_X_AUTH_REQUEST_USER"] = user
    if preferred is not None:
        meta["HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME"] = preferred
    return meta


def capture_on_id_token(email=REAL_EMAIL, mpass_id=MPASS_ID):
    """mpass-auth-proxy's re-signed id_token: overlay email, preferred_username = cognito:username."""
    return sign(id_token_claims(**{"email": email, "cognito:username": mpass_id, "preferred_username": mpass_id}))


def cognito_access_token(mpass_id=MPASS_ID):
    return sign(access_token_claims(username=mpass_id))


def run(meta, authenticated_user=None):
    middleware = make_middleware()
    request = make_request(meta=meta, authenticated_user=authenticated_user)
    with patch(PATCH_USER_LOGIN) as mock_login, patch(PATCH_LOGOUT):
        response = middleware(request)
    return response, mock_login


def logged_in_email(mock_login):
    mock_login.assert_called_once()
    return mock_login.call_args.kwargs["user"].email


# ---------------------------------------------------------------------------
# Rule units
# ---------------------------------------------------------------------------


class TestTokenClaims:
    def test_id_token_names_cognito_username(self):
        assert token_mpass_id({"token_use": "id", "cognito:username": "a", "username": "b"}) == "a"

    def test_access_token_names_username(self):
        assert token_mpass_id({"token_use": "access", "cognito:username": "a", "username": "b"}) == "b"

    def test_unknown_token_use_names_nobody(self):
        assert token_mpass_id({"token_use": "refresh", "username": "b"}) == ""

    def test_email_is_normalised(self):
        assert token_email({"email": "  Owner@Example.COM "}) == "owner@example.com"

    @pytest.mark.parametrize("value", [None, "", "cognito:default_val", 42])
    def test_non_address_email_counts_as_none(self, value):
        assert token_email({"email": value}) == ""


class TestBindingRejection:
    ID_CLAIMS = {"token_use": "id", "cognito:username": MPASS_ID, "email": REAL_EMAIL}
    ACCESS_CLAIMS = {"token_use": "access", "username": MPASS_ID}

    def check(self, claims, email, *mpass_ids):
        return binding_rejection(claims, AssertedIdentity(email, tuple(mpass_ids)), SYNTHETIC_DOMAIN)

    def test_id_token_match(self):
        assert self.check(self.ID_CLAIMS, REAL_EMAIL, MPASS_ID) is None

    def test_id_token_email_mismatch(self):
        assert self.check(self.ID_CLAIMS, VICTIM_EMAIL, MPASS_ID) == "email_mismatch"

    def test_username_mismatch(self):
        assert self.check(self.ID_CLAIMS, REAL_EMAIL, VICTIM_MPASS_ID) == "username_mismatch"

    def test_headers_that_disagree_are_a_mismatch(self):
        assert self.check(self.ID_CLAIMS, REAL_EMAIL, MPASS_ID, VICTIM_MPASS_ID) == "username_mismatch"

    def test_missing_username(self):
        assert self.check(self.ID_CLAIMS, REAL_EMAIL) == "missing_username"

    def test_token_without_username(self):
        assert self.check({"token_use": "id", "email": REAL_EMAIL}, REAL_EMAIL, MPASS_ID) == "token_without_username"

    def test_access_token_with_real_email_binds_on_username(self):
        assert self.check(self.ACCESS_CLAIMS, REAL_EMAIL, MPASS_ID) is None

    def test_access_token_own_synthetic_email(self):
        assert self.check(self.ACCESS_CLAIMS, SYNTHETIC_EMAIL, MPASS_ID) is None

    def test_access_token_someone_elses_synthetic_email(self):
        victim = f"{VICTIM_MPASS_ID}@{SYNTHETIC_DOMAIN}"

        assert self.check(self.ACCESS_CLAIMS, victim, MPASS_ID) == "synthetic_email_mismatch"

    def test_id_token_synthetic_email_must_be_its_own(self):
        victim = f"{VICTIM_MPASS_ID}@{SYNTHETIC_DOMAIN}"
        claims = {**self.ID_CLAIMS, "email": victim}

        assert self.check(claims, victim, MPASS_ID) == "synthetic_email_mismatch"

    def test_synthetic_domain_is_case_insensitive(self):
        assert self.check(self.ACCESS_CLAIMS, SYNTHETIC_EMAIL, MPASS_ID) is None
        assert binding_rejection(self.ACCESS_CLAIMS, AssertedIdentity(SYNTHETIC_EMAIL, (MPASS_ID,)), "ASKII.AI") is None


# ---------------------------------------------------------------------------
# Caller shapes that must keep logging in
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestLegitimateCallers:
    def test_browser_sso_capture_on_verified_user(self):
        """oauth2-proxy cookie session: Cognito access token, User = email, Preferred = mPass id."""
        meta = headers(REAL_EMAIL, cognito_access_token(), user=REAL_EMAIL, preferred=MPASS_ID)

        _, mock_login = run(meta)

        assert logged_in_email(mock_login) == REAL_EMAIL

    def test_browser_sso_capture_on_unverified_user(self):
        meta = headers(SYNTHETIC_EMAIL, cognito_access_token(), user=SYNTHETIC_EMAIL, preferred=MPASS_ID)

        _, mock_login = run(meta)

        assert logged_in_email(mock_login) == SYNTHETIC_EMAIL

    def test_browser_sso_capture_off_has_only_the_user_header(self):
        """Devstack default: USER_ID_CLAIM=cognito:username and no preferred_username claim."""
        meta = headers(REAL_EMAIL, cognito_access_token(), user=MPASS_ID)

        _, mock_login = run(meta)

        assert logged_in_email(mock_login) == REAL_EMAIL

    def test_browser_sso_capture_off_bare_username_is_synthesised(self):
        meta = headers(MPASS_ID, cognito_access_token(), user=MPASS_ID)

        _, mock_login = run(meta)

        assert logged_in_email(mock_login) == SYNTHETIC_EMAIL

    def test_bearer_leg_plane_mcp_and_access_agent_mint(self):
        """plane-mcp and the access-agent send the re-signed id_token as Bearer; oauth2-proxy
        (SKIP_JWT_BEARER_TOKENS) forwards that same token as X-Auth-Request-Access-Token."""
        token = capture_on_id_token()
        meta = headers(REAL_EMAIL, token, user=REAL_EMAIL, preferred=MPASS_ID)

        _, mock_login = run(meta)

        assert logged_in_email(mock_login) == REAL_EMAIL

    def test_bearer_leg_email_case_differs(self):
        meta = headers("Owner@Example.com", capture_on_id_token(), user="Owner@Example.com", preferred=MPASS_ID)

        _, mock_login = run(meta)

        assert logged_in_email(mock_login) == REAL_EMAIL

    def test_bearer_leg_unverified_user(self):
        token = capture_on_id_token(email=SYNTHETIC_EMAIL)
        meta = headers(SYNTHETIC_EMAIL, token, user=SYNTHETIC_EMAIL, preferred=MPASS_ID)

        _, mock_login = run(meta)

        assert logged_in_email(mock_login) == SYNTHETIC_EMAIL

    def test_existing_session_matching_header_needs_no_token(self, django_user_model):
        owner = django_user_model.objects.create(email=REAL_EMAIL, username="owner")
        middleware = make_middleware()
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": REAL_EMAIL}, authenticated_user=owner)
        request.session = {"proxy_auth_smb_membership_ensured": True}

        with patch(PATCH_USER_LOGIN) as mock_login:
            response = middleware(request)

        mock_login.assert_not_called()
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Forged identities behind the edge secret
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestForgedIdentityIsRefused:
    @pytest.mark.parametrize(
        "meta, reason",
        [
            (
                headers(VICTIM_EMAIL, capture_on_id_token(), user=VICTIM_EMAIL, preferred=MPASS_ID),
                "email_mismatch",
            ),
            (
                headers(REAL_EMAIL, capture_on_id_token(), user=REAL_EMAIL, preferred=VICTIM_MPASS_ID),
                "username_mismatch",
            ),
            (
                headers(REAL_EMAIL, cognito_access_token(), user=VICTIM_MPASS_ID, preferred=MPASS_ID),
                "username_mismatch",
            ),
            (
                headers(REAL_EMAIL, cognito_access_token(), user=REAL_EMAIL),
                "missing_username",
            ),
            (
                headers(f"{VICTIM_MPASS_ID}@{SYNTHETIC_DOMAIN}", cognito_access_token(), preferred=MPASS_ID),
                "synthetic_email_mismatch",
            ),
            (
                headers(VICTIM_MPASS_ID, cognito_access_token(), user=MPASS_ID),
                "synthetic_email_mismatch",
            ),
            (
                headers(REAL_EMAIL, sign(access_token_claims(username="")), preferred=MPASS_ID),
                "token_without_username",
            ),
        ],
    )
    def test_refused_with_403_and_mpass_id_only_logs(self, meta, reason, caplog):
        with caplog.at_level(logging.WARNING):
            response, mock_login = run(meta)

        mock_login.assert_not_called()
        assert response.status_code == 403
        assert f"reason={reason}" in caplog.text
        for email in (REAL_EMAIL, VICTIM_EMAIL, SYNTHETIC_EMAIL, f"{VICTIM_MPASS_ID}@{SYNTHETIC_DOMAIN}"):
            assert email not in caplog.text
        assert not User.objects.filter(email=VICTIM_EMAIL).exists()

    def test_refusal_names_both_mpass_ids(self, caplog):
        meta = headers(REAL_EMAIL, capture_on_id_token(), user=REAL_EMAIL, preferred=VICTIM_MPASS_ID)

        with caplog.at_level(logging.WARNING):
            run(meta)

        assert f"mpass_id={VICTIM_MPASS_ID}" in caplog.text
        assert f"token_mpass_id={MPASS_ID}" in caplog.text

    def test_capture_off_cognito_placeholder_email_is_refused(self):
        """A raw Cognito id_token whose email is the cognito:default_val placeholder would
        otherwise collapse every such user onto one cognito:default_val@<domain> account."""
        token = sign(id_token_claims(**{"email": "cognito:default_val", "cognito:username": MPASS_ID}))
        meta = headers("cognito:default_val", token, user=MPASS_ID)

        response, mock_login = run(meta)

        mock_login.assert_not_called()
        assert response.status_code == 403

    def test_session_switch_to_forged_identity_logs_out_and_refuses(self, django_user_model):
        owner = django_user_model.objects.create(email=REAL_EMAIL, username="owner")
        meta = headers(VICTIM_EMAIL, capture_on_id_token(), user=VICTIM_EMAIL, preferred=MPASS_ID)
        middleware = make_middleware()
        request = make_request(meta=meta, authenticated_user=owner)

        with patch(PATCH_USER_LOGIN) as mock_login, patch(PATCH_LOGOUT) as mock_logout:
            response = middleware(request)

        mock_logout.assert_called_once()
        mock_login.assert_not_called()
        assert response.status_code == 403
