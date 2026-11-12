# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.
"""
Tests for FOSS-776: identity headers are trusted only from the mPass edge, and
the forwarded token is signature-verified for the SMB corporate gate.

Run (from apps/api/):
    pytest plane/authentication/tests/test_proxy_auth_trust.py -v
"""

import logging
import time
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory
from rest_framework.test import APIClient

from plane.authentication.middleware.edge_trust import request_is_from_edge
from plane.authentication.middleware.mpass_token import (
    InvalidMpassToken,
    MpassTokenVerifier,
    JWKS_FAILURE_BACKOFF_SECONDS,
    audience_matches,
    cognito_issuer,
    cognito_issuer_from_settings,
)
from plane.authentication.middleware.proxy_auth import ProxyAuthMiddleware
from plane.db.models import User
from plane.db.models.api import APIToken

EDGE_SECRET = "s" * 64
CLIENT_ID = "mpass-client"
CORPORATE_ID = "corp-123"
COGNITO_ISSUER = cognito_issuer("us-east-1", "us-east-1_pool")
MPASS_ISSUER = "http://mpass-auth-proxy:8000"
VICTIM_EMAIL = "victim@example.com"

PATCH_USER_LOGIN = "plane.authentication.middleware.proxy_auth.user_login"
PATCH_LOGOUT = "plane.authentication.middleware.proxy_auth.logout"

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJwksClient:
    def __init__(self, public_key):
        self.public_key = public_key

    def get_signing_key_from_jwt(self, token):
        return MagicMock(key=self.public_key)


def trusting_verifier(issuers=(COGNITO_ISSUER, MPASS_ISSUER)):
    return MpassTokenVerifier(
        issuers,
        CLIENT_ID,
        jwks_client_factory=lambda issuer: FakeJwksClient(SIGNING_KEY.public_key()),
    )


def access_token_claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": COGNITO_ISSUER,
        "sub": "sub-1",
        "username": "mpass-1",
        "client_id": CLIENT_ID,
        "token_use": "access",
        "iat": now,
        "exp": now + 3600,
        "custom:is_corporate": "true",
        "custom:corporate_id": CORPORATE_ID,
    }
    return {**claims, **overrides}


def id_token_claims(**overrides):
    base = access_token_claims(iss=MPASS_ISSUER, token_use="id", aud=CLIENT_ID)
    base.pop("client_id")
    return {**base, **overrides}


def sign(claims, key=SIGNING_KEY):
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})


def make_request(meta=None, edge_secret=EDGE_SECRET, authenticated_user=None, path="/api/users/me/"):
    request = RequestFactory().get(path)
    request.session = {}
    request.user = authenticated_user or AnonymousUser()
    if edge_secret is not None:
        request.META["HTTP_X_MPASS_EDGE_SECRET"] = edge_secret
    request.META.update(meta or {})
    return request


def proxied(email=VICTIM_EMAIL, token=None, user="mpass-1"):
    meta = {"HTTP_X_AUTH_REQUEST_EMAIL": email, "HTTP_X_AUTH_REQUEST_USER": user}
    if token is not None:
        meta["HTTP_X_AUTH_REQUEST_ACCESS_TOKEN"] = token
    return meta


def make_middleware(verifier=None):
    get_response = MagicMock(return_value=MagicMock(status_code=200))
    return ProxyAuthMiddleware(get_response, token_verifier=verifier or trusting_verifier())


@pytest.fixture(autouse=True)
def _mpass_settings(settings):
    settings.MPASS_EDGE_SECRET = EDGE_SECRET
    settings.MPASS_COGNITO_ISSUER_URL = ""
    settings.COGNITO_AWS_REGION = ""
    settings.COGNITO_USER_POOL_ID = ""
    settings.MPASS_TOKEN_ISSUER_URL = ""
    settings.MPASS_OIDC_CLIENT_ID = ""
    settings.SMB_CORPORATE_ID = None
    settings.SMB_DEFAULT_WORKSPACE_NAME = None
    settings.SMB_NAME = None
    return settings


# ---------------------------------------------------------------------------
# Edge secret
# ---------------------------------------------------------------------------


class TestRequestIsFromEdge:
    def test_matching_secret_is_trusted(self):
        assert request_is_from_edge(make_request(), EDGE_SECRET) is True

    def test_missing_header_is_not_trusted(self):
        assert request_is_from_edge(make_request(edge_secret=None), EDGE_SECRET) is False

    def test_wrong_secret_is_not_trusted(self):
        assert request_is_from_edge(make_request(edge_secret="x" * 64), EDGE_SECRET) is False

    def test_empty_configured_secret_trusts_nothing(self):
        assert request_is_from_edge(make_request(edge_secret=""), "") is False

    def test_short_configured_secret_trusts_nothing(self):
        assert request_is_from_edge(make_request(edge_secret="short"), "short") is False


@pytest.mark.django_db
class TestForgedHeadersAreIgnored:
    def test_forged_header_without_secret_does_not_log_in(self, caplog):
        middleware = make_middleware()
        request = make_request(meta=proxied(), edge_secret=None)

        with patch(PATCH_USER_LOGIN) as mock_login, caplog.at_level(logging.WARNING):
            middleware(request)

        mock_login.assert_not_called()
        assert not User.objects.filter(email=VICTIM_EMAIL).exists()
        middleware.get_response.assert_called_once_with(request)
        assert "request lacks the edge secret" in caplog.text
        assert "mpass_id=mpass-1" in caplog.text
        assert VICTIM_EMAIL not in caplog.text

    def test_forged_header_with_wrong_secret_does_not_log_in(self):
        middleware = make_middleware()
        request = make_request(meta=proxied(), edge_secret="w" * 64)

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_not_called()

    def test_forged_header_cannot_end_an_existing_session(self, django_user_model):
        owner = django_user_model.objects.create(email="owner@example.com", username="owner")
        middleware = make_middleware()
        request = make_request(meta=proxied(), edge_secret=None, authenticated_user=owner)
        request.session = {"proxy_auth_smb_membership_ensured": True}

        with patch(PATCH_LOGOUT) as mock_logout, patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_logout.assert_not_called()
        mock_login.assert_not_called()
        assert request.user == owner

    @pytest.mark.parametrize("configured", ["", "too-short"])
    def test_unusable_configured_secret_ignores_headers(self, configured, settings, caplog):
        settings.MPASS_EDGE_SECRET = configured
        with caplog.at_level(logging.ERROR):
            middleware = make_middleware()
        request = make_request(meta=proxied(), edge_secret=configured)

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_not_called()
        assert "MPASS_EDGE_SECRET is unset or shorter than 32 characters" in caplog.text

    def test_edge_request_logs_in(self):
        middleware = make_middleware()
        request = make_request(meta=proxied())

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_called_once()
        assert mock_login.call_args.kwargs["user"].email == VICTIM_EMAIL


@pytest.mark.django_db
class TestApiKeyPathUnaffected:
    @pytest.fixture
    def key_owner(self, django_user_model):
        return django_user_model.objects.create(email="key-owner@example.com", username="key-owner")

    @pytest.fixture
    def api_key_client(self, key_owner):
        token = APIToken.objects.create(user=key_owner, label="foss-776", token="plane_api_foss776")
        client = APIClient()
        client.credentials(HTTP_X_API_KEY=token.token)
        return client

    def test_api_key_with_forged_header_authenticates_as_key_owner(self, api_key_client, key_owner):
        response = api_key_client.get(
            "/api/v1/users/me/",
            HTTP_X_AUTH_REQUEST_EMAIL=VICTIM_EMAIL,
        )

        assert response.status_code == 200
        assert response.json()["id"] == str(key_owner.id)
        assert not User.objects.filter(email=VICTIM_EMAIL).exists()

    def test_forged_header_alone_is_unauthorized(self):
        response = APIClient().get("/api/users/me/", HTTP_X_AUTH_REQUEST_EMAIL=VICTIM_EMAIL)

        assert response.status_code == 401
        assert not User.objects.filter(email=VICTIM_EMAIL).exists()


# ---------------------------------------------------------------------------
# Corporate gate with a signature-verified token
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestCorporateGate:
    @pytest.fixture(autouse=True)
    def _gate_on(self, settings):
        settings.SMB_CORPORATE_ID = CORPORATE_ID

    def _run(self, token, verifier=None):
        middleware = make_middleware(verifier)
        request = make_request(meta=proxied(token=token))
        with patch(PATCH_USER_LOGIN) as mock_login:
            response = middleware(request)
        return response, mock_login

    def test_valid_cognito_access_token_logs_in(self):
        response, mock_login = self._run(sign(access_token_claims()))

        mock_login.assert_called_once()
        assert response.status_code == 200

    def test_valid_mpass_resigned_id_token_logs_in(self):
        response, mock_login = self._run(sign(id_token_claims()))

        mock_login.assert_called_once()

    @pytest.mark.parametrize(
        "token_factory, reason",
        [
            (lambda: sign(access_token_claims(), key=OTHER_KEY), "bad_signature"),
            (lambda: sign(access_token_claims(exp=int(time.time()) - 3600)), "expired"),
            (lambda: sign(access_token_claims(iss="https://evil.example")), "untrusted_issuer"),
            (lambda: sign(access_token_claims(client_id="other-client")), "wrong_audience"),
            (lambda: sign(id_token_claims(aud="other-client")), "wrong_audience"),
            (lambda: sign(access_token_claims(token_use="refresh")), "wrong_audience"),
            (lambda: sign(access_token_claims(**{"custom:is_corporate": "false"})), "not_corporate"),
            (lambda: sign(access_token_claims(**{"custom:corporate_id": "corp-999"})), "wrong_organization"),
            (lambda: "not-a-jwt", "malformed"),
            (lambda: jwt.encode(access_token_claims(), "k" * 32, algorithm="HS256"), "invalid"),
        ],
    )
    def test_rejected_tokens_return_403(self, token_factory, reason, caplog):
        with caplog.at_level(logging.WARNING):
            response, mock_login = self._run(token_factory())

        mock_login.assert_not_called()
        assert response.status_code == 403
        assert f"reason={reason}" in caplog.text
        assert VICTIM_EMAIL not in caplog.text
        assert not User.objects.filter(email=VICTIM_EMAIL).exists()

    def test_unsigned_token_is_rejected(self):
        unsigned = jwt.encode(access_token_claims(), None, algorithm="none")

        response, mock_login = self._run(unsigned)

        mock_login.assert_not_called()
        assert response.status_code == 403

    def test_missing_token_returns_403(self, caplog):
        with caplog.at_level(logging.WARNING):
            response, mock_login = self._run(None)

        assert response.status_code == 403
        assert "reason=missing_token" in caplog.text

    def test_unconfigured_verifier_fails_closed(self):
        response, mock_login = self._run(sign(access_token_claims()), verifier=MpassTokenVerifier((), ""))

        mock_login.assert_not_called()
        assert response.status_code == 403


@pytest.mark.django_db
class TestCorporateGateOff:
    def test_unset_corporate_id_logs_in_without_reading_the_token(self):
        verifier = MagicMock()
        middleware = make_middleware(verifier)
        request = make_request(meta=proxied(token="garbage"))

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_called_once()
        verifier.verify.assert_not_called()


# ---------------------------------------------------------------------------
# Verifier units
# ---------------------------------------------------------------------------


class TestMpassTokenVerifier:
    def test_from_settings_trusts_cognito_and_mpass_issuers(self, settings):
        settings.COGNITO_AWS_REGION = "us-east-1"
        settings.COGNITO_USER_POOL_ID = "us-east-1_pool"
        settings.MPASS_TOKEN_ISSUER_URL = MPASS_ISSUER
        settings.MPASS_OIDC_CLIENT_ID = CLIENT_ID
        fetched = []

        verifier = MpassTokenVerifier.from_settings(settings)
        verifier._jwks_client_factory = lambda issuer: (
            fetched.append(issuer) or FakeJwksClient(SIGNING_KEY.public_key())
        )

        assert verifier.verify(sign(access_token_claims()))["sub"] == "sub-1"
        assert verifier.verify(sign(id_token_claims()))["sub"] == "sub-1"
        assert fetched == [COGNITO_ISSUER, MPASS_ISSUER]

    def test_jwks_client_is_cached_per_issuer(self):
        created = []
        verifier = MpassTokenVerifier(
            (COGNITO_ISSUER,),
            CLIENT_ID,
            jwks_client_factory=lambda issuer: created.append(issuer) or FakeJwksClient(SIGNING_KEY.public_key()),
        )

        verifier.verify(sign(access_token_claims()))
        verifier.verify(sign(access_token_claims()))

        assert created == [COGNITO_ISSUER]

    def test_issuer_outside_allowlist_never_fetches_jwks(self):
        factory = MagicMock()
        verifier = MpassTokenVerifier((COGNITO_ISSUER,), CLIENT_ID, jwks_client_factory=factory)

        with pytest.raises(InvalidMpassToken) as excinfo:
            verifier.verify(sign(id_token_claims()))

        assert excinfo.value.reason == "untrusted_issuer"
        factory.assert_not_called()

    def test_jwks_fetch_failure_fails_closed(self):
        class Unreachable:
            def get_signing_key_from_jwt(self, token):
                raise jwt.PyJWKClientConnectionError("down")

        verifier = MpassTokenVerifier((COGNITO_ISSUER,), CLIENT_ID, jwks_client_factory=lambda issuer: Unreachable())

        with pytest.raises(InvalidMpassToken) as excinfo:
            verifier.verify(sign(access_token_claims()))

        assert excinfo.value.reason == "jwks_unavailable"

    def test_missing_required_claim_is_rejected(self):
        claims = access_token_claims()
        claims.pop("iat")

        with pytest.raises(InvalidMpassToken):
            trusting_verifier().verify(sign(claims))

    def test_cognito_issuer_needs_both_parts(self):
        assert cognito_issuer("", "pool") == ""
        assert cognito_issuer("us-east-1", "") == ""

    @pytest.mark.parametrize(
        "claims, expected",
        [
            ({"token_use": "access", "client_id": CLIENT_ID}, True),
            ({"token_use": "id", "aud": CLIENT_ID}, True),
            ({"token_use": "id", "aud": ["x", CLIENT_ID]}, True),
            ({"token_use": "id", "aud": "x"}, False),
            ({"token_use": "access", "aud": CLIENT_ID}, False),
            ({"aud": CLIENT_ID}, False),
        ],
    )
    def test_audience_matches(self, claims, expected):
        assert audience_matches(claims, CLIENT_ID) is expected


class FailingJwksClient:
    def __init__(self, error):
        self.error = error
        self.calls = 0

    def get_signing_key_from_jwt(self, token):
        self.calls += 1
        raise self.error


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class TestCognitoIssuerFromSettings:
    def test_explicit_issuer_wins_and_loses_trailing_slash(self, settings):
        settings.MPASS_COGNITO_ISSUER_URL = COGNITO_ISSUER + "/"
        settings.COGNITO_AWS_REGION = "eu-west-1"
        settings.COGNITO_USER_POOL_ID = "eu-west-1_other"

        assert cognito_issuer_from_settings(settings) == COGNITO_ISSUER

    def test_falls_back_to_region_and_pool(self, settings):
        settings.COGNITO_AWS_REGION = "us-east-1"
        settings.COGNITO_USER_POOL_ID = "us-east-1_pool"

        assert cognito_issuer_from_settings(settings) == COGNITO_ISSUER

    def test_placeholders_are_ignored(self, settings):
        settings.MPASS_COGNITO_ISSUER_URL = "CHANGE_ME_OIDC_BASE_URI"
        settings.COGNITO_AWS_REGION = "CHANGE_ME_COGNITO_AWS_REGION"
        settings.COGNITO_USER_POOL_ID = "CHANGE_ME_COGNITO_USER_POOL_ID"

        assert cognito_issuer_from_settings(settings) == ""

    def test_placeholder_explicit_issuer_falls_back(self, settings):
        settings.MPASS_COGNITO_ISSUER_URL = "CHANGE_ME_OIDC_BASE_URI"
        settings.COGNITO_AWS_REGION = "us-east-1"
        settings.COGNITO_USER_POOL_ID = "us-east-1_pool"

        assert cognito_issuer_from_settings(settings) == COGNITO_ISSUER

    def test_placeholder_client_id_leaves_verifier_unconfigured(self, settings):
        settings.MPASS_COGNITO_ISSUER_URL = COGNITO_ISSUER
        settings.MPASS_OIDC_CLIENT_ID = "CHANGE_ME_OIDC_CLIENT_ID"

        assert MpassTokenVerifier.from_settings(settings).is_configured is False

    def test_explicit_issuer_verifies_tokens(self, settings):
        settings.MPASS_COGNITO_ISSUER_URL = COGNITO_ISSUER
        settings.MPASS_OIDC_CLIENT_ID = CLIENT_ID
        verifier = MpassTokenVerifier.from_settings(settings)
        verifier._jwks_client_factory = lambda issuer: FakeJwksClient(SIGNING_KEY.public_key())

        assert verifier.verify(sign(access_token_claims()))["sub"] == "sub-1"


class TestMisconfiguredGateIsLogged:
    def test_gate_on_without_issuer_logs_error(self, settings, caplog):
        settings.SMB_CORPORATE_ID = CORPORATE_ID
        settings.MPASS_OIDC_CLIENT_ID = CLIENT_ID

        with caplog.at_level(logging.ERROR):
            ProxyAuthMiddleware(MagicMock())

        assert "SMB_CORPORATE_ID is set but no token issuer or client id" in caplog.text

    def test_gate_on_without_client_id_logs_error(self, settings, caplog):
        settings.SMB_CORPORATE_ID = CORPORATE_ID
        settings.MPASS_COGNITO_ISSUER_URL = COGNITO_ISSUER

        with caplog.at_level(logging.ERROR):
            ProxyAuthMiddleware(MagicMock())

        assert "SMB_CORPORATE_ID is set but no token issuer or client id" in caplog.text

    def test_configured_gate_logs_nothing(self, settings, caplog):
        settings.SMB_CORPORATE_ID = CORPORATE_ID
        settings.MPASS_COGNITO_ISSUER_URL = COGNITO_ISSUER
        settings.MPASS_OIDC_CLIENT_ID = CLIENT_ID

        with caplog.at_level(logging.ERROR):
            ProxyAuthMiddleware(MagicMock())

        assert "SMB_CORPORATE_ID is set" not in caplog.text

    def test_gate_off_logs_nothing(self, caplog):
        with caplog.at_level(logging.ERROR):
            ProxyAuthMiddleware(MagicMock())

        assert "SMB_CORPORATE_ID is set" not in caplog.text


class TestJwksFailures:
    @pytest.mark.parametrize(
        "error",
        [ValueError("JWKS body is not JSON"), ConnectionResetError("reset"), OSError("unreachable")],
    )
    def test_fetch_errors_fail_closed(self, error):
        verifier = MpassTokenVerifier(
            (COGNITO_ISSUER,), CLIENT_ID, jwks_client_factory=lambda issuer: FailingJwksClient(error)
        )

        with pytest.raises(InvalidMpassToken) as excinfo:
            verifier.verify(sign(access_token_claims()))

        assert excinfo.value.reason == "jwks_unavailable"

    @pytest.mark.django_db
    def test_non_json_jwks_returns_403_not_500(self, settings):
        settings.SMB_CORPORATE_ID = CORPORATE_ID
        verifier = MpassTokenVerifier(
            (COGNITO_ISSUER,),
            CLIENT_ID,
            jwks_client_factory=lambda issuer: FailingJwksClient(ValueError("not json")),
        )
        middleware = make_middleware(verifier)

        with patch(PATCH_USER_LOGIN) as mock_login:
            response = middleware(make_request(meta=proxied(token=sign(access_token_claims()))))

        mock_login.assert_not_called()
        assert response.status_code == 403

    def test_failed_fetch_is_not_retried_within_backoff(self):
        client = FailingJwksClient(jwt.PyJWKClientConnectionError("down"))
        clock = FakeClock()
        verifier = MpassTokenVerifier(
            (COGNITO_ISSUER,), CLIENT_ID, jwks_client_factory=lambda issuer: client, clock=clock
        )
        token = sign(access_token_claims())

        for _ in range(3):
            with pytest.raises(InvalidMpassToken):
                verifier.verify(token)

        assert client.calls == 1

    def test_fetch_is_retried_after_backoff(self):
        client = FailingJwksClient(jwt.PyJWKClientConnectionError("down"))
        clock = FakeClock()
        verifier = MpassTokenVerifier(
            (COGNITO_ISSUER,), CLIENT_ID, jwks_client_factory=lambda issuer: client, clock=clock
        )
        token = sign(access_token_claims())

        with pytest.raises(InvalidMpassToken):
            verifier.verify(token)
        clock.now += JWKS_FAILURE_BACKOFF_SECONDS
        with pytest.raises(InvalidMpassToken):
            verifier.verify(token)

        assert client.calls == 2

    def test_backoff_is_per_issuer(self):
        clients = {
            COGNITO_ISSUER: FailingJwksClient(jwt.PyJWKClientConnectionError("down")),
            MPASS_ISSUER: FakeJwksClient(SIGNING_KEY.public_key()),
        }
        verifier = MpassTokenVerifier(
            (COGNITO_ISSUER, MPASS_ISSUER), CLIENT_ID, jwks_client_factory=clients.__getitem__, clock=FakeClock()
        )

        with pytest.raises(InvalidMpassToken):
            verifier.verify(sign(access_token_claims()))

        assert verifier.verify(sign(id_token_claims()))["sub"] == "sub-1"
